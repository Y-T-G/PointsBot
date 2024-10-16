import logging
import re
import sys
from collections import namedtuple
from logging.handlers import RotatingFileHandler

import praw
import prawcore

from . import config, database, level, reply

### Globals ###

USER_AGENT = 'PointsBot (by u/JustSomeStuffIDid)'

# The pattern that determines whether a post is marked as helpful
THANKED_PATTERN = re.compile(r'\b([Tt]hanks)(?!\s+to)\b|([Tt]hank [Yy]ou)|\b([Tt]y)\b|\b([Tt]hx)\b')
MOD_THANKED_PATTERN = re.compile('/[Hh]elped')
MOD_REMOVE_PATTERN = re.compile('/[Rr]emove[Pp]oint')


### Main Function ###


def run():
    print_welcome_message()

    cfg = config.load()

    file_handler = RotatingFileHandler(cfg.log_path, maxBytes=1024*1024, backupCount=3, encoding='utf-8')
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)

    logging.basicConfig(handlers=[file_handler, console_handler],
                        level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s:%(module)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    levels = cfg.levels
    db = database.Database(cfg.database_path)

    # Run indefinitely, reconnecting any time a connection is lost
    while True:
        try:
            reddit = praw.Reddit(client_id=cfg.client_id,
                                 client_secret=cfg.client_secret,
                                 username=cfg.username,
                                 password=cfg.password,
                                 user_agent=USER_AGENT)
            logging.info('Connected to Reddit as %s', reddit.user.me())
            access_type = 'read-only' if reddit.read_only else 'write'
            logging.info(f'Has {access_type} access to Reddit')

            subreddit = reddit.subreddit(cfg.subreddit)
            logging.info('Watching subreddit %s', subreddit.title)
            is_mod = subreddit.moderator(redditor=reddit.user.me())
            logging.info(f'Is {"" if is_mod else "NOT "}moderator for subreddit')

            monitor_comments(reddit, subreddit, db, levels, cfg)

        # Ignoring other potential exceptions for now, since we may not be able
        # to recover from them as well as from these ones
        except prawcore.exceptions.RequestException as e:
            logging.error('Unable to connect to Reddit')
            logging.error('Error message: %s', e)
            logging.error('Trying again')
        except prawcore.exceptions.ServerError as e:
            logging.error('Lost connection to Reddit')
            logging.error('Error message: %s', e)
            logging.error('Attempting to reconnect')


def monitor_comments(reddit, subreddit, db, levels, cfg):
    """Monitor new comments in the subreddit, looking for confirmed awards."""
    # Passing pause_after=0 will bypass the internal exponential delay, but have
    # to check if any comments are returned after each query
    for comm in subreddit.stream.comments(skip_existing=True, pause_after=0):
        if comm is None:
            continue
        if comm.author == reddit.user.me():
            logging.info('Comment was posted by this bot')
            continue
        if comm.author.name == reddit.user.me().name:
            logging.info('Comment was posted by this bot name')
            continue

        logging.info('Found comment')
        logging.debug('Comment author: "%s"', comm.author.name)
        logging.debug('Comment text: "%s"', comm.body)

        award_point, remove_point, is_mod_command = awards_point(comm)
        if award_point:
            logging.info('Comment marks awards point')
        elif remove_point:
            logging.info('Comment removes point')
        else:
            # Skip this comment
            logging.info('Comment does not have a valid command')
            continue

        if is_mod_command:
            logging.info('Comment was submitted by mod')
        elif is_valid_tag(comm, cfg.tags):
            logging.info('Comment has a valid tag')

        helper, helper_comment = find_helper_and_comment(comm)
        helper_has_already_helped = db.has_already_helped_once(helper_comment.submission, helper)
        if not remove_point and helper_has_already_helped:
            logging.info('User "%s" has already been awarded for this submission once', helper.name)
            logging.info('No additional points awarded')
            continue

        if remove_point:
            db.soft_remove_point_for_answer(comm.submission, helper, comm.author, comm)
            logging.info('Removed point for user "%s"', helper.name)
        else:
            logging.info('Post awarded')
            logging.debug('Helper comment:')
            logging.debug('Author: %s', helper_comment.author.name)
            logging.debug('Body:   %s', helper_comment.body)
            db.add_point_for_answer(comm.submission, helper, helper_comment, comm.author, comm)
            logging.info('Added point for user "%s"', helper.name)

        points = db.get_points(helper)
        logging.info('Total points for user "%s": %d', helper.name, points)
        if points > 0:
            level_info = level.user_level_info(points, levels)
        else:
            level_info = None

        # Reply to the comment thanking the helper
        reply_body = reply.make(helper,
                                points,
                                level_info,
                                feedback_url=cfg.feedback_url,
                                scoreboard_url=cfg.scoreboard_url,
                                is_add=not remove_point)
        try:
            comm.reply(reply_body)
            logging.info('Replied to the comment')
            logging.debug('Reply body: %s', reply_body)
        except praw.exceptions.APIException as e:
            logging.error('Unable to reply to comment: %s', e)
            if remove_point:
                db.add_back_point_for_answer(comm.submission, helper)
                logging.error('Re-added point that was just removed from user "%s"', helper.name)
            else:
                db.remove_point_and_delete_answer(comm.submission, helper)
                logging.error('Removed point that was just awarded to user "%s"', helper.name)
            logging.error('Skipping comment')
            continue

        # Check if (non-mod) user flair should be updated to new level
        if level_info and level_info.current and level_info.current.points == points:
            lvl = level_info.current
            logging.info('User reached level: %s', lvl.name)
            if not subreddit.moderator(redditor=helper):
                logging.info('User is not mod; setting flair')
                logging.info('Flair text: %s', lvl.name)
                logging.info('Flair template ID: %s', lvl.flair_template_id)
                subreddit.flair.set(helper,
                                    text=lvl.name,
                                    flair_template_id=lvl.flair_template_id)
            else:
                logging.info('helper is mod; don\'t alter flair')


### Reddit Comment Functions ###

AnswerResponseRule = namedtuple('AnswerResponseRule',
                                  'description success_msg failure_msg check')

OP_RESPONSE_RULES = [
    AnswerResponseRule(
        'user "thanked" pattern',
        '[PASS] Comment contains user "thanked" pattern',
        '[FAIL] Comment does not contain user "thanked" pattern',
        lambda c: THANKED_PATTERN.search(c.body),
    ),
    AnswerResponseRule(
        'is a reply (not top-level)',
        '[PASS] Comment is a reply to another comment',
        '[FAIL] Comment is a top-level comment',
        lambda c: not c.is_root,
    ),
    AnswerResponseRule(
        'author is OP',
        '[PASS] Comment author is thread OP',
        '[FAIL] Comment author is not thread OP',
        lambda c: c.is_submitter,
    ),
    AnswerResponseRule(
        "OP of thread can't be awarded",
        '[PASS] Thanked comment author is different from thread author',
        "[FAIL] Thread author is thanking themselves",
        lambda c: not c.is_root and not c.parent().is_submitter,
    ),
    AnswerResponseRule(
        "Mod can't be awarded",
        '[PASS] Thanked comment author is not mod',
        "[FAIL] Thanked comment author is a mod",
        lambda c: not is_mod_comment(c.parent()),
    ),
]

MOD_RESPONSE_RULES = [
    AnswerResponseRule(
        'contains mod "thanked" pattern',
        '[PASS] Comment contains mod "thanked" pattern',
        '[FAIL] Comment does not contain mod "thanked" pattern',
        lambda c: MOD_THANKED_PATTERN.search(c.body),
    ),
    AnswerResponseRule(
        'is a reply (not top-level)',
        '[PASS] Comment is a reply to another comment',
        '[FAIL] Comment is a top-level comment',
        lambda c: not c.is_root,
    ),
    AnswerResponseRule(
        'author is mod',
        '[PASS] Comment author is a mod',
        '[FAIL] Comment author is not a mod',
        # TODO Initialize rules in a function so that they can include other functions
        lambda c: is_mod_comment(c),
    ),
]

MOD_REMOVE_RULES = [
    AnswerResponseRule(
        'contains mod "removepoint" pattern',
        '[PASS] Comment contains mod "removepoint" pattern',
        '[FAIL] Comment does not contain mod "removepoint" pattern',
        lambda c: MOD_REMOVE_PATTERN.search(c.body),
    ),
    AnswerResponseRule(
        'is a reply (not top-level)',
        '[PASS] Comment is a reply to another comment',
        '[FAIL] Comment is a top-level comment',
        lambda c: not c.is_root,
    ),
    AnswerResponseRule(
        'author is mod',
        '[PASS] Comment author is a mod',
        '[FAIL] Comment author is not a mod',
        lambda c: is_mod_comment(c),
    ),
]

# GENERAL_RESPONSE_RULES = []


def check_rules(rules, comment):
    all_rules_passed = True
    for rule in rules:
        rule_passed = rule.check(comment)
        logging.info(rule.success_msg if rule_passed else rule.failure_msg)
        all_rules_passed = all_rules_passed and rule_passed
    return all_rules_passed


def awards_point(comment):
    """Return True if the comment meets the criteria for awarding points, False otherwise.
    """
    # TODO should enforce that only one or the other can pass?
    op_rules_pass = check_rules(OP_RESPONSE_RULES, comment)
    if op_rules_pass:
        logging.info('OP awarded point')

    mod_rules_pass = check_rules(MOD_RESPONSE_RULES, comment)
    if mod_rules_pass:
        logging.info('Mod awarded point')

    mod_remove_pass = check_rules(MOD_REMOVE_RULES, comment)
    if mod_remove_pass:
        logging.info('Mod removed point')

    return op_rules_pass or mod_rules_pass, mod_remove_pass, mod_rules_pass or mod_remove_pass


def is_mod_comment(comment):
    return comment.subreddit.moderator(redditor=comment.author)


def is_valid_tag(awarder_comment, valid_tags):
    """Return True if this comments post has one of the allowed tags, False otherwise.
    If there aren't any tags configured, skip this check"""
    if valid_tags is None:
        return True

    submission_title = awarder_comment.submission.title.lower()

    for valid_tag in valid_tags:
        if f"[{valid_tag}]" in submission_title:
            return True

    return False


def find_helper_and_comment(awarder_comment):
    """Determine the redditor responsible for helping."""
    # TODO plz make this better someday
    # return awarder_comment.parent().author
    helper_comment = awarder_comment.parent()
    return helper_comment.author, helper_comment


### Print & Logging Functions ###


def print_welcome_message():
    print_separator_line()
    print('\n*** Welcome to PointsBot! ***\n')
    print_separator_line()
    print('\nThis bot will monitor the subreddit specified in the '
          'configuration file as long as this program is running.')
    print('\nAny Reddit activity that occurs while this program is not running '
          'will be missed. You can work around this by using features '
          'mentioned in the README.')
    print('\nThe output from this program can be referenced if any issues are '
          'to occur, and the relevant error message or crash report can be '
          'sent to the developer by reporting an issue on the Github page.')
    print('\nFuture updates will hopefully resolve these issues, but for the '
          "moment, this is what we've got to work with! :)\n")
    print_separator_line()


def print_separator_line():
    print('#' * 80)

