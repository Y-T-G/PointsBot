import pointsbot

def test_matches():
    positive = ["Thanks bro", "thanks", "ty", "ty.", "Thx!", "Thanks a lot", "Thank you", "thank you"]
    negative = ["thanks to nobody", "humpty", "hanks"]
    assert all([pointsbot.bot.awards_point(c) for c in positive])
    assert not all([pointsbot.bot.awards_point(c) for c in negative])
