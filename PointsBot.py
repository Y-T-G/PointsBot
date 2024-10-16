"""Entry point used for either runnning or freezing the bot."""
import pointsbot

while True:
    try:
        pointsbot.run()
    except KeyboardInterrupt as e:
        print('\nShutting down...\n')
        break
