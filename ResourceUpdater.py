"""
Demonstrates how to use the background scheduler to schedule a job that executes on 3 second
intervals.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import time
import os, sys
import Client
import logging

# basicConfig with logging features to keep my ass out of Scheduler troubles.
logging.basicConfig()


def StartUpdater():
    Client.Updater()

if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(StartUpdater, 'interval', minutes=0.5)
    scheduler.start()
    try:
        # This is here to simulate application activity (which keeps the main thread alive).
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()