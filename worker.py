#!/usr/bin/env python3
"""
Standalone job worker for production.

Use when gunicorn runs multiple web workers — set config worker.enabled_in_web=false
and run this process once:

    export FLASK_SECRET_KEY=...
    cd client && python worker.py

Systemd: see deploy/openworld-worker.service.example
"""
import logging
import os
import signal
import sys
import threading

# Ensure client/ is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] worker: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Prevent main.py from starting an extra in-process thread on import
os.environ["OPENWORLD_WORKER"] = "1"

# Import app module for job loop + config
import main as panel


def main():
    stop = threading.Event()

    def _sig(_signum, _frame):
        logging.info("Signal received, shutting down…")
        stop.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    logging.info(
        "Standalone worker pid=%s poll=%s maint=%ss",
        os.getpid(),
        panel._worker_cfg()["poll_seconds"],
        panel._worker_cfg()["maintenance_seconds"],
    )
    # Run loop in this process (not daemon thread) so signals work cleanly
    panel._jobworker(stop_event=stop)
    logging.info("Exit")


if __name__ == "__main__":
    main()
