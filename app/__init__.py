import logging
import os
from datetime import datetime
from flask import Flask
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from .db import init_db

logger = logging.getLogger(__name__)


def _start_reminder_scheduler(app):
    """
    Start a background APScheduler job that fires every minute.
    For each user whose enabled send_time matches the current HH:MM and who
    hasn't already received today's email, we send the daily study reminder.
    """
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.warning("APScheduler not installed – daily reminders disabled.")
        return

    from .db import get_all_active_reminders, get_daily_study_summary, mark_reminder_sent
    from .email_utils import send_daily_study_reminder

    def _send_due_reminders():
        now_time = datetime.now().strftime("%H:%M")
        today = datetime.now().strftime("%Y-%m-%d")
        db_path = app.config["DATABASE"]

        try:
            reminders = get_all_active_reminders(db_path)
        except Exception as exc:
            logger.error("Failed to fetch reminders: %s", exc)
            return

        for reminder in reminders:
            if reminder["send_time"] != now_time:
                continue
            if reminder.get("last_sent_date") == today:
                continue  # already sent today

            email = reminder["email"]
            full_name = reminder.get("full_name", email.split("@")[0])
            try:
                summary = get_daily_study_summary(db_path, email)
                send_daily_study_reminder(app, email, full_name, summary)
                mark_reminder_sent(db_path, email, today)
                logger.info("Daily reminder sent to %s", email)
            except Exception as exc:
                logger.error("Failed to send reminder to %s: %s", email, exc)

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(_send_due_reminders, "interval", minutes=1, id="daily_reminder")
    scheduler.start()
    logger.info("Daily reminder scheduler started.")


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = str(Path(app.root_path).parent / "data" / "preppulse.db")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
    app.config["RESET_TOKEN_MAX_AGE"] = int(os.getenv("RESET_TOKEN_MAX_AGE", "900"))
    app.config["SMTP_HOST"] = os.getenv("SMTP_HOST", "smtp.gmail.com")
    app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "587"))
    app.config["SMTP_USER"] = os.getenv("SMTP_USER", "")
    app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD", "")
    app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")
    
    # Get Groq API key - explicitly from .env
    groq_key = os.getenv("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
    app.config["GROQ_API_KEY"] = groq_key
    print(f"*** GROQ_API_KEY loaded: {('Yes - ' + str(len(groq_key)) + ' chars') if groq_key else 'No'} ***", flush=True)

    init_db(app)

    # Import routes
    from .routes import main
    app.register_blueprint(main)

    # Start background scheduler for daily study reminders
    _start_reminder_scheduler(app)

    return app
