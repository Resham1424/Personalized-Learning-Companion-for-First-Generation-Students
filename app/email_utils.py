import smtplib
from email.message import EmailMessage

from flask import current_app


def send_email(to_email, subject, body):
    host = current_app.config["SMTP_HOST"]
    port = current_app.config["SMTP_PORT"]
    user = current_app.config["SMTP_USER"]
    password = current_app.config["SMTP_PASSWORD"]
    use_tls = current_app.config["SMTP_USE_TLS"]

    if not host or not port or not user or not password:
        raise ValueError("SMTP configuration is incomplete.")

    message = EmailMessage()
    message["From"] = user
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    if use_tls:
        with smtplib.SMTP(host, port) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP_SSL(host, port) as smtp:
            smtp.login(user, password)
            smtp.send_message(message)


# ─────────────────────────────────────────────────────────────────────────────
# Daily study-plan reminder
# ─────────────────────────────────────────────────────────────────────────────

def _build_reminder_html(full_name: str, summary: dict) -> str:
    """Return a styled HTML string for the daily study reminder email."""
    today_str = summary.get("today", "today")
    habits_total = summary.get("habits_total", 0)
    habits_done = summary.get("habits_done_today", 0)
    pending_skills = summary.get("pending_skills", [])
    recent_mock = summary.get("recent_mock")
    iv_sessions = summary.get("interview_sessions", 0)
    iv_accuracy = summary.get("interview_accuracy", 0)

    # --- Habits section ---
    if habits_total:
        habit_bar_pct = int(habits_done / habits_total * 100)
        habits_html = f"""
        <p style="margin:0 0 6px 0; font-size:14px; color:#555;">
            <strong>{habits_done}/{habits_total}</strong> habits checked in today
        </p>
        <div style="background:#e9ecef; border-radius:6px; height:10px; width:100%; margin-bottom:18px;">
            <div style="background:#FF6B35; width:{habit_bar_pct}%; height:10px; border-radius:6px;"></div>
        </div>"""
    else:
        habits_html = (
            '<p style="color:#888; font-size:13px; margin-bottom:18px;">'
            'No habits set up yet – add some on your dashboard!</p>'
        )

    # --- Pending skills section ---
    if pending_skills:
        items_html = "".join(
            f'<li style="margin-bottom:4px; font-size:13px; color:#444;">'
            f'<span style="color:#888; font-size:11px;">[{s["category"]}]</span> {s["label"]}'
            f'</li>'
            for s in pending_skills
        )
        skills_html = f'<ul style="padding-left:18px; margin:0 0 18px 0;">{items_html}</ul>'
    else:
        skills_html = (
            '<p style="color:#22bb66; font-size:13px; margin-bottom:18px;">'
            '&#10003; All skill items checked off – great work!</p>'
        )

    # --- Mock test section ---
    if recent_mock:
        pct = round(recent_mock["score"] / recent_mock["max_score"] * 100, 1) if recent_mock["max_score"] else 0
        mock_html = (
            f'<p style="font-size:13px; color:#444; margin-bottom:18px;">'
            f'Last test: <strong>{recent_mock["test_name"]}</strong> &mdash; '
            f'{recent_mock["score"]}/{recent_mock["max_score"]} ({pct}%) on {recent_mock["date_taken"]}</p>'
        )
    else:
        mock_html = (
            '<p style="color:#888; font-size:13px; margin-bottom:18px;">'
            'No mock tests recorded yet – take one today!</p>'
        )

    # --- Interview section ---
    interview_html = (
        f'<p style="font-size:13px; color:#444; margin-bottom:18px;">'
        f'{iv_sessions} session(s) completed &mdash; overall accuracy '
        f'<strong>{iv_accuracy}%</strong></p>'
    )

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8; padding:30px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#ffffff; border-radius:10px; overflow:hidden;
                      box-shadow:0 2px 8px rgba(0,0,0,.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);
                       padding:28px 36px; text-align:center;">
              <h1 style="margin:0; color:#FF6B35; font-size:26px; letter-spacing:1px;">
                PrepPulse
              </h1>
              <p style="margin:6px 0 0 0; color:#c8d6e5; font-size:14px;">
                Daily Study Reminder &mdash; {today_str}
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:30px 36px;">
              <p style="font-size:16px; color:#222; margin-top:0;">
                Hi <strong>{full_name}</strong> 👋
              </p>
              <p style="font-size:14px; color:#555; margin-bottom:24px;">
                Here's a quick snapshot of your progress to kickstart your study session today.
              </p>

              <!-- Habits -->
              <h3 style="margin:0 0 10px 0; color:#1a1a2e; font-size:15px; border-bottom:2px solid #FF6B35;
                         padding-bottom:6px;">🔥 Daily Habits</h3>
              {habits_html}

              <!-- Pending Skills -->
              <h3 style="margin:0 0 10px 0; color:#1a1a2e; font-size:15px; border-bottom:2px solid #FF6B35;
                         padding-bottom:6px;">📋 Skills to Work On</h3>
              {skills_html}

              <!-- Mock Tests -->
              <h3 style="margin:0 0 10px 0; color:#1a1a2e; font-size:15px; border-bottom:2px solid #FF6B35;
                         padding-bottom:6px;">📝 Mock Tests</h3>
              {mock_html}

              <!-- Interview Practice -->
              <h3 style="margin:0 0 10px 0; color:#1a1a2e; font-size:15px; border-bottom:2px solid #FF6B35;
                         padding-bottom:6px;">🎤 Interview Practice</h3>
              {interview_html}

              <!-- CTA -->
              <div style="text-align:center; margin-top:28px;">
                <a href="#" style="background:#FF6B35; color:#fff; text-decoration:none;
                                   padding:12px 32px; border-radius:6px; font-size:14px;
                                   font-weight:bold; display:inline-block;">
                  Open Dashboard
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f4f6f8; padding:16px 36px; text-align:center;">
              <p style="margin:0; font-size:11px; color:#aaa;">
                You're receiving this because you enabled daily study reminders in PrepPulse.<br>
                You can turn them off anytime from your dashboard settings.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_daily_study_reminder(app, to_email: str, full_name: str, summary: dict):
    """
    Send the daily study-plan HTML email for *to_email*.
    Must be called inside an active Flask application context.
    Raises on SMTP errors so the caller can decide whether to retry.
    """
    host = app.config.get("SMTP_HOST", "")
    port = app.config.get("SMTP_PORT", 587)
    user = app.config.get("SMTP_USER", "")
    password = app.config.get("SMTP_PASSWORD", "")
    use_tls = app.config.get("SMTP_USE_TLS", True)

    if not host or not user or not password:
        raise ValueError("SMTP configuration is incomplete – daily reminder not sent.")

    today_str = summary.get("today", "today")
    subject = f"PrepPulse – Your Daily Study Plan for {today_str}"

    html_body = _build_reminder_html(full_name, summary)
    plain_body = (
        f"Hi {full_name},\n\n"
        f"Here is your PrepPulse daily study reminder for {today_str}.\n\n"
        f"Habits done today: {summary.get('habits_done_today', 0)}/{summary.get('habits_total', 0)}\n"
        f"Pending skill items: {len(summary.get('pending_skills', []))}\n"
        f"Interview sessions: {summary.get('interview_sessions', 0)} "
        f"(accuracy {summary.get('interview_accuracy', 0)}%)\n\n"
        f"Log in to PrepPulse to keep up your streak!\n"
    )

    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(plain_body)
    msg.add_alternative(html_body, subtype="html")

    if use_tls:
        with smtplib.SMTP(host, port) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP_SSL(host, port) as smtp:
            smtp.login(user, password)
            smtp.send_message(msg)
