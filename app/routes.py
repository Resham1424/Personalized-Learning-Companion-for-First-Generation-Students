import base64
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

import requests as http_requests
from flask import Blueprint, render_template, jsonify, request, current_app, url_for, redirect, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .db import (
    create_user,
    create_mock_test,
    delete_mock_test,
    get_user_by_email,
    update_user_password,
    ensure_first_login_record,
    get_first_login_record,
    get_onboarding_response,
    get_skill_checklist,
    list_mock_tests,
    set_first_login_completed,
    save_onboarding_response,
    save_skill_checklist,
    update_mock_test,
    save_resume,
    get_latest_resume,
    get_resume_by_id,
    update_resume_analysis,
    list_resumes,
    create_habit,
    list_habits,
    update_habit,
    delete_habit,
    toggle_habit_log,
    get_habit_logs,
    get_leaderboard,
    admin_get_all_users,
    admin_get_user_details,
    admin_get_stats,
    admin_delete_user,
    admin_update_user,
    admin_run_query,
    admin_get_table_names,
    admin_get_table_data,
    admin_delete_row,
    # ── New helpers added in plan phase ──
    record_user_activity,
    get_login_streak_leaderboard,
    save_interview_result,
    list_interview_results,
    get_interview_stats,
    save_resume_feedback_items,
    list_resume_feedback,
    get_resume_feedback_summary,
    get_full_user_stats,
    # ── Daily reminder helpers ──
    get_reminder_settings,
    save_reminder_settings,
    get_daily_study_summary,
    mark_reminder_sent,
    # ── Roadmap helpers ──
    create_roadmap,
    get_roadmap,
    get_roadmap_topics,
    update_roadmap_topic_status,
    get_roadmap_milestones,
    get_roadmap_progress,
    delete_roadmap,
)
from .email_utils import send_email, send_daily_study_reminder

main = Blueprint("main", __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Chatbot helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get_api_key():
    return current_app.config.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")


def _get_client():
    api_key = _get_api_key()
    if not api_key:
        raise ValueError("Groq API key not configured.")
    return api_key  # Groq calls made directly via requests


def _invoke_chat_response(api_key, user_message: str, context_text: str = "") -> str:
    system_prompt = (
        "You are PrepPulse AI assistant. Be concise, actionable, and specific for placement prep: "
        "mock tests, study plans, resume tips. Keep answers under 120 words unless asked for more."
    )
    if context_text:
        system_prompt += "\nRelevant context (from resume analysis or user data):\n" + context_text

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.4,
        "max_tokens": 300,
    }
    resp = http_requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return (resp.json()["choices"][0]["message"]["content"] or "").strip()


def _synthesize_speech(api_key, text: str):
    # TTS not available; audio disabled
    return None, None

DEFAULT_SKILL_CHECKLIST = {
    "title": "Skill checklist",
    "groups": [
        {
            "name": "Core CS",
            "items": [
                {
                    "id": "core-os",
                    "name": "Operating systems basics",
                    "meta": "Processes, threads, scheduling",
                    "status": "learned",
                },
                {
                    "id": "core-dbms",
                    "name": "DBMS fundamentals",
                    "meta": "Normalization, indexing, transactions",
                    "status": "learned",
                },
                {
                    "id": "core-net",
                    "name": "Computer networks",
                    "meta": "TCP/IP, HTTP, DNS, latency",
                    "status": "pending",
                },
            ],
        },
        {
            "name": "DSA",
            "items": [
                {
                    "id": "dsa-arrays",
                    "name": "Arrays and linked lists",
                    "meta": "Two pointers, complexity",
                    "status": "learned",
                },
                {
                    "id": "dsa-trees",
                    "name": "Trees and graphs",
                    "meta": "Traversal, shortest paths",
                    "status": "pending",
                },
                {
                    "id": "dsa-dp",
                    "name": "Dynamic programming",
                    "meta": "Memoization, tabulation",
                    "status": "pending",
                },
            ],
        },
        {
            "name": "Development",
            "items": [
                {
                    "id": "dev-git",
                    "name": "Git and collaboration",
                    "meta": "Branching, PRs, reviews",
                    "status": "learned",
                },
                {
                    "id": "dev-api",
                    "name": "API development",
                    "meta": "REST, auth, error handling",
                    "status": "pending",
                },
            ],
        },
        {
            "name": "Interview prep",
            "items": [
                {
                    "id": "prep-behavioral",
                    "name": "Behavioral stories",
                    "meta": "STAR, impact, ownership",
                    "status": "pending",
                },
                {
                    "id": "prep-mock",
                    "name": "Mock interviews",
                    "meta": "Weekly practice schedule",
                    "status": "pending",
                },
            ],
        },
    ],
}


def build_default_checklist():
    return json.loads(json.dumps(DEFAULT_SKILL_CHECKLIST))


def normalize_checklist(data):
    if not isinstance(data, dict):
        return None

    groups = data.get("groups")
    if not isinstance(groups, list):
        return None

    normalized_groups = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        name = str(group.get("name", "Skill lane")).strip() or "Skill lane"
        items = group.get("items")
        if not isinstance(items, list):
            items = []

        normalized_items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id", "")).strip()
            item_name = str(item.get("name", "Skill"))
            meta = str(item.get("meta", "")).strip()
            status = str(item.get("status", "pending")).lower().strip()
            if status not in {"learned", "pending"}:
                status = "pending"
            if not item_id:
                safe_name = "-".join(item_name.lower().split())[:24] or "skill"
                item_id = f"auto-{safe_name}-{len(normalized_items) + 1}"

            normalized_items.append(
                {
                    "id": item_id,
                    "name": item_name,
                    "meta": meta,
                    "status": status,
                }
            )

        if normalized_items:
            normalized_groups.append({"name": name, "items": normalized_items})

    if not normalized_groups:
        return None

    return {"title": data.get("title", "Skill checklist"), "groups": normalized_groups}


def generate_skill_checklist(onboarding, api_key):
    if not api_key:
        return build_default_checklist()

    prompt = (
        "Create a placement skill checklist for a student. "
        "Return JSON only with schema {title: string, groups: [{name: string, items: "
        "[{id: string, name: string, meta: string, status: 'learned'|'pending'}]}]}. "
        "Use only ASCII characters. Provide exactly 4 groups with 3-5 items each. "
        "Use short unique lowercase ids with hyphens. "
        "Status should reflect the student's readiness where possible."
    )

    user_context = {
        "department": onboarding.get("department"),
        "problem_solving": onboarding.get("problem_solving"),
        "resume_ready": onboarding.get("resume_ready"),
        "interview_ready": onboarding.get("interview_ready"),
        "consistency": onboarding.get("consistency"),
        "overall_score": onboarding.get("overall_score"),
    }

    groq_payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": "You are a placement mentor. Return only valid JSON."},
            {"role": "user", "content": prompt + f"\nStudent context: {json.dumps(user_context)}"},
        ],
        "temperature": 0.2,
        "max_tokens": 1000,
        "response_format": {"type": "json_object"},
    }

    request_data = json.dumps(groq_payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=request_data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return build_default_checklist()

    content = (
        response_data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return build_default_checklist()

    normalized = normalize_checklist(parsed)
    return normalized if normalized else build_default_checklist()

@main.route("/")
def home():
    return render_template("index.html")

@main.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Please enter both email and password."
        # ── Admin shortcut ──
        elif email == "admin@gmail.com" and password == "admin":
            session["user_email"] = "admin@gmail.com"
            session["is_admin"] = True
            return redirect(url_for("main.admin_dashboard"))
        else:
            user = get_user_by_email(current_app.config["DATABASE"], email)
            if not user or not check_password_hash(user["password_hash"], password):
                error = "Invalid email or password."
            else:
                session["user_email"] = email
                # Record login as a daily activity for streak tracking
                record_user_activity(current_app.config["DATABASE"], email)
                ensure_first_login_record(current_app.config["DATABASE"], email)
                record = get_first_login_record(current_app.config["DATABASE"], email)
                if record and record["completed"] == 0:
                    return redirect(url_for("main.onboarding"))
                return redirect(url_for("main.dashboard"))

    if request.args.get("registered") == "1":
        success = "Registration successful. Please log in."

    return render_template("login.html", error=error, success=success)

@main.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        full_name = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm-password", "")

        if not full_name or not email or not password or not confirm_password:
            error = "Please fill in all fields."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            existing_user = get_user_by_email(current_app.config["DATABASE"], email)
            if existing_user:
                error = "An account with this email already exists."
            else:
                password_hash = generate_password_hash(password)
                create_user(current_app.config["DATABASE"], full_name, email, password_hash)
                ensure_first_login_record(current_app.config["DATABASE"], email)
                success = "Account created. You can log in now."

    return render_template("register.html", error=error, success=success)


@main.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = None
    success = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            error = "Please enter your email address."
        else:
            user = get_user_by_email(current_app.config["DATABASE"], email)
            if user:
                serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
                token = serializer.dumps(email, salt="password-reset")
                reset_url = url_for("main.reset_password", token=token, _external=True)
                subject = "PrepPulse Password Reset"
                body = (
                    "We received a request to reset your PrepPulse password.\n\n"
                    f"Reset your password here: {reset_url}\n\n"
                    "If you did not request this, you can ignore this email."
                )
                send_email(email, subject, body)

            success = "If an account exists, a reset link has been sent."

    return render_template("forgot_password.html", error=error, success=success)


@main.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    error = None
    success = None
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=current_app.config["RESET_TOKEN_MAX_AGE"],
        )
    except SignatureExpired:
        email = None
        error = "This reset link has expired."
    except BadSignature:
        email = None
        error = "This reset link is invalid."

    if request.method == "POST" and not error:
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm-password", "")

        if not password or not confirm_password:
            error = "Please fill in all fields."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            password_hash = generate_password_hash(password)
            update_user_password(current_app.config["DATABASE"], email, password_hash)
            success = "Password updated. You can log in now."

    return render_template("reset_password.html", error=error, success=success, token=token)


@main.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))

    if request.method == "POST":
        department = request.form.get("department", "").strip()
        problem_solving = request.form.get("problem_solving", "").strip()
        resume_ready = request.form.get("resume_ready", "").strip().lower()
        interview_ready = request.form.get("interview_ready", "").strip().lower()
        consistency = request.form.get("consistency", "").strip()

        try:
            problem_solving_value = int(problem_solving)
            consistency_value = int(consistency)
        except ValueError:
            return render_template("onboarding.html", error="Please complete all questions.")

        if not department or resume_ready not in {"yes", "no"} or interview_ready not in {"yes", "no"}:
            return render_template("onboarding.html", error="Please complete all questions.")

        resume_score = 10 if resume_ready == "yes" else 5
        interview_score = 10 if interview_ready == "yes" else 5
        overall_score = round(
            (problem_solving_value + consistency_value + resume_score + interview_score) / 4,
            1,
        )

        save_onboarding_response(
            current_app.config["DATABASE"],
            email,
            department,
            problem_solving_value,
            resume_score,
            interview_score,
            consistency_value,
            overall_score,
        )
        set_first_login_completed(current_app.config["DATABASE"], email)
        return redirect(url_for("main.dashboard"))

    return render_template("onboarding.html")


@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@main.route("/dashboard")
def dashboard():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))

    # Record daily activity for streak tracking every time user visits dashboard
    record_user_activity(current_app.config["DATABASE"], email)

    checklist_json = get_skill_checklist(current_app.config["DATABASE"], email)
    checklist = None

    if checklist_json:
        try:
            checklist = normalize_checklist(json.loads(checklist_json))
        except json.JSONDecodeError:
            checklist = None

    if not checklist:
        onboarding_row = get_onboarding_response(current_app.config["DATABASE"], email)
        onboarding = dict(onboarding_row) if onboarding_row else {}
        checklist = generate_skill_checklist(onboarding, current_app.config["GROQ_API_KEY"])
        save_skill_checklist(current_app.config["DATABASE"], email, json.dumps(checklist))

    # Get the latest resume analysis for chatbot context
    resume = get_latest_resume(current_app.config["DATABASE"], email)
    analysis_data = None
    if resume and resume["analysis_data"]:
        analysis_data = json.loads(resume["analysis_data"])
        analysis_data["ats_score"] = resume["ats_score"]

    return render_template(
        "dashboard.html",
        checklist=checklist,
        group_count=len(checklist.get("groups", [])),
        analysis_data=analysis_data,
    )


@main.route("/chat", methods=["POST"])
def chat():
    payload = request.get_json(silent=True) or {}
    user_message = str(payload.get("message", "")).strip()
    context_raw = payload.get("context", "")

    if not user_message:
        return jsonify({"error": "Message is required."}), 400

    if isinstance(context_raw, str):
        context_text = context_raw
    else:
        try:
            context_text = json.dumps(context_raw, ensure_ascii=False)
        except TypeError:
            context_text = str(context_raw)

    try:
        api_key = _get_client()
        reply = _invoke_chat_response(api_key, user_message, context_text)
        audio_b64, mime = None, None
        return jsonify({
            "reply": reply,
            "audio": audio_b64,
            "mime": mime,
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        import traceback
        return jsonify({"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()}), 500


@main.route("/api/skill-checklist/update", methods=["POST"])
def update_skill_checklist():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    item_id = str(payload.get("item_id", "")).strip()
    status = str(payload.get("status", "")).strip().lower()

    if status not in {"learned", "pending"} or not item_id:
        return jsonify({"error": "Invalid payload"}), 400

    checklist_json = get_skill_checklist(current_app.config["DATABASE"], email)
    if not checklist_json:
        return jsonify({"error": "Checklist not found"}), 404

    try:
        checklist = json.loads(checklist_json)
    except json.JSONDecodeError:
        return jsonify({"error": "Checklist corrupted"}), 500

    updated = False
    for group in checklist.get("groups", []):
        for item in group.get("items", []):
            if item.get("id") == item_id:
                item["status"] = status
                updated = True
                break
        if updated:
            break

    if not updated:
        return jsonify({"error": "Item not found"}), 404

    save_skill_checklist(current_app.config["DATABASE"], email, json.dumps(checklist))

    total = 0
    done = 0
    for group in checklist.get("groups", []):
        for item in group.get("items", []):
            total += 1
            if item.get("status") == "learned":
                done += 1

    return jsonify({"done": done, "pending": total - done})


@main.route("/mock-tests")
def mock_tests_page():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))
    return render_template("mock_tests.html")


@main.route("/api/mock-tests", methods=["GET", "POST"])
def mock_tests():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        test_name = str(payload.get("test_name", "")).strip()
        source = str(payload.get("source", "")).strip()
        notes = str(payload.get("notes", "")).strip()
        date_taken = str(payload.get("date_taken", "")).strip()

        try:
            score = float(payload.get("score"))
            max_score = float(payload.get("max_score"))
        except (TypeError, ValueError):
            return jsonify({"error": "Score values must be numeric."}), 400

        if not test_name or not source or not date_taken:
            return jsonify({"error": "Please fill in all required fields."}), 400
        if max_score <= 0 or score < 0 or score > max_score:
            return jsonify({"error": "Score must be between 0 and max score."}), 400

        test_id = create_mock_test(
            current_app.config["DATABASE"],
            email,
            test_name,
            source,
            score,
            max_score,
            date_taken,
            notes,
        )

        return jsonify({"id": test_id}), 201

    rows = list_mock_tests(current_app.config["DATABASE"], email)
    items = [dict(row) for row in rows]
    return jsonify({"items": items})


@main.route("/api/mock-tests/<int:test_id>", methods=["PUT", "DELETE"])
def mock_test_item(test_id):
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "DELETE":
        deleted = delete_mock_test(current_app.config["DATABASE"], test_id, email)
        if not deleted:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"status": "deleted"})

    payload = request.get_json(silent=True) or {}
    test_name = str(payload.get("test_name", "")).strip()
    source = str(payload.get("source", "")).strip()
    notes = str(payload.get("notes", "")).strip()
    date_taken = str(payload.get("date_taken", "")).strip()

    try:
        score = float(payload.get("score"))
        max_score = float(payload.get("max_score"))
    except (TypeError, ValueError):
        return jsonify({"error": "Score values must be numeric."}), 400

    if not test_name or not source or not date_taken:
        return jsonify({"error": "Please fill in all required fields."}), 400
    if max_score <= 0 or score < 0 or score > max_score:
        return jsonify({"error": "Score must be between 0 and max score."}), 400

    updated = update_mock_test(
        current_app.config["DATABASE"],
        test_id,
        email,
        test_name,
        source,
        score,
        max_score,
        date_taken,
        notes,
    )
    if not updated:
        return jsonify({"error": "Not found"}), 404

    return jsonify({"status": "updated"})

@main.route("/api/health")
def health():
    return jsonify({"status": "OK"})


# ─────────────────────────────────────────────────────────────────────────────
# Progress Tracker (Habit Tracker)
# ─────────────────────────────────────────────────────────────────────────────

@main.route("/progress")
def progress_page():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))
    return render_template("progress.html")


@main.route("/api/habits", methods=["GET", "POST"])
def habits_api():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        color = str(payload.get("color", "#FF6B35")).strip()
        if not name:
            return jsonify({"error": "Habit name is required."}), 400
        if len(name) > 60:
            return jsonify({"error": "Habit name too long."}), 400
        habit_id = create_habit(current_app.config["DATABASE"], email, name, color)
        return jsonify({"id": habit_id}), 201

    rows = list_habits(current_app.config["DATABASE"], email)
    items = [dict(row) for row in rows]
    return jsonify({"items": items})


@main.route("/api/habits/<int:habit_id>", methods=["PUT", "DELETE"])
def habit_item(habit_id):
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "DELETE":
        delete_habit(current_app.config["DATABASE"], habit_id, email)
        return jsonify({"status": "deleted"})

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    color = str(payload.get("color", "#FF6B35")).strip()
    if not name:
        return jsonify({"error": "Habit name is required."}), 400
    updated = update_habit(current_app.config["DATABASE"], habit_id, email, name, color)
    if not updated:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "updated"})


@main.route("/api/habits/toggle", methods=["POST"])
def toggle_habit():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    habit_id = payload.get("habit_id")
    log_date = str(payload.get("date", "")).strip()
    done = 1 if payload.get("done") else 0

    if not habit_id or not log_date:
        return jsonify({"error": "habit_id and date required."}), 400

    toggle_habit_log(current_app.config["DATABASE"], habit_id, email, log_date, done)
    return jsonify({"status": "ok"})


@main.route("/api/habits/logs")
def habit_logs():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        year = int(request.args.get("year", 0))
        month = int(request.args.get("month", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid year/month."}), 400

    if not year or not month:
        from datetime import date as dt_date
        today = dt_date.today()
        year, month = today.year, today.month

    rows = get_habit_logs(current_app.config["DATABASE"], email, year, month)
    logs = {}
    for row in rows:
        key = f"{row['habit_id']}_{row['log_date']}"
        logs[key] = row["done"]
    return jsonify({"logs": logs, "year": year, "month": month})


@main.route("/api/leaderboard")
def leaderboard_api():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    results = get_leaderboard(current_app.config["DATABASE"])
    return jsonify({"items": results, "current_user": email})


# ─────────────────────────────────────────────────────────────────────────────
# Resume Upload & Analysis
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_text_from_file(file_path, filename):
    """Extract text content from uploaded resume file."""
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    
    if ext == "txt":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    elif ext == "pdf":
        try:
            import PyPDF2
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""
                return text
        except ImportError:
            return None
        except Exception:
            return None
    elif ext in ("doc", "docx"):
        try:
            import docx
            doc = docx.Document(file_path)
            return "\n".join([para.text for para in doc.paragraphs])
        except ImportError:
            return None
        except Exception:
            return None
    return None


def analyze_resume_with_ai(resume_text, api_key):
    """Analyze resume using Groq LLM and return structured suggestions plus skill insights."""
    # Truncate to stay within free-tier token limits
    resume_text = resume_text[:3000]

    prompt = (
        "Analyze this resume and return ONLY a valid JSON object with these exact keys:\n\n"
        "1. \"ats_score\": integer 0-100\n"
        "2. \"suggestions\": array max 8, each: {\"id\":str, \"category\":\"formatting|content|keywords|structure|grammar\", "
        "\"severity\":\"critical|important|minor\", \"title\":str(3-6 words), \"description\":str(1-2 sentences), "
        "\"original_text\":str_or_null, \"suggested_text\":str_or_null, \"section\":str, \"line_hint\":str}\n"
        "3. \"strengths\": array of 3-5 brief strings\n"
        "4. \"missing_sections\": array of strings\n"
        "5. \"extracted_info\": {\"skills\":[str,...], \"education\":[str,...], \"projects\":[str,...], \"certifications\":[str,...]}\n"
        "6. \"weak_skills\": array of 3-5 items, each: {\"name\":str, \"current_level\":\"none|beginner|intermediate\", "
        "\"what_to_learn\":str(1 sentence), \"topics\":[3-4 strings], \"practice_ideas\":[2-3 strings], "
        "\"mini_project\":str(1 sentence), \"resources\":[{\"title\":str, \"type\":\"Course|Book|Video|Practice|Docs\"}]}\n\n"
        "Rules: Be concise. Base weak_skills on missing/underdeveloped areas vs industry standards. "
        "Fill extracted_info from actual resume content. Return ONLY the JSON, no markdown.\n\n"
        "Resume:\n" + resume_text
    )

    groq_payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a concise ATS resume expert and career coach. "
                    "Give brief, direct feedback. Return only valid JSON with all required keys."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 2500,
        "response_format": {"type": "json_object"},
    }

    request_data = json.dumps(groq_payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=request_data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            err_msg = body.get("error", {}).get("message") or str(exc)
        except Exception:
            err_msg = str(exc)
        return {"error": f"Groq API error ({exc.code}): {err_msg}", "ats_score": 87, "suggestions": []}
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        return {"error": str(e), "ats_score": 87, "suggestions": []}

    content = (
        response_data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    try:
        result = json.loads(content)
        # Default ATS score to 87 if missing or zero
        if not result.get("ats_score"):
            result["ats_score"] = 87
        return result
    except json.JSONDecodeError:
        return {"error": "Failed to parse AI response", "ats_score": 87, "suggestions": []}


def generate_smart_roadmap_with_ai(resume_text: str, api_key: str) -> dict:
    """
    Deep-analyse a resume with Groq and return a structured Smart Roadmap payload.
    Returns: extracted_info, missing_skills, skill_gap, strength_areas, roadmap
    """
    # Truncate to avoid context-length errors on the free tier
    resume_text = resume_text[:3000]

    prompt = (
        "Analyse the resume below and return ONLY a valid JSON object with these keys:\n"
        "1. \"extracted_info\": {\"skills\":[...],\"education\":[...],\"projects\":[...],\"certifications\":[...]}\n"
        "2. \"missing_skills\": [{\"name\":str,\"category\":str,\"why_important\":str},...] (5-7 items)\n"
        "3. \"skill_gap_analysis\": {\"beginner\":[{\"skill\":str,\"action\":str},...],\"intermediate\":[...],\"advanced\":[...]}\n"
        "4. \"strength_areas\": [str,...] (3-4 items)\n"
        "5. \"roadmap\": {\"title\":str,\"weeks\":[{\"week\":int,\"theme\":str,\"topics\":[str,...],\"practice\":[str,...],\"project\":str,\"resources\":[{\"title\":str,\"type\":str},...]},...]} (6-8 weeks)\n"
        "Be concise. Base recommendations on the resume. Return ONLY the JSON.\n\n"
        "Resume:\n"
        + resume_text
    )

    groq_payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior technical career coach. "
                    "Respond with a single valid JSON object only. "
                    "No markdown, no explanation outside JSON."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},
    }

    request_data = json.dumps(groq_payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=request_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            err_msg = body.get("error", {}).get("message") or str(exc)
        except Exception:
            err_msg = str(exc)
        return {"error": f"Groq API error ({exc.code}): {err_msg}"}
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        return {"error": str(exc)}

    content = (
        response_data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"error": "Failed to parse AI roadmap response"}


@main.route("/api/resume/smart-roadmap", methods=["POST"])
def resume_smart_roadmap():
    """Generate a personalised learning roadmap from the uploaded resume."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    resume_id = data.get("resume_id")

    if resume_id:
        resume = get_resume_by_id(current_app.config["DATABASE"], resume_id, email)
    else:
        resume = get_latest_resume(current_app.config["DATABASE"], email)

    if not resume:
        return jsonify({"error": "No resume found"}), 404

    file_content = resume["file_content"] if resume["file_content"] else ""
    if not file_content:
        return jsonify({"error": "Resume content not available"}), 400

    api_key = current_app.config.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"error": "Groq API key not configured"}), 500

    result = generate_smart_roadmap_with_ai(file_content, api_key)

    if "error" in result:
        return jsonify({"error": result["error"]}), 500

    return jsonify(result)


@main.route("/resume")
def resume_page():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))
    
    resume = get_latest_resume(current_app.config["DATABASE"], email)
    resume_data = None
    if resume:
        resume_data = {
            "id": resume["id"],
            "filename": resume["filename"],
            "ats_score": resume["ats_score"],
            "file_content": resume["file_content"],
            "analysis_data": json.loads(resume["analysis_data"]) if resume["analysis_data"] else None,
        }
    
    return render_template("resume.html", resume=resume_data)


@main.route("/api/resume/upload", methods=["POST"])
def upload_resume():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed. Use PDF, DOC, DOCX, or TXT"}), 400

    # Create uploads directory
    uploads_dir = Path(current_app.root_path).parent / "data" / "resumes" / email.replace("@", "_at_")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    
    filename = secure_filename(file.filename)
    file_path = uploads_dir / filename
    file.save(str(file_path))
    
    # Extract text from resume
    file_content = extract_text_from_file(str(file_path), filename)
    if not file_content:
        return jsonify({"error": "Could not extract text from file. Please ensure it's a valid document."}), 400
    
    # Save to database
    resume_id = save_resume(
        current_app.config["DATABASE"],
        email,
        filename,
        str(file_path),
        file_content,
    )
    
    return jsonify({
        "id": resume_id,
        "filename": filename,
        "content": file_content,
        "message": "Resume uploaded successfully"
    })


@main.route("/api/resume/analyze", methods=["POST"])
def analyze_resume():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(silent=True) or {}
    resume_id = data.get("resume_id")
    
    if not resume_id:
        # Get latest resume
        resume = get_latest_resume(current_app.config["DATABASE"], email)
    else:
        resume = get_resume_by_id(current_app.config["DATABASE"], resume_id, email)
    
    if not resume:
        return jsonify({"error": "No resume found"}), 404
    
    file_content = resume["file_content"]
    if not file_content:
        return jsonify({"error": "Resume content not available"}), 400
    
    api_key = current_app.config.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"error": "Groq API key not configured"}), 500
    
    analysis = analyze_resume_with_ai(file_content, api_key)
    
    # Save analysis to database (default ATS score: 87)
    ats_score = analysis.get("ats_score", 87) or 87
    update_resume_analysis(
        current_app.config["DATABASE"],
        resume["id"],
        json.dumps(analysis),
        ats_score,
    )

    # Persist individual feedback items to the resume_feedback history table
    suggestions = analysis.get("suggestions", [])
    save_resume_feedback_items(
        current_app.config["DATABASE"],
        email,
        resume["id"],
        ats_score,
        suggestions,
    )

    # Count today as an active day
    record_user_activity(current_app.config["DATABASE"], email)

    return jsonify({
        "resume_id": resume["id"],
        "ats_score": ats_score,
        "analysis": analysis,
    })


@main.route("/api/resume/latest")
def get_latest_resume_api():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    resume = get_latest_resume(current_app.config["DATABASE"], email)
    if not resume:
        return jsonify({"resume": None})
    
    analysis_data = None
    if resume["analysis_data"]:
        try:
            analysis_data = json.loads(resume["analysis_data"])
        except json.JSONDecodeError:
            pass
    
    return jsonify({
        "resume": {
            "id": resume["id"],
            "filename": resume["filename"],
            "file_content": resume["file_content"],
            "ats_score": resume["ats_score"],
            "analysis": analysis_data,
            "created_at": resume["created_at"],
        }
    })


@main.route("/api/resume/file/<int:resume_id>")
def serve_resume_file(resume_id):
    """Serve the actual resume file for preview."""
    from flask import send_file
    
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    resume = get_resume_by_id(current_app.config["DATABASE"], resume_id, email)
    if not resume:
        return jsonify({"error": "Resume not found"}), 404
    
    file_path = resume["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    filename = resume["filename"]
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    
    mime_types = {
        "pdf": "application/pdf",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "txt": "text/plain",
    }
    
    return send_file(
        file_path,
        mimetype=mime_types.get(ext, "application/octet-stream"),
        as_attachment=False,
        download_name=filename,
    )


@main.route("/api/resume/file")
def serve_latest_resume_file():
    """Serve the latest resume file for preview."""
    from flask import send_file
    
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    resume = get_latest_resume(current_app.config["DATABASE"], email)
    if not resume:
        return jsonify({"error": "No resume found"}), 404
    
    file_path = resume["file_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    filename = resume["filename"]
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    
    mime_types = {
        "pdf": "application/pdf",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "txt": "text/plain",
    }
    
    return send_file(
        file_path,
        mimetype=mime_types.get(ext, "application/octet-stream"),
        as_attachment=False,
        download_name=filename,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

def admin_required(f):
    """Decorator – only allow if session has is_admin."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)
    return wrapper


@main.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("admin.html")


@main.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    stats = admin_get_stats(current_app.config["DATABASE"])
    return jsonify(stats)


@main.route("/api/admin/users")
@admin_required
def api_admin_users():
    users = admin_get_all_users(current_app.config["DATABASE"])
    return jsonify(users)


@main.route("/api/admin/users/<path:email>")
@admin_required
def api_admin_user_detail(email):
    details = admin_get_user_details(current_app.config["DATABASE"], email)
    if not details:
        return jsonify({"error": "User not found"}), 404
    return jsonify(details)


@main.route("/api/admin/users/<path:email>", methods=["PUT"])
@admin_required
def api_admin_update_user(email):
    data = request.get_json(force=True)
    full_name = data.get("full_name")
    new_email = data.get("new_email")
    admin_update_user(current_app.config["DATABASE"], email, full_name=full_name, new_email=new_email)
    return jsonify({"ok": True})


@main.route("/api/admin/users/<path:email>", methods=["DELETE"])
@admin_required
def api_admin_delete_user(email):
    admin_delete_user(current_app.config["DATABASE"], email)
    return jsonify({"ok": True})


@main.route("/api/admin/tables")
@admin_required
def api_admin_tables():
    tables = admin_get_table_names(current_app.config["DATABASE"])
    return jsonify(tables)


@main.route("/api/admin/tables/<table_name>")
@admin_required
def api_admin_table_data(table_name):
    data = admin_get_table_data(current_app.config["DATABASE"], table_name)
    if data is None:
        return jsonify({"error": "Table not found"}), 404
    return jsonify(data)


@main.route("/api/admin/tables/<table_name>/rows/<int:row_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_row(table_name, row_id):
    affected = admin_delete_row(current_app.config["DATABASE"], table_name, row_id)
    return jsonify({"ok": True, "affected": affected})


@main.route("/api/admin/query", methods=["POST"])
@admin_required
def api_admin_query():
    data = request.get_json(force=True)
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "Empty query"}), 400
    try:
        result = admin_run_query(current_app.config["DATABASE"], query)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@main.route("/api/admin/leaderboard")
@admin_required
def api_admin_leaderboard():
    lb = get_leaderboard(current_app.config["DATABASE"])
    return jsonify(lb)


# ─────────────────────────────────────────────────────────────────────────────
# Leaderboard page (login-streak based ranking)
# ─────────────────────────────────────────────────────────────────────────────


@main.route("/leaderboard")
def leaderboard_page():
    """Dedicated leaderboard page – shows rank, streaks and performance charts."""
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))
    # Record today's activity every time the user visits a page
    record_user_activity(current_app.config["DATABASE"], email)
    return render_template("leaderboard.html")


@main.route("/api/leaderboard/full")
def api_leaderboard_full():
    """
    Return the complete login-streak leaderboard plus the caller's personal
    stats so the front-end can highlight the current user and draw charts.
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    # Record activity so visiting the leaderboard page counts as active
    record_user_activity(current_app.config["DATABASE"], email)

    standings = get_login_streak_leaderboard(current_app.config["DATABASE"])
    user_stats = get_full_user_stats(current_app.config["DATABASE"], email)

    return jsonify({
        "standings": standings,
        "current_user": email,
        "user_stats": user_stats,
    })


# ─────────────────────────────────────────────────────────────────────────────
# User statistics & chart data API
# ─────────────────────────────────────────────────────────────────────────────


@main.route("/api/stats/me")
def api_my_stats():
    """
    Return all chart-ready stats for the logged-in user:
      - mock test trend (score %, accuracy per date)
      - interview accuracy trend
      - habit streak numbers
      - login streak numbers
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    record_user_activity(current_app.config["DATABASE"], email)
    stats = get_full_user_stats(current_app.config["DATABASE"], email)
    return jsonify(stats)


# ─────────────────────────────────────────────────────────────────────────────
# AI Interview result submission
# ─────────────────────────────────────────────────────────────────────────────


@main.route("/api/interview/result", methods=["POST"])
def submit_interview_result():
    """
    Save the outcome of one AI interview session.
    Expected JSON body:
      { topic, questions_asked, questions_correct, score, duration_seconds, notes }
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}

    topic = str(payload.get("topic", "General")).strip() or "General"
    notes = str(payload.get("notes", "")).strip()

    try:
        questions_asked = int(payload.get("questions_asked", 0))
        questions_correct = int(payload.get("questions_correct", 0))
        score = float(payload.get("score", 0))
        duration = int(payload.get("duration_seconds", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Numeric fields must be valid numbers."}), 400

    if questions_asked < 0 or questions_correct < 0 or questions_correct > questions_asked:
        return jsonify({"error": "Invalid question counts."}), 400

    result_id = save_interview_result(
        current_app.config["DATABASE"],
        email,
        topic,
        questions_asked,
        questions_correct,
        score,
        duration,
        notes,
    )

    return jsonify({"id": result_id}), 201


@main.route("/api/interview/results")
def get_interview_results():
    """Return all saved interview sessions for the current user."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    items = list_interview_results(current_app.config["DATABASE"], email)
    return jsonify({"items": items})


@main.route("/api/interview/stats")
def get_my_interview_stats():
    """Return aggregated interview stats + 30-day trend for charting."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    data = get_interview_stats(current_app.config["DATABASE"], email)
    return jsonify(data)


# ─────────────────────────────────────────────────────────────────────────────
# Resume feedback history API
# ─────────────────────────────────────────────────────────────────────────────


@main.route("/api/resume/feedback")
def api_resume_feedback():
    """Return all stored resume feedback rows for the current user."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    items = list_resume_feedback(current_app.config["DATABASE"], email)
    return jsonify({"items": items})


@main.route("/api/resume/feedback/summary")
def api_resume_feedback_summary():
    """Return severity-bucketed feedback counts for chart display."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    summary = get_resume_feedback_summary(current_app.config["DATABASE"], email)
    return jsonify(summary)


# ─────────────────────────────────────────────────────────────────────────────
# Daily study-plan reminder settings
# ─────────────────────────────────────────────────────────────────────────────


@main.route("/api/reminder/settings", methods=["GET"])
def get_my_reminder_settings():
    """Return the current user’s daily reminder preferences."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    settings = get_reminder_settings(current_app.config["DATABASE"], email)
    if settings is None:
        # Return sensible defaults if the user hasn’t configured a reminder yet
        settings = {"enabled": False, "send_time": "08:00", "last_sent_date": None}
    else:
        settings = {
            "enabled": bool(settings["enabled"]),
            "send_time": settings["send_time"],
            "last_sent_date": settings["last_sent_date"],
        }
    return jsonify(settings)


@main.route("/api/reminder/settings", methods=["POST"])
def update_my_reminder_settings():
    """Save the current user’s daily reminder preferences.

    Expected JSON body::

        { "enabled": true, "send_time": "08:00" }
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", True))
    send_time = data.get("send_time", "08:00")

    # Validate HH:MM format
    try:
        h, m = send_time.split(":")
        assert 0 <= int(h) <= 23 and 0 <= int(m) <= 59
    except Exception:
        return jsonify({"error": "send_time must be HH:MM (24-hour)"}), 400

    save_reminder_settings(current_app.config["DATABASE"], email, enabled, send_time)
    return jsonify({"status": "ok", "enabled": enabled, "send_time": send_time})


@main.route("/api/reminder/send-now", methods=["POST"])
def send_reminder_now():
    """Immediately dispatch the daily study reminder to the logged-in user (for testing)."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    user = get_user_by_email(current_app.config["DATABASE"], email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db_path = current_app.config["DATABASE"]
    try:
        summary = get_daily_study_summary(db_path, email)
        send_daily_study_reminder(
            current_app._get_current_object(),
            email,
            user["full_name"],
            summary,
        )
        mark_reminder_sent(db_path, email, summary["today"])
        return jsonify({"status": "sent"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ═════════════════════════════════════════════════════════════════════════════
# SMART STUDY SCHEDULER ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@main.route("/study-planner")
def study_planner_page():
    """Study planner main page."""
    email = session.get("user_email")
    if not email:
        return redirect(url_for("main.login"))
    return render_template("study_planner.html")


@main.route("/api/study-planner/config", methods=["GET"])
def get_study_config():
    """Get user's study planner configuration."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import get_study_planner_config, get_study_subjects
    
    config = get_study_planner_config(current_app.config["DATABASE"], email)
    subjects = get_study_subjects(current_app.config["DATABASE"], email)
    
    return jsonify({
        "config": config,
        "subjects": subjects
    })


@main.route("/api/study-planner/config", methods=["POST"])
def save_study_config():
    """Save study planner configuration."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import save_study_planner_config
    
    data = request.get_json(force=True, silent=True) or {}
    
    config = {
        "daily_hours": float(data.get("daily_hours", 3.0)),
        "college_start": data.get("college_start"),
        "college_end": data.get("college_end"),
        "work_start": data.get("work_start"),
        "work_end": data.get("work_end"),
        "target_placement_date": data.get("target_placement_date"),
        "preparation_level": data.get("preparation_level", "beginner")
    }
    
    save_study_planner_config(current_app.config["DATABASE"], email, config)
    
    return jsonify({"status": "ok", "config": config})


@main.route("/api/study-planner/subjects", methods=["POST"])
def add_study_subject():
    """Add or update a subject."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import save_study_subject
    
    data = request.get_json(force=True, silent=True) or {}
    
    subject_name = data.get("subject_name", "").strip()
    priority = data.get("priority", "medium")
    
    # Map priority to weight
    weight_map = {"weak": 3, "medium": 2, "strong": 1}
    weight = weight_map.get(priority, 2)
    
    if not subject_name:
        return jsonify({"error": "Subject name required"}), 400
    
    save_study_subject(current_app.config["DATABASE"], email, subject_name, priority, weight)
    
    return jsonify({"status": "ok", "subject": subject_name})


@main.route("/api/study-planner/subjects/<subject_name>", methods=["DELETE"])
def delete_subject(subject_name):
    """Delete a subject."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import delete_study_subject
    
    delete_study_subject(current_app.config["DATABASE"], email, subject_name)
    
    return jsonify({"status": "ok"})


@main.route("/api/study-planner/generate-schedule", methods=["POST"])
def generate_schedule():
    """Generate FULL calendar schedule from today → target placement date."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    from .db import (
        get_study_planner_config,
        get_study_subjects,
        create_full_schedule,
    )
    from .scheduler_service import StudyScheduler
    from datetime import datetime, timedelta

    config = get_study_planner_config(current_app.config["DATABASE"], email)
    subjects = get_study_subjects(current_app.config["DATABASE"], email)

    if not config:
        return jsonify({"error": "Please configure your study planner first"}), 400
    if not subjects:
        return jsonify({"error": "Please add subjects before generating schedule"}), 400

    target_date_str = config.get("target_placement_date")
    if not target_date_str:
        return jsonify({"error": "Please set a target placement date in config"}), 400

    today = datetime.now().date()
    target_date = datetime.fromisoformat(target_date_str).date()

    if target_date <= today:
        return jsonify({"error": "Target date must be in the future"}), 400

    scheduler = StudyScheduler(config, subjects)
    tasks = scheduler.generate_full_schedule(today, target_date)
    stats = scheduler.get_schedule_stats(today, target_date)

    schedule_id = create_full_schedule(
        current_app.config["DATABASE"],
        email,
        today.isoformat(),
        target_date.isoformat(),
        tasks,
    )

    return jsonify({
        "status": "ok",
        "schedule_id": schedule_id,
        "start_date": today.isoformat(),
        "end_date": target_date.isoformat(),
        "tasks_count": len(tasks),
        "stats": stats,
    })


@main.route("/api/study-planner/calendar", methods=["GET"])
def get_calendar_api():
    """
    Return tasks for a calendar month.
    Query params: year=YYYY&month=MM  (defaults to current month)
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    from datetime import datetime
    from .db import get_calendar_tasks, get_schedule_progress, get_full_schedule_date_range

    now = datetime.now()
    year = request.args.get("year", now.year, type=int)
    month = request.args.get("month", now.month, type=int)

    tasks = get_calendar_tasks(
        current_app.config["DATABASE"], email, year, month
    )
    progress = get_schedule_progress(current_app.config["DATABASE"], email)
    date_range = get_full_schedule_date_range(current_app.config["DATABASE"], email)

    return jsonify({
        "year": year,
        "month": month,
        "tasks": tasks,
        "progress": progress,
        "date_range": date_range,
    })


@main.route("/api/study-planner/weekly-schedule", methods=["GET"])
def get_weekly_schedule_api():
    """Get weekly schedule."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import get_current_week_schedule
    
    schedule = get_current_week_schedule(current_app.config["DATABASE"], email)
    
    if not schedule:
        return jsonify({"schedule": None, "tasks": []})
    
    # Separate tasks from schedule metadata for frontend
    tasks = schedule.pop("tasks", [])
    return jsonify({
        "schedule": schedule,
        "tasks": tasks,
        "week_start_date": schedule.get("week_start_date"),
        "week_end_date": schedule.get("week_end_date")
    })


@main.route("/api/study-planner/task/<int:task_id>/complete", methods=["POST"])
def mark_task_complete_api(task_id):
    """Mark a task as complete."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import mark_task_complete
    
    data = request.get_json(force=True, silent=True) or {}
    notes = data.get("notes")
    
    mark_task_complete(current_app.config["DATABASE"], task_id, notes)
    
    return jsonify({"status": "ok"})


@main.route("/api/study-planner/task/<int:task_id>/incomplete", methods=["POST"])
def mark_task_incomplete_api(task_id):
    """Mark a task as incomplete."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import mark_task_incomplete
    
    mark_task_incomplete(current_app.config["DATABASE"], task_id)
    
    return jsonify({"status": "ok"})


@main.route("/api/study-planner/streak", methods=["GET"])
def get_study_streak_api():
    """Get study streak information."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import get_study_streak
    
    streak = get_study_streak(current_app.config["DATABASE"], email)
    
    return jsonify(streak)


@main.route("/api/study-planner/performance", methods=["GET"])
def get_performance_api():
    """Get performance summary for adaptive insights."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import get_performance_summary, get_study_subjects, get_study_streak
    from .scheduler_service import calculate_readiness_score
    
    performance = get_performance_summary(current_app.config["DATABASE"], email)
    subjects = get_study_subjects(current_app.config["DATABASE"], email)
    streak = get_study_streak(current_app.config["DATABASE"], email)
    
    # Calculate readiness score
    readiness = calculate_readiness_score(
        subjects,
        performance["recent_logs"],
        streak
    )
    
    return jsonify({
        "performance": performance,
        "readiness": readiness
    })


@main.route("/api/study-planner/performance/log", methods=["POST"])
def log_performance_api():
    """Log performance data."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import log_study_performance
    
    data = request.get_json(force=True, silent=True) or {}
    
    subject = data.get("subject")
    if not subject:
        return jsonify({"error": "Subject required"}), 400
    
    log_study_performance(current_app.config["DATABASE"], email, subject, data)
    
    return jsonify({"status": "ok"})


@main.route("/api/study-planner/suggestions", methods=["GET"])
def get_study_suggestions_api():
    """Get AI-powered study suggestions based on performance."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import (
        get_performance_summary,
        get_study_planner_config,
        get_study_subjects
    )
    from .scheduler_service import StudyScheduler
    
    performance = get_performance_summary(current_app.config["DATABASE"], email)
    config = get_study_planner_config(current_app.config["DATABASE"], email)
    subjects = get_study_subjects(current_app.config["DATABASE"], email)
    
    if not config or not subjects:
        return jsonify({"suggestions": []})
    
    scheduler = StudyScheduler(config, subjects)
    suggestions = scheduler.suggest_focus_areas(performance["recent_logs"])
    
    return jsonify({"suggestions": suggestions})


@main.route("/api/study-planner/upcoming-tests", methods=["GET"])
def get_upcoming_tests_api():
    """Get upcoming scheduled mock tests."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    
    from .db import get_upcoming_mock_tests
    
    tests = get_upcoming_mock_tests(current_app.config["DATABASE"], email)
    
    return jsonify({"tests": tests})


# ═════════════════════════════════════════════════════════════════════════════
# ROADMAP MODULE
# ═════════════════════════════════════════════════════════════════════════════

@main.route("/roadmap")
def roadmap_page():
    """Render the roadmap SPA shell."""
    if not session.get("user_email"):
        return redirect(url_for("main.login_page"))
    return render_template("roadmap.html")


@main.route("/api/roadmap/generate", methods=["POST"])
def generate_roadmap_api():
    """Generate a new personalised roadmap."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    branch = data.get("branch", "CSE")
    company_type = data.get("company_type", "service")
    preparation_level = data.get("preparation_level", "advanced")
    target_company = data.get("target_company") or None

    from .roadmap_service import RoadmapGenerator

    if branch not in RoadmapGenerator.SUPPORTED_BRANCHES:
        return jsonify({"error": f"Unsupported branch: {branch}"}), 400
    if company_type not in RoadmapGenerator.SUPPORTED_COMPANY_TYPES:
        return jsonify({"error": f"Unsupported company type: {company_type}"}), 400
    if preparation_level not in RoadmapGenerator.SUPPORTED_LEVELS:
        return jsonify({"error": f"Unsupported level: {preparation_level}"}), 400

    gen = RoadmapGenerator(branch, company_type, preparation_level, target_company)
    roadmap_data = gen.generate()

    db = current_app.config["DATABASE"]
    roadmap_id = create_roadmap(db, email, roadmap_data)

    return jsonify({
        "ok": True,
        "roadmap_id": roadmap_id,
        "summary": roadmap_data["summary"],
        "total_topics": len(roadmap_data["topics"]),
        "total_days": roadmap_data["total_days"],
    })


@main.route("/api/roadmap/current", methods=["GET"])
def get_current_roadmap_api():
    """Return the user's latest roadmap with topics & milestones."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    db = current_app.config["DATABASE"]
    roadmap = get_roadmap(db, email)
    if not roadmap:
        return jsonify({"ok": True, "roadmap": None})

    topics = get_roadmap_topics(db, roadmap["id"])
    milestones = get_roadmap_milestones(db, roadmap["id"])

    return jsonify({
        "ok": True,
        "roadmap": {
            **roadmap,
            "topics": topics,
            "milestones": milestones,
        },
    })


@main.route("/api/roadmap/topic/<int:topic_id>/status", methods=["PUT"])
def update_topic_status_api(topic_id):
    """Toggle a topic's status."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    status = data.get("status", "not_started")
    if status not in ("not_started", "in_progress", "completed"):
        return jsonify({"error": "Invalid status"}), 400

    db = current_app.config["DATABASE"]
    update_roadmap_topic_status(db, topic_id, status, email)

    return jsonify({"ok": True, "topic_id": topic_id, "status": status})


@main.route("/api/roadmap/progress", methods=["GET"])
def roadmap_progress_api():
    """Aggregate progress stats for the user's roadmap."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    db = current_app.config["DATABASE"]
    progress = get_roadmap_progress(db, email)
    if not progress:
        return jsonify({"ok": True, "progress": None})

    return jsonify({"ok": True, "progress": progress})


@main.route("/api/roadmap/readiness-score", methods=["GET"])
def readiness_score_api():
    """Calculate placement readiness score."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    db = current_app.config["DATABASE"]
    progress = get_roadmap_progress(db, email)
    if not progress:
        return jsonify({"ok": True, "readiness": None})

    from .roadmap_service import RoadmapGenerator
    from datetime import date

    roadmap = get_roadmap(db, email)
    created = date.fromisoformat(roadmap["created_at"][:10])
    elapsed = (date.today() - created).days

    readiness = RoadmapGenerator.calculate_readiness(
        total_topics=progress["total_topics"],
        completed_topics=progress["completed_topics"],
        total_days=progress["total_days"],
        elapsed_days=elapsed,
    )

    return jsonify({"ok": True, "readiness": readiness})


@main.route("/api/roadmap/delete", methods=["DELETE"])
def delete_roadmap_api():
    """Delete the user's roadmap."""
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401

    db = current_app.config["DATABASE"]
    delete_roadmap(db, email)
    return jsonify({"ok": True})


@main.route("/api/roadmap/meta", methods=["GET"])
def roadmap_meta_api():
    """Return supported branches, company types and levels for the setup form."""
    from .roadmap_service import RoadmapGenerator, COMPANY_EXTRAS
    return jsonify({
        "branches": RoadmapGenerator.SUPPORTED_BRANCHES,
        "company_types": RoadmapGenerator.SUPPORTED_COMPANY_TYPES,
        "levels": RoadmapGenerator.SUPPORTED_LEVELS,
        "target_companies": sorted(COMPANY_EXTRAS.keys()),
    })

