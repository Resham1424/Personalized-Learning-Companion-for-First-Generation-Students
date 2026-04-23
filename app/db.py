import json
import sqlite3
from datetime import datetime, date
from pathlib import Path


def init_db(app):
    db_path = Path(app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS first_login (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                completed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS onboarding_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL,
                problem_solving INTEGER NOT NULL,
                resume_ready INTEGER NOT NULL,
                interview_ready INTEGER NOT NULL,
                consistency INTEGER NOT NULL,
                overall_score REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS skill_checklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mock_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                test_name TEXT NOT NULL,
                source TEXT NOT NULL,
                score REAL NOT NULL,
                max_score REAL NOT NULL,
                date_taken TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_content TEXT,
                analysis_data TEXT,
                ats_score REAL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS habits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                color TEXT NOT NULL DEFAULT '#FF6B35',
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS habit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                habit_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                log_date TEXT NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                UNIQUE(habit_id, log_date),
                FOREIGN KEY (habit_id) REFERENCES habits(id) ON DELETE CASCADE
            )
            """
        )

        # ── Login / activity streaks ──────────────────────────────────────────
        # Tracks each day a user is active (login or any API activity).
        # Used to compute daily login streaks shown on the leaderboard.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                activity_date TEXT NOT NULL,
                UNIQUE(email, activity_date)
            )
            """
        )

        # ── AI Interview session results ──────────────────────────────────────
        # Stores question count, correct count and overall score per session.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_interview_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                session_date TEXT NOT NULL DEFAULT (date('now')),
                topic TEXT NOT NULL DEFAULT 'General',
                questions_asked INTEGER NOT NULL DEFAULT 0,
                questions_correct INTEGER NOT NULL DEFAULT 0,
                score REAL NOT NULL DEFAULT 0.0,
                duration_seconds INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # ── Resume feedback history ───────────────────────────────────────────
        # Decoupled from the resumes table so feedback can be versioned
        # without re-uploading the file.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resume_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resume_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                feedback_date TEXT NOT NULL DEFAULT (date('now')),
                ats_score REAL NOT NULL DEFAULT 0.0,
                category TEXT NOT NULL DEFAULT 'general',
                severity TEXT NOT NULL DEFAULT 'minor',
                title TEXT NOT NULL,
                description TEXT,
                section TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (resume_id) REFERENCES resumes(id) ON DELETE CASCADE
            )
            """
        )

        # ── Daily study-plan email reminders ─────────────────────────────────
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_plan_reminders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                send_time TEXT NOT NULL DEFAULT '08:00',
                last_sent_date TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # ── Smart Study Scheduler Tables ──────────────────────────────────────
        
        # User study planner configuration
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_planner_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                daily_hours REAL NOT NULL DEFAULT 3.0,
                college_start TEXT,
                college_end TEXT,
                work_start TEXT,
                work_end TEXT,
                target_placement_date TEXT,
                preparation_level TEXT NOT NULL DEFAULT 'beginner',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # Subject priorities and performance
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'medium',
                weight INTEGER NOT NULL DEFAULT 2,
                total_hours_allocated REAL NOT NULL DEFAULT 0.0,
                hours_completed REAL NOT NULL DEFAULT 0.0,
                performance_score REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(email, subject_name)
            )
            """
        )

        # Weekly schedule generation
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS weekly_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                week_start_date TEXT NOT NULL,
                week_end_date TEXT NOT NULL,
                total_planned_hours REAL NOT NULL DEFAULT 0.0,
                total_completed_hours REAL NOT NULL DEFAULT 0.0,
                completion_percentage REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(email, week_start_date)
            )
            """
        )

        # Individual study tasks
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                schedule_id INTEGER NOT NULL,
                task_date TEXT NOT NULL,
                task_time TEXT NOT NULL,
                subject TEXT NOT NULL,
                topic TEXT NOT NULL,
                task_type TEXT NOT NULL DEFAULT 'study',
                duration_minutes INTEGER NOT NULL DEFAULT 60,
                completed INTEGER NOT NULL DEFAULT 0,
                completed_at TEXT,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (schedule_id) REFERENCES weekly_schedules(id) ON DELETE CASCADE
            )
            """
        )

        # Performance tracking for adaptive scheduling
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_performance_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                log_date TEXT NOT NULL DEFAULT (date('now')),
                mock_score REAL,
                practice_score REAL,
                tasks_completed INTEGER NOT NULL DEFAULT 0,
                tasks_total INTEGER NOT NULL DEFAULT 0,
                study_hours REAL NOT NULL DEFAULT 0.0,
                effectiveness_rating INTEGER,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # Study streak tracking (separate from login streaks)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS study_streaks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                current_streak INTEGER NOT NULL DEFAULT 0,
                best_streak INTEGER NOT NULL DEFAULT 0,
                last_study_date TEXT,
                total_study_days INTEGER NOT NULL DEFAULT 0,
                streak_frozen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # Mock test scheduler integration
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_mock_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                test_name TEXT NOT NULL,
                subject TEXT NOT NULL,
                scheduled_date TEXT NOT NULL,
                scheduled_time TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL DEFAULT 60,
                completed INTEGER NOT NULL DEFAULT 0,
                score REAL,
                completed_at TEXT,
                auto_generated INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # ── Roadmap Module ───────────────────────────────────────────────
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS roadmaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                branch TEXT NOT NULL,
                company_type TEXT NOT NULL,
                company_name TEXT,
                preparation_level TEXT NOT NULL,
                total_days INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS roadmap_topics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                roadmap_id INTEGER NOT NULL,
                topic_name TEXT NOT NULL,
                category TEXT NOT NULL,
                difficulty_level TEXT NOT NULL,
                order_sequence INTEGER NOT NULL,
                estimated_days INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'not_started',
                completed_at TEXT,
                FOREIGN KEY (roadmap_id) REFERENCES roadmaps(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS roadmap_milestones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                roadmap_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                level TEXT NOT NULL,
                after_topic_order INTEGER NOT NULL,
                cumulative_days INTEGER NOT NULL DEFAULT 0,
                reached INTEGER NOT NULL DEFAULT 0,
                reached_at TEXT,
                FOREIGN KEY (roadmap_id) REFERENCES roadmaps(id) ON DELETE CASCADE
            )
            """
        )

        conn.commit()


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_email(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()


def create_user(db_path, full_name, email, password_hash):
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
            (full_name, email, password_hash),
        )
        conn.commit()


def update_user_password(db_path, email, password_hash):
    with get_connection(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (password_hash, email),
        )
        conn.commit()


def get_first_login_record(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT * FROM first_login WHERE email = ?", (email,))
        return cur.fetchone()


def ensure_first_login_record(db_path, email):
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO first_login (email, completed) VALUES (?, 0)",
            (email,),
        )
        conn.commit()


def set_first_login_completed(db_path, email):
    with get_connection(db_path) as conn:
        conn.execute(
            "UPDATE first_login SET completed = 1, updated_at = datetime('now') WHERE email = ?",
            (email,),
        )
        conn.commit()


def save_onboarding_response(
    db_path,
    email,
    department,
    problem_solving,
    resume_ready,
    interview_ready,
    consistency,
    overall_score,
):
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO onboarding_responses
            (email, department, problem_solving, resume_ready, interview_ready, consistency, overall_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                department,
                problem_solving,
                resume_ready,
                interview_ready,
                consistency,
                overall_score,
            ),
        )
        conn.commit()


def get_onboarding_response(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT * FROM onboarding_responses WHERE email = ?", (email,))
        return cur.fetchone()


def get_skill_checklist(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT data FROM skill_checklists WHERE email = ?", (email,))
        row = cur.fetchone()
        return row["data"] if row else None


def save_skill_checklist(db_path, email, data):
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO skill_checklists (email, data, updated_at)
            VALUES (?, ?, datetime('now'))
            """,
            (email, data),
        )
        conn.commit()


def create_mock_test(db_path, email, test_name, source, score, max_score, date_taken, notes):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO mock_tests
            (email, test_name, source, score, max_score, date_taken, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (email, test_name, source, score, max_score, date_taken, notes),
        )
        conn.commit()
        return cur.lastrowid


def list_mock_tests(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM mock_tests
            WHERE email = ?
            ORDER BY date_taken DESC, created_at DESC
            """,
            (email,),
        )
        return cur.fetchall()


def update_mock_test(db_path, test_id, email, test_name, source, score, max_score, date_taken, notes):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE mock_tests
            SET test_name = ?,
                source = ?,
                score = ?,
                max_score = ?,
                date_taken = ?,
                notes = ?,
                updated_at = datetime('now')
            WHERE id = ? AND email = ?
            """,
            (test_name, source, score, max_score, date_taken, notes, test_id, email),
        )
        conn.commit()
        return cur.rowcount


def delete_mock_test(db_path, test_id, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM mock_tests WHERE id = ? AND email = ?",
            (test_id, email),
        )
        conn.commit()
        return cur.rowcount


def save_resume(db_path, email, filename, file_path, file_content):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO resumes (email, filename, file_path, file_content)
            VALUES (?, ?, ?, ?)
            """,
            (email, filename, file_path, file_content),
        )
        conn.commit()
        return cur.lastrowid


def get_latest_resume(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM resumes
            WHERE email = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (email,),
        )
        return cur.fetchone()


def update_resume_analysis(db_path, resume_id, analysis_data, ats_score):
    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE resumes
            SET analysis_data = ?,
                ats_score = ?,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (analysis_data, ats_score, resume_id),
        )
        conn.commit()


def get_resume_by_id(db_path, resume_id, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM resumes WHERE id = ? AND email = ?",
            (resume_id, email),
        )
        return cur.fetchone()


def list_resumes(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT id, filename, ats_score, created_at
            FROM resumes
            WHERE email = ?
            ORDER BY created_at DESC
            """,
            (email,),
        )
        return cur.fetchall()


# ─────────────────────────────────────────────────────────────────────────────
# Habits / Progress Tracker
# ─────────────────────────────────────────────────────────────────────────────


def create_habit(db_path, email, name, color="#FF6B35"):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM habits WHERE email = ?",
            (email,),
        )
        position = cur.fetchone()[0]
        cur = conn.execute(
            "INSERT INTO habits (email, name, color, position) VALUES (?, ?, ?, ?)",
            (email, name, color, position),
        )
        conn.commit()
        return cur.lastrowid


def list_habits(db_path, email):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM habits WHERE email = ? ORDER BY position ASC",
            (email,),
        )
        return cur.fetchall()


def update_habit(db_path, habit_id, email, name, color):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE habits SET name = ?, color = ? WHERE id = ? AND email = ?",
            (name, color, habit_id, email),
        )
        conn.commit()
        return cur.rowcount


def delete_habit(db_path, habit_id, email):
    with get_connection(db_path) as conn:
        conn.execute(
            "DELETE FROM habit_logs WHERE habit_id = ? AND email = ?",
            (habit_id, email),
        )
        conn.execute(
            "DELETE FROM habits WHERE id = ? AND email = ?",
            (habit_id, email),
        )
        conn.commit()
        return 1


def toggle_habit_log(db_path, habit_id, email, log_date, done):
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO habit_logs (habit_id, email, log_date, done)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(habit_id, log_date) DO UPDATE SET done = excluded.done
            """,
            (habit_id, email, log_date, done),
        )
        conn.commit()


def get_habit_logs(db_path, email, year, month):
    with get_connection(db_path) as conn:
        prefix = f"{year:04d}-{month:02d}"
        cur = conn.execute(
            """
            SELECT hl.habit_id, hl.log_date, hl.done
            FROM habit_logs hl
            JOIN habits h ON h.id = hl.habit_id
            WHERE hl.email = ? AND hl.log_date LIKE ?
            ORDER BY hl.log_date
            """,
            (email, f"{prefix}%"),
        )
        return cur.fetchall()


def get_leaderboard(db_path):
    """
    Compute per-user best streak and current streak across ALL habits.
    A "streak day" = a day where the user completed at least one habit.
    Returns list of dicts sorted by best_streak desc.
    """
    with get_connection(db_path) as conn:
        # Get all distinct (email, log_date) where at least one habit was done
        cur = conn.execute(
            """
            SELECT DISTINCT hl.email, hl.log_date
            FROM habit_logs hl
            WHERE hl.done = 1
            ORDER BY hl.email, hl.log_date
            """
        )
        rows = cur.fetchall()

    from datetime import datetime, timedelta

    # Group dates by user
    user_dates = {}
    for row in rows:
        email = row["email"]
        if email not in user_dates:
            user_dates[email] = []
        user_dates[email].append(row["log_date"])

    # Get display names
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT email, full_name FROM users")
        name_map = {r["email"]: r["full_name"] for r in cur.fetchall()}

    # Get habit counts per user
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT email, COUNT(*) as cnt FROM habits GROUP BY email"
        )
        habit_counts = {r["email"]: r["cnt"] for r in cur.fetchall()}

    today_str = datetime.now().strftime("%Y-%m-%d")
    results = []

    for email, dates in user_dates.items():
        sorted_dates = sorted(set(dates))
        if not sorted_dates:
            continue

        # Convert to date objects
        date_objs = []
        for ds in sorted_dates:
            try:
                date_objs.append(datetime.strptime(ds, "%Y-%m-%d").date())
            except ValueError:
                continue

        best_streak = 1
        current_streak = 1
        streak = 1

        for i in range(1, len(date_objs)):
            if (date_objs[i] - date_objs[i - 1]).days == 1:
                streak += 1
            else:
                streak = 1
            if streak > best_streak:
                best_streak = streak

        # Current streak: count backwards from today/yesterday
        today_date = datetime.now().date()
        if date_objs[-1] == today_date or date_objs[-1] == today_date - timedelta(days=1):
            current_streak = 1
            for i in range(len(date_objs) - 2, -1, -1):
                if (date_objs[i + 1] - date_objs[i]).days == 1:
                    current_streak += 1
                else:
                    break
        else:
            current_streak = 0

        results.append({
            "email": email,
            "name": name_map.get(email, email.split("@")[0]),
            "best_streak": best_streak,
            "current_streak": current_streak,
            "total_habits": habit_counts.get(email, 0),
        })

    results.sort(key=lambda x: x["best_streak"], reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Admin helpers
# ─────────────────────────────────────────────────────────────────────────────


def admin_get_all_users(db_path):
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT u.id, u.full_name, u.email, u.created_at,
                   ob.department, ob.overall_score,
                   fl.completed AS onboarding_done
            FROM users u
            LEFT JOIN onboarding_responses ob ON ob.email = u.email
            LEFT JOIN first_login fl ON fl.email = u.email
            ORDER BY u.created_at DESC
            """
        )
        return [dict(r) for r in cur.fetchall()]


def admin_get_user_details(db_path, email):
    """Return everything about a single user."""
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = dict(cur.fetchone()) if cur.fetchone() is None else None

    # re-fetch properly
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT id, full_name, email, created_at FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        user = dict(row) if row else None

    if not user:
        return None

    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT * FROM onboarding_responses WHERE email = ?", (email,))
        row = cur.fetchone()
        onboarding = dict(row) if row else None

        cur = conn.execute("SELECT data FROM skill_checklists WHERE email = ?", (email,))
        row = cur.fetchone()
        checklist = row["data"] if row else None

        cur = conn.execute(
            "SELECT * FROM mock_tests WHERE email = ? ORDER BY date_taken DESC", (email,)
        )
        mock_tests = [dict(r) for r in cur.fetchall()]

        cur = conn.execute(
            "SELECT id, filename, ats_score, created_at FROM resumes WHERE email = ? ORDER BY created_at DESC",
            (email,),
        )
        resumes = [dict(r) for r in cur.fetchall()]

        cur = conn.execute(
            "SELECT * FROM habits WHERE email = ? ORDER BY position", (email,)
        )
        habits = [dict(r) for r in cur.fetchall()]

        cur = conn.execute("SELECT * FROM first_login WHERE email = ?", (email,))
        row = cur.fetchone()
        first_login = dict(row) if row else None

    return {
        "user": user,
        "onboarding": onboarding,
        "checklist": checklist,
        "mock_tests": mock_tests,
        "resumes": resumes,
        "habits": habits,
        "first_login": first_login,
    }


def admin_get_stats(db_path):
    with get_connection(db_path) as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_resumes = conn.execute("SELECT COUNT(*) FROM resumes").fetchone()[0]
        total_mock_tests = conn.execute("SELECT COUNT(*) FROM mock_tests").fetchone()[0]
        total_habits = conn.execute("SELECT COUNT(*) FROM habits").fetchone()[0]
        onboarded = conn.execute(
            "SELECT COUNT(*) FROM first_login WHERE completed = 1"
        ).fetchone()[0]

        # Avg ATS score
        cur = conn.execute("SELECT AVG(ats_score) FROM resumes WHERE ats_score IS NOT NULL")
        avg_ats = cur.fetchone()[0]

        # Avg onboarding score
        cur = conn.execute("SELECT AVG(overall_score) FROM onboarding_responses")
        avg_onboarding = cur.fetchone()[0]

        # Departments breakdown
        cur = conn.execute(
            "SELECT department, COUNT(*) as cnt FROM onboarding_responses GROUP BY department ORDER BY cnt DESC"
        )
        departments = [dict(r) for r in cur.fetchall()]

    return {
        "total_users": total_users,
        "total_resumes": total_resumes,
        "total_mock_tests": total_mock_tests,
        "total_habits": total_habits,
        "onboarded": onboarded,
        "avg_ats": round(avg_ats, 1) if avg_ats else 0,
        "avg_onboarding": round(avg_onboarding, 1) if avg_onboarding else 0,
        "departments": departments,
    }


def admin_delete_user(db_path, email):
    """Delete user and ALL related data."""
    with get_connection(db_path) as conn:
        # get habit ids for cascade
        cur = conn.execute("SELECT id FROM habits WHERE email = ?", (email,))
        habit_ids = [r["id"] for r in cur.fetchall()]
        for hid in habit_ids:
            conn.execute("DELETE FROM habit_logs WHERE habit_id = ?", (hid,))

        conn.execute("DELETE FROM habits WHERE email = ?", (email,))
        conn.execute("DELETE FROM mock_tests WHERE email = ?", (email,))
        conn.execute("DELETE FROM resumes WHERE email = ?", (email,))
        conn.execute("DELETE FROM skill_checklists WHERE email = ?", (email,))
        conn.execute("DELETE FROM onboarding_responses WHERE email = ?", (email,))
        conn.execute("DELETE FROM first_login WHERE email = ?", (email,))
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()


def admin_update_user(db_path, email, full_name=None, new_email=None):
    with get_connection(db_path) as conn:
        if full_name:
            conn.execute("UPDATE users SET full_name = ? WHERE email = ?", (full_name, email))
        if new_email and new_email != email:
            conn.execute("UPDATE users SET email = ? WHERE email = ?", (new_email, email))
            # update all related tables
            for table in ["first_login", "onboarding_responses", "skill_checklists",
                          "mock_tests", "resumes", "habits", "habit_logs"]:
                conn.execute(f"UPDATE {table} SET email = ? WHERE email = ?", (new_email, email))
        conn.commit()


def admin_run_query(db_path, query):
    """Run a raw SQL query (read-only SELECT for safety display, but allows all for admin)."""
    with get_connection(db_path) as conn:
        cur = conn.execute(query)
        if query.strip().upper().startswith("SELECT"):
            cols = [desc[0] for desc in cur.description] if cur.description else []
            rows = [dict(r) for r in cur.fetchall()]
            return {"columns": cols, "rows": rows, "affected": len(rows)}
        else:
            conn.commit()
            return {"columns": [], "rows": [], "affected": cur.rowcount}


def admin_get_table_names(db_path):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [r["name"] for r in cur.fetchall()]


def admin_get_table_data(db_path, table_name):
    """Get all rows from a specific table with column names."""
    # sanitize table name
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table_name,))
        if not cur.fetchone():
            return None
        cur = conn.execute(f'SELECT * FROM "{table_name}" LIMIT 500')
        cols = [desc[0] for desc in cur.description] if cur.description else []
        rows = [dict(r) for r in cur.fetchall()]
        return {"columns": cols, "rows": rows}


def admin_delete_row(db_path, table_name, row_id):
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table_name,))
        if not cur.fetchone():
            return 0
        cur = conn.execute(f'DELETE FROM "{table_name}" WHERE id = ?', (row_id,))
        conn.commit()
        return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# User Activity / Login Streak tracking
# ─────────────────────────────────────────────────────────────────────────────


def record_user_activity(db_path, email):
    """
    Insert today's date for the user into activity log (idempotent via IGNORE).
    Call this on every authenticated request to keep streaks alive.
    """
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO user_activity_log (email, activity_date) VALUES (?, date('now'))",
            (email,),
        )
        conn.commit()


def get_user_activity_dates(db_path, email):
    """Return all distinct activity dates for a user, sorted ascending."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT activity_date FROM user_activity_log WHERE email = ? ORDER BY activity_date ASC",
            (email,),
        )
        return [row["activity_date"] for row in cur.fetchall()]


def compute_login_streaks(date_strings):
    """
    Given a sorted list of 'YYYY-MM-DD' date strings, compute:
      - best_streak   : longest consecutive day chain
      - current_streak: consecutive days ending today or yesterday
    Returns a dict with both values.
    """
    from datetime import datetime, timedelta

    if not date_strings:
        return {"best_streak": 0, "current_streak": 0}

    # Parse and deduplicate
    date_objs = sorted(
        {datetime.strptime(d, "%Y-%m-%d").date() for d in date_strings}
    )

    # Walk through and compute longest chain
    best = 1
    run = 1
    for idx in range(1, len(date_objs)):
        gap = (date_objs[idx] - date_objs[idx - 1]).days
        if gap == 1:
            run += 1
            best = max(best, run)
        else:
            run = 1

    # Current streak: count backwards from today / yesterday
    today = datetime.now().date()
    anchor = date_objs[-1]
    if anchor < today - timedelta(days=1):
        # Last activity was 2+ days ago — streak is broken
        current = 0
    else:
        current = 1
        for idx in range(len(date_objs) - 2, -1, -1):
            if (date_objs[idx + 1] - date_objs[idx]).days == 1:
                current += 1
            else:
                break

    return {"best_streak": best, "current_streak": current}


def get_login_streak_leaderboard(db_path):
    """
    Rank every user by their best login streak.
    Returns a list of dicts sorted by best_streak DESC.
    """
    with get_connection(db_path) as conn:
        # Fetch name map
        cur = conn.execute("SELECT email, full_name FROM users")
        name_map = {r["email"]: r["full_name"] for r in cur.fetchall()}

        # Fetch all activity rows grouped by user
        cur = conn.execute(
            "SELECT email, activity_date FROM user_activity_log ORDER BY email, activity_date"
        )
        rows = cur.fetchall()

    # Group dates per user
    user_dates: dict = {}
    for row in rows:
        user_dates.setdefault(row["email"], []).append(row["activity_date"])

    leaderboard = []
    for email, dates in user_dates.items():
        streaks = compute_login_streaks(dates)
        leaderboard.append(
            {
                "email": email,
                "name": name_map.get(email, email.split("@")[0]),
                "best_streak": streaks["best_streak"],
                "current_streak": streaks["current_streak"],
                "total_active_days": len(set(dates)),
            }
        )

    leaderboard.sort(key=lambda x: x["best_streak"], reverse=True)

    # Attach rank numbers
    for position, entry in enumerate(leaderboard, start=1):
        entry["rank"] = position

    return leaderboard


# ─────────────────────────────────────────────────────────────────────────────
# AI Interview Results
# ─────────────────────────────────────────────────────────────────────────────


def save_interview_result(
    db_path, email, topic, questions_asked, questions_correct, score, duration_seconds=0, notes=""
):
    """Persist one AI interview session outcome."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO ai_interview_results
            (email, topic, questions_asked, questions_correct, score, duration_seconds, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (email, topic, questions_asked, questions_correct, score, duration_seconds, notes),
        )
        conn.commit()
        return cur.lastrowid


def list_interview_results(db_path, email):
    """Return all interview sessions for a user, newest first."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM ai_interview_results
            WHERE email = ?
            ORDER BY session_date DESC, created_at DESC
            """,
            (email,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_interview_stats(db_path, email):
    """
    Aggregate statistics across all interview sessions for a user:
      - total_sessions
      - total_questions
      - total_correct
      - overall_accuracy (%)
      - avg_score
      - Trend: last-7-days questions and accuracy for charting
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT
                COUNT(*)                          AS total_sessions,
                COALESCE(SUM(questions_asked), 0) AS total_questions,
                COALESCE(SUM(questions_correct),0)AS total_correct,
                COALESCE(AVG(score), 0)           AS avg_score
            FROM ai_interview_results
            WHERE email = ?
            """,
            (email,),
        )
        agg = dict(cur.fetchone())

        # Daily trend for the last 30 days
        cur = conn.execute(
            """
            SELECT session_date,
                   SUM(questions_asked)   AS day_questions,
                   SUM(questions_correct) AS day_correct,
                   AVG(score)             AS day_avg_score
            FROM ai_interview_results
            WHERE email = ?
              AND session_date >= date('now', '-29 days')
            GROUP BY session_date
            ORDER BY session_date ASC
            """,
            (email,),
        )
        trend = [dict(r) for r in cur.fetchall()]

    total_q = agg["total_questions"]
    total_c = agg["total_correct"]
    accuracy = round((total_c / total_q * 100) if total_q > 0 else 0, 1)

    return {
        "total_sessions": agg["total_sessions"],
        "total_questions": total_q,
        "total_correct": total_c,
        "overall_accuracy": accuracy,
        "avg_score": round(agg["avg_score"], 1),
        "trend": trend,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Resume Feedback History
# ─────────────────────────────────────────────────────────────────────────────


def save_resume_feedback_items(db_path, email, resume_id, ats_score, suggestions):
    """
    Persist each suggestion from an AI analysis run as individual feedback rows.
    Clears old feedback for the same resume_id first so re-analysis stays clean.
    """
    with get_connection(db_path) as conn:
        # Remove stale feedback for this resume before inserting fresh results
        conn.execute(
            "DELETE FROM resume_feedback WHERE resume_id = ? AND email = ?",
            (resume_id, email),
        )
        for item in suggestions:
            conn.execute(
                """
                INSERT INTO resume_feedback
                (resume_id, email, ats_score, category, severity, title, description, section)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resume_id,
                    email,
                    ats_score,
                    item.get("category", "general"),
                    item.get("severity", "minor"),
                    item.get("title", "Suggestion"),
                    item.get("description", ""),
                    item.get("section", "General"),
                ),
            )
        conn.commit()


def list_resume_feedback(db_path, email):
    """Return all feedback entries for a user, newest first."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT rf.*, r.filename
            FROM resume_feedback rf
            JOIN resumes r ON r.id = rf.resume_id
            WHERE rf.email = ?
            ORDER BY rf.created_at DESC
            """,
            (email,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_resume_feedback_summary(db_path, email):
    """
    Count feedback by severity across all resumes for a user.
    Useful for the progress/leaderboard charts.
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM resume_feedback
            WHERE email = ?
            GROUP BY severity
            """,
            (email,),
        )
        rows = {r["severity"]: r["cnt"] for r in cur.fetchall()}

    return {
        "critical": rows.get("critical", 0),
        "important": rows.get("important", 0),
        "minor": rows.get("minor", 0),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Daily study-plan email reminder helpers
# ─────────────────────────────────────────────────────────────────────────────


def get_reminder_settings(db_path, email):
    """Return the reminder row for *email*, or None if not set up yet."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM study_plan_reminders WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def save_reminder_settings(db_path, email, enabled: bool, send_time: str):
    """Upsert reminder preferences (enabled flag and HH:MM send time)."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO study_plan_reminders (email, enabled, send_time, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(email) DO UPDATE SET
                enabled    = excluded.enabled,
                send_time  = excluded.send_time,
                updated_at = excluded.updated_at
            """,
            (email, int(enabled), send_time),
        )
        conn.commit()


def mark_reminder_sent(db_path, email, sent_date: str):
    """Record that the daily reminder was successfully sent on *sent_date* (YYYY-MM-DD)."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE study_plan_reminders
            SET last_sent_date = ?, updated_at = datetime('now')
            WHERE email = ?
            """,
            (sent_date, email),
        )
        conn.commit()


def get_all_active_reminders(db_path):
    """
    Return all enabled reminder rows joined with the user's full_name.
    Used by the scheduler to decide who to email each minute.
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT spr.email,
                   spr.send_time,
                   spr.last_sent_date,
                   u.full_name
            FROM study_plan_reminders spr
            JOIN users u ON u.email = spr.email
            WHERE spr.enabled = 1
            """
        )
        return [dict(r) for r in cur.fetchall()]


def get_daily_study_summary(db_path, email):
    """
    Build a lightweight summary dict used to populate the daily reminder email:
      - habits: list of habit names the user has set up
      - habits_done_today: count done so far today
      - pending_skills: first 5 unchecked skill items across all categories
      - recent_mock: the most recent mock-test entry (or None)
      - interview_stats: total sessions + overall accuracy
    """
    today = date.today().isoformat()

    with get_connection(db_path) as conn:
        # --- Habits ---
        cur = conn.execute(
            "SELECT id, name FROM habits WHERE email = ? ORDER BY position ASC",
            (email,),
        )
        habits = [dict(r) for r in cur.fetchall()]

        done_today = 0
        if habits:
            habit_ids = [h["id"] for h in habits]
            placeholders = ",".join("?" * len(habit_ids))
            cur = conn.execute(
                f"""
                SELECT COUNT(*) AS cnt
                FROM habit_logs
                WHERE email = ? AND log_date = ? AND done = 1
                  AND habit_id IN ({placeholders})
                """,
                [email, today, *habit_ids],
            )
            done_today = cur.fetchone()["cnt"]

        # --- Skill checklist pending items ---
        cur = conn.execute(
            "SELECT data FROM skill_checklists WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()
        pending_skills = []
        if row:
            try:
                checklist = json.loads(row["data"])
                for category, items in checklist.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict) and not item.get("done", False):
                                pending_skills.append(
                                    {"category": category, "label": item.get("label", "")}
                                )
                    elif isinstance(items, dict):
                        for sub_label, sub_items in items.items():
                            if isinstance(sub_items, list):
                                for item in sub_items:
                                    if isinstance(item, dict) and not item.get("done", False):
                                        pending_skills.append(
                                            {
                                                "category": f"{category} – {sub_label}",
                                                "label": item.get("label", ""),
                                            }
                                        )
                    if len(pending_skills) >= 5:
                        break
                pending_skills = pending_skills[:5]
            except (json.JSONDecodeError, AttributeError):
                pass

        # --- Most recent mock test ---
        cur = conn.execute(
            """
            SELECT test_name, score, max_score, date_taken
            FROM mock_tests
            WHERE email = ?
            ORDER BY date_taken DESC, created_at DESC
            LIMIT 1
            """,
            (email,),
        )
        recent_mock_row = cur.fetchone()
        recent_mock = dict(recent_mock_row) if recent_mock_row else None

        # --- Interview stats ---
        cur = conn.execute(
            """
            SELECT COUNT(*) AS sessions,
                   COALESCE(SUM(questions_asked), 0)  AS total_q,
                   COALESCE(SUM(questions_correct), 0) AS total_c
            FROM ai_interview_results
            WHERE email = ?
            """,
            (email,),
        )
        iv = dict(cur.fetchone())
        accuracy = round(iv["total_c"] / iv["total_q"] * 100, 1) if iv["total_q"] > 0 else 0

    return {
        "habits": habits,
        "habits_total": len(habits),
        "habits_done_today": done_today,
        "pending_skills": pending_skills,
        "recent_mock": recent_mock,
        "interview_sessions": iv["sessions"],
        "interview_accuracy": accuracy,
        "today": today,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Combined user stats for the leaderboard / charts page
# ─────────────────────────────────────────────────────────────────────────────


def get_full_user_stats(db_path, email):
    """
    Bundle all per-user chart data into one call:
      - login streak
      - mock test history (score trend + accuracy)
      - interview stats
      - resume feedback summary
      - habit stats (current streak, best streak, total days done)
    """
    activity_dates = get_user_activity_dates(db_path, email)
    login_streaks = compute_login_streaks(activity_dates)

    interview = get_interview_stats(db_path, email)
    resume_summary = get_resume_feedback_summary(db_path, email)

    # Mock test trend for charts
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT date_taken,
                   score,
                   max_score,
                   ROUND(score * 100.0 / max_score, 1) AS pct
            FROM mock_tests
            WHERE email = ?
            ORDER BY date_taken ASC
            """,
            (email,),
        )
        mock_trend = [dict(r) for r in cur.fetchall()]

    # Habit streaks (reuse existing leaderboard logic)
    habit_lb_raw = get_leaderboard(db_path)
    habit_streaks = next(
        (e for e in habit_lb_raw if e["email"] == email),
        {"best_streak": 0, "current_streak": 0, "total_habits": 0},
    )

    return {
        "login_streak": login_streaks,
        "mock_trend": mock_trend,
        "interview": interview,
        "resume_feedback": resume_summary,
        "habit_streaks": habit_streaks,
    }


# ═════════════════════════════════════════════════════════════════════════════
# SMART STUDY SCHEDULER FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════


def get_study_planner_config(db_path, email):
    """Get user's study planner configuration."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM study_planner_config WHERE email = ?", (email,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def save_study_planner_config(db_path, email, config):
    """Save or update study planner configuration."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO study_planner_config 
            (email, daily_hours, college_start, college_end, work_start, work_end, 
             target_placement_date, preparation_level, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(email) DO UPDATE SET
                daily_hours = excluded.daily_hours,
                college_start = excluded.college_start,
                college_end = excluded.college_end,
                work_start = excluded.work_start,
                work_end = excluded.work_end,
                target_placement_date = excluded.target_placement_date,
                preparation_level = excluded.preparation_level,
                updated_at = datetime('now')
            """,
            (
                email,
                config.get("daily_hours", 3.0),
                config.get("college_start"),
                config.get("college_end"),
                config.get("work_start"),
                config.get("work_end"),
                config.get("target_placement_date"),
                config.get("preparation_level", "beginner"),
            ),
        )
        conn.commit()


def get_study_subjects(db_path, email):
    """Get all subjects for a user."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM study_subjects 
            WHERE email = ? 
            ORDER BY weight DESC, subject_name ASC
            """,
            (email,),
        )
        return [dict(r) for r in cur.fetchall()]


def save_study_subject(db_path, email, subject_name, priority, weight):
    """Save or update a subject."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO study_subjects (email, subject_name, priority, weight, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(email, subject_name) DO UPDATE SET
                priority = excluded.priority,
                weight = excluded.weight,
                updated_at = datetime('now')
            """,
            (email, subject_name, priority, weight),
        )
        conn.commit()


def delete_study_subject(db_path, email, subject_name):
    """Delete a subject."""
    with get_connection(db_path) as conn:
        conn.execute(
            "DELETE FROM study_subjects WHERE email = ? AND subject_name = ?",
            (email, subject_name),
        )
        conn.commit()


def get_weekly_schedule(db_path, email, week_start_date):
    """Get weekly schedule for a specific week."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM weekly_schedules WHERE email = ? AND week_start_date = ?",
            (email, week_start_date),
        )
        schedule = cur.fetchone()
        if not schedule:
            return None

        schedule_dict = dict(schedule)
        
        # Get tasks for this schedule
        cur = conn.execute(
            """
            SELECT * FROM study_tasks 
            WHERE schedule_id = ? 
            ORDER BY task_date ASC, task_time ASC
            """,
            (schedule_dict["id"],),
        )
        schedule_dict["tasks"] = [dict(r) for r in cur.fetchall()]
        
        return schedule_dict


def get_current_week_schedule(db_path, email):
    """Get schedule for current week."""
    from datetime import datetime, timedelta
    
    today = datetime.now().date()
    # Get Monday of current week
    week_start = today - timedelta(days=today.weekday())
    
    return get_weekly_schedule(db_path, email, week_start.isoformat())


def create_weekly_schedule(db_path, email, week_start_date, week_end_date, tasks):
    """Create a new weekly schedule with tasks."""
    with get_connection(db_path) as conn:
        # Calculate total planned hours
        total_planned_hours = sum(task["duration_minutes"] for task in tasks) / 60.0
        
        # Create or update schedule
        conn.execute(
            """
            INSERT INTO weekly_schedules 
            (email, week_start_date, week_end_date, total_planned_hours, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(email, week_start_date) DO UPDATE SET
                week_end_date = excluded.week_end_date,
                total_planned_hours = excluded.total_planned_hours,
                updated_at = datetime('now')
            """,
            (email, week_start_date, week_end_date, total_planned_hours),
        )
        # Fetch the schedule_id (compatible with all SQLite versions)
        cur = conn.execute(
            "SELECT id FROM weekly_schedules WHERE email = ? AND week_start_date = ?",
            (email, week_start_date),
        )
        schedule_id = cur.fetchone()[0]
        
        # Delete old tasks if regenerating
        conn.execute("DELETE FROM study_tasks WHERE schedule_id = ?", (schedule_id,))
        
        # Insert tasks
        for task in tasks:
            conn.execute(
                """
                INSERT INTO study_tasks 
                (email, schedule_id, task_date, task_time, subject, topic, 
                 task_type, duration_minutes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    schedule_id,
                    task["date"],
                    task["time"],
                    task["subject"],
                    task["topic"],
                    task.get("type", "study"),
                    task["duration_minutes"],
                ),
            )
        
        conn.commit()
        return schedule_id


def mark_task_complete(db_path, task_id, notes=None):
    """Mark a study task as complete."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE study_tasks 
            SET completed = 1, 
                completed_at = datetime('now'),
                notes = ?,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (notes, task_id),
        )
        conn.commit()
        
        # Update streak
        cur = conn.execute("SELECT email FROM study_tasks WHERE id = ?", (task_id,))
        row = cur.fetchone()
        if row:
            update_study_streak(db_path, row["email"])


def mark_task_incomplete(db_path, task_id):
    """Mark a study task as incomplete."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE study_tasks 
            SET completed = 0, 
                completed_at = NULL,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (task_id,),
        )
        conn.commit()


def get_study_streak(db_path, email):
    """Get study streak information."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM study_streaks WHERE email = ?", (email,)
        )
        row = cur.fetchone()
        if row:
            return dict(row)
        
        # Initialize streak record
        conn.execute(
            """
            INSERT INTO study_streaks (email, current_streak, best_streak)
            VALUES (?, 0, 0)
            """,
            (email,),
        )
        conn.commit()
        return {"current_streak": 0, "best_streak": 0, "total_study_days": 0}


def update_study_streak(db_path, email):
    """Update study streak based on completed tasks."""
    from datetime import datetime, timedelta
    
    with get_connection(db_path) as conn:
        # Get last 30 days of task completion
        cur = conn.execute(
            """
            SELECT DISTINCT task_date, COUNT(*) as completed_count
            FROM study_tasks
            WHERE email = ? AND completed = 1
            GROUP BY task_date
            ORDER BY task_date DESC
            LIMIT 30
            """,
            (email,),
        )
        completed_dates = [row["task_date"] for row in cur.fetchall()]
        
        if not completed_dates:
            conn.execute(
                """
                UPDATE study_streaks 
                SET current_streak = 0, updated_at = datetime('now')
                WHERE email = ?
                """,
                (email,),
            )
            conn.commit()
            return
        
        # Calculate current streak
        today = datetime.now().date()
        current_streak = 0
        check_date = today
        
        for i in range(30):
            date_str = check_date.isoformat()
            if date_str in completed_dates:
                current_streak += 1
                check_date -= timedelta(days=1)
            else:
                break
        
        # Update streak
        cur = conn.execute(
            "SELECT best_streak FROM study_streaks WHERE email = ?", (email,)
        )
        row = cur.fetchone()
        best_streak = row["best_streak"] if row else 0
        best_streak = max(best_streak, current_streak)
        
        conn.execute(
            """
            UPDATE study_streaks 
            SET current_streak = ?,
                best_streak = ?,
                last_study_date = ?,
                total_study_days = ?,
                updated_at = datetime('now')
            WHERE email = ?
            """,
            (current_streak, best_streak, today.isoformat(), len(completed_dates), email),
        )
        conn.commit()


def log_study_performance(db_path, email, subject, data):
    """Log performance data for adaptive scheduling."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO study_performance_logs
            (email, subject, log_date, mock_score, practice_score, 
             tasks_completed, tasks_total, study_hours, effectiveness_rating, notes)
            VALUES (?, ?, date('now'), ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                subject,
                data.get("mock_score"),
                data.get("practice_score"),
                data.get("tasks_completed", 0),
                data.get("tasks_total", 0),
                data.get("study_hours", 0.0),
                data.get("effectiveness_rating"),
                data.get("notes"),
            ),
        )
        conn.commit()


def get_performance_summary(db_path, email):
    """Get performance summary for adaptive scheduling."""
    with get_connection(db_path) as conn:
        # Subject-wise performance
        cur = conn.execute(
            """
            SELECT 
                subject,
                AVG(mock_score) as avg_mock_score,
                AVG(practice_score) as avg_practice_score,
                SUM(tasks_completed) as total_completed,
                SUM(tasks_total) as total_tasks,
                SUM(study_hours) as total_hours,
                AVG(effectiveness_rating) as avg_effectiveness
            FROM study_performance_logs
            WHERE email = ?
            GROUP BY subject
            """,
            (email,),
        )
        subject_performance = [dict(r) for r in cur.fetchall()]
        
        # Recent performance (last 7 days)
        cur = conn.execute(
            """
            SELECT *
            FROM study_performance_logs
            WHERE email = ? 
            AND log_date >= date('now', '-7 days')
            ORDER BY log_date DESC
            """,
            (email,),
        )
        recent_logs = [dict(r) for r in cur.fetchall()]
        
        return {
            "subject_performance": subject_performance,
            "recent_logs": recent_logs,
        }


def schedule_mock_test(db_path, email, test_data):
    """Schedule a mock test."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scheduled_mock_tests
            (email, test_name, subject, scheduled_date, scheduled_time, 
             duration_minutes, auto_generated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                test_data["test_name"],
                test_data["subject"],
                test_data["date"],
                test_data["time"],
                test_data.get("duration_minutes", 60),
                test_data.get("auto_generated", 1),
            ),
        )
        conn.commit()


def get_upcoming_mock_tests(db_path, email):
    """Get upcoming scheduled mock tests."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM scheduled_mock_tests
            WHERE email = ? AND completed = 0
            AND scheduled_date >= date('now')
            ORDER BY scheduled_date ASC, scheduled_time ASC
            """,
            (email,),
        )
        return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# ★ Full-calendar schedule functions
# ─────────────────────────────────────────────────────────────────────────────

def create_full_schedule(db_path, email, start_date, end_date, tasks):
    """
    Create a full-calendar schedule (today → target date).
    Re-uses the weekly_schedules table for the metadata row so that
    the existing study_tasks FK stays valid.
    All previous tasks for this user are deleted first.
    """
    with get_connection(db_path) as conn:
        # Remove any previous full schedules + their tasks for this user
        cur = conn.execute(
            "SELECT id FROM weekly_schedules WHERE email = ?", (email,)
        )
        old_ids = [r["id"] for r in cur.fetchall()]
        for oid in old_ids:
            conn.execute("DELETE FROM study_tasks WHERE schedule_id = ?", (oid,))
        conn.execute("DELETE FROM weekly_schedules WHERE email = ?", (email,))

        total_planned_hours = sum(t["duration_minutes"] for t in tasks) / 60.0

        conn.execute(
            """
            INSERT INTO weekly_schedules
            (email, week_start_date, week_end_date, total_planned_hours, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            """,
            (email, start_date, end_date, total_planned_hours),
        )
        cur = conn.execute(
            "SELECT id FROM weekly_schedules WHERE email = ? AND week_start_date = ?",
            (email, start_date),
        )
        schedule_id = cur.fetchone()[0]

        # Batch insert tasks (100 at a time for perf)
        BATCH = 100
        for i in range(0, len(tasks), BATCH):
            batch = tasks[i : i + BATCH]
            conn.executemany(
                """
                INSERT INTO study_tasks
                (email, schedule_id, task_date, task_time, subject, topic,
                 task_type, duration_minutes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        email,
                        schedule_id,
                        t["date"],
                        t["time"],
                        t["subject"],
                        t["topic"],
                        t.get("type", "study"),
                        t["duration_minutes"],
                    )
                    for t in batch
                ],
            )

        conn.commit()
        return schedule_id


def get_calendar_tasks(db_path, email, year, month):
    """Return all tasks for a given calendar month."""
    start = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end = f"{year + 1:04d}-01-01"
    else:
        end = f"{year:04d}-{month + 1:02d}-01"

    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM study_tasks
            WHERE email = ? AND task_date >= ? AND task_date < ?
            ORDER BY task_date ASC, task_time ASC
            """,
            (email, start, end),
        )
        return [dict(r) for r in cur.fetchall()]


def get_schedule_progress(db_path, email):
    """
    Return overall schedule statistics:
    total tasks, completed tasks, % complete, remaining days, etc.
    """
    with get_connection(db_path) as conn:
        # Schedule metadata
        cur = conn.execute(
            """
            SELECT week_start_date AS start_date, week_end_date AS end_date,
                   total_planned_hours
            FROM weekly_schedules
            WHERE email = ?
            ORDER BY id DESC LIMIT 1
            """,
            (email,),
        )
        meta = cur.fetchone()
        if not meta:
            return None

        meta = dict(meta)

        # Aggregated task counts
        cur = conn.execute(
            """
            SELECT
                COUNT(*)                     AS total_tasks,
                SUM(CASE WHEN completed=1 THEN 1 ELSE 0 END)  AS completed_tasks,
                SUM(duration_minutes)        AS total_minutes,
                SUM(CASE WHEN completed=1 THEN duration_minutes ELSE 0 END) AS completed_minutes,
                COUNT(DISTINCT task_date)    AS scheduled_days
            FROM study_tasks
            WHERE email = ?
            """,
            (email,),
        )
        stats = dict(cur.fetchone())

        total = stats["total_tasks"] or 0
        done = stats["completed_tasks"] or 0
        pct = round((done / total) * 100, 1) if total else 0

        from datetime import datetime
        today = datetime.now().date()
        end_date = datetime.fromisoformat(meta["end_date"]).date()
        remaining_days = max((end_date - today).days, 0)

        return {
            "start_date": meta["start_date"],
            "end_date": meta["end_date"],
            "total_planned_hours": meta["total_planned_hours"],
            "total_tasks": total,
            "completed_tasks": done,
            "completion_pct": pct,
            "remaining_days": remaining_days,
            "total_minutes": stats["total_minutes"] or 0,
            "completed_minutes": stats["completed_minutes"] or 0,
            "scheduled_days": stats["scheduled_days"] or 0,
        }


def get_full_schedule_date_range(db_path, email):
    """Return the (start_date, end_date) of the user's latest full schedule."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT week_start_date AS start_date, week_end_date AS end_date
            FROM weekly_schedules
            WHERE email = ?
            ORDER BY id DESC LIMIT 1
            """,
            (email,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


# ═════════════════════════════════════════════════════════════════════════════
# ROADMAP MODULE – CRUD
# ═════════════════════════════════════════════════════════════════════════════

def create_roadmap(db_path, email, roadmap_data):
    """
    Persist a freshly generated roadmap. Deletes any existing one first.
    roadmap_data: output of RoadmapGenerator.generate()
    Returns the new roadmap id.
    """
    with get_connection(db_path) as conn:
        # Delete previous roadmap(s) for this user
        old = conn.execute("SELECT id FROM roadmaps WHERE email = ?", (email,)).fetchall()
        for row in old:
            conn.execute("DELETE FROM roadmap_topics WHERE roadmap_id = ?", (row["id"],))
            conn.execute("DELETE FROM roadmap_milestones WHERE roadmap_id = ?", (row["id"],))
        conn.execute("DELETE FROM roadmaps WHERE email = ?", (email,))

        summary = roadmap_data["summary"]
        cur = conn.execute(
            """
            INSERT INTO roadmaps (email, branch, company_type, company_name,
                                  preparation_level, total_days)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                summary["branch"],
                summary["company_type"],
                summary.get("target_company"),
                summary["preparation_level"],
                summary["total_days"],
            ),
        )
        roadmap_id = cur.lastrowid

        # Bulk-insert topics
        for t in roadmap_data["topics"]:
            conn.execute(
                """
                INSERT INTO roadmap_topics
                    (roadmap_id, topic_name, category, difficulty_level,
                     order_sequence, estimated_days, status)
                VALUES (?, ?, ?, ?, ?, ?, 'not_started')
                """,
                (
                    roadmap_id,
                    t["topic"],
                    t.get("category", ""),
                    t["level"],
                    t["order_sequence"],
                    t["estimated_days"],
                ),
            )

        # Milestones
        for m in roadmap_data["milestones"]:
            conn.execute(
                """
                INSERT INTO roadmap_milestones
                    (roadmap_id, title, description, level,
                     after_topic_order, cumulative_days)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    roadmap_id,
                    m["title"],
                    m["description"],
                    m["level"],
                    m["after_topic_order"],
                    m["cumulative_days"],
                ),
            )

        conn.commit()
        return roadmap_id


def get_roadmap(db_path, email):
    """Return the latest roadmap row for the user, or None."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM roadmaps WHERE email = ? ORDER BY id DESC LIMIT 1",
            (email,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_roadmap_topics(db_path, roadmap_id):
    """Return all topics for a roadmap, ordered."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM roadmap_topics
            WHERE roadmap_id = ?
            ORDER BY order_sequence
            """,
            (roadmap_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def update_roadmap_topic_status(db_path, topic_id, status, email):
    """
    Update a single topic's status. Returns True if updated.
    Status: 'not_started', 'in_progress', 'completed'
    """
    with get_connection(db_path) as conn:
        completed_at = "datetime('now')" if status == "completed" else "NULL"
        conn.execute(
            f"""
            UPDATE roadmap_topics
            SET status = ?,
                completed_at = CASE WHEN ? = 'completed' THEN datetime('now') ELSE NULL END
            WHERE id = ?
              AND roadmap_id IN (SELECT id FROM roadmaps WHERE email = ?)
            """,
            (status, status, topic_id, email),
        )
        conn.commit()

        # Check & update milestones
        _refresh_milestones(conn, email)
        conn.commit()
        return True


def _refresh_milestones(conn, email):
    """Auto-set milestones as reached when all preceding topics are done."""
    roadmap = conn.execute(
        "SELECT id FROM roadmaps WHERE email = ? ORDER BY id DESC LIMIT 1",
        (email,),
    ).fetchone()
    if not roadmap:
        return
    rid = roadmap["id"]
    milestones = conn.execute(
        "SELECT * FROM roadmap_milestones WHERE roadmap_id = ? ORDER BY after_topic_order",
        (rid,),
    ).fetchall()
    for ms in milestones:
        done = conn.execute(
            """
            SELECT COUNT(*) as cnt FROM roadmap_topics
            WHERE roadmap_id = ? AND order_sequence <= ? AND status = 'completed'
            """,
            (rid, ms["after_topic_order"]),
        ).fetchone()["cnt"]
        total = conn.execute(
            """
            SELECT COUNT(*) as cnt FROM roadmap_topics
            WHERE roadmap_id = ? AND order_sequence <= ?
            """,
            (rid, ms["after_topic_order"]),
        ).fetchone()["cnt"]
        if total > 0 and done >= total and not ms["reached"]:
            conn.execute(
                "UPDATE roadmap_milestones SET reached = 1, reached_at = datetime('now') WHERE id = ?",
                (ms["id"],),
            )


def get_roadmap_milestones(db_path, roadmap_id):
    """Return all milestones for a roadmap."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM roadmap_milestones WHERE roadmap_id = ? ORDER BY after_topic_order",
            (roadmap_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_roadmap_progress(db_path, email):
    """
    Aggregate progress: total, per-level, per-status counts.
    """
    with get_connection(db_path) as conn:
        roadmap = conn.execute(
            "SELECT * FROM roadmaps WHERE email = ? ORDER BY id DESC LIMIT 1",
            (email,),
        ).fetchone()
        if not roadmap:
            return None
        rid = roadmap["id"]

        # Overall
        total = conn.execute(
            "SELECT COUNT(*) as cnt FROM roadmap_topics WHERE roadmap_id = ?", (rid,)
        ).fetchone()["cnt"]
        completed = conn.execute(
            "SELECT COUNT(*) as cnt FROM roadmap_topics WHERE roadmap_id = ? AND status = 'completed'",
            (rid,),
        ).fetchone()["cnt"]
        in_progress = conn.execute(
            "SELECT COUNT(*) as cnt FROM roadmap_topics WHERE roadmap_id = ? AND status = 'in_progress'",
            (rid,),
        ).fetchone()["cnt"]

        # Per-level breakdown
        levels = {}
        for lv in ("beginner", "intermediate", "advanced"):
            lv_total = conn.execute(
                "SELECT COUNT(*) as cnt FROM roadmap_topics WHERE roadmap_id = ? AND difficulty_level = ?",
                (rid, lv),
            ).fetchone()["cnt"]
            lv_done = conn.execute(
                "SELECT COUNT(*) as cnt FROM roadmap_topics WHERE roadmap_id = ? AND difficulty_level = ? AND status = 'completed'",
                (rid, lv),
            ).fetchone()["cnt"]
            levels[lv] = {"total": lv_total, "completed": lv_done}

        milestones = [dict(m) for m in conn.execute(
            "SELECT * FROM roadmap_milestones WHERE roadmap_id = ? ORDER BY after_topic_order",
            (rid,),
        ).fetchall()]

        return {
            "roadmap_id": rid,
            "branch": roadmap["branch"],
            "company_type": roadmap["company_type"],
            "company_name": roadmap["company_name"],
            "preparation_level": roadmap["preparation_level"],
            "total_topics": total,
            "completed_topics": completed,
            "in_progress_topics": in_progress,
            "not_started_topics": total - completed - in_progress,
            "total_days": roadmap["total_days"],
            "levels": levels,
            "milestones": milestones,
        }


def delete_roadmap(db_path, email):
    """Remove the user's roadmap and all associated data."""
    with get_connection(db_path) as conn:
        old = conn.execute("SELECT id FROM roadmaps WHERE email = ?", (email,)).fetchall()
        for row in old:
            conn.execute("DELETE FROM roadmap_topics WHERE roadmap_id = ?", (row["id"],))
            conn.execute("DELETE FROM roadmap_milestones WHERE roadmap_id = ?", (row["id"],))
        conn.execute("DELETE FROM roadmaps WHERE email = ?", (email,))
        conn.commit()
        return True

