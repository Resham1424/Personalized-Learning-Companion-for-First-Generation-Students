"""
Smart Study Scheduler Service
==============================
Intelligent scheduling algorithm that generates optimal study timetables.

Two modes:
 1. Weekly schedule  – legacy 7-day window (kept for backward compat)
 2. Full calendar    – date-wise plan from today → target placement date

Algorithm Logic:
1. Calculate available daily hours (capped at MAX_DAILY_HOURS)
2. Assign priority weights to subjects (Weak=3, Medium=2, Strong=1)
3. Distribute daily study minutes proportionally across subjects
4. Every 3rd day → Revision session
5. Every 7th day → Full mock-test
6. Rotate topics within each subject cyclically
7. Adapt weights based on past performance
"""

from datetime import datetime, timedelta, date as _date
from typing import List, Dict, Any, Generator
import math


class StudyScheduler:
    """Intelligent study scheduler with adaptive algorithms."""

    # Task type constants
    TASK_TYPE_STUDY = "study"
    TASK_TYPE_REVISION = "revision"
    TASK_TYPE_MOCK_TEST = "mock_test"
    TASK_TYPE_PRACTICE = "practice"

    # Priority weights
    PRIORITY_WEAK = 3
    PRIORITY_MEDIUM = 2
    PRIORITY_STRONG = 1

    # Time constants
    DEFAULT_SESSION_DURATION = 60   # minutes
    MAX_DAILY_HOURS = 4             # burnout cap
    MIN_SESSION_DURATION = 30
    REVISION_DURATION = 45          # minutes
    MOCK_TEST_DURATION = 90         # minutes

    # Study time slots (24-hour format)
    DEFAULT_STUDY_SLOTS = [
        ("06:00", "08:00"),   # Early morning
        ("14:00", "16:00"),   # Afternoon
        ("18:00", "20:00"),   # Evening
        ("20:00", "22:00"),   # Night
    ]

    # ── Topic banks for each common subject ───────────────────────────────
    TOPIC_BANKS: Dict[str, List[str]] = {
        "DSA": [
            "Arrays & Strings", "Linked Lists", "Stacks & Queues",
            "Trees & BST", "Graphs – BFS/DFS", "Dynamic Programming",
            "Greedy Algorithms", "Recursion & Backtracking",
            "Hashing & Maps", "Sorting & Searching",
        ],
        "Aptitude": [
            "Quantitative – Numbers", "Quantitative – Percentages",
            "Logical Reasoning", "Verbal Ability",
            "Data Interpretation", "Puzzles & Arrangements",
        ],
        "Core CS": [
            "OS – Processes & Threads", "OS – Memory Management",
            "DBMS – SQL Queries", "DBMS – Normalization",
            "Networks – TCP/IP", "Networks – OSI Model",
            "OOP Principles", "System Design Basics",
        ],
        "Programming": [
            "Java Fundamentals", "Python Fundamentals",
            "Problem Solving – Easy", "Problem Solving – Medium",
            "Code Practice – Patterns", "Code Practice – Strings",
        ],
    }

    def __init__(self, user_config: Dict[str, Any], subjects: List[Dict[str, Any]]):
        self.user_config = user_config
        self.subjects = subjects
        self.daily_hours = min(
            float(user_config.get("daily_hours", 3.0)),
            self.MAX_DAILY_HOURS,
        )
        self.preparation_level = user_config.get("preparation_level", "beginner")

    # ─────────────────────────────────────────────────────────────────────
    # Time-slot helpers
    # ─────────────────────────────────────────────────────────────────────

    def get_available_slots(self, day_date) -> List[tuple]:
        """Return available (start, end) time-slot tuples for *day_date*."""
        is_weekend = day_date.weekday() >= 5

        college_start = self.user_config.get("college_start")
        college_end = self.user_config.get("college_end")
        work_start = self.user_config.get("work_start")
        work_end = self.user_config.get("work_end")

        if not college_start and not work_start:
            return list(self.DEFAULT_STUDY_SLOTS)

        available = []
        for slot_s, slot_e in self.DEFAULT_STUDY_SLOTS:
            if not is_weekend and college_start and college_end:
                if self._slots_overlap(slot_s, slot_e, college_start, college_end):
                    continue
            if work_start and work_end:
                if self._slots_overlap(slot_s, slot_e, work_start, work_end):
                    continue
            available.append((slot_s, slot_e))

        return available if available else [("20:00", "22:00")]

    @staticmethod
    def _slots_overlap(s1: str, e1: str, s2: str, e2: str) -> bool:
        def _m(t: str) -> int:
            h, m = map(int, t.split(":"))
            return h * 60 + m
        return _m(s1) < _m(e2) and _m(s2) < _m(e1)

    # ─────────────────────────────────────────────────────────────────────
    # Hour distribution helpers
    # ─────────────────────────────────────────────────────────────────────

    def _daily_study_minutes(self, is_weekend: bool = False) -> int:
        """Effective study minutes for one day (excl. revision / mock)."""
        base = self.daily_hours * 60
        if is_weekend:
            base = min(self.daily_hours * 1.5, self.MAX_DAILY_HOURS) * 60
        return int(base)

    def _subject_daily_allocation(self, day_date) -> List[Dict[str, Any]]:
        """
        Return a list of subject session dicts for a single study day.
        Sessions are proportional to weight and capped to daily hours.
        """
        is_weekend = day_date.weekday() >= 5
        available_minutes = self._daily_study_minutes(is_weekend)

        total_weight = sum(s["weight"] for s in self.subjects) or 1
        sessions = []
        used = 0

        for subj in self.subjects:
            mins = int((subj["weight"] / total_weight) * available_minutes)
            mins = max(mins, self.MIN_SESSION_DURATION)
            if used + mins > available_minutes:
                mins = available_minutes - used
            if mins < self.MIN_SESSION_DURATION:
                continue
            sessions.append({
                "subject_name": subj["subject_name"],
                "duration_minutes": mins,
                "weight": subj["weight"],
            })
            used += mins

        return sessions

    # ─────────────────────────────────────────────────────────────────────
    # Topic rotation
    # ─────────────────────────────────────────────────────────────────────

    def _generate_topic(self, subject_name: str, global_session_idx: int) -> str:
        """Cycle through topic bank for a subject."""
        bank = self.TOPIC_BANKS.get(subject_name)
        if not bank:
            bank = [f"Topic {i+1}" for i in range(6)]
        return bank[global_session_idx % len(bank)]

    # ─────────────────────────────────────────────────────────────────────
    # Legacy: weekly schedule (kept for backward compatibility)
    # ─────────────────────────────────────────────────────────────────────

    def calculate_weekly_hours(self) -> float:
        weekday_hours = self.daily_hours * 5
        weekend_hours = min(self.daily_hours * 1.5, self.MAX_DAILY_HOURS) * 2
        return weekday_hours + weekend_hours

    def distribute_hours(self) -> Dict[str, float]:
        total = self.calculate_weekly_hours()
        rev = total * 0.15
        mock = 1.5
        study = total - rev - mock
        tw = sum(s["weight"] for s in self.subjects) or 1
        return {
            s["subject_name"]: round((s["weight"] / tw) * study, 2)
            for s in self.subjects
        }

    def generate_weekly_schedule(self, week_start_date) -> List[Dict[str, Any]]:
        """Generate tasks for a single Mon-Sun week (legacy API)."""
        return list(self.generate_date_range_schedule(
            week_start_date,
            week_start_date + timedelta(days=6),
        ))

    # ─────────────────────────────────────────────────────────────────────
    # ★ NEW: Full-calendar schedule (today → target placement date)
    # ─────────────────────────────────────────────────────────────────────

    def generate_full_schedule(self, start_date, end_date) -> List[Dict[str, Any]]:
        """
        Public entry-point: returns a *list* of task dicts covering
        [start_date … end_date] inclusive.
        """
        return list(self.generate_date_range_schedule(start_date, end_date))

    def generate_date_range_schedule(
        self, start_date, end_date
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields one task dict at a time for every day
        in the range.  Keeps memory flat even for 200+ day spans.

        Algorithm per day:
         • Day N (1-indexed from start_date)
         • If N % 7 == 0  → Mock-test day (afternoon slot)
         • If N % 3 == 0  → Append a Revision session after study
         • Otherwise      → Normal study sessions (weight-proportional)
        """
        total_days = (end_date - start_date).days + 1
        subject_session_counters: Dict[str, int] = {
            s["subject_name"]: 0 for s in self.subjects
        }

        for day_num in range(total_days):
            current_date = start_date + timedelta(days=day_num)
            day_index = day_num + 1  # 1-based
            slots = self.get_available_slots(current_date)
            if not slots:
                continue

            slot_cursor = 0  # rotate through available slots

            # ── Mock-test day (every 7th) ─────────────────────────────
            if day_index % 7 == 0 and day_index > 1:
                slot = slots[min(1, len(slots) - 1)]
                yield {
                    "date": current_date.isoformat(),
                    "time": slot[0],
                    "subject": "Full Mock Test",
                    "topic": f"Assessment #{day_index // 7}",
                    "type": self.TASK_TYPE_MOCK_TEST,
                    "duration_minutes": self.MOCK_TEST_DURATION,
                }
                # Still allow study tasks on mock-test day (remaining slots)
                slot_cursor = 2

            # ── Study sessions ────────────────────────────────────────
            sessions = self._subject_daily_allocation(current_date)
            for sess in sessions:
                if slot_cursor >= len(slots):
                    break
                sname = sess["subject_name"]
                idx = subject_session_counters.get(sname, 0)

                yield {
                    "date": current_date.isoformat(),
                    "time": slots[slot_cursor][0],
                    "subject": sname,
                    "topic": self._generate_topic(sname, idx),
                    "type": self.TASK_TYPE_STUDY,
                    "duration_minutes": sess["duration_minutes"],
                }
                subject_session_counters[sname] = idx + 1
                slot_cursor += 1

            # ── Revision session (every 3rd day) ─────────────────────
            if day_index % 3 == 0:
                rev_slot = slots[-1] if slots else ("20:00", "22:00")
                # pick weakest subject for focused revision
                weakest = max(self.subjects, key=lambda s: s["weight"])
                yield {
                    "date": current_date.isoformat(),
                    "time": rev_slot[0] if isinstance(rev_slot, tuple) else rev_slot,
                    "subject": f"Revision – {weakest['subject_name']}",
                    "topic": "Review weak areas",
                    "type": self.TASK_TYPE_REVISION,
                    "duration_minutes": self.REVISION_DURATION,
                }

    # ─────────────────────────────────────────────────────────────────────
    # Summary helpers
    # ─────────────────────────────────────────────────────────────────────

    def get_schedule_stats(self, start_date, end_date) -> Dict[str, Any]:
        """Pre-compute stats without generating all tasks."""
        total_days = (end_date - start_date).days + 1
        total_study_hours = 0.0
        for d in range(total_days):
            dt = start_date + timedelta(days=d)
            total_study_hours += self._daily_study_minutes(dt.weekday() >= 5) / 60.0
        return {
            "total_days": total_days,
            "total_study_hours": round(total_study_hours, 1),
            "subjects": len(self.subjects),
            "mock_tests": total_days // 7,
            "revisions": total_days // 3,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }

    # ─────────────────────────────────────────────────────────────────────
    # Adaptive / suggestion helpers (unchanged logic)
    # ─────────────────────────────────────────────────────────────────────

    def adapt_schedule(self, performance_data: List[Dict[str, Any]]) -> Dict[str, int]:
        adjustments = {}
        for subject in self.subjects:
            sn = subject["subject_name"]
            cw = subject["weight"]
            sp = [p for p in performance_data if p.get("subject") == sn]
            if not sp:
                adjustments[sn] = cw
                continue
            scores = [p["mock_score"] for p in sp if p.get("mock_score")]
            avg = sum(scores) / len(scores) if scores else 0
            if avg < 40:
                adjustments[sn] = min(cw + 1, self.PRIORITY_WEAK)
            elif avg > 80:
                adjustments[sn] = max(cw - 1, self.PRIORITY_STRONG)
            else:
                adjustments[sn] = cw
        return adjustments

    def suggest_focus_areas(self, performance_data: List[Dict[str, Any]]) -> List[str]:
        suggestions = []
        for subject in self.subjects:
            sn = subject["subject_name"]
            sp = [p for p in performance_data if p.get("subject") == sn]
            if not sp:
                continue
            tt = sum(p.get("tasks_total", 0) for p in sp)
            tc = sum(p.get("tasks_completed", 0) for p in sp)
            cr = (tc / tt * 100) if tt > 0 else 0
            if cr < 50:
                suggestions.append(
                    f"⚠️ {sn}: Low completion ({cr:.0f}%). Try shorter sessions."
                )
            scores = [p["mock_score"] for p in sp if p.get("mock_score")]
            if scores:
                avg = sum(scores) / len(scores)
                if avg < 60:
                    suggestions.append(f"📚 {sn}: Score {avg:.0f}% – schedule extra practice.")
                elif avg > 85:
                    suggestions.append(f"✨ {sn}: Great progress ({avg:.0f}%)!")
        return suggestions


# ─────────────────────────────────────────────────────────────────────────────
# Standalone helpers (used by routes.py)
# ─────────────────────────────────────────────────────────────────────────────

def calculate_readiness_score(
    subjects: List[Dict[str, Any]],
    performance_data: List[Dict[str, Any]],
    streak_data: Dict[str, int],
) -> Dict[str, Any]:
    if subjects:
        avg_subj = sum(s.get("performance_score", 0) for s in subjects) / len(subjects)
    else:
        avg_subj = 0

    cs = min(streak_data.get("current_streak", 0) * 5, 100)

    mp = [p for p in performance_data if p.get("mock_score")]
    avg_mock = (sum(p["mock_score"] for p in mp) / len(mp)) if mp else 0

    total = avg_subj * 0.60 + cs * 0.25 + avg_mock * 0.15

    if total >= 80:
        level, emoji = "Placement Ready", "🚀"
    elif total >= 60:
        level, emoji = "Almost There", "💪"
    elif total >= 40:
        level, emoji = "Building Momentum", "📈"
    else:
        level, emoji = "Getting Started", "🌱"

    return {
        "score": round(total, 1),
        "level": level,
        "emoji": emoji,
        "breakdown": {
            "subject_performance": round(avg_subj, 1),
            "consistency": round(cs, 1),
            "mock_tests": round(avg_mock, 1),
        },
    }
