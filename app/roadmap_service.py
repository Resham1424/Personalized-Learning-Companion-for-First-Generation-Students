"""
Personalized Study Roadmap Service
====================================
Core algorithm that generates branch-aware, company-specific study roadmaps
with structured progression: Beginner → Intermediate → Advanced.

Pipeline:
 1. Load branch skill matrix
 2. Apply company-type weight modifiers
 3. Filter by preparation level
 4. Assign estimated durations
 5. Insert milestone checkpoints
 6. Return ordered topic list
"""

from __future__ import annotations

import math
from datetime import date, timedelta
from typing import Any, Dict, List, Optional


# ═════════════════════════════════════════════════════════════════════════════
# 1. BRANCH SKILL MATRICES
# ═════════════════════════════════════════════════════════════════════════════

BRANCH_TEMPLATES: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    # ── CSE ────────────────────────────────────────────────────────────────
    "CSE": {
        "beginner": [
            {"topic": "Programming Basics (C / Python)", "days": 5, "category": "programming"},
            {"topic": "Variables, Data Types & Operators", "days": 3, "category": "programming"},
            {"topic": "Control Structures & Loops", "days": 3, "category": "programming"},
            {"topic": "Functions & Scope", "days": 3, "category": "programming"},
            {"topic": "Arrays & Strings", "days": 4, "category": "dsa"},
            {"topic": "Linked Lists", "days": 4, "category": "dsa"},
            {"topic": "Basic Aptitude – Numbers & Percentages", "days": 3, "category": "aptitude"},
            {"topic": "Basic Aptitude – Time & Work", "days": 3, "category": "aptitude"},
            {"topic": "Logical Reasoning Fundamentals", "days": 3, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Stacks & Queues", "days": 4, "category": "dsa"},
            {"topic": "Recursion & Backtracking", "days": 5, "category": "dsa"},
            {"topic": "Trees & Binary Search Trees", "days": 5, "category": "dsa"},
            {"topic": "Hashing & Hash Maps", "days": 3, "category": "dsa"},
            {"topic": "Sorting & Searching Algorithms", "days": 4, "category": "dsa"},
            {"topic": "DBMS – SQL, Normalization, Joins", "days": 5, "category": "core_cs"},
            {"topic": "OS – Processes, Threads, Scheduling", "days": 5, "category": "core_cs"},
            {"topic": "OOP Concepts (Java / C++)", "days": 4, "category": "programming"},
            {"topic": "Networking – TCP/IP, OSI Model", "days": 4, "category": "core_cs"},
            {"topic": "Verbal Ability & Reading Comprehension", "days": 3, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "Graphs – BFS, DFS, Shortest Path", "days": 6, "category": "dsa"},
            {"topic": "Dynamic Programming", "days": 7, "category": "dsa"},
            {"topic": "Greedy Algorithms", "days": 3, "category": "dsa"},
            {"topic": "System Design Basics", "days": 5, "category": "system_design"},
            {"topic": "Design Patterns & SOLID Principles", "days": 4, "category": "system_design"},
            {"topic": "Advanced SQL & Query Optimization", "days": 3, "category": "core_cs"},
            {"topic": "Mock Interviews & HR Preparation", "days": 5, "category": "soft_skills"},
            {"topic": "Resume Building & Project Showcase", "days": 3, "category": "soft_skills"},
        ],
    },

    # ── ECE ────────────────────────────────────────────────────────────────
    "ECE": {
        "beginner": [
            {"topic": "Basic Electronics & Circuit Theory", "days": 5, "category": "core_ece"},
            {"topic": "Network Theory – KVL, KCL, Thevenin", "days": 5, "category": "core_ece"},
            {"topic": "Digital Electronics – Logic Gates", "days": 4, "category": "core_ece"},
            {"topic": "Number Systems & Boolean Algebra", "days": 3, "category": "core_ece"},
            {"topic": "Programming Basics (C / Python)", "days": 5, "category": "programming"},
            {"topic": "Basic Aptitude", "days": 4, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Signals & Systems", "days": 5, "category": "core_ece"},
            {"topic": "Analog Electronics – Op-Amps, BJT", "days": 5, "category": "core_ece"},
            {"topic": "Microprocessors & Microcontrollers", "days": 5, "category": "core_ece"},
            {"topic": "Communication Systems – AM, FM, PM", "days": 5, "category": "core_ece"},
            {"topic": "Control Systems Basics", "days": 4, "category": "core_ece"},
            {"topic": "Data Structures – Arrays, Linked List", "days": 4, "category": "dsa"},
            {"topic": "DBMS Fundamentals", "days": 3, "category": "core_cs"},
            {"topic": "Verbal & Logical Reasoning", "days": 3, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "VLSI Design Basics", "days": 5, "category": "core_ece"},
            {"topic": "Electromagnetic Theory", "days": 5, "category": "core_ece"},
            {"topic": "DSP – Digital Signal Processing", "days": 5, "category": "core_ece"},
            {"topic": "Embedded Systems & IoT", "days": 5, "category": "core_ece"},
            {"topic": "Trees, Graphs & DP (for IT roles)", "days": 6, "category": "dsa"},
            {"topic": "Mock Interviews & HR Preparation", "days": 4, "category": "soft_skills"},
        ],
    },

    # ── Mechanical ─────────────────────────────────────────────────────────
    "Mechanical": {
        "beginner": [
            {"topic": "Engineering Mechanics & Statics", "days": 5, "category": "core_mech"},
            {"topic": "Thermodynamics – Laws & Cycles", "days": 5, "category": "core_mech"},
            {"topic": "Strength of Materials – Stress, Strain", "days": 5, "category": "core_mech"},
            {"topic": "Engineering Drawing & GD&T", "days": 4, "category": "core_mech"},
            {"topic": "Programming Basics (C / Python)", "days": 4, "category": "programming"},
            {"topic": "Basic Aptitude", "days": 4, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Fluid Mechanics", "days": 5, "category": "core_mech"},
            {"topic": "Heat Transfer", "days": 5, "category": "core_mech"},
            {"topic": "Machine Design", "days": 5, "category": "core_mech"},
            {"topic": "Manufacturing Processes & Welding", "days": 5, "category": "core_mech"},
            {"topic": "Theory of Machines – Gears, Cams", "days": 4, "category": "core_mech"},
            {"topic": "Material Science", "days": 3, "category": "core_mech"},
            {"topic": "Quantitative & Logical Aptitude", "days": 4, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "IC Engines & Automobiles", "days": 5, "category": "core_mech"},
            {"topic": "Power Plant Engineering", "days": 4, "category": "core_mech"},
            {"topic": "CAD/CAM/CAE Tools", "days": 5, "category": "core_mech"},
            {"topic": "Industrial Engineering & Operations Research", "days": 4, "category": "core_mech"},
            {"topic": "Advanced DSA (for IT roles)", "days": 5, "category": "dsa"},
            {"topic": "Mock Interviews & HR Preparation", "days": 4, "category": "soft_skills"},
        ],
    },

    # ── EEE ─────────────────────────────────────────────────────────────────
    "EEE": {
        "beginner": [
            {"topic": "Basic Electrical Engineering", "days": 5, "category": "core_eee"},
            {"topic": "Circuit Theory & Network Analysis", "days": 5, "category": "core_eee"},
            {"topic": "Electromagnetic Fields", "days": 4, "category": "core_eee"},
            {"topic": "Programming Basics (C / Python)", "days": 4, "category": "programming"},
            {"topic": "Basic Aptitude", "days": 4, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Electrical Machines – DC & AC", "days": 6, "category": "core_eee"},
            {"topic": "Power Systems", "days": 5, "category": "core_eee"},
            {"topic": "Control Systems", "days": 5, "category": "core_eee"},
            {"topic": "Power Electronics", "days": 5, "category": "core_eee"},
            {"topic": "Data Structures Basics", "days": 4, "category": "dsa"},
            {"topic": "Verbal & Logical Reasoning", "days": 3, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "Switchgear & Protection", "days": 4, "category": "core_eee"},
            {"topic": "Instrumentation & Measurements", "days": 4, "category": "core_eee"},
            {"topic": "Renewable Energy Systems", "days": 4, "category": "core_eee"},
            {"topic": "Advanced DSA (for IT roles)", "days": 5, "category": "dsa"},
            {"topic": "Mock Interviews & HR Preparation", "days": 4, "category": "soft_skills"},
        ],
    },

    # ── Civil ──────────────────────────────────────────────────────────────
    "Civil": {
        "beginner": [
            {"topic": "Engineering Mechanics", "days": 5, "category": "core_civil"},
            {"topic": "Surveying", "days": 4, "category": "core_civil"},
            {"topic": "Building Materials & Construction", "days": 4, "category": "core_civil"},
            {"topic": "Programming Basics (C / Python)", "days": 4, "category": "programming"},
            {"topic": "Basic Aptitude", "days": 4, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Structural Analysis", "days": 5, "category": "core_civil"},
            {"topic": "Concrete Technology", "days": 4, "category": "core_civil"},
            {"topic": "Geotechnical Engineering", "days": 5, "category": "core_civil"},
            {"topic": "Fluid Mechanics & Hydraulics", "days": 5, "category": "core_civil"},
            {"topic": "Environmental Engineering", "days": 4, "category": "core_civil"},
            {"topic": "Quantitative & Logical Aptitude", "days": 4, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "Design of Steel & RCC Structures", "days": 6, "category": "core_civil"},
            {"topic": "Transportation Engineering", "days": 4, "category": "core_civil"},
            {"topic": "Project Management – CPM/PERT", "days": 4, "category": "core_civil"},
            {"topic": "AutoCAD / Revit / STAAD Pro", "days": 5, "category": "core_civil"},
            {"topic": "Mock Interviews & HR Preparation", "days": 4, "category": "soft_skills"},
        ],
    },

    # ── IT  (alias for CSE with slight tweaks) ─────────────────────────────
    "IT": {
        "beginner": [
            {"topic": "Programming Basics (Python / Java)", "days": 5, "category": "programming"},
            {"topic": "Variables, Data Types & Operators", "days": 3, "category": "programming"},
            {"topic": "Control Structures & Loops", "days": 3, "category": "programming"},
            {"topic": "Functions & Scope", "days": 3, "category": "programming"},
            {"topic": "Arrays & Strings", "days": 4, "category": "dsa"},
            {"topic": "Linked Lists", "days": 4, "category": "dsa"},
            {"topic": "Web Basics – HTML, CSS, JS", "days": 4, "category": "web"},
            {"topic": "Basic Aptitude", "days": 4, "category": "aptitude"},
        ],
        "intermediate": [
            {"topic": "Stacks & Queues", "days": 4, "category": "dsa"},
            {"topic": "Recursion & Backtracking", "days": 5, "category": "dsa"},
            {"topic": "Trees & Binary Search Trees", "days": 5, "category": "dsa"},
            {"topic": "DBMS – SQL, Normalization, Joins", "days": 5, "category": "core_cs"},
            {"topic": "OS – Processes, Threads, Scheduling", "days": 5, "category": "core_cs"},
            {"topic": "Networking – TCP/IP, OSI Model", "days": 4, "category": "core_cs"},
            {"topic": "OOP Concepts (Java / C++)", "days": 4, "category": "programming"},
            {"topic": "React / Node.js Basics", "days": 5, "category": "web"},
            {"topic": "Verbal & Logical Reasoning", "days": 3, "category": "aptitude"},
        ],
        "advanced": [
            {"topic": "Graphs – BFS, DFS, Shortest Path", "days": 6, "category": "dsa"},
            {"topic": "Dynamic Programming", "days": 7, "category": "dsa"},
            {"topic": "System Design Basics", "days": 5, "category": "system_design"},
            {"topic": "Cloud & DevOps Fundamentals", "days": 4, "category": "web"},
            {"topic": "Mock Interviews & HR Preparation", "days": 5, "category": "soft_skills"},
            {"topic": "Resume Building & Projects", "days": 3, "category": "soft_skills"},
        ],
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# 2. COMPANY-TYPE WEIGHT MODIFIERS
# ═════════════════════════════════════════════════════════════════════════════

COMPANY_WEIGHTS: Dict[str, Dict[str, float]] = {
    "service": {
        # Service-based (TCS, Infosys, Wipro, Cognizant)
        "aptitude":       1.4,
        "core_cs":        1.2,
        "dsa":            0.9,
        "programming":    1.1,
        "system_design":  0.5,
        "soft_skills":    1.3,
        "web":            0.8,
        # Core branch categories get lower weight for service IT
        "core_ece":  0.6, "core_mech": 0.6, "core_eee": 0.6, "core_civil": 0.6,
    },
    "product": {
        # Product-based (Google, Amazon, Microsoft, Flipkart)
        "aptitude":       0.7,
        "core_cs":        1.2,
        "dsa":            1.5,
        "programming":    1.3,
        "system_design":  1.5,
        "soft_skills":    1.0,
        "web":            1.1,
        "core_ece":  0.4, "core_mech": 0.4, "core_eee": 0.4, "core_civil": 0.4,
    },
    "core": {
        # Core companies (L&T, BHEL, ONGC, NTPC, ISRO)
        "aptitude":       1.0,
        "core_cs":        0.8,
        "dsa":            0.6,
        "programming":    0.7,
        "system_design":  0.3,
        "soft_skills":    1.0,
        "web":            0.3,
        "core_ece":  1.6, "core_mech": 1.6, "core_eee": 1.6, "core_civil": 1.6,
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# 3. COMPANY-SPECIFIC EXTRAS (optional bolt-ons)
# ═════════════════════════════════════════════════════════════════════════════

COMPANY_EXTRAS: Dict[str, List[Dict[str, Any]]] = {
    "TCS": [
        {"topic": "TCS NQT – Quantitative Practice", "days": 3, "category": "aptitude", "level": "beginner"},
        {"topic": "TCS NQT – Coding Practice", "days": 3, "category": "programming", "level": "intermediate"},
    ],
    "Infosys": [
        {"topic": "InfyTQ Platform Practice", "days": 3, "category": "programming", "level": "beginner"},
        {"topic": "Infosys SP & DSE – OOP & DSA", "days": 4, "category": "dsa", "level": "intermediate"},
    ],
    "Wipro": [
        {"topic": "Wipro NLTH – Aptitude Practice", "days": 3, "category": "aptitude", "level": "beginner"},
        {"topic": "Wipro – Coding & Essay Round", "days": 3, "category": "programming", "level": "intermediate"},
    ],
    "Cognizant": [
        {"topic": "CTS GenC – Aptitude & Coding", "days": 3, "category": "aptitude", "level": "beginner"},
    ],
    "Amazon": [
        {"topic": "Amazon OA – Problem Sets", "days": 4, "category": "dsa", "level": "advanced"},
        {"topic": "Amazon Leadership Principles", "days": 2, "category": "soft_skills", "level": "advanced"},
    ],
    "Google": [
        {"topic": "Google Coding Practice – LC Medium/Hard", "days": 5, "category": "dsa", "level": "advanced"},
        {"topic": "Google System Design Rounds", "days": 4, "category": "system_design", "level": "advanced"},
    ],
    "Microsoft": [
        {"topic": "Microsoft OA Practice", "days": 4, "category": "dsa", "level": "advanced"},
        {"topic": "Microsoft Design Round Prep", "days": 3, "category": "system_design", "level": "advanced"},
    ],
}


# ═════════════════════════════════════════════════════════════════════════════
# 4. MILESTONE DEFINITIONS
# ═════════════════════════════════════════════════════════════════════════════

MILESTONE_DEFS = [
    {"after_level": "beginner",     "title": "🏁 Foundation Complete",     "description": "You've built the base! Time to level up."},
    {"after_level": "intermediate", "title": "⚡ Core Skills Mastered",    "description": "Strong mid-level skills. Keep pushing!"},
    {"after_level": "advanced",     "title": "🚀 Placement Ready",         "description": "You've covered all key topics. Start applying!"},
]


# ═════════════════════════════════════════════════════════════════════════════
# 5. ROADMAP GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

class RoadmapGenerator:
    """
    Stateless generator.  Takes user inputs, returns an ordered topic list.
    """

    SUPPORTED_BRANCHES = list(BRANCH_TEMPLATES.keys())
    SUPPORTED_COMPANY_TYPES = list(COMPANY_WEIGHTS.keys())
    SUPPORTED_LEVELS = ["beginner", "intermediate", "advanced"]

    def __init__(
        self,
        branch: str,
        company_type: str,
        preparation_level: str,
        target_company: Optional[str] = None,
    ):
        self.branch = branch
        self.company_type = company_type
        self.preparation_level = preparation_level
        self.target_company = target_company

    # ────────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────────

    def generate(self) -> Dict[str, Any]:
        """
        Main pipeline.  Returns:
        {
            "topics": [{ topic, level, days, category, order, ... }, ...],
            "milestones": [{ ... }],
            "total_days": int,
            "summary": { ... },
        }
        """
        # 1. Load branch template
        raw_topics = self._load_branch_topics()

        # 2. Apply company-type weight multipliers → adjust days
        weighted = self._apply_company_weights(raw_topics)

        # 3. Filter by preparation level
        filtered = self._filter_by_level(weighted)

        # 4. Inject company-specific extras
        if self.target_company:
            filtered = self._inject_company_extras(filtered)

        # 5. Assign order sequence
        ordered = self._assign_order(filtered)

        # 6. Build milestones
        milestones = self._build_milestones(ordered)

        total_days = sum(t["estimated_days"] for t in ordered)

        return {
            "topics": ordered,
            "milestones": milestones,
            "total_days": total_days,
            "summary": {
                "branch": self.branch,
                "company_type": self.company_type,
                "preparation_level": self.preparation_level,
                "target_company": self.target_company,
                "topic_count": len(ordered),
                "total_days": total_days,
                "levels_included": sorted({t["level"] for t in ordered}),
            },
        }

    # ────────────────────────────────────────────────────────────────
    # Pipeline steps
    # ────────────────────────────────────────────────────────────────

    def _load_branch_topics(self) -> List[Dict[str, Any]]:
        template = BRANCH_TEMPLATES.get(self.branch, BRANCH_TEMPLATES["CSE"])
        topics: List[Dict[str, Any]] = []
        for level in self.SUPPORTED_LEVELS:
            for t in template.get(level, []):
                topics.append({**t, "level": level})
        return topics

    def _apply_company_weights(
        self, topics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        weights = COMPANY_WEIGHTS.get(self.company_type, COMPANY_WEIGHTS["service"])
        result = []
        for t in topics:
            w = weights.get(t["category"], 1.0)
            if w < 0.3:
                continue  # category irrelevant for this company type → drop
            adjusted_days = max(1, round(t["days"] * w))
            result.append({
                **t,
                "estimated_days": adjusted_days,
                "weight": w,
            })
        return result

    def _filter_by_level(
        self, topics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Include topics up to and including the user's level.
        Beginner   → only beginner
        Intermediate → beginner + intermediate
        Advanced   → all levels
        """
        level_order = {lv: i for i, lv in enumerate(self.SUPPORTED_LEVELS)}
        max_idx = level_order.get(self.preparation_level, 2)
        return [t for t in topics if level_order.get(t["level"], 0) <= max_idx]

    def _inject_company_extras(
        self, topics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        extras = COMPANY_EXTRAS.get(self.target_company, [])
        level_order = {lv: i for i, lv in enumerate(self.SUPPORTED_LEVELS)}
        max_idx = level_order.get(self.preparation_level, 2)

        for ex in extras:
            if level_order.get(ex.get("level", "beginner"), 0) <= max_idx:
                topics.append({
                    "topic": ex["topic"],
                    "level": ex["level"],
                    "days": ex["days"],
                    "category": ex["category"],
                    "estimated_days": ex["days"],
                    "weight": 1.0,
                })
        return topics

    def _assign_order(
        self, topics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        level_order = {lv: i for i, lv in enumerate(self.SUPPORTED_LEVELS)}
        topics.sort(key=lambda t: (level_order.get(t["level"], 0), t.get("estimated_days", 0)))
        for idx, t in enumerate(topics, start=1):
            t["order_sequence"] = idx
        return topics

    def _build_milestones(
        self, topics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        milestones = []
        day_cursor = 0
        for mdef in MILESTONE_DEFS:
            level = mdef["after_level"]
            level_topics = [t for t in topics if t["level"] == level]
            if not level_topics:
                continue
            day_cursor += sum(t["estimated_days"] for t in level_topics)
            last_order = max(t["order_sequence"] for t in level_topics)
            milestones.append({
                "title": mdef["title"],
                "description": mdef["description"],
                "after_topic_order": last_order,
                "cumulative_days": day_cursor,
                "level": level,
            })
        return milestones

    # ────────────────────────────────────────────────────────────────
    # Readiness score  (called separately, needs DB completion data)
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def calculate_readiness(
        total_topics: int,
        completed_topics: int,
        total_days: int,
        elapsed_days: int,
    ) -> Dict[str, Any]:
        """
        Placement readiness score: 0 – 100

        Formula:
         completion_pct = completed / total * 100
         pace_score     = min(100, (completed / max(1, expected_by_now)) * 100)
         readiness      = completion_pct * 0.7 + pace_score * 0.3
        """
        if total_topics == 0:
            return {"score": 0, "level": "Not Started", "emoji": "🌱",
                    "completion_pct": 0, "pace_score": 0}

        completion_pct = (completed_topics / total_topics) * 100

        # Expected topics by now (linear)
        expected_rate = total_topics / max(total_days, 1)
        expected_by_now = expected_rate * elapsed_days
        pace_score = min(100, (completed_topics / max(1, expected_by_now)) * 100)

        readiness = completion_pct * 0.70 + pace_score * 0.30

        if readiness >= 80:
            level, emoji = "Placement Ready", "🚀"
        elif readiness >= 60:
            level, emoji = "Almost There", "💪"
        elif readiness >= 35:
            level, emoji = "Building Momentum", "📈"
        else:
            level, emoji = "Getting Started", "🌱"

        return {
            "score": round(readiness, 1),
            "level": level,
            "emoji": emoji,
            "completion_pct": round(completion_pct, 1),
            "pace_score": round(pace_score, 1),
        }
