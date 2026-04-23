/* ═════════════════════════════════════════════════════════════════════════
   roadmap.js – Personalized Study Roadmap frontend
   Vanilla JS IIFE – matches LearnMate architecture
   ═════════════════════════════════════════════════════════════════════════ */
(function () {
    "use strict";

    // ── DOM refs ────────────────────────────────────────────────────────
    const setupView        = document.getElementById("roadmapSetup");
    const roadmapView      = document.getElementById("roadmapView");
    const branchGrid       = document.getElementById("branchGrid");
    const companyTypeGrid  = document.getElementById("companyTypeGrid");
    const levelGrid        = document.getElementById("levelGrid");
    const targetSelect     = document.getElementById("targetCompany");
    const form             = document.getElementById("roadmapForm");
    const btnGenerate      = document.getElementById("btnGenerate");
    const btnBackSetup     = document.getElementById("btnBackSetup");
    const timeline         = document.getElementById("roadmapTimeline");
    const milestonesRow    = document.getElementById("milestonesRow");
    const progressFill     = document.getElementById("progressFill");

    // Selected state
    let selected = { branch: null, company_type: null, preparation_level: null };

    // ── Helpers ─────────────────────────────────────────────────────────
    async function api(url, opts = {}) {
        const res = await fetch(url, {
            headers: { "Content-Type": "application/json" },
            ...opts,
        });
        return res.json();
    }

    function q(id) { return document.getElementById(id); }

    function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

    const LEVEL_LABELS = {
        beginner: "Beginner – I'm just starting out",
        intermediate: "Intermediate – I know the basics",
        advanced: "Advanced – Cover everything",
    };

    const TYPE_LABELS = {
        service: "Service-Based (TCS, Infosys…)",
        product: "Product-Based (Google, Amazon…)",
        core: "Core (L&T, BHEL, ISRO…)",
    };

    // ── Build setup form ────────────────────────────────────────────────
    async function initSetup() {
        const meta = await api("/api/roadmap/meta");

        // Branches
        meta.branches.forEach(b => {
            const pill = makePill(b, b, "branch");
            branchGrid.appendChild(pill);
        });
        // Company types
        meta.company_types.forEach(ct => {
            const pill = makePill(TYPE_LABELS[ct] || ct, ct, "company_type");
            companyTypeGrid.appendChild(pill);
        });
        // Levels
        meta.levels.forEach(lv => {
            const pill = makePill(LEVEL_LABELS[lv] || lv, lv, "preparation_level");
            levelGrid.appendChild(pill);
        });
        // Target companies
        meta.target_companies.forEach(c => {
            const opt = document.createElement("option");
            opt.value = c; opt.textContent = c;
            targetSelect.appendChild(opt);
        });
    }

    function makePill(label, value, group) {
        const el = document.createElement("div");
        el.className = "option-pill";
        el.textContent = label;
        el.dataset.value = value;
        el.addEventListener("click", () => {
            el.parentElement.querySelectorAll(".option-pill").forEach(p => p.classList.remove("selected"));
            el.classList.add("selected");
            selected[group] = value;
        });
        return el;
    }

    // ── Generate roadmap ────────────────────────────────────────────────
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selected.branch || !selected.company_type || !selected.preparation_level) {
            alert("Please select Branch, Company Type, and Preparation Level.");
            return;
        }
        btnGenerate.disabled = true;
        btnGenerate.textContent = "Generating…";

        try {
            const body = {
                branch: selected.branch,
                company_type: selected.company_type,
                preparation_level: selected.preparation_level,
                target_company: targetSelect.value || null,
            };
            await api("/api/roadmap/generate", {
                method: "POST",
                body: JSON.stringify(body),
            });
            await loadRoadmap();
        } catch (err) {
            console.error(err);
            alert("Failed to generate roadmap. Please try again.");
        } finally {
            btnGenerate.disabled = false;
            btnGenerate.innerHTML =
                '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Generate My Roadmap';
        }
    });

    // ── Back to setup ───────────────────────────────────────────────────
    btnBackSetup.addEventListener("click", async () => {
        if (!confirm("Go back to setup? Your current roadmap will be deleted.")) return;
        await api("/api/roadmap/delete", { method: "DELETE" });
        roadmapView.style.display = "none";
        setupView.style.display = "";
    });

    // ── Load & render existing roadmap ──────────────────────────────────
    async function loadRoadmap() {
        const data = await api("/api/roadmap/current");
        if (!data.ok || !data.roadmap) {
            setupView.style.display = "";
            roadmapView.style.display = "none";
            return;
        }

        const rm = data.roadmap;
        setupView.style.display = "none";
        roadmapView.style.display = "";

        // Meta tags
        q("tagBranch").textContent = rm.branch;
        q("tagType").textContent = rm.company_type.replace("_", " ");
        q("tagLevel").textContent = rm.preparation_level;
        if (rm.company_name) {
            const t = q("tagCompany");
            t.textContent = rm.company_name;
            t.style.display = "";
        } else {
            q("tagCompany").style.display = "none";
        }

        // Stats
        const completed = rm.topics.filter(t => t.status === "completed").length;
        const inProg    = rm.topics.filter(t => t.status === "in_progress").length;
        const remaining = rm.topics.length - completed - inProg;
        q("statCompleted").textContent  = completed;
        q("statInProgress").textContent = inProg;
        q("statRemaining").textContent  = remaining;

        const pct = rm.topics.length > 0 ? Math.round((completed / rm.topics.length) * 100) : 0;
        progressFill.style.width = pct + "%";

        // Readiness score
        loadReadiness();

        // Milestones
        renderMilestones(rm.milestones);

        // Timeline
        renderTimeline(rm.topics, rm.milestones);
    }

    // ── Readiness score ─────────────────────────────────────────────────
    async function loadReadiness() {
        const data = await api("/api/roadmap/readiness-score");
        if (data.ok && data.readiness) {
            q("readinessScore").textContent = data.readiness.score + "%";
        }
    }

    // ── Milestones ──────────────────────────────────────────────────────
    function renderMilestones(milestones) {
        milestonesRow.innerHTML = "";
        milestones.forEach(ms => {
            const card = document.createElement("div");
            card.className = "milestone-card" + (ms.reached ? " reached" : "");
            const emoji = ms.title.match(/^[\p{Emoji}\u200d]+/u)?.[0] || "🎯";
            const text  = ms.title.replace(/^[\p{Emoji}\u200d]+\s*/u, "");
            card.innerHTML = `
                <div class="mc-header">
                    <span class="mc-emoji">${emoji}</span>
                    <span class="mc-title">${text}</span>
                </div>
                <p class="mc-desc">${ms.description || ""}</p>
                <span class="mc-badge ${ms.reached ? "reached" : "pending"}">
                    ${ms.reached ? "Reached" : "Pending"}
                </span>
            `;
            milestonesRow.appendChild(card);
        });
    }

    // ── Timeline ────────────────────────────────────────────────────────
    function renderTimeline(topics, milestones) {
        timeline.innerHTML = "";

        // Build milestone map: after_topic_order → milestone
        const msMap = {};
        milestones.forEach(ms => { msMap[ms.after_topic_order] = ms; });

        let currentLevel = null;

        topics.forEach(t => {
            // Level separator
            if (t.difficulty_level !== currentLevel) {
                currentLevel = t.difficulty_level;
                const levelTopics = topics.filter(x => x.difficulty_level === currentLevel);
                const sep = document.createElement("div");
                sep.className = "rml-level-sep";
                sep.innerHTML = `
                    <span class="rml-level-title">${capitalize(currentLevel)}</span>
                    <span class="rml-level-count">${levelTopics.length} topics</span>
                `;
                timeline.appendChild(sep);
            }

            // Topic card
            const card = document.createElement("div");
            card.className = "rml-topic status-" + t.status;
            card.dataset.topicId = t.id;
            card.innerHTML = `
                <span class="rml-order">#${t.order_sequence}</span>
                <div class="rml-info">
                    <div class="rml-name">${t.topic_name}</div>
                    <div class="rml-cat">${(t.category || "").replace(/_/g, " ")}</div>
                </div>
                <span class="rml-days">${t.estimated_days}d</span>
                <button class="rml-status-btn" title="Toggle status">
                    ${statusIcon(t.status)}
                </button>
            `;

            // Status toggle
            card.querySelector(".rml-status-btn").addEventListener("click", (e) => {
                e.stopPropagation();
                toggleStatus(t.id, t.status, card);
            });

            timeline.appendChild(card);

            // Milestone marker after this topic?
            if (msMap[t.order_sequence]) {
                const ms = msMap[t.order_sequence];
                const marker = document.createElement("div");
                marker.className = "rml-milestone-marker";
                const emoji = ms.title.match(/^[\p{Emoji}\u200d]+/u)?.[0] || "🏁";
                const text  = ms.title.replace(/^[\p{Emoji}\u200d]+\s*/u, "");
                marker.innerHTML = `
                    <span class="rmm-emoji">${emoji}</span>
                    <span class="rmm-text">${text}</span>
                `;
                timeline.appendChild(marker);
            }
        });
    }

    // ── Status helpers ──────────────────────────────────────────────────
    const STATUS_CYCLE = { not_started: "in_progress", in_progress: "completed", completed: "not_started" };

    function statusIcon(s) {
        if (s === "completed")   return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
        if (s === "in_progress") return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="6"/></svg>';
        return '';
    }

    async function toggleStatus(topicId, currentStatus, card) {
        const next = STATUS_CYCLE[currentStatus] || "not_started";
        try {
            await api(`/api/roadmap/topic/${topicId}/status`, {
                method: "PUT",
                body: JSON.stringify({ status: next }),
            });
            // Re-render the whole roadmap to update stats + progress
            await loadRoadmap();
        } catch (err) {
            console.error("Failed to update status", err);
        }
    }

    // ── Init ────────────────────────────────────────────────────────────
    async function init() {
        await initSetup();
        await loadRoadmap();
    }
    init();
})();
