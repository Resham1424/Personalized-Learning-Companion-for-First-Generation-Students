/* ─────────────────────────────────────────────────────────────────────────────
   Progress Tracker – LearnMate
   Full CRUD for habits + daily toggle + score chart
   ───────────────────────────────────────────────────────────────────────────── */

(function () {
    "use strict";

    const MONTH_NAMES = [
        "January","February","March","April","May","June",
        "July","August","September","October","November","December"
    ];

    // ── State ──
    let habits  = [];
    let logs    = {};   // "habitId_YYYY-MM-DD" → 1|0
    let curYear, curMonth, daysInMonth, today;

    // ── DOM refs ──
    const $grid       = document.querySelector("[data-habit-grid]");
    const $empty      = document.querySelector("[data-habit-empty]");
    const $monthLabel = document.querySelector("[data-month-label]");
    const $prevBtn    = document.querySelector("[data-month-prev]");
    const $nextBtn    = document.querySelector("[data-month-next]");
    const $nameInput  = document.querySelector("[data-habit-name]");
    const $colorInput = document.querySelector("[data-habit-color]");
    const $addBtn     = document.querySelector("[data-add-habit]");

    // Stats
    const $totalHabits = document.querySelector("[data-total-habits]");
    const $todayDone   = document.querySelector("[data-today-done]");
    const $streakBest  = document.querySelector("[data-streak-best]");
    const $scoreSvg    = document.querySelector("[data-score-chart]");
    const $scoreMonth  = document.querySelector("[data-score-month]");

    // ── Init ──
    function init() {
        today = new Date();
        curYear  = today.getFullYear();
        curMonth = today.getMonth() + 1;
        loadAll();
        bindEvents();
        injectEditModal();
        loadLeaderboard();
    }

    // ── Data fetching ──
    async function loadAll() {
        await Promise.all([loadHabits(), loadLogs()]);
        render();
    }

    async function loadHabits() {
        try {
            const res = await fetch("/api/habits");
            const data = await res.json();
            habits = data.items || [];
        } catch { habits = []; }
    }

    async function loadLogs() {
        try {
            const res = await fetch(`/api/habits/logs?year=${curYear}&month=${curMonth}`);
            const data = await res.json();
            logs = data.logs || {};
        } catch { logs = {}; }
    }

    // ── CRUD ──
    async function addHabit() {
        const name = $nameInput.value.trim();
        const color = $colorInput.value;
        if (!name) { $nameInput.focus(); return; }
        try {
            const res = await fetch("/api/habits", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, color }),
            });
            if (!res.ok) return;
            $nameInput.value = "";
            await loadHabits();
            render();
        } catch {}
    }

    async function deleteHabit(id) {
        if (!confirm("Delete this habit and all its logs?")) return;
        try {
            await fetch(`/api/habits/${id}`, { method: "DELETE" });
            await loadAll();
        } catch {}
    }

    async function updateHabit(id, name, color) {
        try {
            await fetch(`/api/habits/${id}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, color }),
            });
            await loadHabits();
            render();
        } catch {}
    }

    async function toggleDay(habitId, dateStr, currentlyDone) {
        const newDone = currentlyDone ? 0 : 1;
        const key = `${habitId}_${dateStr}`;
        logs[key] = newDone;
        render();   // optimistic
        try {
            await fetch("/api/habits/toggle", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ habit_id: habitId, date: dateStr, done: !!newDone }),
            });
            loadLeaderboard();  // refresh leaderboard after toggle
        } catch {
            logs[key] = currentlyDone ? 1 : 0;
            render();
        }
    }

    // ── Rendering ──
    function render() {
        daysInMonth = new Date(curYear, curMonth, 0).getDate();
        $monthLabel.textContent = `${MONTH_NAMES[curMonth - 1]} ${curYear}`;
        $scoreMonth.textContent = `${MONTH_NAMES[curMonth - 1]} ${curYear}`;

        if (!habits.length) {
            $grid.style.display = "none";
            $empty.hidden = false;
        } else {
            $grid.style.display = "grid";
            $empty.hidden = true;
        }

        renderGrid();
        renderStats();
        renderScoreChart();
    }

    function renderGrid() {
        const cols = daysInMonth + 1;  // +1 for name column
        $grid.style.gridTemplateColumns = `180px repeat(${daysInMonth}, 36px)`;
        $grid.innerHTML = "";

        // Corner
        const corner = document.createElement("div");
        corner.className = "hg-corner";
        corner.textContent = "Habits / Protocols";
        $grid.appendChild(corner);

        // Day headers
        const todayStr = fmtDate(today);
        for (let d = 1; d <= daysInMonth; d++) {
            const dh = document.createElement("div");
            dh.className = "hg-day-header";
            const ds = `${curYear}-${pad(curMonth)}-${pad(d)}`;
            if (ds === todayStr) dh.classList.add("is-today");
            dh.textContent = d;
            $grid.appendChild(dh);
        }

        // Habit rows
        habits.forEach(h => {
            // Name cell
            const nameCell = document.createElement("div");
            nameCell.className = "hg-habit-name";
            nameCell.innerHTML = `
                <span class="hg-color-dot" style="background:${esc(h.color)}"></span>
                <span class="hg-name-text" title="${esc(h.name)}">${esc(h.name)}</span>
                <span class="hg-actions">
                    <button class="hg-act-btn edit" data-edit-id="${h.id}" title="Edit">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    <button class="hg-act-btn delete" data-delete-id="${h.id}" title="Delete">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3,6 5,6 21,6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </button>
                </span>
            `;
            $grid.appendChild(nameCell);

            // Day cells
            for (let d = 1; d <= daysInMonth; d++) {
                const ds = `${curYear}-${pad(curMonth)}-${pad(d)}`;
                const key = `${h.id}_${ds}`;
                const done = !!logs[key];
                const isFuture = new Date(curYear, curMonth - 1, d) > today;

                const cell = document.createElement("div");
                cell.className = "hg-cell" + (isFuture ? " is-future" : "");
                const check = document.createElement("div");
                check.className = "hg-check" + (done ? " is-done" : "");
                check.style.setProperty("--habit-color", h.color);
                cell.appendChild(check);
                if (!isFuture) {
                    cell.addEventListener("click", () => toggleDay(h.id, ds, done));
                }
                $grid.appendChild(cell);
            }
        });

        // Bind edit/delete buttons
        $grid.querySelectorAll("[data-edit-id]").forEach(btn => {
            btn.addEventListener("click", e => {
                e.stopPropagation();
                const id = Number(btn.dataset.editId);
                const h = habits.find(x => x.id === id);
                if (h) openEditModal(h);
            });
        });
        $grid.querySelectorAll("[data-delete-id]").forEach(btn => {
            btn.addEventListener("click", e => {
                e.stopPropagation();
                deleteHabit(Number(btn.dataset.deleteId));
            });
        });
    }

    function renderStats() {
        $totalHabits.textContent = habits.length;

        const todayStr = fmtDate(today);
        let doneToday = 0;
        habits.forEach(h => {
            if (logs[`${h.id}_${todayStr}`]) doneToday++;
        });
        $todayDone.textContent = doneToday;

        // Best streak (consecutive days with ALL habits done)
        let bestStreak = 0, streak = 0;
        if (habits.length) {
            for (let d = 1; d <= daysInMonth; d++) {
                const ds = `${curYear}-${pad(curMonth)}-${pad(d)}`;
                let allDone = true;
                habits.forEach(h => {
                    if (!logs[`${h.id}_${ds}`]) allDone = false;
                });
                if (allDone) {
                    streak++;
                    if (streak > bestStreak) bestStreak = streak;
                } else {
                    streak = 0;
                }
            }
        }
        $streakBest.textContent = bestStreak;
    }

    function renderScoreChart() {
        if (!habits.length) {
            $scoreSvg.innerHTML = `<text x="310" y="100" text-anchor="middle" fill="rgba(255,255,255,0.3)" font-size="13">Add habits to see your score graph</text>`;
            return;
        }

        const maxHabits = habits.length;
        const padL = 30, padR = 10, padT = 15, padB = 30;
        const w = 620 - padL - padR;
        const h = 200 - padT - padB;
        const barW = Math.min(16, (w / daysInMonth) - 2);
        const gap  = (w - barW * daysInMonth) / (daysInMonth + 1);

        let svg = "";

        // Y-axis grid lines + labels
        for (let i = 0; i <= maxHabits; i++) {
            const y = padT + h - (i / maxHabits) * h;
            svg += `<line class="score-grid-line" x1="${padL}" y1="${y}" x2="${620 - padR}" y2="${y}"/>`;
            svg += `<text class="score-y-label" x="${padL - 6}" y="${y + 3}">${i}</text>`;
        }

        const todayStr = fmtDate(today);

        // Bars
        for (let d = 1; d <= daysInMonth; d++) {
            const ds = `${curYear}-${pad(curMonth)}-${pad(d)}`;
            let count = 0;
            habits.forEach(hb => {
                if (logs[`${hb.id}_${ds}`]) count++;
            });

            const x = padL + gap + (d - 1) * (barW + gap);
            const barH = maxHabits ? (count / maxHabits) * h : 0;
            const y = padT + h - barH;
            const opacity = count === 0 ? 0.15 : (0.4 + 0.6 * (count / maxHabits));

            const isToday = ds === todayStr;
            const fill = isToday ? "#FF6B35" : `rgba(255, 107, 53, ${opacity})`;
            const stroke = isToday ? "rgba(255,200,170,0.6)" : "none";

            svg += `<rect class="score-bar" x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${fill}" stroke="${stroke}" stroke-width="${isToday ? 1.5 : 0}" rx="4">
                <title>Day ${d}: ${count}/${maxHabits}</title>
            </rect>`;

            // Value label (only if done > 0)
            if (count > 0) {
                svg += `<text class="score-val-label" x="${x + barW / 2}" y="${y - 4}">${count}</text>`;
            }

            // X-axis day label
            svg += `<text class="score-label" x="${x + barW / 2}" y="${padT + h + 18}" ${isToday ? 'fill="#FF6B35" font-weight="700"' : ''}>${d}</text>`;
        }

        $scoreSvg.innerHTML = svg;
    }

    // ── Edit modal ──
    let $editOverlay, $editName, $editColor, $editSaveBtn, editingId = null;

    function injectEditModal() {
        const overlay = document.createElement("div");
        overlay.className = "habit-edit-overlay";
        overlay.innerHTML = `
            <div class="habit-edit-modal">
                <h3>Edit Habit</h3>
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" data-edit-habit-name maxlength="60">
                </div>
                <div class="form-group">
                    <label>Color</label>
                    <input type="color" class="habit-color-picker" data-edit-habit-color value="#FF6B35">
                </div>
                <div class="habit-edit-actions">
                    <button class="btn-cancel-edit" data-edit-cancel>Cancel</button>
                    <button class="btn-save-edit" data-edit-save>Save</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        $editOverlay = overlay;
        $editName    = overlay.querySelector("[data-edit-habit-name]");
        $editColor   = overlay.querySelector("[data-edit-habit-color]");
        $editSaveBtn = overlay.querySelector("[data-edit-save]");

        overlay.querySelector("[data-edit-cancel]").addEventListener("click", closeEditModal);
        overlay.addEventListener("click", e => { if (e.target === overlay) closeEditModal(); });
        $editSaveBtn.addEventListener("click", async () => {
            if (editingId == null) return;
            await updateHabit(editingId, $editName.value.trim(), $editColor.value);
            closeEditModal();
        });
    }

    function openEditModal(habit) {
        editingId = habit.id;
        $editName.value = habit.name;
        $editColor.value = habit.color || "#FF6B35";
        $editOverlay.classList.add("is-open");
        $editName.focus();
    }

    function closeEditModal() {
        editingId = null;
        $editOverlay.classList.remove("is-open");
    }

    // ── Events ──
    function bindEvents() {
        $addBtn.addEventListener("click", addHabit);
        $nameInput.addEventListener("keydown", e => { if (e.key === "Enter") addHabit(); });

        $prevBtn.addEventListener("click", () => {
            curMonth--;
            if (curMonth < 1) { curMonth = 12; curYear--; }
            loadLogs().then(render);
        });

        $nextBtn.addEventListener("click", () => {
            curMonth++;
            if (curMonth > 12) { curMonth = 1; curYear++; }
            loadLogs().then(render);
        });
    }

    // ── Helpers ──
    function pad(n) { return String(n).padStart(2, "0"); }
    function fmtDate(d) {
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    }
    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    // ═══════════════════════════════════════════════════════════════════
    // Leaderboard
    // ═══════════════════════════════════════════════════════════════════

    const $lbPodium = document.querySelector("[data-lb-podium]");
    const $lbTable  = document.querySelector("[data-lb-table]");
    const $lbEmpty  = document.querySelector("[data-lb-empty]");

    async function loadLeaderboard() {
        try {
            const res = await fetch("/api/leaderboard");
            const data = await res.json();
            renderLeaderboard(data.items || [], data.current_user || "");
        } catch {
            if ($lbEmpty) { $lbEmpty.hidden = false; }
        }
    }

    function getInitials(name) {
        return name.split(/\s+/).map(w => w[0]).join("").toUpperCase().slice(0, 2);
    }

    function renderLeaderboard(items, currentUser) {
        if (!$lbPodium || !$lbTable) return;

        if (!items.length) {
            $lbPodium.innerHTML = "";
            $lbTable.innerHTML = "";
            if ($lbEmpty) $lbEmpty.hidden = false;
            return;
        }
        if ($lbEmpty) $lbEmpty.hidden = true;

        // Top 3 podium
        const top3 = items.slice(0, 3);
        const podiumColors = ["#ffd700", "#c0c0c0", "#cd7f32"];
        const trophySizes = [70, 56, 50];
        const starCounts = [3, 2, 1];

        let podiumHTML = "";
        [1, 0, 2].forEach(idx => {   // Display order: 2nd, 1st, 3rd
            const user = top3[idx];
            if (!user) return;
            const rank = idx + 1;
            const initials = getInitials(user.name);
            const color = podiumColors[idx];
            const size = trophySizes[idx];
            const stars = "⭐".repeat(starCounts[idx]);

            const sparkles = rank === 1 ? `
                <div class="lb-sparkles">
                    <div class="lb-sparkle"></div><div class="lb-sparkle"></div>
                    <div class="lb-sparkle"></div><div class="lb-sparkle"></div>
                    <div class="lb-sparkle"></div>
                </div>` : "";

            podiumHTML += `
                <div class="lb-podium-item rank-${rank}">
                    <div class="lb-trophy">
                        <div class="trophy-stars">${stars.split("").map(s => `<span class="trophy-star">${s}</span>`).join("")}</div>
                        <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="1.5">
                            <path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/>
                            <path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/>
                            <path d="M4 22h16"/>
                            <path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/>
                            <path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/>
                            <path d="M18 2H6v7a6 6 0 0 0 12 0V2Z" fill="${color}" fill-opacity="0.15"/>
                        </svg>
                        ${sparkles}
                    </div>
                    <div class="lb-avatar">${esc(initials)}</div>
                    <div class="lb-podium-info">
                        <div class="lb-podium-name">${esc(user.name)}</div>
                        <div class="lb-podium-streak">Max Streak: <strong>${user.best_streak}</strong></div>
                        <div class="lb-podium-streak">Current Streak: <strong>${user.current_streak}</strong></div>
                    </div>
                    <div class="lb-pedestal"><span class="lb-pedestal-rank">#${rank}</span></div>
                </div>
            `;
        });
        $lbPodium.innerHTML = podiumHTML;

        // Table rows (rank 4+)
        const rest = items.slice(3);
        if (!rest.length) {
            $lbTable.closest(".lb-table-wrapper").style.display = "none";
        } else {
            $lbTable.closest(".lb-table-wrapper").style.display = "";
            let tableHTML = "";
            rest.forEach((user, i) => {
                const rank = i + 4;
                const isYou = user.email === currentUser;
                const initials = getInitials(user.name);
                tableHTML += `
                    <div class="lb-table-row ${isYou ? "is-you" : ""}">
                        <span class="lb-rank-badge">#${rank}</span>
                        <span class="lb-user-cell">
                            <span class="lb-table-avatar">${esc(initials)}</span>
                            <span class="lb-table-name">${esc(user.name)}${isYou ? '<span class="you-badge">You</span>' : ""}</span>
                        </span>
                        <span class="lb-streak-cell"><span class="lb-streak-icon">🔥</span> ${user.current_streak}</span>
                        <span class="lb-streak-cell"><span class="lb-streak-icon">⚡</span> ${user.best_streak}</span>
                        <span class="lb-habits-cell">${user.total_habits}</span>
                    </div>
                `;
            });
            $lbTable.innerHTML = tableHTML;
        }

        // Also highlight top 3 if current user is there
        top3.forEach((user, idx) => {
            if (user && user.email === currentUser) {
                const podItem = $lbPodium.querySelector(`.rank-${idx + 1} .lb-podium-name`);
                if (podItem) podItem.innerHTML += ' <span class="you-badge" style="font-size:0.55rem;">You</span>';
            }
        });
    }

    // Start
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
