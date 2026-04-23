/* ═══════════════════════════════════════════════════════════════════════════
   LearnMate – Command Center JS  (Premium Admin)
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
    "use strict";

    /* ── DOM refs ── */
    const sidebar      = document.getElementById("sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");
    const panelTitle    = document.getElementById("panelTitle");
    const panelSubtitle = document.getElementById("panelSubtitle");
    const navItems      = document.querySelectorAll(".nav-item[data-panel]");

    // Overview
    const statsGrid   = document.getElementById("statsGrid");
    const deptList    = document.getElementById("deptList");
    const recentUsers = document.getElementById("recentUsers");

    // Streaks
    const podiumStage     = document.getElementById("podiumStage");
    const streakInsights  = document.getElementById("streakInsights");
    const leaderboardBody = document.getElementById("leaderboardBody");

    // Users
    const usersBody     = document.getElementById("usersBody");
    const userSearch    = document.getElementById("userSearch");
    const userCount     = document.getElementById("userCount");
    const userDrawer    = document.getElementById("userDrawer");
    const drawerOverlay = document.getElementById("drawerOverlay");
    const drawerClose   = document.getElementById("drawerClose");
    const drawerTitle   = document.getElementById("drawerTitle");
    const drawerEmail   = document.getElementById("drawerEmail");
    const drawerAvatar  = document.getElementById("drawerAvatar");
    const drawerBody    = document.getElementById("drawerBody");

    // Database
    const tableTabs = document.getElementById("tableTabs");
    const dbHead    = document.getElementById("dbHead");
    const dbBody    = document.getElementById("dbBody");
    const dbInfo    = document.getElementById("dbInfo");

    // Query
    const queryInput   = document.getElementById("queryInput");
    const queryRun     = document.getElementById("queryRun");
    const queryStatus  = document.getElementById("queryStatus");
    const queryResults = document.getElementById("queryResults");

    let allUsers = [];
    let currentTable = "";

    /* ── Sidebar toggle ── */
    sidebarToggle.addEventListener("click", () => sidebar.classList.toggle("open"));

    /* ── Panel navigation ── */
    const subtitles = {
        overview: "Platform analytics at a glance",
        streaks:  "Streak rankings & habit insights",
        users:    "Manage all registered users",
        database: "Browse & manage tables",
        query:    "Execute raw SQL queries"
    };
    const titles = {
        overview: "Overview",
        streaks:  "Streaks & Ranks",
        users:    "Users",
        database: "Database",
        query:    "SQL Console"
    };

    navItems.forEach(item => {
        item.addEventListener("click", e => {
            e.preventDefault();
            switchPanel(item.dataset.panel);
        });
    });

    function switchPanel(name) {
        document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
        const target = document.getElementById("panel-" + name);
        if (target) target.classList.add("active");

        navItems.forEach(n => n.classList.toggle("active", n.dataset.panel === name));
        panelTitle.textContent = titles[name] || name;
        panelSubtitle.textContent = subtitles[name] || "";
        sidebar.classList.remove("open");

        if (name === "overview") loadOverview();
        if (name === "streaks")  loadStreaks();
        if (name === "users")    loadUsers();
        if (name === "database") loadTables();
    }

    /* ══════════════════════════════════════════════════════════════════════════
       OVERVIEW
       ══════════════════════════════════════════════════════════════════════════ */

    async function loadOverview() {
        try {
            const [statsRes, usersRes] = await Promise.all([
                fetch("/api/admin/stats"),
                fetch("/api/admin/users")
            ]);
            const stats = await statsRes.json();
            const users = await usersRes.json();
            renderStats(stats);
            renderDepts(stats.departments || []);
            renderRecentUsers(users.slice(0, 8));
        } catch (err) { console.error("Failed to load overview:", err); }
    }

    function renderStats(s) {
        const cards = [
            { label: "Total Users",    value: s.total_users,     accent: "orange", icon: "users" },
            { label: "Onboarded",      value: s.onboarded,       accent: "teal",   icon: "check" },
            { label: "Resumes",        value: s.total_resumes,   accent: "orange", icon: "file" },
            { label: "Mock Tests",     value: s.total_mock_tests,accent: "gold",   icon: "test" },
            { label: "Habits Tracked", value: s.total_habits,    accent: "green",  icon: "habit" },
            { label: "Avg ATS Score",  value: s.avg_ats,         accent: "gold",   icon: "star" },
            { label: "Avg Onboarding", value: s.avg_onboarding,  accent: "teal",   icon: "bar" },
        ];
        const icons = {
            users: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>',
            check: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            file:  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            test:  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
            habit: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
            star:  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
            bar:   '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>'
        };
        statsGrid.innerHTML = cards.map(c => `
            <div class="stat-card" data-accent="${c.accent}">
                <div class="stat-icon ${c.accent}">${icons[c.icon]}</div>
                <div class="stat-value">${c.value}</div>
                <div class="stat-label">${c.label}</div>
            </div>`).join("");
    }

    function renderDepts(depts) {
        if (!depts.length) { deptList.innerHTML = '<p style="color:var(--text-dim);font-size:13px">No data yet</p>'; return; }
        deptList.innerHTML = depts.map(d => `
            <div class="dept-row">
                <span class="dept-name">${esc(d.department)}</span>
                <span class="dept-count">${d.cnt}</span>
            </div>`).join("");
    }

    function renderRecentUsers(users) {
        if (!users.length) { recentUsers.innerHTML = '<p style="color:var(--text-dim);font-size:13px">No users yet</p>'; return; }
        recentUsers.innerHTML = users.map(u => `
            <div class="recent-row">
                <div class="recent-avatar">${(u.full_name || "?")[0].toUpperCase()}</div>
                <div class="recent-info">
                    <div class="recent-name">${esc(u.full_name || "—")}</div>
                    <div class="recent-email">${esc(u.email)}</div>
                </div>
                <span class="recent-time">${formatDate(u.created_at)}</span>
            </div>`).join("");
    }

    /* ══════════════════════════════════════════════════════════════════════════
       STREAKS & LEADERBOARD
       ══════════════════════════════════════════════════════════════════════════ */

    async function loadStreaks() {
        try {
            const res = await fetch("/api/admin/leaderboard");
            const lb = await res.json();
            renderPodium(lb.slice(0, 3));
            renderStreakInsights(lb);
            renderLeaderboard(lb);
        } catch (err) { console.error("Failed to load streaks:", err); }
    }

    function renderPodium(top) {
        if (!top.length) {
            podiumStage.innerHTML = '<p style="color:var(--text-dim);padding:40px 0;text-align:center">No streak data yet</p>';
            return;
        }
        // Reorder for podium: [2nd, 1st, 3rd]
        const ordered = top.length >= 3 ? [top[1], top[0], top[2]] : top.length === 2 ? [top[1], top[0]] : [top[0]];
        podiumStage.innerHTML = ordered.map((p, i) => {
            const actualRank = top.indexOf(p) + 1;
            const initial = (p.name || p.email || "?")[0].toUpperCase();
            const name = p.name || p.email.split("@")[0];
            const crown = actualRank === 1 ? '<span class="podium-crown">👑</span>' : '';
            return `
                <div class="podium-player rank-${actualRank}">
                    ${crown}
                    <div class="podium-avatar">${initial}</div>
                    <div class="podium-name" title="${esc(name)}">${esc(name)}</div>
                    <div class="podium-streak">${p.best_streak} day${p.best_streak !== 1 ? 's' : ''} best</div>
                    <div class="podium-block"><span class="podium-rank">${actualRank}</span></div>
                </div>`;
        }).join("");
    }

    function renderStreakInsights(lb) {
        const total = lb.length;
        const active = lb.filter(u => u.current_streak > 0).length;
        const bestOverall = lb.length ? Math.max(...lb.map(u => u.best_streak)) : 0;
        const avgStreak = total ? (lb.reduce((s, u) => s + u.best_streak, 0) / total).toFixed(1) : 0;
        const totalHabits = lb.reduce((s, u) => s + (u.total_habits || 0), 0);

        streakInsights.innerHTML = `
            <div class="insight-item">
                <div class="insight-icon fire">🔥</div>
                <div class="insight-data">
                    <div class="insight-value">${bestOverall}</div>
                    <div class="insight-label">Longest Streak (days)</div>
                </div>
            </div>
            <div class="insight-item">
                <div class="insight-icon star">⭐</div>
                <div class="insight-data">
                    <div class="insight-value">${avgStreak}</div>
                    <div class="insight-label">Average Best Streak</div>
                </div>
            </div>
            <div class="insight-item">
                <div class="insight-icon users">👥</div>
                <div class="insight-data">
                    <div class="insight-value">${active}<span style="font-size:13px;font-weight:500;color:var(--text-dim)"> / ${total}</span></div>
                    <div class="insight-label">Currently Active Streakers</div>
                </div>
            </div>
            <div class="insight-item">
                <div class="insight-icon chart">📊</div>
                <div class="insight-data">
                    <div class="insight-value">${totalHabits}</div>
                    <div class="insight-label">Total Habits Tracked</div>
                </div>
            </div>`;
    }

    function renderLeaderboard(lb) {
        if (!lb.length) {
            leaderboardBody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-dim)">No leaderboard data</td></tr>';
            return;
        }
        const maxStreak = Math.max(...lb.map(u => u.best_streak), 1);
        leaderboardBody.innerHTML = lb.map((u, i) => {
            const rank = i + 1;
            let medalClass = "default";
            if (rank === 1) medalClass = "gold";
            else if (rank === 2) medalClass = "silver";
            else if (rank === 3) medalClass = "bronze";

            const name = u.name || u.email.split("@")[0];
            const barW = Math.max(8, (u.best_streak / maxStreak) * 100);
            const isActive = u.current_streak > 0;

            return `<tr>
                <td><span class="rank-medal ${medalClass}">${rank}</span></td>
                <td style="font-weight:600;color:var(--text)">${esc(name)}</td>
                <td style="color:var(--text-dim)">${esc(u.email)}</td>
                <td>
                    <span style="font-family:'JetBrains Mono',monospace;font-weight:600">${u.best_streak}</span>
                    <div class="streak-bar-wrap"><div class="streak-bar" style="width:${barW}%"></div></div>
                </td>
                <td style="font-family:'JetBrains Mono',monospace;font-weight:600;color:${isActive ? 'var(--green)' : 'var(--text-dim)'}">${u.current_streak}</td>
                <td style="font-family:'JetBrains Mono',monospace">${u.total_habits || 0}</td>
                <td><span class="status-badge ${isActive ? 'active' : 'inactive'}">${isActive ? 'Active' : 'Idle'}</span></td>
            </tr>`;
        }).join("");
    }

    /* ══════════════════════════════════════════════════════════════════════════
       USERS
       ══════════════════════════════════════════════════════════════════════════ */

    async function loadUsers() {
        try {
            const res = await fetch("/api/admin/users");
            allUsers = await res.json();
            renderUsersTable(allUsers);
        } catch (err) { console.error("Failed to load users:", err); }
    }

    function renderUsersTable(users) {
        userCount.textContent = `${users.length} user${users.length !== 1 ? "s" : ""}`;
        usersBody.innerHTML = users.map(u => `
            <tr>
                <td style="font-family:'JetBrains Mono',monospace;color:var(--text-dim)">${u.id}</td>
                <td style="font-weight:600;color:var(--text)">${esc(u.full_name || "—")}</td>
                <td>${esc(u.email)}</td>
                <td>${esc(u.department || "—")}</td>
                <td style="font-family:'JetBrains Mono',monospace">${u.overall_score != null ? u.overall_score : "—"}</td>
                <td>${u.onboarding_done ? '<span class="onboarded-yes">Yes</span>' : '<span class="onboarded-no">No</span>'}</td>
                <td>${formatDate(u.created_at)}</td>
                <td>
                    <button class="btn-view" onclick="adminViewUser('${esc(u.email)}')">View</button>
                    <button class="btn-delete" onclick="adminDeleteUser('${esc(u.email)}','${esc(u.full_name || u.email)}')">Delete</button>
                </td>
            </tr>`).join("");
    }

    userSearch.addEventListener("input", () => {
        const q = userSearch.value.toLowerCase();
        renderUsersTable(allUsers.filter(u =>
            (u.full_name || "").toLowerCase().includes(q) ||
            u.email.toLowerCase().includes(q) ||
            (u.department || "").toLowerCase().includes(q)
        ));
    });

    /* ── User drawer ── */
    window.adminViewUser = async function (email) {
        try {
            const res = await fetch("/api/admin/users/" + encodeURIComponent(email));
            const data = await res.json();
            if (data.error) return alert(data.error);
            openDrawer(data);
        } catch (err) { console.error(err); }
    };

    function openDrawer(data) {
        const u = data.user;
        const name = u.full_name || u.email;
        drawerTitle.textContent = name;
        drawerEmail.textContent = u.email;
        drawerAvatar.textContent = name[0].toUpperCase();

        let html = "";

        // Profile
        html += section("Profile", `
            <div class="detail-grid">
                <div class="detail-item"><div class="detail-label">Name</div><div class="detail-value">${esc(u.full_name)}</div></div>
                <div class="detail-item"><div class="detail-label">Email</div><div class="detail-value mono">${esc(u.email)}</div></div>
                <div class="detail-item"><div class="detail-label">Joined</div><div class="detail-value">${formatDate(u.created_at)}</div></div>
                <div class="detail-item"><div class="detail-label">Onboarding</div><div class="detail-value">${data.first_login && data.first_login.completed ? "✅ Done" : "❌ Not done"}</div></div>
            </div>`);

        // Onboarding
        if (data.onboarding) {
            const ob = data.onboarding;
            html += section("Onboarding Responses", `
                <div class="detail-grid">
                    <div class="detail-item"><div class="detail-label">Department</div><div class="detail-value">${esc(ob.department)}</div></div>
                    <div class="detail-item"><div class="detail-label">Score</div><div class="detail-value mono">${ob.overall_score}</div></div>
                    <div class="detail-item"><div class="detail-label">Problem Solving</div><div class="detail-value">${ob.problem_solving}/10</div></div>
                    <div class="detail-item"><div class="detail-label">Resume Ready</div><div class="detail-value">${ob.resume_ready}/10</div></div>
                    <div class="detail-item"><div class="detail-label">Interview Ready</div><div class="detail-value">${ob.interview_ready}/10</div></div>
                    <div class="detail-item"><div class="detail-label">Consistency</div><div class="detail-value">${ob.consistency}/10</div></div>
                </div>`);
        }

        // Mock Tests
        if (data.mock_tests && data.mock_tests.length) {
            html += section(`Mock Tests (${data.mock_tests.length})`,
                data.mock_tests.map(t => `
                    <div class="mini-mock">
                        <div class="mini-mock-topic">${esc(t.test_name)}</div>
                        <div class="mini-mock-meta">${esc(t.source)} • ${formatDate(t.taken_at)}</div>
                        <div class="mini-mock-score">${t.score}/${t.max_score}</div>
                    </div>`).join(""));
        }

        // Resumes
        if (data.resumes && data.resumes.length) {
            html += section(`Resumes (${data.resumes.length})`,
                data.resumes.map(r => `
                    <div class="checklist-item">
                        <span class="checklist-skill">${esc(r.filename)}</span>
                        <span class="checklist-level" style="color:var(--orange)">${r.ats_score != null ? "ATS " + r.ats_score : "—"}</span>
                    </div>`).join(""));
        }

        // Habits
        if (data.habits && data.habits.length) {
            html += section(`Habits (${data.habits.length})`,
                data.habits.map(h => `
                    <div class="habit-row">
                        <span class="habit-name"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${h.color};margin-right:8px"></span>${esc(h.name)}</span>
                        <span class="habit-streak">streak</span>
                    </div>`).join(""));
        }

        // Skill Checklist
        if (data.checklist) {
            try {
                const cl = JSON.parse(data.checklist);
                const groups = cl.groups || [];
                let total = 0, learned = 0;
                groups.forEach(g => (g.items || []).forEach(i => { total++; if (i.status === "learned") learned++; }));
                html += section("Skill Checklist", `
                    <div class="detail-grid">
                        <div class="detail-item"><div class="detail-label">Groups</div><div class="detail-value">${groups.length}</div></div>
                        <div class="detail-item"><div class="detail-label">Progress</div><div class="detail-value">${learned}/${total} learned</div></div>
                    </div>`);
            } catch (_) {}
        }

        drawerBody.innerHTML = html;
        userDrawer.classList.add("open");
    }

    function section(title, content) {
        return `<div class="drawer-section"><div class="drawer-section-title">${title}</div>${content}</div>`;
    }

    drawerClose.addEventListener("click", () => userDrawer.classList.remove("open"));
    drawerOverlay.addEventListener("click", () => userDrawer.classList.remove("open"));

    window.adminDeleteUser = async function (email, name) {
        if (!confirm(`Delete user "${name}" and ALL their data? This cannot be undone.`)) return;
        try {
            await fetch("/api/admin/users/" + encodeURIComponent(email), { method: "DELETE" });
            loadUsers();
        } catch (err) { console.error(err); }
    };

    /* ══════════════════════════════════════════════════════════════════════════
       DATABASE EXPLORER
       ══════════════════════════════════════════════════════════════════════════ */

    async function loadTables() {
        try {
            const res = await fetch("/api/admin/tables");
            const tables = await res.json();
            tableTabs.innerHTML = tables.map(t =>
                `<button class="tab-btn${t === currentTable ? " active" : ""}" data-table="${esc(t)}">${esc(t)}</button>`
            ).join("");
            tableTabs.querySelectorAll(".tab-btn").forEach(btn =>
                btn.addEventListener("click", () => selectTable(btn.dataset.table))
            );
            if (tables.length && !currentTable) selectTable(tables[0]);
        } catch (err) { console.error(err); }
    }

    async function selectTable(name) {
        currentTable = name;
        tableTabs.querySelectorAll(".tab-btn").forEach(b =>
            b.classList.toggle("active", b.dataset.table === name)
        );
        try {
            const res = await fetch("/api/admin/tables/" + encodeURIComponent(name));
            const data = await res.json();
            renderDBTable(data, name);
        } catch (err) { console.error(err); }
    }

    function renderDBTable(data, tableName) {
        if (!data.columns || !data.columns.length) {
            dbHead.innerHTML = "";
            dbBody.innerHTML = '<tr><td style="padding:30px;color:var(--text-dim);text-align:center">Empty table</td></tr>';
            dbInfo.textContent = `${tableName} — 0 rows`;
            return;
        }
        dbHead.innerHTML = `<tr>${data.columns.map(c => `<th>${esc(c)}</th>`).join("")}<th>Actions</th></tr>`;
        dbBody.innerHTML = data.rows.map(row => `
            <tr>
                ${data.columns.map(c => `<td title="${esc(String(row[c] ?? ""))}">${esc(truncate(String(row[c] ?? "—"), 60))}</td>`).join("")}
                <td><button class="btn-delete" onclick="adminDeleteRow('${esc(tableName)}', ${row.id || 0})">Del</button></td>
            </tr>`).join("");
        dbInfo.textContent = `${tableName} — ${data.rows.length} row${data.rows.length !== 1 ? "s" : ""}`;
    }

    window.adminDeleteRow = async function (table, id) {
        if (!id) return alert("Cannot delete: no id column");
        if (!confirm(`Delete row #${id} from ${table}?`)) return;
        try {
            await fetch(`/api/admin/tables/${encodeURIComponent(table)}/rows/${id}`, { method: "DELETE" });
            selectTable(table);
        } catch (err) { console.error(err); }
    };

    /* ══════════════════════════════════════════════════════════════════════════
       SQL CONSOLE
       ══════════════════════════════════════════════════════════════════════════ */

    queryRun.addEventListener("click", runQuery);
    queryInput.addEventListener("keydown", e => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runQuery();
    });

    async function runQuery() {
        const sql = queryInput.value.trim();
        if (!sql) return;
        queryStatus.textContent = "Running…";
        queryStatus.style.color = "";

        try {
            const res = await fetch("/api/admin/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ query: sql })
            });
            const data = await res.json();

            if (data.error) {
                queryStatus.textContent = "Error";
                queryStatus.style.color = "var(--red)";
                queryResults.innerHTML = `<div class="empty-state"><p style="color:var(--red)">${esc(data.error)}</p></div>`;
                return;
            }

            if (data.columns && data.columns.length) {
                queryStatus.textContent = `${data.rows.length} row${data.rows.length !== 1 ? "s" : ""}`;
                queryStatus.style.color = "var(--green)";
                queryResults.innerHTML = `
                    <table class="admin-table">
                        <thead><tr>${data.columns.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
                        <tbody>${data.rows.map(r =>
                            `<tr>${data.columns.map(c => `<td title="${esc(String(r[c] ?? ""))}">${esc(truncate(String(r[c] ?? "—"), 80))}</td>`).join("")}</tr>`
                        ).join("")}</tbody>
                    </table>`;
            } else {
                queryStatus.textContent = `${data.affected} affected`;
                queryStatus.style.color = "var(--green)";
                queryResults.innerHTML = `<div class="empty-state"><p style="color:var(--green)">${data.affected} row(s) affected</p></div>`;
            }
        } catch (err) {
            queryStatus.textContent = "Network error";
            queryStatus.style.color = "var(--red)";
        }
    }

    /* ══════════════════════════════════════════════════════════════════════════
       HELPERS
       ══════════════════════════════════════════════════════════════════════════ */

    function esc(str) {
        const d = document.createElement("div");
        d.textContent = str;
        return d.innerHTML;
    }

    function truncate(str, len) {
        return str.length > len ? str.slice(0, len) + "…" : str;
    }

    function formatDate(d) {
        if (!d) return "—";
        try { return new Date(d).toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" }); }
        catch (_) { return d; }
    }

    /* ── Init ── */
    loadOverview();
})();