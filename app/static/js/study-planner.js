/**
 * Smart Study Planner JavaScript – Full-calendar version
 * Monthly calendar view with date-range scheduling (today → target date)
 */

(function () {
    'use strict';

    // ─── State ───────────────────────────────────────────────────────────
    let currentConfig = null;
    let currentSubjects = [];
    let viewYear = new Date().getFullYear();
    let viewMonth = new Date().getMonth() + 1;   // 1-indexed
    let monthTasks = [];   // tasks fetched for the current view month
    let scheduleProgress = null;
    let scheduleDateRange = null;

    // ─── DOM Elements ────────────────────────────────────────────────────
    const calendarViewBtn = document.getElementById('calendarViewBtn');
    const setupViewBtn    = document.getElementById('setupViewBtn');
    const calendarView    = document.getElementById('calendarView');
    const setupView       = document.getElementById('setupView');
    const configForm      = document.getElementById('configForm');
    const addSubjectForm  = document.getElementById('addSubjectForm');
    const subjectsList    = document.getElementById('subjectsList');
    const calGrid         = document.getElementById('calGrid');
    const calMonthLabel   = document.getElementById('calMonthLabel');
    const prevMonthBtn    = document.getElementById('prevMonthBtn');
    const nextMonthBtn    = document.getElementById('nextMonthBtn');
    const generateBtn     = document.getElementById('generateBtn');
    const setupPromptBtn  = document.getElementById('setupPromptBtn');
    const dayDetail       = document.getElementById('dayDetail');
    const dayDetailTitle  = document.getElementById('dayDetailTitle');
    const dayDetailTasks  = document.getElementById('dayDetailTasks');
    const closeDayDetail  = document.getElementById('closeDayDetail');
    const suggestionsBanner  = document.getElementById('suggestionsBanner');
    const suggestionsContent = document.getElementById('suggestionsContent');
    const readinessScore  = document.getElementById('readinessScore');
    const readinessLevel  = document.getElementById('readinessLevel');
    const readinessEmoji  = document.getElementById('readinessEmoji');
    const performanceGrid = document.getElementById('performanceGrid');

    // Progress overview elements
    const progressOverview  = document.getElementById('progressOverview');
    const statDaysRemaining = document.getElementById('statDaysRemaining');
    const statTasksDone     = document.getElementById('statTasksDone');
    const statTotalTasks    = document.getElementById('statTotalTasks');
    const statHoursStudied  = document.getElementById('statHoursStudied');
    const progressBarFill   = document.getElementById('progressBarFill');
    const progressPct       = document.getElementById('progressPct');

    // ─── View toggle ─────────────────────────────────────────────────────
    calendarViewBtn.addEventListener('click', () => switchView('calendar'));
    setupViewBtn.addEventListener('click', () => switchView('setup'));
    if (setupPromptBtn) setupPromptBtn.addEventListener('click', () => switchView('setup'));

    function switchView(view) {
        if (view === 'calendar') {
            calendarViewBtn.classList.add('active');
            setupViewBtn.classList.remove('active');
            calendarView.classList.add('active');
            setupView.classList.remove('active');
            loadCalendar();
        } else {
            setupViewBtn.classList.add('active');
            calendarViewBtn.classList.remove('active');
            setupView.classList.add('active');
            calendarView.classList.remove('active');
        }
    }

    // ─── Month navigation ────────────────────────────────────────────────
    prevMonthBtn.addEventListener('click', () => {
        viewMonth--;
        if (viewMonth < 1) { viewMonth = 12; viewYear--; }
        loadCalendar();
    });

    nextMonthBtn.addEventListener('click', () => {
        viewMonth++;
        if (viewMonth > 12) { viewMonth = 1; viewYear++; }
        loadCalendar();
    });

    // ─── Close day-detail panel ──────────────────────────────────────────
    if (closeDayDetail) closeDayDetail.addEventListener('click', () => {
        dayDetail.style.display = 'none';
    });

    // ─── Configuration Form ──────────────────────────────────────────────
    configForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(configForm);
        const config = Object.fromEntries(formData.entries());

        try {
            const res = await fetch('/api/study-planner/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            if (res.ok) {
                showNotification('Configuration saved!', 'success');
                currentConfig = config;
            } else {
                showNotification('Failed to save configuration', 'error');
            }
        } catch (err) {
            console.error('Error saving config:', err);
            showNotification('Error saving configuration', 'error');
        }
    });

    // ─── Subjects ────────────────────────────────────────────────────────
    addSubjectForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(addSubjectForm);
        const subject = Object.fromEntries(formData.entries());

        try {
            const res = await fetch('/api/study-planner/subjects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(subject),
            });
            if (res.ok) {
                showNotification('Subject added!', 'success');
                addSubjectForm.reset();
                loadSubjects();
            } else {
                showNotification('Failed to add subject', 'error');
            }
        } catch (err) {
            console.error('Error adding subject:', err);
        }
    });

    async function loadSubjects() {
        try {
            const res = await fetch('/api/study-planner/config');
            if (res.ok) {
                const data = await res.json();
                currentSubjects = data.subjects || [];
                renderSubjects();
            }
        } catch (err) { console.error(err); }
    }

    function renderSubjects() {
        if (!currentSubjects.length) {
            subjectsList.innerHTML = '<p class="text-dim">No subjects added yet</p>';
            return;
        }
        subjectsList.innerHTML = currentSubjects.map(s => `
            <div class="subject-item">
                <div class="subject-info">
                    <span class="subject-name">${esc(s.subject_name)}</span>
                    <span class="priority-badge priority-${s.priority}">${s.priority} – wt ${s.weight}</span>
                </div>
                <button class="btn-delete" onclick="deleteSubject('${esc(s.subject_name)}')">Delete</button>
            </div>
        `).join('');
    }

    window.deleteSubject = async function (name) {
        if (!confirm(`Delete ${name}?`)) return;
        try {
            const res = await fetch(`/api/study-planner/subjects/${encodeURIComponent(name)}`, { method: 'DELETE' });
            if (res.ok) { showNotification('Subject deleted', 'success'); loadSubjects(); }
        } catch (err) { console.error(err); }
    };

    // ─── Generate Full Schedule ──────────────────────────────────────────
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/></svg> Generating…';

        try {
            const res = await fetch('/api/study-planner/generate-schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
            if (res.ok) {
                const data = await res.json();
                showNotification(`Schedule generated! ${data.tasks_count} tasks created.`, 'success');
                // Reset view to current month and reload
                const now = new Date();
                viewYear = now.getFullYear();
                viewMonth = now.getMonth() + 1;
                await loadCalendar();
            } else {
                const err = await res.json();
                showNotification(err.error || 'Failed to generate schedule', 'error');
            }
        } catch (err) {
            console.error(err);
            showNotification('Error generating schedule', 'error');
        } finally {
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/></svg> Generate Full Schedule';
        }
    });

    // ─── Calendar API ────────────────────────────────────────────────────
    async function loadCalendar() {
        try {
            const res = await fetch(`/api/study-planner/calendar?year=${viewYear}&month=${viewMonth}`);
            if (!res.ok) return;
            const data = await res.json();
            monthTasks = data.tasks || [];
            scheduleProgress = data.progress;
            scheduleDateRange = data.date_range;
            updateProgressOverview();
            renderMonthlyCalendar();
        } catch (err) { console.error('Error loading calendar:', err); }
    }

    // ─── Progress overview ───────────────────────────────────────────────
    function updateProgressOverview() {
        if (!scheduleProgress) {
            progressOverview.style.display = 'none';
            return;
        }
        progressOverview.style.display = '';
        statDaysRemaining.textContent = scheduleProgress.remaining_days;
        statTasksDone.textContent = scheduleProgress.completed_tasks;
        statTotalTasks.textContent = scheduleProgress.total_tasks;
        statHoursStudied.textContent = Math.round(scheduleProgress.completed_minutes / 60);
        const pct = scheduleProgress.completion_pct || 0;
        progressBarFill.style.width = pct + '%';
        progressPct.textContent = pct + '%';
    }

    // ─── Render monthly calendar ─────────────────────────────────────────
    function renderMonthlyCalendar() {
        const MONTH_NAMES = [
            '', 'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December',
        ];
        calMonthLabel.textContent = `${MONTH_NAMES[viewMonth]} ${viewYear}`;

        if (!monthTasks.length && !scheduleDateRange) {
            calGrid.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
                        <rect x="3" y="4" width="18" height="18" rx="2"/>
                        <line x1="16" y1="2" x2="16" y2="6"/>
                        <line x1="8" y1="2" x2="8" y2="6"/>
                        <line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    <p>No schedule generated yet</p>
                    <button class="btn-setup" onclick="document.getElementById('setupViewBtn').click()">
                        Configure Planner →
                    </button>
                </div>`;
            return;
        }

        // Build a tasksByDate map
        const tasksByDate = {};
        monthTasks.forEach(t => {
            const d = t.task_date;
            if (!tasksByDate[d]) tasksByDate[d] = [];
            tasksByDate[d].push(t);
        });

        const todayStr = new Date().toISOString().slice(0, 10);

        // First day of the month and padding
        const firstDay = new Date(viewYear, viewMonth - 1, 1);
        const startPad = firstDay.getDay(); // 0=Sun
        const daysInMonth = new Date(viewYear, viewMonth, 0).getDate();

        // Previous month tail
        const prevMonthDays = new Date(viewYear, viewMonth - 1, 0).getDate();

        let html = '';

        // Leading blanks (previous month)
        for (let i = startPad - 1; i >= 0; i--) {
            const d = prevMonthDays - i;
            html += `<div class="cal-cell outside"><span class="cal-date-num">${d}</span></div>`;
        }

        // Actual days
        for (let d = 1; d <= daysInMonth; d++) {
            const dateStr = `${viewYear}-${String(viewMonth).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
            const dayTasks = tasksByDate[dateStr] || [];
            const isToday = dateStr === todayStr;
            const total = dayTasks.length;
            const doneCnt = dayTasks.filter(t => t.completed).length;
            const allDone = total > 0 && doneCnt === total;

            let cls = 'cal-cell';
            if (isToday) cls += ' today';
            if (total > 0) cls += ' has-tasks';
            if (allDone) cls += ' all-done';

            // Dots (max 6 shown)
            let dots = '';
            dayTasks.slice(0, 6).forEach(t => {
                let dotCls = 'cal-dot';
                if (t.completed) dotCls += ' done';
                else if (t.task_type === 'revision') dotCls += ' revision';
                else if (t.task_type === 'mock_test') dotCls += ' mock';
                dots += `<span class="${dotCls}"></span>`;
            });

            html += `
                <div class="${cls}" data-date="${dateStr}" onclick="openDayDetail('${dateStr}')">
                    <span class="cal-date-num">${d}</span>
                    <div class="cal-dots">${dots}</div>
                    ${total > 0 ? `<span class="cal-task-count">${doneCnt}/${total}</span>` : ''}
                </div>`;
        }

        // Trailing blanks
        const totalCells = startPad + daysInMonth;
        const trailing = (7 - (totalCells % 7)) % 7;
        for (let i = 1; i <= trailing; i++) {
            html += `<div class="cal-cell outside"><span class="cal-date-num">${i}</span></div>`;
        }

        calGrid.innerHTML = html;
    }

    // ─── Day detail panel ────────────────────────────────────────────────
    window.openDayDetail = function (dateStr) {
        const tasks = monthTasks.filter(t => t.task_date === dateStr);
        if (!tasks.length) {
            dayDetail.style.display = 'none';
            return;
        }

        const d = new Date(dateStr + 'T00:00:00');
        const opts = { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' };
        dayDetailTitle.textContent = d.toLocaleDateString('en-US', opts);

        dayDetailTasks.innerHTML = tasks.map(t => renderTask(t)).join('');
        dayDetail.style.display = '';
        dayDetail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };

    function renderTask(task) {
        const typeClass = `task-type-${task.task_type}`;
        return `
            <div class="task-item ${task.completed ? 'completed' : ''}"
                 data-task-id="${task.id}"
                 onclick="toggleTask(${task.id}, ${task.completed ? 1 : 0}); event.stopPropagation();">
                <span class="task-time">${formatTime(task.task_time)}</span>
                <span class="task-subject">${esc(task.subject)}</span>
                <span class="task-topic">${esc(task.topic)}</span>
                <span class="task-type-badge ${typeClass}">${task.task_type.replace('_', ' ')}</span>
            </div>`;
    }

    // ─── Toggle task ─────────────────────────────────────────────────────
    window.toggleTask = async function (taskId, isCompleted) {
        const url = isCompleted
            ? `/api/study-planner/task/${taskId}/incomplete`
            : `/api/study-planner/task/${taskId}/complete`;

        try {
            const res = await fetch(url, { method: 'POST' });
            if (res.ok) {
                await loadCalendar();
                // Re-open the same day detail if it was open
                const openDate = dayDetailTitle.textContent;
                if (dayDetail.style.display !== 'none' && openDate) {
                    // Find the date str from existing tasks
                    const task = monthTasks.find(t => t.id === taskId);
                    if (task) window.openDayDetail(task.task_date);
                }
            }
        } catch (err) { console.error(err); }
    };

    // ─── Performance & readiness ─────────────────────────────────────────
    async function loadPerformance() {
        try {
            const res = await fetch('/api/study-planner/performance');
            if (!res.ok) return;
            const data = await res.json();
            updateReadiness(data.readiness);
            renderPerformance(data.performance);
        } catch (err) { console.error(err); }
    }

    function updateReadiness(r) {
        if (!r) return;
        readinessScore.textContent = `${r.score}%`;
        readinessLevel.textContent = r.level;
        readinessEmoji.textContent = r.emoji;
    }

    function renderPerformance(p) {
        if (!p || !p.subject_performance || !p.subject_performance.length) {
            performanceGrid.innerHTML = '<p class="text-dim">Complete tasks to see insights</p>';
            return;
        }
        performanceGrid.innerHTML = p.subject_performance.map(s => `
            <div class="performance-card">
                <div class="perf-label">Completion Rate</div>
                <div class="perf-value">${calcCompletion(s)}%</div>
                <div class="perf-subject">${esc(s.subject)}</div>
            </div>
        `).join('');
    }

    function calcCompletion(s) {
        return s.total_tasks ? Math.round((s.total_completed / s.total_tasks) * 100) : 0;
    }

    // ─── Suggestions ─────────────────────────────────────────────────────
    async function loadSuggestions() {
        try {
            const res = await fetch('/api/study-planner/suggestions');
            if (!res.ok) return;
            const data = await res.json();
            if (data.suggestions && data.suggestions.length) {
                suggestionsBanner.style.display = 'flex';
                suggestionsContent.innerHTML = data.suggestions.map(s => `<p>${esc(s)}</p>`).join('');
            } else {
                suggestionsBanner.style.display = 'none';
            }
        } catch (err) { console.error(err); }
    }

    // ─── Config loader ───────────────────────────────────────────────────
    async function loadConfig() {
        try {
            const res = await fetch('/api/study-planner/config');
            if (!res.ok) return;
            const data = await res.json();
            currentConfig = data.config;
            currentSubjects = data.subjects || [];
            if (currentConfig) populateConfigForm(currentConfig);
            renderSubjects();
        } catch (err) { console.error(err); }
    }

    function populateConfigForm(cfg) {
        if (!cfg) return;
        Object.keys(cfg).forEach(k => {
            const el = configForm.elements[k];
            if (el && cfg[k]) el.value = cfg[k];
        });
    }

    // ─── Utilities ───────────────────────────────────────────────────────
    function formatTime(t) {
        const [h, m] = t.split(':');
        const hr = parseInt(h, 10);
        return `${hr % 12 || 12}:${m} ${hr >= 12 ? 'PM' : 'AM'}`;
    }

    function esc(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    function showNotification(message, type = 'info') {
        const n = document.createElement('div');
        n.textContent = message;
        n.style.cssText = `
            position:fixed;top:20px;right:20px;padding:16px 24px;
            background:${type === 'success' ? 'rgba(74,222,128,.2)' : 'rgba(255,77,77,.2)'};
            border:1px solid ${type === 'success' ? 'rgba(74,222,128,.4)' : 'rgba(255,77,77,.4)'};
            color:#fff;border-radius:12px;z-index:1000;
            animation:slideInRight .3s ease;font-size:.9rem;
        `;
        document.body.appendChild(n);
        setTimeout(() => { n.style.animation = 'slideOutRight .3s ease'; setTimeout(() => n.remove(), 300); }, 3000);
    }

    // Inject animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight  { from{transform:translateX(100%);opacity:0} to{transform:translateX(0);opacity:1} }
        @keyframes slideOutRight { from{transform:translateX(0);opacity:1}   to{transform:translateX(100%);opacity:0} }
        .spin { animation:spin 1s linear infinite; }
        @keyframes spin { to{transform:rotate(360deg)} }
    `;
    document.head.appendChild(style);

    // ─── Init ────────────────────────────────────────────────────────────
    async function init() {
        await loadConfig();
        await loadPerformance();
        await loadSuggestions();
        await loadCalendar();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
