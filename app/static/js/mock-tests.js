const mockState = {
  items: [],
  editingId: null,
};

let lineChartPoints = [];
let barChartPoints = [];

const selectors = {
  form: '[data-mock-form]',
  alert: '[data-mock-alert]',
  list: '[data-mock-list]',
  empty: '[data-mock-empty]',
  avg: '[data-mock-average]',
  best: '[data-mock-best]',
  count: '[data-mock-count]',
  range: '[data-mock-range]',
  latest: '[data-mock-latest]',
  lineChart: '[data-line-chart]',
  barChart: '[data-bar-chart]',
  submitLabel: '[data-submit-label]',
  cancelEdit: '[data-cancel-edit]',
  idField: '[data-mock-id]',
};

function getElement(selector) {
  return document.querySelector(selector);
}

function showAlert(message, type) {
  const alert = getElement(selectors.alert);
  if (!alert) {
    return;
  }
  alert.textContent = message;
  alert.classList.remove('error', 'success');
  alert.classList.add(type);
  alert.hidden = false;
}

function clearAlert() {
  const alert = getElement(selectors.alert);
  if (!alert) {
    return;
  }
  alert.textContent = '';
  alert.classList.remove('error', 'success');
  alert.hidden = true;
}

function formatPercent(value) {
  if (Number.isNaN(value)) {
    return '0%';
  }
  return `${Math.round(value)}%`;
}

function parseNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizeItem(item) {
  const score = parseNumber(item.score);
  const maxScore = parseNumber(item.max_score) || 1;
  const percent = Math.min(100, Math.max(0, (score / maxScore) * 100));
  return {
    ...item,
    score,
    max_score: maxScore,
    percent,
  };
}

function formatDate(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleDateString('en-IN', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
}

function ensureChartTooltip(card) {
  if (!card) {
    return null;
  }
  let tooltip = card.querySelector('.chart-tooltip');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.className = 'chart-tooltip';
    tooltip.setAttribute('role', 'status');
    tooltip.setAttribute('aria-live', 'polite');
    card.appendChild(tooltip);
  }
  return tooltip;
}

function positionTooltip(card, tooltip, x, y, label) {
  if (!card || !tooltip) {
    return;
  }
  tooltip.textContent = label;
  const cardRect = card.getBoundingClientRect();
  tooltip.style.left = `${x - cardRect.left}px`;
  tooltip.style.top = `${y - cardRect.top}px`;
  tooltip.classList.add('is-visible');
}

function hideTooltip(tooltip) {
  if (!tooltip) {
    return;
  }
  tooltip.classList.remove('is-visible');
}

function setEditing(item) {
  const form = getElement(selectors.form);
  const submitLabel = getElement(selectors.submitLabel);
  const cancel = getElement(selectors.cancelEdit);
  const idField = getElement(selectors.idField);
  if (!form || !submitLabel || !cancel || !idField) {
    return;
  }

  form.test_name.value = item.test_name;
  form.source.value = item.source;
  form.score.value = item.score;
  form.max_score.value = item.max_score;
  form.date_taken.value = item.date_taken;
  form.notes.value = item.notes || '';
  idField.value = String(item.id);
  mockState.editingId = item.id;
  submitLabel.textContent = 'Update score';
  cancel.hidden = false;
}

function resetForm() {
  const form = getElement(selectors.form);
  const submitLabel = getElement(selectors.submitLabel);
  const cancel = getElement(selectors.cancelEdit);
  const idField = getElement(selectors.idField);
  if (!form || !submitLabel || !cancel || !idField) {
    return;
  }
  form.reset();
  idField.value = '';
  mockState.editingId = null;
  submitLabel.textContent = 'Save mock test';
  cancel.hidden = true;
  const dateInput = form.querySelector('input[name="date_taken"]');
  if (dateInput && !dateInput.value) {
    dateInput.valueAsDate = new Date();
  }
}

async function fetchMockTests() {
  console.log('Fetching mock tests...');
  const response = await fetch('/api/mock-tests');
  console.log('Response status:', response.status);
  if (!response.ok) {
    throw new Error('Failed to load mock tests');
  }
  const data = await response.json();
  console.log('Fetched data:', data);
  console.log('Items count:', data.items ? data.items.length : 0);
  mockState.items = (data.items || []).map(normalizeItem);
  console.log('Normalized items:', mockState.items);
}

async function saveMockTest(payload) {
  const url = mockState.editingId ? `/api/mock-tests/${mockState.editingId}` : '/api/mock-tests';
  const method = mockState.editingId ? 'PUT' : 'POST';
  const response = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Save failed');
  }
}

async function deleteMockTest(testId) {
  const response = await fetch(`/api/mock-tests/${testId}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Delete failed');
  }
}

function renderStats() {
  const avgEl = getElement(selectors.avg);
  const bestEl = getElement(selectors.best);
  const countEl = getElement(selectors.count);
  const latestEl = getElement(selectors.latest);
  const rangeEl = getElement(selectors.range);

  const items = mockState.items;
  if (!items.length) {
    if (avgEl) avgEl.textContent = '0%';
    if (bestEl) bestEl.textContent = '0%';
    if (countEl) countEl.textContent = '0';
    if (latestEl) latestEl.textContent = '0%';
    if (rangeEl) rangeEl.textContent = 'No tests yet';
    return;
  }

  const average = items.reduce((sum, item) => sum + item.percent, 0) / items.length;
  const best = Math.max(...items.map((item) => item.percent));
  const latest = items[0].percent;

  if (avgEl) avgEl.textContent = formatPercent(average);
  if (bestEl) bestEl.textContent = formatPercent(best);
  if (countEl) countEl.textContent = String(items.length);
  if (latestEl) latestEl.textContent = formatPercent(latest);
  if (rangeEl) rangeEl.textContent = `Last ${Math.min(8, items.length)} tests`;
}

function renderLineChart() {
  const svg = getElement(selectors.lineChart);
  if (!svg) {
    return;
  }

  const items = [...mockState.items].reverse().slice(-8);
  const width = 320;
  const height = 180;
  const padding = 24;

  const points = items.map((item, index) => {
    const xStep = items.length > 1 ? (width - padding * 2) / (items.length - 1) : 0;
    const x = padding + index * xStep;
    const y = height - padding - (item.percent / 100) * (height - padding * 2);
    return {
      x,
      y,
      percent: item.percent,
      index,
      label: `${formatPercent(item.percent)} • ${formatDate(item.date_taken)}`,
    };
  });

  lineChartPoints = points;

  const gridLines = [0.25, 0.5, 0.75].map((ratio) => {
    const y = height - padding - ratio * (height - padding * 2);
    return `<line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="rgba(255,180,140,0.06)" stroke-width="1" stroke-dasharray="4 4" />`;
  });

  // Create smooth bezier curve path
  let curvePath = '';
  if (points.length > 1) {
    curvePath = `M ${points[0].x} ${points[0].y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const midX = (p0.x + p1.x) / 2;
      curvePath += ` C ${midX} ${p0.y}, ${midX} ${p1.y}, ${p1.x} ${p1.y}`;
    }
  } else if (points.length === 1) {
    curvePath = `M ${points[0].x} ${points[0].y}`;
  }

  const polyline = curvePath
    ? `<path class="chart-line" fill="none" stroke="url(#lineGradient)" stroke-width="3.5" d="${curvePath}" />`
    : '';

  const areaPath = points.length > 1
    ? `${curvePath} L ${points[points.length - 1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`
    : '';

  const dots = points
    .map(
      (point) =>
        `<circle class="chart-dot" data-index="${point.index}" cx="${point.x}" cy="${point.y}" r="6" />
         <circle class="chart-dot-glow" cx="${point.x}" cy="${point.y}" r="12" fill="rgba(255,107,53,0.15)" />`
    )
    .join('');

  svg.innerHTML = `
    <defs>
      <linearGradient id="lineGlow" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="rgba(255,140,100,0.4)" />
        <stop offset="60%" stop-color="rgba(255,107,53,0.1)" />
        <stop offset="100%" stop-color="rgba(255,107,53,0)" />
      </linearGradient>
      <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#ff8c5a" />
        <stop offset="50%" stop-color="#FF6B35" />
        <stop offset="100%" stop-color="#ffb899" />
      </linearGradient>
      <filter id="glow">
        <feGaussianBlur stdDeviation="3" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
    ${gridLines.join('')}
    ${areaPath ? `<path class="chart-area" d="${areaPath}" fill="url(#lineGlow)" />` : ''}
    ${polyline}
    ${dots}
  `;

  if (!svg.dataset.bound) {
    svg.dataset.bound = 'true';
    const card = svg.closest('.chart-card');
    const tooltip = ensureChartTooltip(card);
    svg.addEventListener('mousemove', (event) => {
      if (!lineChartPoints.length) {
        hideTooltip(tooltip);
        return;
      }
      const rect = svg.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const nearest = lineChartPoints.reduce((prev, curr) =>
        Math.abs(curr.x - x) < Math.abs(prev.x - x) ? curr : prev
      );
      const dotsList = svg.querySelectorAll('.chart-dot');
      dotsList.forEach((dot) => {
        dot.classList.toggle('is-active', dot.dataset.index === String(nearest.index));
      });
      positionTooltip(card, tooltip, rect.left + nearest.x, rect.top + nearest.y, nearest.label);
    });
    svg.addEventListener('mouseleave', () => {
      const dotsList = svg.querySelectorAll('.chart-dot');
      dotsList.forEach((dot) => dot.classList.remove('is-active'));
      hideTooltip(tooltip);
    });
  }

  // Update trend insight
  const insightEl = document.querySelector('[data-trend-insight]');
  if (insightEl) {
    const insights = [
      'Keep going - consistency is key!',
      'Every test makes you stronger.',
      'Progress happens one step at a time.',
      'You\u2019re building something great.',
      'Trust the process!'
    ];
    if (items.length === 0) {
      insightEl.textContent = 'Add your first test to see your journey!';
    } else if (items.length >= 2) {
      const recent = items.slice(-3);
      const trend = recent[recent.length - 1].percent - recent[0].percent;
      if (trend > 5) {
        insightEl.textContent = '\ud83d\ude80 You\u2019re on an upward trend! Keep it up!';
      } else if (trend < -5) {
        insightEl.textContent = '\ud83d\udcaa Don\u2019t worry, every expert was once a beginner.';
      } else {
        insightEl.textContent = '\u2728 Steady progress - you\u2019re doing great!';
      }
    } else {
      insightEl.textContent = insights[Math.floor(Math.random() * insights.length)];
    }
  }
}

function renderBarChart() {
  const svg = getElement(selectors.barChart);
  if (!svg) {
    return;
  }

  const items = mockState.items.slice(0, 6).reverse();
  const width = 320;
  const height = 120;
  const padding = 20;
  const gap = 12;
  const barWidth = items.length ? (width - padding * 2 - gap * (items.length - 1)) / items.length : 0;

  const bars = items
    .map((item, index) => {
      const barHeight = Math.max(8, (item.percent / 100) * (height - padding * 2));
      const x = padding + index * (barWidth + gap);
      const y = height - padding - barHeight;
      return {
        x,
        y,
        barWidth,
        barHeight,
        index,
        percent: item.percent,
        label: `${formatPercent(item.percent)} • ${formatDate(item.date_taken)}`,
      };
    })
    ;

  barChartPoints = bars;
  const barsMarkup = bars
    .map(
      (bar) =>
        `<rect class="chart-bar" data-index="${bar.index}" x="${bar.x}" y="${bar.y}" width="${bar.barWidth}" height="${bar.barHeight}" rx="10" fill="url(#barGradient)" />`
    )
    .join('');

  svg.innerHTML = `
    <defs>
      <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#ff8c5a" />
        <stop offset="100%" stop-color="#FF6B35" />
      </linearGradient>
    </defs>
    <rect x="${padding}" y="${padding}" width="${width - padding * 2}" height="${height - padding * 2}" rx="12" fill="rgba(255,180,140,0.03)" />
    ${barsMarkup}
  `;

  if (!svg.dataset.bound) {
    svg.dataset.bound = 'true';
    const card = svg.closest('.chart-card');
    const tooltip = ensureChartTooltip(card);
    svg.addEventListener('mousemove', (event) => {
      if (!barChartPoints.length) {
        hideTooltip(tooltip);
        return;
      }
      const rect = svg.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const nearest = barChartPoints.reduce((prev, curr) => {
        const prevCenter = prev.x + prev.barWidth / 2;
        const currCenter = curr.x + curr.barWidth / 2;
        return Math.abs(currCenter - x) < Math.abs(prevCenter - x) ? curr : prev;
      });
      const barsList = svg.querySelectorAll('.chart-bar');
      barsList.forEach((bar) => {
        bar.classList.toggle('is-active', bar.dataset.index === String(nearest.index));
      });
      positionTooltip(card, tooltip, rect.left + nearest.x + nearest.barWidth / 2, rect.top + nearest.y, nearest.label);
    });
    svg.addEventListener('mouseleave', () => {
      const barsList = svg.querySelectorAll('.chart-bar');
      barsList.forEach((bar) => bar.classList.remove('is-active'));
      hideTooltip(tooltip);
    });
  }
}

function renderList() {
  const list = getElement(selectors.list);
  const empty = getElement(selectors.empty);
  if (!list || !empty) {
    return;
  }

  list.innerHTML = '';
  if (!mockState.items.length) {
    list.hidden = true;
    empty.hidden = false;
    return;
  }

  list.hidden = false;
  empty.hidden = true;
  mockState.items.forEach((item, idx) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'mocktest-log-item';
    wrapper.dataset.testId = item.id;
    wrapper.style.animationDelay = `${idx * 50}ms`;
    wrapper.innerHTML = `
      <div class="mocktest-log-main">
        <div class="mocktest-title">${item.test_name}</div>
        <div class="mocktest-meta">\ud83d\udccd ${item.source} \u2022 \ud83d\udcc5 ${formatDate(item.date_taken)}</div>
        ${item.notes ? `<div class="mocktest-meta">\ud83d\udcdd ${item.notes}</div>` : ''}
        <div class="mocktest-actions-row">
          <button type="button" data-action="edit">\u270f\ufe0f Edit</button>
          <button type="button" data-action="delete">\ud83d\uddd1\ufe0f Remove</button>
        </div>
      </div>
      <div class="mocktest-score">
        <span class="mocktest-score-value">${formatPercent(item.percent)}</span>
        <span>${item.score} / ${item.max_score}</span>
      </div>
    `;
    list.appendChild(wrapper);
  });
}

function renderAll() {
  renderStats();
  renderLineChart();
  renderBarChart();
  renderList();
}

async function loadMockTests() {
  try {
    await fetchMockTests();
    renderAll();
  } catch (error) {
    showAlert('Unable to load mock tests right now.', 'error');
  }
}

function bindForm() {
  const form = getElement(selectors.form);
  const cancel = getElement(selectors.cancelEdit);
  if (!form || !cancel) {
    return;
  }

  const dateInput = form.querySelector('input[name="date_taken"]');
  if (dateInput && !dateInput.value) {
    dateInput.valueAsDate = new Date();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAlert();

    const payload = {
      test_name: form.test_name.value.trim(),
      source: form.source.value.trim(),
      score: form.score.value,
      max_score: form.max_score.value,
      date_taken: form.date_taken.value,
      notes: form.notes.value.trim(),
    };

    try {
      await saveMockTest(payload);
      await loadMockTests();
      showAlert(mockState.editingId ? 'Mock test updated.' : 'Mock test saved.', 'success');
      resetForm();
    } catch (error) {
      showAlert(error.message, 'error');
    }
  });

  cancel.addEventListener('click', () => {
    clearAlert();
    resetForm();
  });
}

function bindListActions() {
  const list = getElement(selectors.list);
  if (!list) {
    return;
  }

  list.addEventListener('click', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    const item = target.closest('.mocktest-log-item');
    if (!item) {
      return;
    }

    const testId = Number(item.dataset.testId);
    const data = mockState.items.find((entry) => entry.id === testId);
    if (!data) {
      return;
    }

    if (target.dataset.action === 'delete') {
      try {
        await deleteMockTest(testId);
        await loadMockTests();
        if (mockState.editingId === testId) {
          resetForm();
        }
      } catch (error) {
        showAlert(error.message, 'error');
      }
      return;
    }

    if (target.dataset.action === 'edit') {
      setEditing(data);
      return;
    }

    setEditing(data);
  });
}

function initMockTests() {
  if (!getElement(selectors.form)) {
    return;
  }
  bindForm();
  bindListActions();
  loadMockTests();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initMockTests);
} else {
  initMockTests();
}
