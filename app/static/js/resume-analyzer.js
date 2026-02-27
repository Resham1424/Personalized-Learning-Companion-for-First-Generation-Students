/**
 * Resume Analyzer - Interactive Suggestion Mapping
 * Hover over suggestions to highlight relevant text in resume preview
 */

const resumeState = {
  resumeId: null,
  filename: null,
  content: null,
  analysis: null,
  atsScore: 0,
  activeFilter: 'all',
  activeTab: 'overview',
  highlightMap: new Map(),
  currentPage: 1,
  totalPages: 1,
};

const selectors = {
  uploadSection: '#upload-section',
  analysisSection: '#analysis-section',
  uploadForm: '#resume-upload-form',
  dropzone: '#dropzone',
  fileInput: '#resume-file',
  uploadBtn: '#upload-btn',
  selectedFilename: '#selected-filename',
  newUploadBtn: '#new-upload-btn',
  analysisFilename: '#analysis-filename',
  atsScoreValue: '#ats-score-value',
  atsRingFill: '#ats-ring-fill',
  suggestionsLoading: '#suggestions-loading',
  suggestionsList: '#suggestions-list',
  strengthsSection: '#strengths-section',
  strengthsList: '#strengths-list',
  resumeContent: '#resume-content',
  filterPills: '#filter-pills',
};

function getElement(selector) {
  return document.querySelector(selector);
}

// ─────────────────────────────────────────────────────────────────────────────
// File Upload Handling
// ─────────────────────────────────────────────────────────────────────────────

function initUpload() {
  const dropzone = getElement(selectors.dropzone);
  const fileInput = getElement(selectors.fileInput);
  const uploadForm = getElement(selectors.uploadForm);
  const uploadBtn = getElement(selectors.uploadBtn);

  if (!dropzone || !fileInput) return;

  // Click to select file
  dropzone.addEventListener('click', () => fileInput.click());

  // Drag and drop
  ['dragenter', 'dragover'].forEach((event) => {
    dropzone.addEventListener(event, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((event) => {
    dropzone.addEventListener(event, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length) {
      fileInput.files = files;
      handleFileSelect(files[0]);
    }
  });

  // File input change
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      handleFileSelect(fileInput.files[0]);
    }
  });

  // Form submit
  if (uploadForm) {
    uploadForm.addEventListener('submit', handleUploadSubmit);
  }

  // New upload button
  const newUploadBtn = getElement(selectors.newUploadBtn);
  if (newUploadBtn) {
    newUploadBtn.addEventListener('click', showUploadSection);
  }
}

function handleFileSelect(file) {
  const filenameEl = getElement(selectors.selectedFilename);
  const uploadBtn = getElement(selectors.uploadBtn);

  if (filenameEl) {
    filenameEl.textContent = `Selected: ${file.name}`;
  }

  if (uploadBtn) {
    uploadBtn.disabled = false;
  }
}

async function handleUploadSubmit(e) {
  e.preventDefault();

  const fileInput = getElement(selectors.fileInput);
  const uploadBtn = getElement(selectors.uploadBtn);
  const btnText = uploadBtn?.querySelector('.btn-text');
  const btnLoader = uploadBtn?.querySelector('.btn-loader');

  if (!fileInput?.files.length) return;

  // Show loading state
  if (uploadBtn) uploadBtn.disabled = true;
  if (btnText) btnText.textContent = 'Uploading...';
  if (btnLoader) btnLoader.hidden = false;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const response = await fetch('/api/resume/upload', {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Upload failed');
    }

    // Store resume data
    resumeState.resumeId = data.id;
    resumeState.filename = data.filename;
    resumeState.content = data.content;

    // Show analysis section
    showAnalysisSection();

    // Update preview with PDF
    updateResumePreview(data.id);

    // Update filename
    const analysisFilename = getElement(selectors.analysisFilename);
    if (analysisFilename) {
      analysisFilename.textContent = data.filename;
    }

    // Start analysis
    await analyzeResume();
  } catch (error) {
    alert(error.message || 'Failed to upload resume');
    if (btnText) btnText.textContent = 'Upload & Analyze';
    if (uploadBtn) uploadBtn.disabled = false;
  } finally {
    if (btnLoader) btnLoader.hidden = true;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section Visibility
// ─────────────────────────────────────────────────────────────────────────────

function showUploadSection() {
  const uploadSection = getElement(selectors.uploadSection);
  const analysisSection = getElement(selectors.analysisSection);

  if (uploadSection) uploadSection.style.display = '';
  if (analysisSection) analysisSection.style.display = 'none';

  // Reset form
  const fileInput = getElement(selectors.fileInput);
  const uploadBtn = getElement(selectors.uploadBtn);
  const filenameEl = getElement(selectors.selectedFilename);
  const btnText = uploadBtn?.querySelector('.btn-text');

  if (fileInput) fileInput.value = '';
  if (uploadBtn) uploadBtn.disabled = true;
  if (filenameEl) filenameEl.textContent = '';
  if (btnText) btnText.textContent = 'Upload & Analyze';
}

function showAnalysisSection() {
  const uploadSection = getElement(selectors.uploadSection);
  const analysisSection = getElement(selectors.analysisSection);

  if (uploadSection) uploadSection.style.display = 'none';
  if (analysisSection) analysisSection.style.display = '';
}

// ─────────────────────────────────────────────────────────────────────────────
// Resume Analysis
// ─────────────────────────────────────────────────────────────────────────────

async function analyzeResume() {
  const loadingEl = getElement(selectors.suggestionsLoading);
  const listEl = getElement(selectors.suggestionsList);

  if (loadingEl) loadingEl.style.display = '';

  try {
    const response = await fetch('/api/resume/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resume_id: resumeState.resumeId }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Analysis failed');
    }

    resumeState.analysis = data.analysis;
    resumeState.atsScore = data.ats_score || 87;

    // Update UI
    updateAtsScore(data.ats_score || 87);
    renderSuggestions(data.analysis.suggestions || []);
    renderStrengths(data.analysis.strengths || []);
    renderResumeInsights(data.analysis);
    highlightResumeText();
  } catch (error) {
    if (listEl) {
      listEl.innerHTML = `
        <div class="suggestions-empty">
          <div class="suggestions-empty-icon">⚠️</div>
          <p class="suggestions-empty-text">${error.message || 'Failed to analyze resume'}</p>
        </div>
      `;
    }
  } finally {
    if (loadingEl) loadingEl.style.display = 'none';
  }
}

function updateAtsScore(score) {
  const scoreValue = getElement(selectors.atsScoreValue);
  const ringFill = getElement(selectors.atsRingFill);

  if (scoreValue) {
    animateNumber(scoreValue, 0, score, 1000);
  }

  if (ringFill) {
    setTimeout(() => {
      ringFill.style.strokeDasharray = `${score}, 100`;
    }, 100);
  }
}

function animateNumber(element, start, end, duration) {
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
    const current = Math.round(start + (end - start) * eased);

    element.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

// ─────────────────────────────────────────────────────────────────────────────
// Suggestions Rendering
// ─────────────────────────────────────────────────────────────────────────────

function renderSuggestions(suggestions) {
  const listEl = getElement(selectors.suggestionsList);
  if (!listEl) return;

  // Clear loading
  const loadingEl = listEl.querySelector('.suggestions-loading');
  if (loadingEl) loadingEl.remove();

  if (!suggestions.length) {
    listEl.innerHTML = `
      <div class="suggestions-empty">
        <div class="suggestions-empty-icon">🎉</div>
        <p class="suggestions-empty-text">Your resume looks great! No major improvements needed.</p>
      </div>
    `;
    return;
  }

  // Create suggestion cards
  suggestions.forEach((suggestion, index) => {
    const card = createSuggestionCard(suggestion, index);
    listEl.appendChild(card);
  });

  // Update page count in tab
  const pageCountEl = document.getElementById('page-1-count');
  if (pageCountEl) {
    pageCountEl.textContent = suggestions.length;
  }

  // Setup tabs
  setupSuggestionTabs(suggestions);
}

function createSuggestionCard(suggestion, index) {
  const card = document.createElement('div');
  card.className = 'suggestion-card';
  card.dataset.suggestionId = suggestion.id || `sug-${index}`;
  card.dataset.severity = suggestion.severity || 'minor';
  card.dataset.originalText = suggestion.original_text || '';

  const hasTextChange = suggestion.original_text && suggestion.suggested_text;
  const hasLineHint = suggestion.line_hint;
  
  // Map categories to icon types
  const categoryIcons = {
    'format': 'info',
    'formatting': 'info',
    'content': 'info',
    'citation': 'warning',
    'list': 'info',
    'figure': 'info',
    'section': 'info',
    'table': 'info',
    'grammar': 'warning',
    'skills': 'info',
    'experience': 'info',
    'education': 'info',
    'general': 'info'
  };
  
  const category = (suggestion.category || 'general').toLowerCase();
  const iconType = categoryIcons[category] || 'info';
  const categoryLabel = (suggestion.category || 'general').toUpperCase();

  card.innerHTML = `
    <div class="suggestion-header">
      <div class="suggestion-icon ${iconType}">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
      </div>
      <div class="suggestion-content">
        <span class="suggestion-category">${categoryLabel}</span>
        <h4 class="suggestion-title">${escapeHtml(suggestion.title || 'Suggestion')}</h4>
        <span class="suggestion-location">${hasLineHint ? escapeHtml(suggestion.line_hint) : 'Throughout the document'}</span>
      </div>
      <div class="suggestion-expand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </div>
    </div>
    <p class="suggestion-description">${escapeHtml(suggestion.description || '')}</p>
    ${hasTextChange ? `
      <div class="suggestion-text-change">
        <div class="text-original">
          <strong>Current:</strong>
          <span>${escapeHtml(suggestion.original_text)}</span>
        </div>
        <div class="text-suggested">
          <strong>Suggested:</strong>
          <span>${escapeHtml(suggestion.suggested_text)}</span>
        </div>
      </div>
    ` : ''}
  `;

  // Add click to expand/collapse
  card.addEventListener('click', () => {
    card.classList.toggle('expanded');
  });

  // Add hover interaction for mapping
  if (suggestion.original_text) {
    card.addEventListener('mouseenter', () => {
      highlightTextInPreview(suggestion.original_text, true);
      card.classList.add('is-active');
    });

    card.addEventListener('mouseleave', () => {
      highlightTextInPreview(suggestion.original_text, false);
      card.classList.remove('is-active');
    });
  }

  return card;
}

function setupFilterPills(suggestions) {
  // Legacy - kept for backwards compatibility
}

function setupSuggestionTabs(suggestions) {
  const tabsContainer = document.getElementById('suggestions-tabs');
  if (!tabsContainer) return;

  tabsContainer.addEventListener('click', (e) => {
    const tab = e.target.closest('.suggestion-tab');
    if (!tab) return;

    // Update active state
    tabsContainer.querySelectorAll('.suggestion-tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');

    const tabType = tab.dataset.tab;
    resumeState.activeTab = tabType;

    // Show/hide suggestions based on tab
    const listEl = getElement(selectors.suggestionsList);
    if (!listEl) return;

    if (tabType === 'overview') {
      // Show overview stats
      showOverviewTab(suggestions);
    } else {
      // Show all suggestions
      showSuggestionsTab();
    }
  });
}

function showOverviewTab(suggestions) {
  const listEl = getElement(selectors.suggestionsList);
  if (!listEl) return;

  // Group suggestions by category
  const categories = {};
  suggestions.forEach((s) => {
    const cat = s.category || 'general';
    if (!categories[cat]) categories[cat] = [];
    categories[cat].push(s);
  });

  let overviewHtml = '<div class="overview-content">';
  overviewHtml += '<div class="overview-stats">';
  overviewHtml += `<div class="stat-item"><span class="stat-value">${suggestions.length}</span><span class="stat-label">Total Suggestions</span></div>`;
  
  // Count by severity
  const critical = suggestions.filter(s => s.severity === 'critical').length;
  const important = suggestions.filter(s => s.severity === 'important').length;
  const minor = suggestions.filter(s => s.severity === 'minor').length;
  
  if (critical > 0) overviewHtml += `<div class="stat-item critical"><span class="stat-value">${critical}</span><span class="stat-label">Critical</span></div>`;
  if (important > 0) overviewHtml += `<div class="stat-item warning"><span class="stat-value">${important}</span><span class="stat-label">Important</span></div>`;
  if (minor > 0) overviewHtml += `<div class="stat-item info"><span class="stat-value">${minor}</span><span class="stat-label">Minor</span></div>`;
  
  overviewHtml += '</div>';
  overviewHtml += '<h4 class="overview-section-title">Categories</h4>';
  overviewHtml += '<div class="category-grid">';
  
  Object.keys(categories).forEach((cat) => {
    overviewHtml += `<div class="category-item"><span class="category-name">${cat}</span><span class="category-count">${categories[cat].length}</span></div>`;
  });
  
  overviewHtml += '</div></div>';

  listEl.innerHTML = overviewHtml;
}

function showSuggestionsTab() {
  // Re-render suggestions
  if (resumeState.analysis && resumeState.analysis.suggestions) {
    const listEl = getElement(selectors.suggestionsList);
    if (!listEl) return;
    listEl.innerHTML = '';
    
    resumeState.analysis.suggestions.forEach((suggestion, index) => {
      const card = createSuggestionCard(suggestion, index);
      listEl.appendChild(card);
    });
  }
}

function renderStrengths(strengths) {
  const section = getElement(selectors.strengthsSection);
  const list = getElement(selectors.strengthsList);

  if (!section || !list || !strengths.length) return;

  section.hidden = false;
  list.innerHTML = strengths.map((s) => `<li>${escapeHtml(s)}</li>`).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// PDF.js Rendering & Highlighting
// ─────────────────────────────────────────────────────────────────────────────

let pdfDoc = null;
let pdfTextContent = [];

async function loadPdfPreview(resumeId) {
  const pdfContainer = document.getElementById('pdf-pages');
  if (!pdfContainer) return;

  pdfContainer.innerHTML = '<p style="color: #888; padding: 20px;">Loading PDF...</p>';

  try {
    // Set worker source
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

    // Load PDF
    const pdfUrl = `/api/resume/file/${resumeId}`;
    pdfDoc = await pdfjsLib.getDocument(pdfUrl).promise;
    
    pdfContainer.innerHTML = '';
    pdfTextContent = [];
    
    // Update page count
    resumeState.totalPages = pdfDoc.numPages;
    resumeState.currentPage = 1;
    updatePageNavigation();

    // Render only the first page initially
    await renderCurrentPage();
  } catch (error) {
    console.error('Error loading PDF:', error);
    pdfContainer.innerHTML = '<p style="color: #f66; padding: 20px;">Failed to load PDF preview</p>';
  }
}

async function renderCurrentPage() {
  const pdfContainer = document.getElementById('pdf-pages');
  if (!pdfContainer || !pdfDoc) return;

  pdfContainer.innerHTML = '';
  
  const page = await pdfDoc.getPage(resumeState.currentPage);
  const pageContainer = await renderPdfPage(page, resumeState.currentPage);
  pdfContainer.appendChild(pageContainer);
}

async function renderPdfPage(page, pageNum) {
  const scale = 0.65;
  const viewport = page.getViewport({ scale });

  // Create page container
  const pageDiv = document.createElement('div');
  pageDiv.className = 'pdf-page';
  pageDiv.dataset.pageNum = pageNum;
  pageDiv.style.width = `${viewport.width}px`;
  pageDiv.style.height = `${viewport.height}px`;

  // Create canvas for rendering
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  pageDiv.appendChild(canvas);

  // Render page to canvas
  await page.render({
    canvasContext: context,
    viewport: viewport,
  }).promise;

  // Create text layer
  const textContent = await page.getTextContent();
  const textLayerDiv = document.createElement('div');
  textLayerDiv.className = 'pdf-text-layer';
  textLayerDiv.style.width = `${viewport.width}px`;
  textLayerDiv.style.height = `${viewport.height}px`;

  // Store text content for search
  pdfTextContent.push({
    pageNum,
    items: textContent.items.map((item, idx) => ({
      str: item.str,
      transform: item.transform,
      width: item.width,
      height: item.height,
      dir: item.dir,
      id: `text-${pageNum}-${idx}`,
    })),
  });

  // Render text layer items
  textContent.items.forEach((item, idx) => {
    if (!item.str.trim()) return;

    const tx = pdfjsLib.Util.transform(
      viewport.transform,
      item.transform
    );

    const span = document.createElement('span');
    span.textContent = item.str;
    span.dataset.textId = `text-${pageNum}-${idx}`;
    span.style.left = `${tx[4]}px`;
    span.style.top = `${tx[5] - item.height * scale}px`;
    span.style.fontSize = `${Math.abs(tx[0])}px`;
    span.style.fontFamily = item.fontName || 'sans-serif';

    textLayerDiv.appendChild(span);
  });

  pageDiv.appendChild(textLayerDiv);
  return pageDiv;
}

function highlightTextInPdf(searchText, active) {
  if (!searchText || !pdfTextContent.length) return;

  const normalizedSearch = searchText.toLowerCase().trim();
  const pdfPagesContainer = document.getElementById('pdf-pages');
  if (!pdfPagesContainer) return;

  // Remove existing highlights
  pdfPagesContainer.querySelectorAll('.pdf-text-layer span.highlight').forEach((el) => {
    el.classList.remove('highlight', 'active');
  });

  if (!active) return;

  // Search through all text spans
  let found = false;
  for (const pageData of pdfTextContent) {
    const pageDiv = pdfPagesContainer.querySelector(`[data-page-num="${pageData.pageNum}"]`);
    if (!pageDiv) continue;

    const textLayer = pageDiv.querySelector('.pdf-text-layer');
    if (!textLayer) continue;

    textLayer.querySelectorAll('span').forEach((span) => {
      const spanText = span.textContent.toLowerCase();
      if (normalizedSearch.includes(spanText) || spanText.includes(normalizedSearch.substring(0, 20))) {
        span.classList.add('highlight', 'active');
        if (!found) {
          span.scrollIntoView({ behavior: 'smooth', block: 'center' });
          found = true;
        }
      }
    });
  }
}

function updateResumePreview(resumeId) {
  loadPdfPreview(resumeId);
}

function updatePageNavigation() {
  const currentPageEl = document.getElementById('current-page');
  const totalPagesEl = document.getElementById('total-pages');
  const prevBtn = document.getElementById('prev-page-btn');
  const nextBtn = document.getElementById('next-page-btn');

  if (currentPageEl) currentPageEl.textContent = resumeState.currentPage;
  if (totalPagesEl) totalPagesEl.textContent = resumeState.totalPages;

  if (prevBtn) prevBtn.disabled = resumeState.currentPage <= 1;
  if (nextBtn) nextBtn.disabled = resumeState.currentPage >= resumeState.totalPages;
}

function initPageNavigation() {
  const prevBtn = document.getElementById('prev-page-btn');
  const nextBtn = document.getElementById('next-page-btn');

  if (prevBtn) {
    prevBtn.addEventListener('click', async () => {
      if (resumeState.currentPage > 1) {
        resumeState.currentPage--;
        await renderCurrentPage();
        updatePageNavigation();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', async () => {
      if (resumeState.currentPage < resumeState.totalPages) {
        resumeState.currentPage++;
        await renderCurrentPage();
        updatePageNavigation();
      }
    });
  }
}

function scrollToPage(pageNum) {
  // No longer needed - we render one page at a time
}

function highlightResumeText() {
  // PDF highlighting is handled dynamically on hover
}

function highlightTextInPreview(text, active) {
  highlightTextInPdf(text, active);
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────────────────────

function initResumeAnalyzer() {
  initUpload();
  initPageNavigation();

  // If we have existing resume data, load it
  if (typeof RESUME_DATA !== 'undefined' && RESUME_DATA) {
    resumeState.resumeId = RESUME_DATA.id;
    resumeState.filename = RESUME_DATA.filename;
    resumeState.content = RESUME_DATA.file_content;
    resumeState.analysis = RESUME_DATA.analysis_data;
    resumeState.atsScore = RESUME_DATA.ats_score || 0;

    if (RESUME_DATA.analysis_data) {
      // Update UI with existing analysis
      updateAtsScore(RESUME_DATA.ats_score || 0);
      renderSuggestions(RESUME_DATA.analysis_data.suggestions || []);
      renderStrengths(RESUME_DATA.analysis_data.strengths || []);
      renderResumeInsights(RESUME_DATA.analysis_data);

      // Hide loading
      const loadingEl = getElement(selectors.suggestionsLoading);
      if (loadingEl) loadingEl.style.display = 'none';
    } else if (RESUME_DATA.id) {
      // Resume exists but not analyzed - trigger analysis
      analyzeResume();
    }

    // Load PDF preview for existing resume
    if (RESUME_DATA.id) {
      updateResumePreview(RESUME_DATA.id);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resume Insights: Info, Weak Skills, Improvement Suggestions
// ─────────────────────────────────────────────────────────────────────────────

function renderResumeInsights(analysis) {
  if (!analysis) return;

  const section = document.getElementById('resume-insights-section');

  const hasInfo = analysis.extracted_info &&
    (analysis.extracted_info.skills?.length ||
     analysis.extracted_info.education?.length ||
     analysis.extracted_info.projects?.length ||
     analysis.extracted_info.certifications?.length);

  const hasWeak = analysis.weak_skills && analysis.weak_skills.length > 0;

  if (!hasInfo && !hasWeak) return;  // nothing new to show

  if (section) section.style.display = '';

  if (hasInfo) renderResumeInfo(analysis.extracted_info);
  if (hasWeak) {
    renderWeakSkillsList(analysis.weak_skills);
    renderImprovementSuggestions(analysis.weak_skills);
  }

  // Scroll into view smoothly
  if (section) setTimeout(() => section.scrollIntoView({ behavior: 'smooth', block: 'start' }), 400);
}

function renderResumeInfo(info) {
  const grid = document.getElementById('resume-info-grid');
  if (!grid) return;

  const blocks = [
    { label: '🛠 Skills',         items: info.skills         || [], color: 'teal'   },
    { label: '🎓 Education',      items: info.education      || [], color: 'blue'   },
    { label: '🗂 Projects',       items: info.projects       || [], color: 'orange' },
    { label: '🏅 Certifications', items: info.certifications || [], color: 'purple' },
  ];

  grid.innerHTML = blocks.map(({ label, items, color }) => `
    <div class="info-block info-block--${color}">
      <div class="info-block-label">${label}</div>
      ${items.length
        ? `<ul class="info-block-list">${items.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`
        : `<p class="info-block-empty">Not found</p>`}
    </div>
  `).join('');
}

function renderWeakSkillsList(weakSkills) {
  const list = document.getElementById('weak-skills-list');
  if (!list) return;

  const levelColors = { none: 'red', beginner: 'orange', intermediate: 'yellow' };

  list.innerHTML = weakSkills.map((ws, idx) => {
    const level = (ws.current_level || 'none').toLowerCase();
    const colorClass = levelColors[level] || 'red';
    return `
    <div class="weak-skill-chip" data-idx="${idx}">
      <span class="weak-skill-name">${escapeHtml(ws.name || '')}</span>
      <span class="weak-skill-level weak-skill-level--${colorClass}">${escapeHtml(ws.current_level || 'None')}</span>
      <p class="weak-skill-what">${escapeHtml(ws.what_to_learn || '')}</p>
    </div>`;
  }).join('');
}

function renderImprovementSuggestions(weakSkills) {
  const list = document.getElementById('improvement-list');
  if (!list) return;

  list.innerHTML = weakSkills.map((ws) => {
    const topics    = (ws.topics         || []).slice(0, 4);
    const practice  = (ws.practice_ideas || []).slice(0, 3);
    const resources = (ws.resources      || []).slice(0, 3);

    return `
    <div class="improve-card">
      <div class="improve-card-header">
        <span class="improve-skill-name">${escapeHtml(ws.name || '')}</span>
        ${ws.mini_project ? `<span class="improve-project-badge">🚀 ${escapeHtml(ws.mini_project)}</span>` : ''}
      </div>

      ${topics.length ? `
      <div class="improve-section">
        <div class="improve-section-label">📚 What to Learn</div>
        <div class="improve-tags">
          ${topics.map(t => `<span class="improve-tag improve-tag--topic">${escapeHtml(t)}</span>`).join('')}
        </div>
      </div>` : ''}

      ${practice.length ? `
      <div class="improve-section">
        <div class="improve-section-label">🏋 Practice Ideas</div>
        <ul class="improve-list-items">
          ${practice.map(p => `<li>${escapeHtml(p)}</li>`).join('')}
        </ul>
      </div>` : ''}

      ${resources.length ? `
      <div class="improve-section">
        <div class="improve-section-label">🔗 Resources</div>
        <div class="improve-tags">
          ${resources.map(r => `
            <span class="improve-tag improve-tag--resource">
              <span class="resource-type-badge">${escapeHtml(r.type || 'Link')}</span>
              ${escapeHtml(r.title || '')}
            </span>`).join('')}
        </div>
      </div>` : ''}
    </div>`;
  }).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Smart Roadmap Feature (legacy - button removed)
// ─────────────────────────────────────────────────────────────────────────────

function initSmartRoadmap() {
  const btn = document.getElementById('smart-roadmap-btn');
  if (!btn) return;
  btn.addEventListener('click', handleSmartRoadmap);
}

async function handleSmartRoadmap() {
  const btn = document.getElementById('smart-roadmap-btn');
  const btnText = btn?.querySelector('.sr-btn-text');
  const btnLoader = btn?.querySelector('.sr-btn-loader');
  const section = document.getElementById('smart-roadmap-section');

  if (!resumeState.resumeId) {
    alert('Please upload and analyse your resume first.');
    return;
  }

  // Loading state
  if (btn) btn.disabled = true;
  if (btnText) btnText.textContent = 'Generating…';
  if (btnLoader) btnLoader.hidden = false;
  if (section) section.style.display = 'none';

  try {
    const response = await fetch('/api/resume/smart-roadmap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resume_id: resumeState.resumeId }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to generate roadmap');
    }

    renderSmartRoadmap(data);

    if (section) {
      section.style.display = '';
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  } catch (error) {
    alert(error.message || 'An error occurred while generating the roadmap.');
  } finally {
    if (btn) btn.disabled = false;
    if (btnText) btnText.textContent = 'Generate Smart Roadmap';
    if (btnLoader) btnLoader.hidden = true;
  }
}

// ── Rendering helpers ────────────────────────────────────────────────────────

function renderSmartRoadmap(data) {
  renderResumeSummary(data.extracted_info || {});
  renderSkillGap(data.missing_skills || [], data.skill_gap_analysis || {}, data.strength_areas || []);
  renderRoadmap(data.roadmap || {});
}

function renderResumeSummary(info) {
  const grid = document.getElementById('summary-grid');
  if (!grid) return;

  const sections = [
    { label: '🛠 Skills',          items: info.skills          || [], color: 'teal'   },
    { label: '🎓 Education',       items: info.education       || [], color: 'blue'   },
    { label: '🗂 Projects',        items: info.projects        || [], color: 'orange' },
    { label: '🏅 Certifications',  items: info.certifications  || [], color: 'purple' },
  ];

  grid.innerHTML = sections.map(({ label, items, color }) => `
    <div class="summary-block summary-block--${color}">
      <div class="summary-block-title">${label}</div>
      ${items.length
        ? `<ul class="summary-block-list">${items.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`
        : `<p class="summary-empty">Not detected</p>`
      }
    </div>
  `).join('');
}

function renderSkillGap(missingSkills, gapAnalysis, strengthAreas) {
  // Strength areas
  const strengthRow = document.getElementById('strength-areas-row');
  if (strengthRow) {
    if (strengthAreas.length) {
      strengthRow.innerHTML = `
        <div class="strength-heading">✨ Strength Areas</div>
        <div class="strength-tags">${strengthAreas.map(s => `<span class="strength-tag">${escapeHtml(s)}</span>`).join('')}</div>
      `;
    } else {
      strengthRow.innerHTML = '';
    }
  }

  // Gap tiers
  const tiers = ['beginner', 'intermediate', 'advanced'];
  tiers.forEach((tier) => {
    const listEl = document.getElementById(`gap-${tier}-list`);
    const sectionEl = document.getElementById(`gap-${tier}`);
    const items = gapAnalysis[tier] || [];

    if (!listEl || !sectionEl) return;

    if (!items.length) {
      sectionEl.style.display = 'none';
      return;
    }

    sectionEl.style.display = '';
    listEl.innerHTML = items.map(({ skill, action }) => `
      <div class="gap-skill-item">
        <span class="gap-skill-name">${escapeHtml(skill || '')}</span>
        <span class="gap-skill-action">${escapeHtml(action || '')}</span>
      </div>
    `).join('');
  });

  // Missing skills summary pill list (shown inside gap card header area)
  const gapCard = document.getElementById('skill-gap-card');
  const existingPills = gapCard?.querySelector('.missing-skills-pills');
  if (existingPills) existingPills.remove();

  if (missingSkills.length && gapCard) {
    const pillsDiv = document.createElement('div');
    pillsDiv.className = 'missing-skills-pills';
    pillsDiv.innerHTML = `
      <div class="missing-heading">⚠ Missing Skills</div>
      <div class="missing-pills-wrap">
        ${missingSkills.map(({ name, category, why_important }) => `
          <div class="missing-pill" title="${escapeHtml(why_important || '')}">
            <span class="missing-pill-name">${escapeHtml(name || '')}</span>
            ${category ? `<span class="missing-pill-cat">${escapeHtml(category)}</span>` : ''}
          </div>
        `).join('')}
      </div>
    `;
    // Insert after ai-card-header
    const header = gapCard.querySelector('.ai-card-header');
    if (header) header.insertAdjacentElement('afterend', pillsDiv);
  }
}

function renderRoadmap(roadmap) {
  const timeline = document.getElementById('roadmap-timeline');
  const titleEl = document.getElementById('roadmap-title');

  if (titleEl && roadmap.title) {
    titleEl.textContent = roadmap.title;
  }

  if (!timeline) return;
  const weeks = roadmap.weeks || [];

  if (!weeks.length) {
    timeline.innerHTML = '<p class="roadmap-empty">No roadmap data available.</p>';
    return;
  }

  timeline.innerHTML = weeks.map((w, idx) => `
    <div class="roadmap-week ${idx === 0 ? 'is-first' : ''}">
      <div class="roadmap-week-marker">
        <div class="week-dot"></div>
        ${idx < weeks.length - 1 ? '<div class="week-line"></div>' : ''}
      </div>
      <div class="roadmap-week-card">
        <div class="week-header">
          <span class="week-badge">Week ${w.week}</span>
          <span class="week-theme">${escapeHtml(w.theme || '')}</span>
        </div>
        <div class="week-sections">
          ${renderWeekSection('📚 Topics', w.topics || [])}
          ${renderWeekSection('🏋 Practice', w.practice || [])}
          ${w.project ? `<div class="week-section"><div class="week-section-label">🚀 Project</div><div class="week-project">${escapeHtml(w.project)}</div></div>` : ''}
          ${(w.resources || []).length ? `
            <div class="week-section">
              <div class="week-section-label">🔗 Resources</div>
              <div class="week-resources">
                ${(w.resources || []).map(r => `
                  <span class="resource-chip">
                    <span class="resource-type resource-type--${(r.type || 'docs').toLowerCase()}">${escapeHtml(r.type || 'Docs')}</span>
                    ${escapeHtml(r.title || '')}
                  </span>
                `).join('')}
              </div>
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

function renderWeekSection(label, items) {
  if (!items.length) return '';
  return `
    <div class="week-section">
      <div class="week-section-label">${label}</div>
      <ul class="week-list">${items.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────────────────────

// Run on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initResumeAnalyzer);
} else {
  initResumeAnalyzer();
}
