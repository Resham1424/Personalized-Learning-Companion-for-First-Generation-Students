function updateSyllabusTags() {
  const container = document.querySelector('[data-syllabus-tags]');
  if (!container) {
    return;
  }

  const checkedItems = Array.from(
    document.querySelectorAll('.checklist-item input[type="checkbox"]:checked')
  );
  const names = Array.from(
    new Set(
      checkedItems
        .map((item) => item.closest('.checklist-item')?.querySelector('.skill-name')?.textContent?.trim())
        .filter(Boolean)
    )
  );

  container.innerHTML = '';

  if (names.length === 0) {
    const emptyChip = document.createElement('span');
    emptyChip.className = 'focus-chip';
    emptyChip.textContent = 'No skills selected yet';
    container.appendChild(emptyChip);
    return;
  }

  names.forEach((name) => {
    const chip = document.createElement('span');
    chip.className = 'focus-chip';
    chip.textContent = name;
    container.appendChild(chip);
  });
}

function updateChecklist() {
  const checklist = document.querySelector('.skill-checklist');
  if (!checklist) {
    return;
  }

  const items = Array.from(checklist.querySelectorAll('input[type="checkbox"]'));
  const total = items.length;
  const done = items.filter((item) => item.checked).length;
  const pending = total - done;
  const percent = total === 0 ? 0 : Math.round((done / total) * 100);

  const readinessValue = document.querySelector('[data-readiness-value]');
  const readinessLabel = document.querySelector('[data-readiness-label]');
  const readinessBar = document.querySelector('.readiness-bar');
  const readinessFill = document.querySelector('.readiness-fill');
  const doneCount = document.querySelector('[data-done-count]');
  const pendingCount = document.querySelector('[data-pending-count]');

  if (readinessValue) {
    readinessValue.textContent = `${percent}%`;
  }
  if (doneCount) {
    doneCount.textContent = String(done);
  }
  if (pendingCount) {
    pendingCount.textContent = String(pending);
  }
  if (readinessBar) {
    readinessBar.setAttribute('aria-valuenow', String(percent));
  }
  if (readinessFill) {
    readinessFill.style.width = `${percent}%`;
  }
  if (readinessLabel) {
    if (percent >= 80) {
      readinessLabel.textContent = 'Placement ready';
    } else if (percent >= 50) {
      readinessLabel.textContent = 'On track';
    } else {
      readinessLabel.textContent = 'Building momentum';
    }
  }

  items.forEach((item) => {
    const status = item.closest('.checklist-item')?.querySelector('[data-item-status]');
    if (!status) {
      return;
    }

    if (item.checked) {
      status.textContent = 'Learned';
      status.classList.add('is-done');
      status.classList.remove('is-pending');
    } else {
      status.textContent = 'Pending';
      status.classList.add('is-pending');
      status.classList.remove('is-done');
    }
  });

  updateSyllabusTags();
}

async function persistItemStatus(itemId, status) {
  try {
    await fetch('/api/skill-checklist/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        item_id: itemId,
        status,
      }),
    });
  } catch (error) {
    console.warn('Checklist update failed', error);
  }
}

function bindChecklist() {
  const checklist = document.querySelector('.skill-checklist');
  if (!checklist) {
    return;
  }

  checklist.addEventListener('change', (event) => {
    const target = event.target;
    if (target instanceof HTMLInputElement && target.type === 'checkbox') {
      const item = target.closest('.checklist-item');
      const itemId = item?.dataset.itemId;
      updateChecklist();
      if (itemId) {
        const status = target.checked ? 'learned' : 'pending';
        persistItemStatus(itemId, status);
      }
    }
  });

  updateChecklist();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bindChecklist);
} else {
  bindChecklist();
}
