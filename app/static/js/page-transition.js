const FADE_DURATION_MS = 260;

function prepareTransition() {
  document.body.classList.add('page-fade');

  const links = document.querySelectorAll('a[href]');
  links.forEach((link) => {
    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) {
      return;
    }

    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }

      event.preventDefault();
      document.body.classList.add('page-fade-exit');
      window.setTimeout(() => {
        window.location.href = link.href;
      }, FADE_DURATION_MS);
    });
  });

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      document.body.classList.remove('page-fade-exit');
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', prepareTransition);
} else {
  prepareTransition();
}
