// MkDocs theme asset override: support color modes without CDN highlight.js.
(() => {
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  const allowed = new Set(['light', 'dark', 'auto']);
  let selected = 'auto';
  try {
    const stored = localStorage.getItem('mkdocs-colormode');
    if (allowed.has(stored)) selected = stored;
  } catch {}

  function render() {
    const resolved = selected === 'auto' ? (system.matches ? 'dark' : 'light') : selected;
    document.documentElement.setAttribute('data-bs-theme', resolved);
    const menu = document.getElementById('theme-menu');
    document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
      const active = toggle.getAttribute('data-bs-theme-value') === selected;
      toggle.setAttribute('aria-pressed', String(active));
      toggle.lastElementChild?.classList.toggle('d-none', !active);
      if (active && menu?.firstElementChild && toggle.firstElementChild) {
        menu.firstElementChild.className = toggle.firstElementChild.className;
      }
    });
  }

  document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
    toggle.addEventListener('click', () => {
      const value = toggle.getAttribute('data-bs-theme-value');
      if (!allowed.has(value)) return;
      selected = value;
      try { localStorage.setItem('mkdocs-colormode', selected); } catch {}
      render();
    });
  });
  system.addEventListener('change', render);
  window.addEventListener('storage', event => {
    if (event.key !== 'mkdocs-colormode') return;
    selected = allowed.has(event.newValue) ? event.newValue : 'auto';
    render();
  });
  render();
})();
