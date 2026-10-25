'use strict';
// Run before CSS loads. Only the theme preference is stored, never credentials.
(() => {
  const key = 'nf-theme';
  const valid = value => ['system', 'light', 'dark'].includes(value);
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { const saved = localStorage.getItem(key); if (valid(saved)) preference = saved; } catch {}
  function apply() {
    const resolved = preference === 'system' ? (system.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = resolved;
    window.dispatchEvent(new CustomEvent('nf-theme-change', {detail: {preference, resolved}}));
  }
  window.NFTheme = {
    get preference() { return preference; },
    set(value) { if (!valid(value)) return; preference = value; try { localStorage.setItem(key, value); } catch {} apply(); },
  };
  system.addEventListener('change', () => { if (preference === 'system') apply(); });
  window.addEventListener('storage', event => { if (event.key === key || event.key === null) { preference = valid(event.newValue) ? event.newValue : 'system'; apply(); } });
  apply();
})();
