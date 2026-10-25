'use strict';

const app = document.getElementById('app');
const dialog = document.getElementById('dialog');
dialog.className = 'dialog';
const state = {session: null, page: 'overview', auto: true, request: 0, agentsQuery: '', agentsOffset: 0, eventQuery: '', eventKind: '', eventOffset: 0, hours: 24};
let updated = null;
let lastTouch = 0;
let main;
const navLabels = {overview: 'Обзор', agents: 'Агенты', traffic: 'Трафик', events: 'События', security: 'Безопасность'};
const paths = {
  pulse: ['M2 12h5l3-8 4 16 3-8h5'],
  overview: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M3 14h7v7H3z', 'M14 14h7v7h-7z'],
  agents: ['M3 4h18v12H3z', 'M8 21h8', 'M12 16v5', 'M7 8h.01', 'M11 8h6'],
  traffic: ['M4 19V9', 'M10 19V4', 'M16 19v-7', 'M22 19V7'],
  events: ['M12 3 2 20h20L12 3z', 'M12 9v4', 'M12 17h.01'],
  security: ['M12 3 3 7v5c0 5 9 10 9 10s9-5 9-10V7l-9-4z', 'm8 12 3 3 5-6'],
  logout: ['M9 4H4v16h5', 'M13 8l4 4-4 4', 'M8 12h13'],
  plus: ['M12 5v14', 'M5 12h14'],
  refresh: ['M20 7a9 9 0 1 0 1 7', 'M20 3v5h-5'],
  search: ['M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15', 'm16 16 5 5'],
  close: ['M6 6l12 12', 'M18 6 6 18'],
  chevron: ['m9 5 7 7-7 7'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M4 16v5h16v-5'],
  key: ['M14 3a7 7 0 1 0 7 7 7 7 0 0 0-7-7', 'M9 15l-7 7', 'm4 18 3 3'],
  clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18', 'M12 7v5l3 2'],
};
function node(tag, cls, text) { const item = document.createElement(tag); if (cls) item.className = cls; if (text !== undefined) item.textContent = text; return item; }
function icon(name) { const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.setAttribute('viewBox', '0 0 24 24'); svg.classList.add('icon'); svg.setAttribute('aria-hidden', 'true'); for (const d of (paths[name] || paths.pulse)) { const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', d); svg.append(path); } return svg; }
function button(text, cls, action, glyph) { const item = node('button', cls || 'button', text); item.type = 'button'; if (glyph) item.prepend(icon(glyph)); if (action) item.addEventListener('click', action); return item; }
function brand() { const item = node('div', 'brand'); const mark = node('span', 'brand-mark'); mark.append(icon('pulse')); const text = node('span', '', 'NFDetector'); text.append(node('small', '', 'NETWORK SECURITY')); item.append(mark, text); return item; }
function badge(text, color = '', withDot = false) { const item = node('span', 'badge ' + color); if (withDot) item.append(node('i', 'dot')); item.append(document.createTextNode(text)); return item; }
function number(value) { return new Intl.NumberFormat('ru-RU').format(Number(value || 0)); }
function bytes(value) { let count = Number(value || 0); const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']; let index = 0; while (count >= 1024 && index < units.length - 1) { count /= 1024; index++; } return count.toLocaleString('ru-RU', {maximumFractionDigits: count >= 100 || !index ? 0 : 1}) + ' ' + units[index]; }
function time(value) { if (!value) return '—'; return new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString('ru-RU', {day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'}); }
function relative(value) { if (!value) return 'Ещё не подключался'; const sec = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000); if (sec < 60) return 'Только что'; if (sec < 3600) return Math.floor(sec / 60) + ' мин назад'; if (sec < 86400) return Math.floor(sec / 3600) + ' ч назад'; return time(value); }
function empty(title, hint, compact = false) { const item = node('div', 'empty' + (compact ? ' compact' : '')); item.append(node('strong', '', title), node('span', '', hint)); return item; }
function toast(text, error = false) { const container = document.getElementById('notifications'); container.replaceChildren(node('div', 'notification' + (error ? ' error' : ''), text)); window.setTimeout(() => container.replaceChildren(), 4500); }
class ApiError extends Error { constructor(message, code, status) { super(message); this.code = code; this.status = status; } }
async function api(path, options = {}) {
  const method = options.method || 'GET';
  const headers = {'Accept': 'application/json'};
  if (method !== 'GET') { headers['Content-Type'] = 'application/json'; if (state.session?.csrf_token) headers['X-CSRF-Token'] = state.session.csrf_token; }
  const response = await fetch('/admin/api' + path, {method, headers, credentials: 'same-origin', cache: 'no-store', ...(options.body !== undefined ? {body: JSON.stringify(options.body)} : {})});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    const message = typeof detail === 'string' ? detail : (detail?.message || 'Проверьте данные и повторите запрос');
    if (response.status === 401 && state.session?.authenticated) { const setup = Boolean(state.session.must_change_password); state.session = null; state.request++; if (dialog.open) dialog.close(); showLogin(setup); }
    throw new ApiError(message, detail?.code, response.status);
  }
  return data;
}
async function mutate(path, body = {}) { try { return await api(path, {method: 'POST', body}); } catch (error) { if (error.code === 'reauth_required') { await reauthenticate(); return api(path, {method: 'POST', body}); } throw error; } }
function field(label, name, type = 'text', hint = '', value = '') { const wrapper = node('label', 'field', label); const input = node('input'); input.name = name; input.type = type; input.value = value; input.required = true; input.maxLength = type === 'password' ? 128 : 128; if (type === 'password') input.autocomplete = name === 'new_password' || name === 'confirm_password' ? 'new-password' : 'current-password'; wrapper.append(input); if (hint) wrapper.append(node('small', '', hint)); return {wrapper, input}; }
function formHandler(form, submit, errorBox, handler) { form.addEventListener('submit', async event => { event.preventDefault(); submit.disabled = true; errorBox.textContent = ''; try { await handler(); } catch (error) { errorBox.textContent = error.message || 'Нет связи с сервером'; } finally { submit.disabled = false; } }); }
function openDialog(title, content) { const header = node('div', 'dialog-head'); const heading = node('h2', '', title); heading.id = 'dialog-title'; const close = button('', 'icon-button', () => dialog.close(), 'close'); close.setAttribute('aria-label', 'Закрыть'); header.append(heading, close); const body = node('div', 'dialog-body'); body.append(content); dialog.replaceChildren(header, body); if (!dialog.open) dialog.showModal(); }
dialog.addEventListener('close', () => { dialog.replaceChildren(); });
function reauthenticate() { return new Promise((resolve, reject) => {
  const form = node('form', 'form'); form.append(node('p', 'dialog-intro', 'Для управления ключами подтвердите текущий пароль.')); const pwd = field('Текущий пароль', 'password', 'password'); const error = node('div', 'form-error'); const submit = node('button', 'button', 'Подтвердить'); submit.type = 'submit'; form.append(pwd.wrapper, error, submit);
  let complete = false;
  const closed = () => { if (!complete) reject(new Error('Действие отменено')); };
  dialog.addEventListener('close', closed, {once: true});
  formHandler(form, submit, error, async () => { await api('/reauth', {method: 'POST', body: {password: pwd.input.value}}); pwd.input.value = ''; complete = true; dialog.close(); resolve(); });
  openDialog('Подтверждение входа', form); pwd.input.focus();
}); }
function themeControl() {
  const select = node('select', 'theme-select'); select.setAttribute('aria-label', 'Тема оформления');
  for (const [value, label] of [['system', 'Системная'], ['light', 'Светлая'], ['dark', 'Тёмная']]) { const option = node('option', '', label); option.value = value; select.append(option); }
  select.value = window.NFTheme?.preference || 'system';
  select.addEventListener('change', () => window.NFTheme?.set(select.value)); return select;
}
window.addEventListener('nf-theme-change', () => { for (const control of document.querySelectorAll('.theme-select')) control.value = window.NFTheme.preference; });
function authLayout(card, first = false) { if (main) clearCharts(); app.replaceChildren(); const shell = node('div', 'auth-shell'); const aside = node('aside', 'auth-aside'); aside.append(brand()); const copy = node('div', 'auth-copy'); copy.append(node('p', 'eyebrow', 'Сеть под наблюдением'), node('h1', '', 'Видеть активность.\nЗамечать угрозы.'), node('p', '', 'Агенты, сетевой трафик и события безопасности — в одном центре управления.')); const foot = node('div', 'auth-foot'); foot.append(icon('security'), document.createTextNode('Защищённая панель управления')); aside.append(copy, foot); const area = node('main', 'auth-main'); const theme = node('div', 'auth-theme'); theme.append(themeControl()); area.append(theme); const mobile = node('div', 'mobile-brand'); mobile.append(brand()); card.prepend(mobile); area.append(card); shell.append(aside, area); app.append(shell); app.setAttribute('aria-busy', 'false'); }
function showLogin(setup) { const card = node('section', 'auth-card'); card.append(node('p', 'eyebrow', setup ? 'Первоначальная настройка' : 'Панель управления'), node('h2', '', setup ? 'Добро пожаловать' : 'Вход в NFDetector'), node('p', 'intro', setup ? 'Войдите под root:root. Следующим шагом потребуется установить собственный пароль.' : 'Войдите, чтобы просматривать состояние сети и управлять агентами.'));
  if (setup) { const note = node('div', 'setup-note', 'Для защиты первого входа получите одноразовый код на сервере:'); note.append(node('code', '', 'docker compose exec api python -m distributed setup-code')); card.append(note); }
  const form = node('form', 'form'); const username = field('Имя пользователя', 'username', 'text', '', 'root'); username.input.autocomplete = 'username'; const password = field('Пароль', 'password', 'password'); form.append(username.wrapper, password.wrapper); let code;
  if (setup) { code = field('Одноразовый код установки', 'setup_code', 'password'); code.input.autocomplete = 'one-time-code'; form.append(code.wrapper); }
  const error = node('div', 'form-error'); const submit = node('button', 'button', 'Войти'); submit.type = 'submit'; form.append(error, submit); card.append(form, node('p', 'auth-caption', 'Вход и действия администратора регистрируются в журнале безопасности.'));
  formHandler(form, submit, error, async () => { const session = await api('/login', {method: 'POST', body: {username: username.input.value, password: password.input.value, setup_code: code?.input.value || ''}}); password.input.value = ''; if (code) code.input.value = ''; state.session = session; if (session.must_change_password) showPasswordSetup(); else showShell(); });
  authLayout(card, setup);
}
async function signOut() { const setup = Boolean(state.session?.must_change_password); try { await api('/logout', {method: 'POST', body: {}}); state.session = null; state.request++; if (dialog.open) dialog.close(); showLogin(setup); } catch (error) { toast(error.message, true); } }
function passwordForm(onSuccess) { const form = node('form', 'form'); const current = field('Текущий пароль', 'current_password', 'password'); const password = field('Новый пароль', 'new_password', 'password', 'От 15 до 128 символов. Можно использовать длинную парольную фразу.'); password.input.minLength = 15; const confirm = field('Повторите новый пароль', 'confirm_password', 'password'); confirm.input.minLength = 15; const error = node('div', 'form-error'); const submit = node('button', 'button', 'Сохранить пароль'); submit.type = 'submit'; form.append(current.wrapper, password.wrapper, confirm.wrapper, error, submit);
  formHandler(form, submit, error, async () => { if (password.input.value !== confirm.input.value) throw new Error('Новые пароли не совпадают'); const result = await api('/password', {method: 'POST', body: {current_password: current.input.value, new_password: password.input.value}}); current.input.value = password.input.value = confirm.input.value = ''; state.session = result; onSuccess(); }); return form;
}
function showPasswordSetup() { const card = node('section', 'auth-card'); card.append(node('p', 'eyebrow', 'Шаг 2 из 2'), node('h2', '', 'Установите свой пароль'), node('p', 'intro', 'Первоначальный пароль нужно заменить. Статистика и управление агентами станут доступны после этого шага.'), passwordForm(() => { toast('Пароль установлен. Первоначальный доступ отключён.'); showShell(); }), node('p', 'auth-caption', 'Одноразовый код станет недействительным. Остальные сеансы входа будут завершены.')); authLayout(card, true); }
function showShell() { if (main) clearCharts(); app.replaceChildren(); const shell = node('div', 'shell'); const sidebar = node('aside', 'sidebar'); sidebar.append(brand(), node('div', 'nav-label', 'РАБОЧЕЕ ПРОСТРАНСТВО')); const nav = node('nav', 'nav'); nav.setAttribute('aria-label', 'Главная навигация'); for (const [page, label] of Object.entries(navLabels)) { const item = button('', '', () => navigate(page), page); item.setAttribute('aria-label', label); item.title = label; item.dataset.page = page; item.append(node('span', '', label)); nav.append(item); } sidebar.append(nav); const bottom = node('div', 'sidebar-foot'); const secure = node('div', 'secure-label'); secure.append(icon('security'), document.createTextNode('Защищённое соединение')); const user = node('div', 'user-block'); const copy = node('div', 'user-copy', state.session.username); copy.append(node('small', '', 'Администратор')); const logout = button('', 'logout', signOut, 'logout'); logout.setAttribute('aria-label', 'Выйти'); user.append(node('div', 'avatar', 'R'), copy, logout); bottom.append(secure, user); sidebar.append(bottom); const wrap = node('div', 'main-wrap'); const topbar = node('header', 'topbar'); const crumb = node('div', 'breadcrumb'); crumb.append(node('span', '', 'Центр наблюдения'), node('span', '', '/')); const current = node('strong', '', navLabels[state.page]); current.id = 'breadcrumb-page'; crumb.append(current); const actions = node('div', 'top-actions'); const timestamp = node('span', 'updated'); timestamp.id = 'updated'; const live = button('', 'live', () => { state.auto = !state.auto; live.replaceChildren(node('i', 'dot'), document.createTextNode(state.auto ? 'Автообновление' : 'Обновление на паузе')); live.setAttribute('aria-pressed', String(state.auto)); }); live.append(node('i', 'dot'), document.createTextNode(state.auto ? 'Автообновление' : 'Обновление на паузе')); live.setAttribute('aria-pressed', String(state.auto)); const refresh = button('', 'icon-button', () => loadView(), 'refresh'); refresh.setAttribute('aria-label', 'Обновить данные'); actions.append(timestamp, live, themeControl(), refresh); topbar.append(crumb, actions); main = node('main', 'main'); main.id = 'main-content'; wrap.append(topbar, main); shell.append(sidebar, wrap); app.append(shell); app.setAttribute('aria-busy', 'false'); navigate(state.page); }
function navigate(page) { state.page = page; if (dialog.open) dialog.close(); for (const item of document.querySelectorAll('.nav button')) { item.classList.toggle('active', item.dataset.page === page); if (item.dataset.page === page) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current'); } document.getElementById('breadcrumb-page').textContent = navLabels[page]; loadView(); }
function heading(title, description, action) { const item = node('div', 'page-heading'); const text = node('div'); text.append(node('p', 'eyebrow', 'NFDetector / ' + navLabels[state.page]), node('h1', '', title), node('p', '', description)); item.append(text); if (action) item.append(action); return item; }
function panel(title, subtitle = '', action) { const root = node('section', 'panel'); const head = node('div', 'panel-head'); const text = node('div'); text.append(node('h2', '', title)); if (subtitle) text.append(node('p', '', subtitle)); head.append(text); if (action) head.append(action); root.append(head); return root; }
function metric(label, value, note, glyph, positive = false) { const root = node('div', 'metric'); const head = node('div', 'metric-top', label); const symbol = node('span', 'metric-symbol'); symbol.append(icon(glyph)); head.append(symbol); root.append(head, node('div', 'metric-value', value), node('div', 'metric-note' + (positive ? ' positive' : ''), note)); return root; }
function statusBadge(status, compact = false) { const values = {online: ['На связи', 'green'], offline: ['Нет связи', ''], never_seen: ['Ожидает подключения', 'blue'], revoked: ['Ключ отозван', ''], error: ['Ошибка захвата', 'red']}; const [text, color] = values[status] || [status, '']; const brief = {never_seen: 'Ожидание', revoked: 'Отозван', error: 'Ошибка'}; return badge(compact ? (brief[status] || text) : text, color, true); }
function table(headers) { const root = node('table'); const head = node('thead'); const line = node('tr'); for (const title of headers) line.append(node('th', '', title)); head.append(line); const body = node('tbody'); root.append(head, body); const scroll = node('div', 'table-scroll'); scroll.append(root); return {scroll, body}; }
function cell(text, cls = '') { return node('td', cls, text); }
function nameCell(agent) { const root = cell(); const inner = node('div', 'name-cell'); const device = node('span', 'device-icon'); device.append(icon('agents')); const name = node('div', 'primary-text', agent.name); name.append(node('span', 'secondary-text mono', agent.id.slice(0, 8))); inner.append(device, name); root.append(inner); return root; }
function agentTable(items, compact = false) { if (!items.length) return empty('Агенты ещё не подключены', 'Выпустите ключ и запустите агент на наблюдаемом узле.'); const result = table(compact ? ['Агент', 'Состояние'] : ['Агент', 'Домен', 'Состояние', 'Трафик / пакеты', 'Очередь', 'Действия']); for (const agent of items) { if (compact) result.scroll.classList.add('compact-table'); const tr = node('tr'); const identity = nameCell(agent); if (compact) identity.querySelector('.secondary-text').textContent = relative(agent.last_seen_at); tr.append(identity); if (!compact) tr.append(cell(agent.domain, 'mono')); const status = cell(); status.append(statusBadge(agent.status, compact)); tr.append(status); if (!compact) { const traffic = cell(bytes(agent.received_bytes)); traffic.append(node('span', 'secondary-text', number(agent.packets) + ' пакетов')); const queue = cell(number(agent.queued) + ' файлов'); if (agent.failed) queue.append(node('span', 'secondary-text', number(agent.failed) + ' с ошибкой')); const actions = cell(); const group = node('div', 'row-actions'); group.append(button('Подробнее', '', () => agentDetails(agent)), button('Новый ключ', '', () => rotateDialog(agent))); if (!agent.revoked) group.append(button('Установить', '', () => installationDialog(agent)), button('Отозвать', 'destructive', () => revokeDialog(agent))); actions.append(group); tr.append(traffic, queue, actions); } result.body.append(tr); } return result.scroll; }
function eventKind(reason) { return reason.split(':', 1)[0]; }
function eventTitle(kind) { const labels = {DDOS: 'DDoS / flood', BRUTEFORCE_SSH_HANDSHAKES: 'Возможный перебор SSH', DDoS_SINGLE_IP: 'Высокая частота запросов', DDoS_MULTI_IP: 'Распределённая атака', SYN_FLOOD_HALF_OPEN: 'SYN flood', HTTP_FLOOD: 'HTTP flood', C2_BEACONING: 'Периодические соединения', SUSPICIOUS_SOURCE_IP: 'Подозрительный источник', SUSPICIOUS_DEST_IP: 'Подозрительная цель', DECODE_WARNING: 'Предупреждение разбора'}; return labels[kind] || (kind.startsWith('BRUTEFORCE_') ? 'Перебор · ' + kind.slice(11) : kind); }
function eventBadge(kind) { if (kind === 'DECODE_WARNING') return badge('Разбор', 'blue'); if (kind.startsWith('BRUTEFORCE_') || kind.startsWith('SUSPICIOUS_')) return badge('Внимание', 'orange'); return badge('Высокий', 'red'); }
function incidentDuration(value) { const seconds = Math.max(0, Math.floor(Number(value) || 0)); if (seconds < 60) return seconds + ' с'; const minutes = Math.floor(seconds / 60); if (minutes < 60) return minutes + ' мин ' + (seconds % 60) + ' с'; return Math.floor(minutes / 60) + ' ч ' + (minutes % 60) + ' мин'; }
function incidentStatus(event) { if (event.status === 'closed') return badge(event.close_reason === 'capture_ended' ? 'Захват завершён' : 'Завершён', 'blue'); if (event.status === 'awaiting_data') return badge('Нет свежих данных', 'orange'); return badge('Продолжается', 'green'); }
function eventTable(items, compact = false) {
  if (!items.length) return empty('Инцидентов пока нет', 'Связанные срабатывания будут объединены в события с длительностью.');
  const result = table(compact ? ['Событие', 'Источник → цель', 'Период активности'] : ['Событие', 'Состояние', 'Источник → цель', 'Агент', 'Период активности', '']);
  for (const event of items) {
    const kind = event.kind || eventKind(event.reason); const tr = node('tr'); const title = cell();
    title.append(node('span', 'event-name', eventTitle(kind)), node('span', 'secondary-text', number(event.signal_count || 0) + ' срабатываний'));
    tr.append(title); if (!compact) tr.append(cellWith(incidentStatus(event)));
    const route = cell(); const sources = event.sources || [event.source].filter(Boolean);
    route.append(node('span', 'mono', sources.length > 1 ? sources[0] + ' и ещё ' + (sources.length - 1) : sources[0] || '—'), node('span', 'secondary-text mono', '→ ' + (event.target || '—')));
    tr.append(route); if (!compact) tr.append(cell(event.agent_name));
    const period = cell(time(event.first_seen ?? event.timestamp), 'small muted');
    period.append(node('span', 'secondary-text', '→ ' + time(event.last_seen ?? event.timestamp)), node('span', 'secondary-text', incidentDuration(event.duration_seconds)));
    tr.append(period);
    if (!compact) { const more = cell(); const open = button('', 'icon-button', () => eventDetails(event), 'chevron'); open.setAttribute('aria-label', 'Подробнее о событии'); more.append(open); tr.append(more); }
    result.body.append(tr);
  }
  return result.scroll;
}
function cellWith(child) { const value = cell(); value.append(child); return value; }

const chartDrawers = new WeakMap();
const chartResize = typeof ResizeObserver === 'function' ? new ResizeObserver(entries => { for (const entry of entries) chartDrawers.get(entry.target)?.(entry.contentRect.width); }) : null;
function watchCharts() { for (const plot of main.querySelectorAll('.chart-plot')) { chartDrawers.get(plot)?.(plot.clientWidth); chartResize?.observe(plot); } }
function clearCharts() { for (const plot of main.querySelectorAll('.chart-plot')) chartResize?.unobserve(plot); }
function chart(data, period) {
  const wrap = node('div', 'chart-wrap'); const plot = node('div', 'chart-plot'); plot.tabIndex = 0; plot.setAttribute('role', 'group');
  plot.setAttribute('aria-label', 'Принято PCAP за период. Стрелки влево и вправо показывают значения интервалов.');
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.classList.add('traffic-chart'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Объём принятых PCAP по интервалам');
  const tooltip = node('div', 'chart-tooltip', 'Наведите на график или используйте стрелки для просмотра интервала.');
  plot.append(svg); wrap.append(plot, tooltip);
  const start = new Date(period.start).getTime(); const end = new Date(period.end).getTime();
  const maximum = Math.max(0, ...data.map(item => Number(item.bytes)));
  const power = 10 ** Math.floor(Math.log10(maximum || 1)); const scale = maximum / power;
  const max = Math.max(3, (scale <= 1 ? 1 : scale <= 2 ? 2 : scale <= 5 ? 5 : 10) * power);
  let width = 780, left = 64, right = 764, selected = -1, cursor, dot;
  const y = value => 184 - Number(value) / max * 148;
  const x = timestamp => left + (timestamp - start) / (end - start) * (right - left);
  const center = index => new Date(data[index].hour).getTime() + period.bucket_seconds * 500;
  function shape(tag, attrs, text) { const el = document.createElementNS(svg.namespaceURI, tag); for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value); if (text !== undefined) el.textContent = text; svg.append(el); return el; }
  function select(index) {
    if (!data.length) return;
    selected = Math.max(0, Math.min(data.length - 1, index)); const item = data[selected];
    const xx = x(center(selected)); cursor.setAttribute('x1', xx); cursor.setAttribute('x2', xx); cursor.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', xx); dot.setAttribute('cy', y(item.bytes)); dot.setAttribute('visibility', 'visible');
    tooltip.textContent = time(item.hour) + ' — ' + time(new Date(new Date(item.hour).getTime() + period.bucket_seconds * 1000).toISOString()) + ' · ' + bytes(item.bytes) + ' PCAP · ' + number(item.packets) + ' пакетов · ' + number(item.files) + ' файлов';
  }
  function draw(available) {
    if (available <= 0) return;
    width = Math.max(230, Math.floor(available)); right = width - 14;
    svg.setAttribute('viewBox', '0 0 ' + width + ' 225'); svg.replaceChildren();
    for (let i = 0; i <= 3; i++) { const value = max * (3 - i) / 3; const yy = y(value); shape('line', {x1: left, x2: right, y1: yy, y2: yy, class: 'chart-grid'}); shape('text', {x: left - 9, y: yy + 4, 'text-anchor': 'end', class: 'chart-text'}, bytes(value)); }
    if (data.length) {
      const path = data.map((item, index) => (index ? 'L' : 'M') + x(center(index)).toFixed(2) + ',' + y(item.bytes).toFixed(2)).join(' ');
      shape('path', {d: path + ' L' + x(center(data.length - 1)) + ',184 L' + x(center(0)) + ',184 Z', class: 'chart-area'});
      shape('path', {d: path, class: 'chart-line'});
    }
    const ticks = Math.max(2, Math.floor((right - left) / 110) + 1);
    for (let i = 0; i < ticks; i++) { const t = start + (end - start) * i / (ticks - 1); const label = new Date(t).toLocaleString('ru-RU', period.hours >= 168 ? {day: '2-digit', month: 'short'} : period.hours >= 24 ? {day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'} : {hour: '2-digit', minute: '2-digit', ...(new Date(start).getTimezoneOffset() !== new Date(end).getTimezoneOffset() ? {timeZoneName: 'shortOffset'} : {})}); shape('text', {x: x(t), y: 214, class: 'chart-text', 'text-anchor': i === 0 ? 'start' : i === ticks - 1 ? 'end' : 'middle'}, label); }
    if (!data.some(item => Number(item.files))) shape('text', {x: (left + right) / 2, y: 96, 'text-anchor': 'middle', class: 'chart-text'}, 'За период нет поступивших файлов');
    cursor = shape('line', {x1: left, x2: left, y1: 32, y2: 184, class: 'chart-cursor', visibility: 'hidden'});
    dot = shape('circle', {cx: left, cy: 184, r: 4, class: 'chart-dot', visibility: 'hidden'});
    if (selected >= 0) select(selected);
  }
  chartDrawers.set(plot, draw); draw(780);
  const point = event => { const rect = svg.getBoundingClientRect(); const xx = (event.clientX - rect.left) * width / rect.width; select(Math.floor((xx - left) / (right - left) * data.length)); };
  plot.addEventListener('pointermove', point); plot.addEventListener('pointerdown', point);
  plot.addEventListener('keydown', event => { if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return; event.preventDefault(); select(event.key === 'Home' ? 0 : event.key === 'End' ? data.length - 1 : selected < 0 ? 0 : selected + (event.key === 'ArrowRight' ? 1 : -1)); });
  const caption = node('div', 'chart-caption'); const legend = node('span', 'legend'); legend.append(node('i', 'dot'), document.createTextNode('Принято PCAP')); caption.append(legend, node('span', '', 'Всего: ' + bytes(data.reduce((sum, item) => sum + Number(item.bytes), 0)))); wrap.append(caption); return wrap;
}
function protocols(items) { const root = node('div', 'panel-body'); if (!items.length) { root.append(empty('Нет данных о протоколах', 'За выбранный период нет разобранных пакетов.', true)); return root; } const total = items.reduce((sum, item) => sum + Number(item.packets), 0); for (const item of items) { const row = node('div', 'protocol'); const title = node('div', 'protocol-title'); title.append(node('span', '', ({UNCLASSIFIED: 'Не классифицировано', OTHER_PROTOCOLS: 'Другие'})[item.protocol] || item.protocol), node('span', '', (total ? Number(item.packets) / total : 0).toLocaleString('ru-RU', {style: 'percent', maximumFractionDigits: 1}))); const meter = node('meter'); meter.min = 0; meter.max = total; meter.value = Number(item.packets); meter.setAttribute('aria-label', item.protocol + ': ' + number(item.packets) + ' пакетов'); row.append(title, meter); root.append(row); } root.append(node('div', 'divider'), node('span', 'small muted', 'За период: ' + number(total) + ' пакетов')); return root; }
function footer() { const item = node('footer', 'page-foot'); item.append(node('span', '', 'NFDetector · Центр наблюдения за сетью'), node('span', '', 'Время отображается в часовом поясе браузера')); return item; }
function periodLabel() { return ({1: 'Последний час', 24: 'Последние 24 часа', 168: 'Последние 7 дней'})[state.hours]; }
function periodSelector() { const select = node('select', 'period-select'); select.dataset.period = ''; select.setAttribute('aria-label', 'Период статистики'); for (const [value, label] of [[1, 'Последний час'], [24, 'Последние 24 часа'], [168, 'Последние 7 дней']]) { const item = node('option', '', label); item.value = value; select.append(item); } select.value = state.hours; select.addEventListener('change', () => { state.hours = Number(select.value); loadView(); }); return select; }
function periodNote(period) { return node('p', 'period-note', time(period.start) + ' — ' + time(period.end) + ' · Файлы и протоколы — по времени приёма сервером. Инциденты — по активности в захвате.'); }
function overviewPage(data, traffic, agents, events) {
  const fragment = document.createDocumentFragment(); const actions = node('div', 'heading-actions'); actions.append(periodSelector(), button('Добавить агента', 'button', createAgentDialog, 'plus'));
  fragment.append(heading('Обзор сети', 'Активность агентов, поступающий трафик и события безопасности.', actions), periodNote(data.period));
  const broken = data.domains.filter(item => item.error); if (broken.length) fragment.append(node('div', 'alert-box error', 'Остановлена обработка доменов ' + broken.map(item => item.id).join(', ') + '. Подробности доступны в разделе «Трафик».'));
  const metrics = node('div', 'metrics'); metrics.append(metric('Агенты на связи сейчас', number(data.agents.online) + ' / ' + number(data.agents.total), 'Текущее состояние · последняя минута', 'agents', Boolean(data.agents.online)), metric('Разобрано пакетов', number(data.traffic.packets), number(data.traffic.files) + ' файлов · ' + periodLabel(), 'pulse'), metric('Захваченный трафик', bytes(data.traffic.captured_bytes), 'В файлах, принятых за выбранный период', 'traffic'), metric('Инциденты за период', number(data.alerts.security), number(data.alerts.decode_warnings) + ' предупреждений разбора за период', 'events')); fragment.append(metrics);
  const first = node('div', 'row'); const trend = panel('Поступление PCAP', periodLabel() + ' · шаг ' + incidentDuration(traffic.period.bucket_seconds), button('Весь трафик →', 'text-action', () => navigate('traffic'))); trend.append(chart(traffic.timeline, traffic.period)); const protocol = panel('Протоколы', periodLabel()); protocol.append(protocols(traffic.protocols)); first.append(trend, protocol); fragment.append(first);
  const second = node('div', 'row equal'); const latest = panel('Последние инциденты', 'Последние наблюдения · все периоды', button('Все события →', 'text-action', () => navigate('events'))); latest.append(eventTable(events.events.slice(0, 5), true)); const devices = panel('Агенты', 'Текущее состояние подключения', button('Управление →', 'text-action', () => navigate('agents'))); devices.append(agentTable(agents.agents.slice(0, 5), true)); second.append(latest, devices); fragment.append(second, footer()); return fragment;
}
function searchInput(placeholder, value, action) { const form = node('form', 'search'); form.append(icon('search')); const input = node('input'); input.type = 'search'; input.placeholder = placeholder; input.value = value; input.maxLength = 128; input.setAttribute('aria-label', placeholder); form.append(input); form.addEventListener('submit', event => { event.preventDefault(); action(input.value); }); return form; }
function agentsPage(data) { const fragment = document.createDocumentFragment(); fragment.append(heading('Агенты', 'Подключения, состояние захвата и ключи доступа.', button('Добавить агента', 'button', createAgentDialog, 'plus'))); const toolbar = node('div', 'toolbar'); toolbar.append(searchInput('Найти агента или домен', state.agentsQuery, value => { state.agentsQuery = value; state.agentsOffset = 0; loadView(); }), node('span', 'count-label', 'Найдено: ' + number(data.total))); fragment.append(toolbar); const card = panel('Наблюдаемые узлы', 'Ключ выдаётся один раз. При замене прежний ключ перестаёт работать.'); card.append(agentTable(data.agents)); const pager = node('div', 'pagination'); pager.append(node('span', '', data.total ? number(data.offset + 1) + '–' + number(Math.min(data.offset + data.limit, data.total)) + ' из ' + number(data.total) : 'Нет агентов')); const pages = node('div'); const previous = button('Назад', 'button secondary', () => { state.agentsOffset = Math.max(0, state.agentsOffset - 50); loadView(); }); previous.disabled = data.offset === 0; const next = button('Далее', 'button secondary', () => { state.agentsOffset += 50; loadView(); }); next.disabled = data.offset + data.limit >= data.total; pages.append(previous, next); pager.append(pages); card.append(pager); fragment.append(card, footer()); return fragment; }
function trafficPage(data, overview) {
  const fragment = document.createDocumentFragment(); fragment.append(heading('Сетевой трафик', 'Объёмы, пакеты и очередь для файлов выбранного периода.', periodSelector()), periodNote(data.period));
  const metrics = node('div', 'metrics'); metrics.append(metric('Принято PCAP', bytes(overview.traffic.received_bytes), number(overview.traffic.files) + ' файлов · ' + periodLabel(), 'traffic'), metric('Захваченный трафик', bytes(overview.traffic.captured_bytes), number(overview.traffic.packets) + ' разобранных пакетов за период', 'pulse'), metric('Ожидают разбора', number(overview.traffic.queued), 'Из файлов, принятых за выбранный период', 'clock'), metric('Ошибки файлов', number(overview.traffic.failed), 'Из файлов, принятых за выбранный период', 'events')); fragment.append(metrics);
  if (overview.traffic.legacy_files) fragment.append(node('div', 'alert-box', 'Для ' + number(overview.traffic.legacy_files) + ' файлов периода нет статистики захваченных байтов. Объём PCAP учтён полностью.'));
  const row = node('div', 'row'); const timeline = panel('Поступление PCAP', 'По времени приёма сервером · шаг ' + incidentDuration(data.period.bucket_seconds)); timeline.append(chart(data.timeline, data.period)); const protocol = panel('Протоколы', periodLabel()); protocol.append(protocols(data.protocols)); row.append(timeline, protocol); fragment.append(row);
  const domains = panel('Домены наблюдения', 'Текущее состояние обработки · не зависит от выбранного периода'); const result = table(['Домен', 'Состояние', 'Последнее время пакета', 'Примечание']); for (const domain of overview.domains) { const tr = node('tr'); const status = cell(); status.append(badge(domain.error ? 'Ошибка' : domain.processing ? 'Обрабатывается' : domain.pending ? 'Ожидает данных' : 'Ожидание', domain.error ? 'red' : domain.processing ? 'green' : 'blue')); tr.append(cell(domain.id, 'mono'), status, cell(time(domain.last_timestamp), 'small muted'), cell(domain.error || 'История сохраняется между файлами', 'small muted')); result.body.append(tr); } domains.append(overview.domains.length ? result.scroll : empty('Доменов пока нет', 'Домен создаётся при выпуске первого ключа.')); fragment.append(domains, footer()); return fragment;
}
function eventsPage(data) { const fragment = document.createDocumentFragment(); fragment.append(heading('События безопасности', 'Атака отображается одним инцидентом с периодом активности и числом срабатываний.')); const toolbar = node('div', 'toolbar'); const filters = node('div', 'filters'); filters.append(searchInput('IP, агент или текст события', state.eventQuery, value => { state.eventQuery = value; state.eventOffset = 0; loadView(); })); const select = node('select'); select.setAttribute('aria-label', 'Тип события'); for (const kind of ['', 'DDOS', 'DDoS_SINGLE_IP', 'DDoS_MULTI_IP', 'SYN_FLOOD_HALF_OPEN', 'HTTP_FLOOD', 'BRUTEFORCE_SSH_HANDSHAKES', 'BRUTEFORCE_FTP', 'BRUTEFORCE_HTTP Basic', 'BRUTEFORCE_SMB2', 'C2_BEACONING', 'SUSPICIOUS_SOURCE_IP', 'SUSPICIOUS_DEST_IP', 'DECODE_WARNING']) { const option = node('option', '', kind ? eventTitle(kind) : 'Все типы событий'); option.value = kind; select.append(option); } select.value = state.eventKind; select.addEventListener('change', () => { state.eventKind = select.value; state.eventOffset = 0; loadView(); }); filters.append(select); toolbar.append(filters, node('span', 'count-label', number(data.total) + ' событий')); fragment.append(toolbar); const card = panel('Журнал инцидентов', 'Пауза до ' + incidentDuration(data.incident_gap_seconds) + ' объединяется. Нажмите на стрелку для деталей.'); card.append(eventTable(data.events)); const pagination = node('div', 'pagination'); pagination.append(node('span', '', data.total ? number(data.offset + 1) + '–' + number(Math.min(data.offset + data.limit, data.total)) + ' из ' + number(data.total) : 'Нет событий')); const buttons = node('div'); const previous = button('Назад', 'button secondary', () => { state.eventOffset = Math.max(0, state.eventOffset - 50); loadView(); }); previous.disabled = data.offset === 0; const next = button('Далее', 'button secondary', () => { state.eventOffset += 50; loadView(); }); next.disabled = data.offset + data.limit >= data.total; buttons.append(previous, next); pagination.append(buttons); card.append(pagination); fragment.append(card, footer()); return fragment; }
function securityPage(audit) { const fragment = document.createDocumentFragment(); fragment.append(heading('Безопасность', 'Пароль администратора, параметры входа и журнал действий.', button('Выйти из системы', 'button secondary', signOut, 'logout'))); const row = node('div', 'security-grid'); const password = panel('Изменить пароль', 'Все другие сеансы завершатся после смены пароля'); const body = node('div', 'panel-body'); body.append(passwordForm(() => toast('Пароль изменён. Остальные сеансы завершены.'))); password.append(body); const info = panel('Защита входа', 'Текущий пользователь · ' + state.session.username); const content = node('div', 'panel-body'); for (const [label, value] of [['Соединение', 'HTTPS'], ['Пароль', 'Собственный'], ['Бездействие', '30 минут'], ['Срок сеанса', 'До 8 часов'], ['Управление ключами', 'Подтверждение входа']]) { const line = node('div', 'status-line'); line.append(node('span', 'status-name', label), badge(value, 'green')); content.append(line); } content.append(node('div', 'divider'), node('p', 'small muted', 'Пароли и ключи агентов не сохраняются в браузерном хранилище. Журнал не содержит секретов.')); info.append(content); row.append(password, info); fragment.append(row); const history = panel('Журнал администратора', 'Последние 100 действий'); const labels = {login_succeeded: 'Успешный вход', login_failed: 'Неудачная попытка входа', password_changed: 'Смена пароля', logged_out: 'Выход', reauthenticated: 'Подтверждение пароля', agent_key_created: 'Выпуск ключа', agent_key_rotated: 'Замена ключа', agent_key_revoked: 'Отзыв ключа'}; const result = table(['Действие', 'Пользователь', 'Адрес', 'Объект', 'Время']); for (const entry of audit.entries) { const tr = node('tr'); tr.append(cell(labels[entry.action] || entry.action), cell(entry.actor), cell(entry.client_ip, 'mono'), cell(entry.subject ? entry.subject.slice(0, 12) : '—', 'mono muted'), cell(time(entry.created_at), 'small muted')); result.body.append(tr); } history.append(result.scroll); fragment.append(history, footer()); return fragment; }
async function loadView() {
  if (!state.session?.authenticated || state.session.must_change_password || !main?.isConnected) return;
  const request = ++state.request; const page = state.page; const hours = state.hours;
  main.setAttribute('aria-busy', 'true');
  try {
    let content;
    if (page === 'overview') { const [data, agents, events] = await Promise.all([api('/traffic?hours=' + hours), api('/agents?limit=5'), api('/events?limit=5')]); content = overviewPage(data.summary, data, agents, events); }
    else if (page === 'agents') content = agentsPage(await api('/agents?' + new URLSearchParams({q: state.agentsQuery, offset: state.agentsOffset, limit: 50})));
    else if (page === 'traffic') { const data = await api('/traffic?hours=' + hours); content = trafficPage(data, data.summary); }
    else if (page === 'events') content = eventsPage(await api('/events?' + new URLSearchParams({q: state.eventQuery, kind: state.eventKind, offset: state.eventOffset})));
    else content = securityPage(await api('/audit'));
    if (request !== state.request || !state.session?.authenticated) return;
    clearCharts(); main.replaceChildren(content); watchCharts();
    if (page === 'overview' || page === 'traffic') state.renderedHours = hours;
    updated = new Date(); document.getElementById('updated').textContent = 'Обновлено в ' + updated.toLocaleTimeString('ru-RU');
  } catch (error) {
    if (request === state.request && state.session?.authenticated) {
      if (main.querySelector('[data-period]') && state.renderedHours) { state.hours = state.renderedHours; main.querySelector('[data-period]').value = state.renderedHours; }
      toast(error.message || 'Нет связи с сервером', true); if (!main.childNodes.length) main.append(empty('Не удалось загрузить данные', 'Проверьте соединение и повторите запрос.'));
    }
  } finally { if (request === state.request) main.setAttribute('aria-busy', 'false'); }
}
function installationPanel(agent, initial) {
  const root = node('section', 'installation-panel');
  root.append(node('h3', '', 'Автоматическая установка'));
  root.append(node('p', 'small muted', 'Debian/Ubuntu или Fedora/RHEL, systemd, Python 3 и sudo. Вставьте команду на одном хосте. Интерфейс определяется автоматически.'));
  const form = node('form', 'form');
  const server = field('Адрес панели со стороны агента', 'server_url', 'text', 'IP или DNS-имя, доступные с хоста агента. Например: 192.168.122.1 или https://panel.example:8443.', initial?.server_url || state.session?.agent_install_url || window.location.origin);
  server.input.maxLength = 512;
  const network = field('Интерфейс захвата', 'interface', 'text', 'Оставьте пустым для автоматического выбора.', initial?.interface || '');
  network.input.required = false; network.input.maxLength = 64;
  const error = node('div', 'form-error');
  const generate = node('button', 'button secondary', 'Обновить команду'); generate.type = 'submit';
  const output = node('div', 'installation-output');
  function render(data) {
    output.replaceChildren();
    if (!data?.command) { if (data?.unavailable) output.append(node('p', 'alert-box', data.unavailable)); return; }
    const command = node('textarea', 'install-command'); command.readOnly = true; command.value = data.command; command.rows = 5;
    command.setAttribute('aria-label', 'Команда установки агента'); command.spellcheck = false;
    const copy = button('Копировать команду', 'button', async () => { try { await navigator.clipboard.writeText(command.value); toast('Команда скопирована'); } catch { command.focus(); command.select(); toast('Выделена команда — скопируйте её вручную', true); } });
    output.append(command, copy, node('p', 'small muted', 'Одноразовый код действует до ' + time(data.expires_at) + '. После запуска постоянный ключ сохраняется только на хосте, ручной ключ заменяется. Служба: nfagent.service.'));
  }
  for (const input of [server.input, network.input]) input.addEventListener('input', () => { output.replaceChildren(node('p', 'small muted', 'Обновите команду для изменённых параметров.')); });
  form.append(server.wrapper, network.wrapper, error, generate);
  formHandler(form, generate, error, async () => render(await mutate('/agents/' + (agent.agent_id || agent.id) + '/installation', {server_url: server.input.value, interface: network.input.value})));
  root.append(form, output); render(initial); return root;
}
function installationDialog(agent) { const content = node('div'); content.append(node('p', 'dialog-intro', 'Установка агента «' + agent.name + '». Запуск новой установки заменит его текущий ключ. Для второго хоста создайте отдельного агента.'), installationPanel(agent, {server_url: agent.server_url})); openDialog('Установить агента', content); }
function keyDialog(data) {
  const content = node('div');
  content.append(node('p', 'dialog-intro', 'Агент «' + data.name + '» создан. Скопируйте команду установки или сохраните ключ для ручной настройки.'), installationPanel(data, data.installation));
  const manual = node('details', 'manual-install'); manual.append(node('summary', '', 'Ключ для ручной настройки'));
  const secret = node('code', 'key-box', data.key);
  manual.append(node('p', 'small muted', 'Ключ показывается один раз. Храните файл с правами 0600. Автоматическая установка заменяет этот ключ.'), secret);
  const actions = node('div', 'dialog-actions');
  actions.append(button('Копировать ключ', 'button secondary', async () => { try { await navigator.clipboard.writeText(data.key); toast('Ключ скопирован'); } catch { toast('Копирование недоступно. Скачайте файл.', true); } }), button('Скачать .key', 'button secondary', () => { const url = URL.createObjectURL(new Blob([data.key + '\n'], {type: 'application/octet-stream'})); const link = node('a'); link.href = url; link.download = 'agent-' + data.agent_id.slice(0, 8) + '.key'; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000); }, 'download'));
  manual.append(actions); content.append(manual); openDialog('Подключить агента', content);
}
function createAgentDialog() {
  const form = node('form', 'form');
  form.append(node('p', 'dialog-intro', 'Укажите адрес панели, доступный с хоста нового агента. Команда установки сразу будет использовать этот адрес.'));
  const name = field('Имя агента', 'name', 'text', 'Например, gateway-office');
  const domain = field('Домен наблюдения', 'domain', 'text', 'Объединяйте сенсоры без дублирования одного трафика.', 'main');
  const server = field('Адрес панели со стороны агента', 'server_url', 'text', 'Например: 192.168.122.1 или https://panel.example:8443. Без схемы используется HTTPS.', state.session?.agent_install_url || window.location.origin);
  server.input.maxLength = 512;
  const error = node('div', 'form-error');
  const submit = node('button', 'button', 'Создать агента'); submit.type = 'submit';
  form.append(name.wrapper, domain.wrapper, server.wrapper, error, submit);
  formHandler(form, submit, error, async () => {
    const result = await mutate('/agents', {name: name.input.value, domain: domain.input.value, server_url: server.input.value});
    state.agentsOffset = 0; keyDialog(result); loadView();
  });
  openDialog('Добавить агента', form); name.input.focus();
}
function rotateDialog(agent) { actionDialog('Заменить ключ агента?', 'Агент «' + agent.name + '». Старый ключ перестанет работать. История и потоки сохранятся. После замены обновите ключ на машине агента.', 'Выпустить новый ключ', async () => { const result = await mutate('/agents/' + agent.id + '/rotate'); keyDialog(result); loadView(); }); }
function revokeDialog(agent) { actionDialog('Отозвать доступ агента?', 'Агент «' + agent.name + '» больше не сможет отправлять данные с этим ключом. Сохранённые данные останутся доступны.', 'Отозвать ключ', async () => { await mutate('/agents/' + agent.id + '/revoke'); dialog.close(); toast('Ключ агента отозван'); loadView(); }, true); }
function actionDialog(title, text, label, action, danger = false) { const content = node('div'); content.append(node('p', 'dialog-intro', text)); const error = node('div', 'form-error'); const actions = node('div', 'dialog-actions'); const submit = button(label, danger ? 'button danger' : 'button', async () => { submit.disabled = true; try { await action(); } catch (issue) { error.textContent = issue.message; } finally { submit.disabled = false; } }); actions.append(button('Отмена', 'button secondary', () => dialog.close()), submit); content.append(error, actions); openDialog(title, content); }
async function agentDetails(agent) { try { const result = await api('/agents/' + agent.id + '/streams'); const content = node('div'); const grid = node('div', 'detail-grid'); for (const [label, value] of [['Домен', agent.domain], ['Последняя связь', relative(agent.last_seen_at)], ['Состояние захвата', ({capturing: 'Захват идёт', uploading: 'Отправка файлов', idle: 'Ожидание', stopped: 'Остановлен', error: 'Ошибка', unknown: 'Не сообщено'})[agent.capture_state] || agent.capture_state], ['Очередь на агенте', bytes(agent.backlog_bytes)], ['Файлы на агенте', number(agent.backlog_files)], ['Принято сервером', bytes(agent.received_bytes)]]) { const item = node('div', '', value); item.prepend(node('span', '', label)); grid.append(item); } content.append(grid); if (agent.last_error) content.append(node('div', 'alert-box error', agent.last_error)); content.append(node('p', 'small muted mono', agent.id)); for (const stream of result.streams.slice(0, 8)) { const line = node('div', 'status-line'); const name = node('div', 'small', stream.interface); name.append(node('span', 'secondary-text mono', stream.id.slice(0, 8) + ' · ' + number(stream.files) + ' файлов')); line.append(name, badge(stream.last_sequence === null ? 'Открыт' : 'Закрыт', stream.last_sequence === null ? 'green' : '')); content.append(line); } if (!result.streams.length) content.append(empty('Потоков пока нет', 'Агент ещё не зарегистрировал захват.', true)); openDialog(agent.name, content); } catch (error) { toast(error.message, true); } }
function eventDetails(event) {
  const content = node('div'); const details = node('div', 'detail-grid');
  for (const [label, value] of [['Источник', event.sources?.length > 1 ? event.sources.length + (event.sources_truncated ? '+' : '') + ' источников' : event.source || '—'], ['Цель', event.target || '—'], ['Агент первого срабатывания', event.agent_name], ['Домен', event.domain], ['Начало обнаружения', time(event.first_seen ?? event.timestamp)], ['Последняя активность', time(event.last_seen ?? event.timestamp)], ['Длительность', incidentDuration(event.duration_seconds)], ['Срабатываний', number(event.signal_count || 0)]]) { const item = node('div', '', value); item.prepend(node('span', '', label)); details.append(item); }
  content.append(incidentStatus(event), details);
  if (event.service) content.append(node('p', 'small muted', 'Порт сервиса: ' + event.service));
  if (event.sources?.length > 1) content.append(node('p', 'small muted mono', 'Наблюдаемые источники: ' + event.sources.join(', ') + (event.sources_truncated ? ' · показаны первые 100' : '')));
  if (event.kinds?.length) content.append(node('p', 'small muted', 'Правила: ' + event.kinds.map(eventTitle).join(', ')));
  content.append(node('div', 'detail-reason', event.reason), node('p', 'small muted', event.close_reason === 'capture_ended' ? 'Наблюдение завершилось вместе с захватом. Время окончания атаки за пределами захвата неизвестно.' : event.status === 'awaiting_data' ? 'Новых данных нет: окончание атаки не подтверждено.' : 'Длительность считается по времени пакетов с признаками атаки. Период ожидания закрытия в неё не входит.'));
  openDialog(eventTitle(event.kind || eventKind(event.reason)), content);
}
async function boot() { try { state.session = await api('/session'); if (!state.session.authenticated) showLogin(state.session.setup_required); else if (state.session.must_change_password) showPasswordSetup(); else showShell(); } catch { app.replaceChildren(empty('Нет соединения с сервером', 'Обновите страницу, когда сервер станет доступен.')); app.setAttribute('aria-busy', 'false'); } }
for (const eventName of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(eventName, () => { if (state.session?.authenticated && !state.session.must_change_password && Date.now() - lastTouch > 60000) { lastTouch = Date.now(); api('/session/touch', {method: 'POST', body: {}}).catch(() => {}); } }, {passive: true});
window.setInterval(() => { if (state.auto && !document.hidden && !dialog.open && state.page !== 'security' && !['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName)) loadView(); }, 10000);
boot();

window.addEventListener('pageshow', event => { if (event.persisted) boot(); });
