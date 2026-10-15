/* cyberboba web UI — vanilla JS, no build step, no external resources.
 *
 * Layout of this file:
 *   1. DOM / formatting helpers, toast, modal, form widgets
 *   2. api() helper, global state, header
 *   3. Router + SSE event stream
 *   4. Pages: dashboard, connections, rules, intercept, proxies, vpn, caido, settings
 *   5. Boot
 */
'use strict';

/* ================================================================
 * 1. Helpers
 * ================================================================ */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const PROP_KEYS = new Set(['value', 'checked', 'disabled', 'selected', 'multiple', 'hidden', 'readOnly',
  'indeterminate', 'textContent', 'defaultValue', 'open', 'draggable', 'size']);

/** h(tag, attrs, ...children) — tiny element builder. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k === 'for') el.htmlFor = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (PROP_KEYS.has(k)) el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, children);
  return el;
}
function append(parent, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(parent, c);
    else if (c instanceof Node) parent.appendChild(c);
    else parent.appendChild(document.createTextNode(String(c)));
  }
  return parent;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
/** svg(tag, attrs, ...children) — element builder in the SVG namespace. */
function svg(tag, attrs, ...children) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (attrs) for (const k of Object.keys(attrs)) {
    const v = attrs[k];
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function replace(el, ...children) { clear(el); return append(el, children); }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function uniq(arr) { return Array.from(new Set(arr.filter(x => x !== undefined && x !== null && x !== ''))); }
function isZeroTime(ts) { return !ts || ts.startsWith('0001-') || ts.startsWith('1970-01-01T00:00:00'); }
function pad2(n) { return n < 10 ? '0' + n : String(n); }
function num(v, d = 0) { const n = Number(v); return Number.isFinite(n) ? n : d; }

const fmt = {
  bytes(n) {
    n = num(n);
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    const s = i === 0 ? n.toFixed(0) : n < 10 ? n.toFixed(2) : n < 100 ? n.toFixed(1) : n.toFixed(0);
    return s + ' ' + u[i];
  },
  rate(n) { return fmt.bytes(n) + '/s'; },
  num(n) { return num(n).toLocaleString('en-US'); },
  time(ts) {
    if (isZeroTime(ts)) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  },
  datetime(ts) {
    if (isZeroTime(ts)) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + fmt.time(ts);
  },
  duration(sec) {
    sec = Math.max(0, Math.floor(num(sec)));
    const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (d) return d + 'd ' + hh + 'h ' + m + 'm';
    if (hh) return hh + 'h ' + m + 'm ' + s + 's';
    if (m) return m + 'm ' + s + 's';
    return s + 's';
  },
  ago(ts) {
    if (isZeroTime(ts)) return 'never';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 1) return 'just now';
    return fmt.duration(diff) + ' ago';
  },
  ms(n) { n = num(n); return n >= 1000 ? (n / 1000).toFixed(2) + ' s' : n.toFixed(0) + ' ms'; },
};

/* ---------- toast ---------- */
function toast(msg, kind = 'info', ms = 4000) {
  const box = $('#toasts');
  const t = h('div', { class: 'toast ' + kind, role: 'status' },
    h('span', { class: 'toast-msg' }, String(msg)),
    h('button', { type: 'button', class: 'toast-x', 'aria-label': 'dismiss', onClick: () => t.remove() }, '×'));
  box.appendChild(t);
  while (box.childElementCount > 6) box.firstElementChild.remove();
  if (ms) setTimeout(() => t.remove(), ms);
  return t;
}

/* ---------- modal ---------- */
function openModal({ title, body, buttons = [], width, onClose }) {
  const overlay = h('div', { class: 'modal-overlay' });
  const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, style: width ? { width } : null });
  const prevFocus = document.activeElement;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    overlay.remove();
    document.removeEventListener('keydown', onKey, true);
    if (onClose) onClose();
    if (prevFocus && prevFocus.focus) prevFocus.focus();
  };
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  }
  box.append(
    h('div', { class: 'modal-head' }, h('h3', null, title), btn('×', close, 'icon', { 'aria-label': 'close' })),
    h('div', { class: 'modal-body' }, body),
    buttons.length ? h('div', { class: 'modal-foot' }, ...buttons.map(b => btn(b.label, () => b.onClick ? b.onClick(close) : close(), b.cls || ''))) : null);
  overlay.append(box);
  overlay.addEventListener('mousedown', e => { if (e.target === overlay) close(); });
  document.body.append(overlay);
  document.addEventListener('keydown', onKey, true);
  setTimeout(() => { const f = box.querySelector('input:not([type=checkbox]),select,textarea,button.primary,button'); if (f) f.focus(); }, 0);
  return { close, el: box };
}

/* ---------- widgets ---------- */
function btn(label, onClick, cls = '', attrs = {}) {
  return h('button', Object.assign({ type: 'button', class: 'btn ' + cls, onClick }, attrs), label);
}
function badge(text, cls) { return h('span', { class: 'badge ' + (cls || 'gray') }, text || ''); }

/* emptyState — a friendly empty/placeholder block: a short title, one line that
 * says what belongs here, and optional next-step action button(s). Keeps the
 * .empty class (so existing presence checks like $('.empty', list) still work)
 * and reuses the design-system icon + centering. `opts.cls` adds variants:
 * 'small' (compact) / 'flat' (no icon). `opts.actions` is an array of buttons. */
function emptyState(title, desc, opts = {}) {
  const kids = [];
  if (title) kids.push(h('div', { class: 'empty-title' }, title));
  if (desc) kids.push(h('div', { class: 'empty-desc' }, ...(Array.isArray(desc) ? desc : [desc])));
  const acts = (opts.actions || []).filter(Boolean);
  if (acts.length) kids.push(h('div', { class: 'empty-actions' }, ...acts));
  return h('div', { class: 'empty' + (opts.cls ? ' ' + opts.cls : '') }, ...kids);
}

/* threshold → severity class for CPU/mem/temperature readouts */
function hotClass(v, warn, hot) { if (v == null) return ''; if (v >= hot) return 'hot'; if (v >= warn) return 'warm'; return 'cool'; }
/* a hex colour (#rgb / #rrggbb) with alpha, for sparkline fills */
function hexA(c, a) {
  c = String(c || '').trim();
  if (c[0] === '#') {
    let h = c.slice(1);
    if (h.length === 3) h = h.split('').map(x => x + x).join('');
    const n = parseInt(h, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }
  return c;
}
function setBadge(el, text, cls) { el.textContent = text || ''; el.className = 'badge ' + (cls || 'gray'); }
const ACTION_CLS = { direct: 'gray', proxy: 'blue', vpn: 'green', block: 'red', intercept: 'yellow' };
const STATE_CLS = { open: 'green', closed: 'gray', blocked: 'red', error: 'red', up: 'green', down: 'gray', connecting: 'yellow', starting: 'yellow', stopping: 'yellow', failed: 'red' };

function sel(options, value, attrs = {}) {
  const s = h('select', attrs);
  const opts = options.map(o => (typeof o === 'string' ? { value: o, label: o } : o));
  const v = value === null || value === undefined ? '' : String(value);
  if (v !== '' && !opts.some(o => String(o.value) === v)) opts.push({ value: v, label: v + ' (missing)' });
  for (const o of opts) s.append(h('option', { value: o.value }, o.label));
  s.value = v;
  return s;
}
function checkbox(label, checked, attrs = {}) {
  const input = h('input', Object.assign({ type: 'checkbox', checked: !!checked }, attrs));
  const l = h('label', { class: 'check' }, input, h('span', null, label));
  l.input = input;
  return l;
}
let _uid = 0;
function field(label, control, hint, cls = '') {
  const lab = h('label', { class: 'field-label' }, label);
  const target = control.matches && control.matches('input,select,textarea') ? control : control.querySelector && control.querySelector('input,select,textarea');
  if (target) { if (!target.id) target.id = 'f' + (++_uid); lab.htmlFor = target.id; }
  return h('div', { class: 'field ' + cls }, lab, control, hint ? h('div', { class: 'hint' }, hint) : null);
}
function kv(k, v, cls = '') {
  return h('div', { class: 'kv-row' }, h('span', { class: 'kv-k' }, k),
    h('span', { class: 'kv-v ' + cls }, v === null || v === undefined || v === '' ? '—' : v));
}
function textInput(value, attrs = {}) {
  return h('input', Object.assign({ type: 'text', value: value === null || value === undefined ? '' : String(value) }, attrs));
}
/** bind a text/select/checkbox/number input to obj[key]; calls onChange after each update. */
function bind(input, obj, key, onChange, transform) {
  const isCb = input.type === 'checkbox';
  const isNum = input.type === 'number';
  const ev = isCb || input.tagName === 'SELECT' ? 'change' : 'input';
  input.addEventListener(ev, () => {
    let v = isCb ? input.checked : isNum ? num(input.value) : input.value;
    if (transform) v = transform(v);
    obj[key] = v;
    if (onChange) onChange(v);
  });
  return input;
}

/** Comma-separated tags input with optional <datalist> autocomplete. */
function tagsInput({ values = [], placeholder = '', list = null, onChange = null }) {
  const wrap = h('div', { class: 'tags' });
  const input = h('input', { type: 'text', class: 'tags-in', placeholder, list, autocomplete: 'off', spellcheck: 'false' });
  let vals = (values || []).slice();
  function render() {
    $$('.tag', wrap).forEach(t => t.remove());
    vals.forEach((v, i) => {
      wrap.insertBefore(h('span', { class: 'tag', title: v }, v,
        h('button', { type: 'button', class: 'tag-x', tabindex: -1, 'aria-label': 'remove ' + v,
          onClick: () => { vals.splice(i, 1); render(); fire(); input.focus(); } }, '×')), input);
    });
  }
  function fire() { if (onChange) onChange(vals.slice()); wrap.dispatchEvent(new Event('change', { bubbles: true })); }
  function commit() {
    const parts = input.value.split(',').map(s => s.trim()).filter(Boolean);
    if (!parts.length) { input.value = ''; return; }
    let changed = false;
    for (const p of parts) if (!vals.includes(p)) { vals.push(p); changed = true; }
    input.value = '';
    render();
    if (changed) fire();
  }
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commit(); }
    else if (e.key === 'Backspace' && !input.value && vals.length) { e.preventDefault(); vals.pop(); render(); fire(); }
  });
  input.addEventListener('change', () => { if (input.value.trim()) commit(); });
  input.addEventListener('blur', commit);
  wrap.addEventListener('mousedown', e => { if (e.target === wrap) { e.preventDefault(); input.focus(); } });
  wrap.append(input);
  render();
  wrap.getValues = () => { commit(); return vals.slice(); };
  wrap.setValues = v => { vals = (v || []).slice(); render(); };
  wrap.input = input;
  return wrap;
}

/** Copy text to the clipboard (async API with a hidden-textarea fallback); toasts the outcome. */
async function copyText(text, what = 'Copied') {
  text = String(text === null || text === undefined ? '' : text);
  let ok = false;
  if (navigator.clipboard && window.isSecureContext !== false) {
    try { await navigator.clipboard.writeText(text); ok = true; } catch (_) { /* fallback below */ }
  }
  if (!ok) {
    const ta = h('textarea', { value: text, style: { position: 'fixed', top: '-1000px', left: '-1000px', opacity: '0' } });
    document.body.append(ta); ta.focus(); ta.select();
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
  }
  if (ok) { toast(what + ' (' + fmt.bytes(text.length) + ')', 'ok', 2500); return true; }
  // no clipboard access (e.g. plain-http origin): show the text pre-selected so one keystroke copies it
  const ta = h('textarea', { class: 'code', readOnly: true, rows: 12, spellcheck: 'false', style: { minHeight: '120px' } });
  ta.value = text;
  openModal({ title: 'Copy manually (clipboard unavailable)', width: '640px', body: h('div', { class: 'tab-panel' }, h('div', { class: 'muted small' }, 'The browser refused clipboard access. The text is selected — press Ctrl+C.'), ta), buttons: [{ label: 'Close' }] });
  setTimeout(() => { ta.focus(); ta.select(); }, 0);
  return false;
}
/** Trigger a browser download of `content` (string or Blob) as `filename`. */
function downloadBlob(content, filename, type = 'application/octet-stream') {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename, style: { display: 'none' } });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
/**
 * Download link styled as a button. A plain <a href download> (copyable, open-in-new-tab friendly);
 * when a bearer token is configured the link is fetched with the Authorization header instead.
 */
function dlLink(label, href, filename, attrs = {}) {
  const a = h('a', Object.assign({ class: 'btn', href: typeof href === 'function' ? '#' : href, download: filename || true }, attrs), label);
  a.addEventListener('click', async e => {
    const url = typeof href === 'function' ? href() : href;
    if (typeof href === 'function') a.href = url;
    if (!authToken()) return; // plain navigation
    e.preventDefault();
    try {
      const res = await fetch(url, { headers: { Authorization: 'Bearer ' + authToken() }, cache: 'no-store' });
      if (!res.ok) { let msg = res.status + ' ' + res.statusText; try { msg = (await res.json()).error || msg; } catch (_) { /* ignore */ } throw new Error(msg); }
      downloadBlob(await res.blob(), filename || url.split('/').pop().split('?')[0] || 'download');
    } catch (err) { toast('Download failed: ' + err.message, 'error'); }
  });
  return a;
}

/* ================================================================
 * 2. API helper, state, header
 * ================================================================ */
function authToken() { try { return localStorage.getItem('cyberboba.token') || ''; } catch (_) { return ''; } }

/**
 * api(method, path, body, opts) → parsed JSON (or text when opts.raw).
 * Shows an error toast on failure (reads the `error` field) unless opts.silent.
 */
async function api(method, path, body, opts = {}) {
  const init = { method, headers: {}, cache: 'no-store' };
  const tok = authToken();
  if (tok) init.headers['Authorization'] = 'Bearer ' + tok;
  if (body !== undefined && body !== null) {
    if (opts.raw) { init.body = body; init.headers['Content-Type'] = opts.contentType || 'text/plain; charset=utf-8'; }
    else { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  }
  let res;
  try { res = await fetch(path, init); }
  catch (e) {
    if (!opts.silent) toast('Network error: ' + e.message, 'error');
    throw e;
  }
  const text = await res.text();
  let data = text;
  if (!opts.raw || !res.ok) { try { data = JSON.parse(text); } catch (_) { /* not JSON */ } }
  if (!res.ok) {
    const msg = (data && typeof data === 'object' && data.error) || (typeof data === 'string' && data.trim()) || (res.status + ' ' + res.statusText);
    if (!opts.silent) toast(msg, 'error', 6000);
    const err = new Error(msg); err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

const LOG_MAX = 1000;
const RATE_HIST = 120; // seconds of rate history kept for the dashboard graph
const state = {
  status: null,   // last GET /api/status
  stats: null,    // last stats object (status.stats or SSE)
  logs: [],       // {time, level, msg}
  sse: false,
  intercept: null,        // last intercept status object (GET /api/intercept or SSE `intercept`)
  pendingIds: new Set(),  // ids of flows currently held in the intercept queue
  pendingSeeded: false,   // pendingIds was loaded from GET /api/intercept/pending at least once
  rateHist: [],           // [{t, in, out}] last RATE_HIST stats samples
  fwQueue: [],            // pending firewall asks awaiting a prompt
  fwPromptOpen: false,
  fwPromptId: 0,
  fwPromptClose: null,
};

function pendingCount() {
  if (state.pendingSeeded) return state.pendingIds.size;
  const ic = state.intercept || (state.status && state.status.intercept);
  return ic ? num(ic.pending) : 0;
}
/** Reload the held-flow id set from the daemon (cheap; used to reconcile counts after reconnects). */
const syncPending = debounce(async () => {
  let r; try { r = await api('GET', '/api/intercept/pending', undefined, { silent: true }); } catch (_) { return; }
  state.pendingIds = new Set((r.pending || []).map(f => f.id));
  state.pendingSeeded = true;
  updateHeader();
  Router.dispatch('pending-sync', r.pending || []);
}, 150);
function notePendingFlow(f) {
  if (!f || f.id === undefined) return;
  const held = f.state === 'pending_request' || f.state === 'pending_response';
  if (held) state.pendingIds.add(f.id); else state.pendingIds.delete(f.id);
}

function updateHeader() {
  const s = state.status;
  const pill = $('#hdr-proxify');
  if (s && s.proxify) {
    const on = !!s.proxify.enabled;
    pill.textContent = on ? 'PROXIFY ON' : 'PROXIFY OFF';
    pill.className = 'pill ' + (on ? 'on' : 'off');
    pill.title = on ? 'transparent interception active (' + (s.proxify.listen_tcp || '') + ')' : 'interception disabled';
  }
  const st = state.stats || (s && s.stats);
  const he = $('#hdr-stats');
  if (st) he.textContent = num(st.active) + ' active · ' + fmt.num(st.total) + ' total · ' + num(st.blocked) + ' blocked · ↓ ' + fmt.rate(st.rate_in) + ' ↑ ' + fmt.rate(st.rate_out);
  const dot = $('#hdr-sse');
  dot.className = 'dot ' + (state.sse ? 'ok' : 'bad');
  dot.title = state.sse ? 'event stream connected' : 'event stream disconnected — reconnecting';
  const pc = pendingCount();
  const hp = $('#hdr-pending'), np = $('#nav-pending');
  if (hp) { hp.hidden = pc <= 0; hp.textContent = pc + ' held'; }
  if (np) { np.hidden = pc <= 0; np.textContent = String(pc); }
}

function mergeVpnStatus(list, v) {
  if (!Array.isArray(list) || !v || !v.name) return;
  const i = list.findIndex(x => x.name === v.name);
  if (i >= 0) list[i] = Object.assign({}, list[i], v); else list.push(v);
}

/* ================================================================
 * 3. Router + SSE
 * ================================================================ */
const Pages = {};
const Router = {
  name: null, page: null, root: null,
  async go() {
    let name = (location.hash || '#/dashboard').replace(/^#\/?/, '').split('/')[0].split('?')[0];
    if (!Pages[name]) name = 'dashboard';
    if (name === this.name) { if (this.page && this.page.onHash) { try { this.page.onHash(this.sub()); } catch (e) { console.error(e); } } return; }
    if (this.page && this.page.unmount) { try { this.page.unmount(); } catch (e) { console.error(e); } }
    const main = $('#main');
    clear(main);
    this.name = name; this.page = Pages[name];
    $$('#sidebar a').forEach(a => a.classList.toggle('active', a.dataset.page === name));
    document.title = 'CyberBoba — ' + this.page.title;
    const root = h('div', { class: 'page page-' + name });
    this.root = root;
    main.append(root);
    main.scrollTop = 0;
    try { await this.page.mount(root); }
    catch (e) { console.error(e); if (root.isConnected) root.append(h('div', { class: 'error-box' }, 'Failed to load page: ' + (e.message || e))); }
  },
  /** second hash segment, e.g. "#/intercept/queue" → "queue" */
  sub() { return (location.hash || '').replace(/^#\/?/, '').split('?')[0].split('/').slice(1).join('/'); },
  dispatch(type, data) {
    if (this.page && this.page.onEvent) { try { this.page.onEvent(type, data); } catch (e) { console.error(e); } }
  },
};

const Events = {
  es: null, retry: 1000, timer: null,
  start() { this.connect(); },
  connect() {
    clearTimeout(this.timer);
    if (this.es) { try { this.es.close(); } catch (_) { /* ignore */ } }
    const tok = authToken();
    // EventSource cannot set headers; pass the token as a query parameter (best effort).
    const es = new EventSource('/api/events' + (tok ? '?token=' + encodeURIComponent(tok) : ''));
    this.es = es;
    es.onopen = () => { this.retry = 1000; state.sse = true; updateHeader(); resyncFirewall(); };
    es.onerror = () => {
      state.sse = false; updateHeader();
      es.close();
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.connect(), this.retry);
      this.retry = Math.min(this.retry * 2, 15000);
    };
    for (const t of ['conn', 'stats', 'vpn', 'caido', 'log', 'flow', 'intercept', 'fw_ask', 'fw_resolved', 'fw_block', 'bw_alert']) {
      es.addEventListener(t, ev => {
        let d;
        try { d = JSON.parse(ev.data); } catch (_) { return; }
        handleEvent(t, d);
      });
    }
  },
};

function handleEvent(type, data) {
  if (type === 'stats') {
    state.stats = data;
    if (state.status) state.status.stats = data;
    state.rateHist.push({ t: Date.now(), in: num(data.rate_in), out: num(data.rate_out) });
    if (state.rateHist.length > RATE_HIST) state.rateHist.splice(0, state.rateHist.length - RATE_HIST);
    updateHeader();
  } else if (type === 'flow') {
    notePendingFlow(data);
    updateHeader();
  } else if (type === 'intercept') {
    state.intercept = Object.assign({}, state.intercept, data);
    if (state.status) state.status.intercept = Object.assign({}, state.status.intercept, data);
    if (data && data.pending !== undefined && num(data.pending) !== state.pendingIds.size) syncPending();
    updateHeader();
  } else if (type === 'log') {
    state.logs.push(data);
    if (state.logs.length > LOG_MAX) state.logs.splice(0, state.logs.length - LOG_MAX);
  } else if (type === 'vpn') {
    if (state.status) mergeVpnStatus(state.status.vpns, data);
  } else if (type === 'caido') {
    if (state.status) state.status.caido = Object.assign({}, state.status.caido, data);
  } else if (type === 'fw_ask') {
    if (data && data.id && !state.fwQueue.some(a => a.id === data.id)) state.fwQueue.push(data);
    updateFwBadge();
    maybeShowFwPrompt();
  } else if (type === 'fw_resolved') {
    if (data && data.id) {
      state.fwQueue = state.fwQueue.filter(a => a.id !== data.id);
      updateFwBadge();
      // Timeout (or another client answering) must dismiss the open prompt;
      // otherwise Allow posts a dead id and the next ask is stuck behind it.
      if (state.fwPromptId === data.id && typeof state.fwPromptClose === 'function') {
        state.fwPromptClose();
      }
    }
  } else if (type === 'fw_block') {
    noteFwBlock(data);
  } else if (type === 'bw_alert') {
    noteBwAlert(data);
  }
  Router.dispatch(type, data);
}

/* ---- Firewall block notifications ---- */
const _fwBlockSeen = {};
function noteFwBlock(d) {
  if (!d) return;
  const app = d.app || 'unknown program';
  const dst = d.host || d.ip || '?';
  const seenKey = app + '|' + dst;
  const now = Date.now();
  if (_fwBlockSeen[seenKey] && now - _fwBlockSeen[seenKey] < 8000) return; // dedup bursts
  _fwBlockSeen[seenKey] = now;
  toast('\uD83D\uDEE1 Firewall blocked ' + app + ' \u2192 ' + dst + (d.reason ? ' (' + d.reason + ')' : '') + ' \u2014 see Firewall \u203a Recent activity', 'warn', 7000);
}

/* ---- Bandwidth anomaly alerts ---- */
function noteBwAlert(a) {
  if (!a || !a.app) return;
  state.bwAlerts = state.bwAlerts || [];
  state.bwAlerts.unshift(a);
  if (state.bwAlerts.length > 50) state.bwAlerts.length = 50;
  const dir = a.kind === 'download' ? '\u2193 downloading' : '\u2191 uploading';
  const base = (a.factor && a.factor >= 1.5) ? ' (' + Math.round(a.factor) + '\u00d7 its normal)' : '';
  toast('\u26a0 ' + a.app + ' ' + dir + ' ' + fmt.rate(a.rate || 0) + base, 'warn', 7000);
  updateBwBadge();
}
function updateBwBadge() {
  const el = document.querySelector('#nav-bw');
  if (!el) return;
  const n = (state.bwAlerts || []).length;
  el.textContent = n ? String(n) : '';
  el.hidden = !n;
}

/* ---- Firewall prompt (ZoneAlarm-style popup) ---- */
// On every (re)connect, rebuild the pending-prompt queue from the server's
// truth and recover a stuck prompt state. Without this, a prompt that was open
// when the daemon restarted leaves fwPromptOpen=true forever, silently
// swallowing every later prompt (the "firewall never asks me" bug).
async function resyncFirewall() {
  try {
    const p = await api('GET', '/api/firewall/pending', undefined, { silent: true });
    state.fwQueue = (p && p.pending) || [];
    if (!document.querySelector('.fw-prompt')) { state.fwPromptOpen = false; state.fwPromptId = 0; state.fwPromptClose = null; }
    updateFwBadge();
    maybeShowFwPrompt();
  } catch (_) { /* ignore */ }
}
function updateFwBadge() {
  const el = document.querySelector('#nav-fw');
  if (el) { el.textContent = state.fwQueue.length || ''; el.hidden = !state.fwQueue.length; }
}
function maybeShowFwPrompt() {
  // Inside the desktop app the Electron shell shows a system-wide popup for
  // every ask (visible even when this window is hidden); do not duplicate it.
  if (window.cyberboba && window.cyberboba.desktop) return;
  if (state.fwPromptOpen || !state.fwQueue.length) return;
  const ask = state.fwQueue[0];
  state.fwPromptOpen = true;
  state.fwPromptId = ask.id;
  const dst = (ask.host || ask.ip || '?') + (ask.port ? ':' + ask.port : '');
  const remember = checkbox('Remember this answer for ' + (ask.app || 'this app') + ' (' + ask.zone + ' zone)', true);
  const answer = async (allow) => {
    // Remove from the queue first, so the onClose -> maybeShowFwPrompt (50ms)
    // does not re-open a modal for the ask we just answered (404 + desync).
    state.fwQueue = state.fwQueue.filter(a => a.id !== ask.id);
    updateFwBadge();
    try { await api('POST', '/api/firewall/answer', { id: ask.id, allow, remember: remember.input.checked }, { silent: true }); }
    catch (_) { /* may have timed out */ }
  };
  const m = openModal({
    title: '\uD83D\uDEE1 Firewall \u2014 program wants network access',
    width: '520px',
    body: h('div', { class: 'fw-prompt' },
      h('div', { class: 'fw-prompt-app' }, h('span', { class: 'fw-prompt-ico' }, '\u26A0'), h('b', null, ask.app || '(unknown program)'),
        ask.guess ? h('span', { class: 'muted small' }, ' \u2014 probably ', h('b', null, ask.guess), ' (guessed from earlier connections)') : null,
        ask.user ? h('span', { class: 'muted small' }, ' \u00b7 user ', ask.user) : null),
      h('div', { class: 'fw-prompt-line' }, 'is trying to reach ', h('b', { class: 'mono' }, dst),
        ' in the ', badge(ask.zone, ask.zone === 'trusted' ? 'green' : 'blue'), ' zone.'),
      ask.exe ? h('div', { class: 'muted small mono', style: { marginTop: '4px', wordBreak: 'break-all' } }, ask.exe) : null,
      h('div', { style: { marginTop: '10px' } }, remember)),
    buttons: [
      { label: 'Deny', cls: 'danger', onClick: (close) => { answer(false); close(); } },
      { label: 'Allow', cls: 'primary', onClick: (close) => { answer(true); close(); } },
    ],
    onClose: () => {
      state.fwPromptOpen = false;
      state.fwPromptId = 0;
      state.fwPromptClose = null;
      setTimeout(maybeShowFwPrompt, 50);
    },
  });
  state.fwPromptClose = m.close;
  return m;
}

/* ================================================================
 * 4a. Dashboard
 * ================================================================ */
const TILES = [
  ['active', 'Active connections'], ['total', 'Total'], ['blocked', 'Blocked'],
  ['rate_in', 'Rate in'], ['rate_out', 'Rate out'], ['bytes_in', 'Bytes in'], ['bytes_out', 'Bytes out'],
];

function vpnStateBadge(v) {
  const st = v.state || 'down';
  if (st === 'up' && v.external) { const b = badge('up (external)', 'green'); b.title = 'Brought up outside cyberboba (wg-quick by hand / tray helper); Down still works here'; return b; }
  return badge(st, STATE_CLS[st] || (st === 'up' ? 'green' : 'gray'));
}
function caidoStateBadge(c) {
  if (!c || !c.enabled) return badge('disabled', 'gray');
  if (c.running) return badge(c.reachable ? 'running' : 'running (unreachable)', c.reachable ? 'green' : 'yellow');
  return badge('stopped', 'gray');
}
function interceptStateBadge(ic) {
  if (!ic || !ic.enabled) return badge('disabled', 'gray');
  return badge(ic.recording ? 'recording' : 'paused', ic.recording ? 'green' : 'yellow');
}

/**
 * Live traffic graph: last RATE_HIST seconds of rate_in / rate_out (two filled lines, one shared axis).
 * Colors come from the CSS variables --chart-in / --chart-out so both themes are covered.
 */
function trafficGraph() {
  const canvas = h('canvas', { class: 'graph-canvas', 'aria-label': 'traffic rate graph, last 120 seconds', role: 'img' });
  const readout = h('span', { class: 'graph-readout mono muted small' });
  const legend = h('div', { class: 'graph-legend small' },
    h('span', null, h('i', { class: 'swatch in' }), 'in (download)'),
    h('span', null, h('i', { class: 'swatch out' }), 'out (upload)'),
    h('span', { class: 'spacer' }), readout);
  const el = h('div', { class: 'graph' }, canvas, legend);
  let hoverX = null;
  const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const fmtAxis = v => { // KB/s or MB/s axis labels
    if (v >= 1048576) return (v / 1048576).toFixed(v >= 10485760 ? 0 : 1) + ' MB/s';
    if (v >= 1024) return (v / 1024).toFixed(v >= 10240 ? 0 : 1) + ' KB/s';
    return v.toFixed(0) + ' B/s';
  };
  const niceMax = v => { // round the axis maximum up to 1/2/5 × 10^n (in bytes/s)
    if (v <= 0) return 1024;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
  };
  function draw() {
    if (!canvas.isConnected) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth || 600, H = canvas.clientHeight || 140;
    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const cIn = cssVar('--chart-in') || '#4c8dff', cOut = cssVar('--chart-out') || '#34a848';
    const grid = cssVar('--border') || '#333', ink = cssVar('--fg2') || '#999';
    const padL = 58, padR = 8, padT = 6, padB = 16;
    const gw = W - padL - padR, gh = H - padT - padB;
    const hist = state.rateHist;
    const now = Date.now();
    const maxV = niceMax(hist.reduce((m, s) => Math.max(m, s.in, s.out), 0) * 1.05);
    ctx.font = '10px ' + (cssVar('--mono') || 'monospace');
    ctx.fillStyle = ink; ctx.strokeStyle = grid; ctx.lineWidth = 1;
    // horizontal grid + y labels
    for (let i = 0; i <= 2; i++) {
      const y = padT + gh - (gh * i) / 2;
      ctx.beginPath(); ctx.moveTo(padL, Math.round(y) + 0.5); ctx.lineTo(W - padR, Math.round(y) + 0.5); ctx.stroke();
      ctx.textAlign = 'right'; ctx.textBaseline = i === 0 ? 'bottom' : i === 2 ? 'top' : 'middle';
      ctx.fillText(fmtAxis((maxV * i) / 2), padL - 6, y);
    }
    // x labels
    ctx.textBaseline = 'top';
    for (const [sec, label] of [[RATE_HIST, '-' + RATE_HIST + 's'], [RATE_HIST / 2, '-' + RATE_HIST / 2 + 's'], [0, 'now']]) {
      const x = padL + gw * (1 - sec / RATE_HIST);
      ctx.textAlign = sec === RATE_HIST ? 'left' : sec === 0 ? 'right' : 'center';
      ctx.fillText(label, x, padT + gh + 3);
    }
    const xOf = s => padL + gw * Math.min(1, Math.max(0, 1 - (now - s.t) / (RATE_HIST * 1000)));
    const yOf = v => padT + gh - (gh * Math.min(v, maxV)) / maxV;
    const series = [['out', cOut], ['in', cIn]];
    if (hist.length < 2) {
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillStyle = ink;
      ctx.fillText(state.sse ? 'collecting samples…' : 'waiting for event stream…', padL + gw / 2, padT + gh / 2);
    }
    for (const [k, color] of series) {
      if (hist.length < 2) break;
      ctx.beginPath();
      hist.forEach((s, i) => { const x = xOf(s), y = yOf(s[k]); if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
      const last = hist[hist.length - 1], first = hist[0];
      ctx.lineTo(xOf(last), padT + gh); ctx.lineTo(xOf(first), padT + gh); ctx.closePath();
      const grad = ctx.createLinearGradient(0, padT, 0, padT + gh);
      grad.addColorStop(0, hexA(color, 0.32)); grad.addColorStop(0.55, hexA(color, 0.10)); grad.addColorStop(1, hexA(color, 0.015));
      ctx.fillStyle = grad; ctx.fill();
      ctx.beginPath();
      hist.forEach((s, i) => { const x = xOf(s), y = yOf(s[k]); if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
      ctx.shadowColor = hexA(color, 0.45); ctx.shadowBlur = 5; ctx.stroke(); ctx.shadowBlur = 0; ctx.shadowColor = 'transparent';
    }
    // hover crosshair
    const cur = hist.length ? hist[hist.length - 1] : null;
    let pick = cur;
    if (hoverX !== null && hist.length) {
      pick = hist.reduce((b, s) => Math.abs(xOf(s) - hoverX) < Math.abs(xOf(b) - hoverX) ? s : b, hist[0]);
      const x = Math.round(xOf(pick)) + 0.5;
      ctx.strokeStyle = ink; ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + gh); ctx.stroke(); ctx.setLineDash([]);
      for (const [k, color] of series) { ctx.fillStyle = color; ctx.beginPath(); ctx.arc(xOf(pick), yOf(pick[k]), 3.5, 0, Math.PI * 2); ctx.fill(); }
    }
    readout.textContent = pick ? (hoverX === null ? 'now' : '-' + Math.round((now - pick.t) / 1000) + 's') + '  ↓ ' + fmt.rate(pick.in) + '  ↑ ' + fmt.rate(pick.out) : '';
  }
  canvas.addEventListener('mousemove', e => { hoverX = e.offsetX; draw(); });
  canvas.addEventListener('mouseleave', () => { hoverX = null; draw(); });
  el.draw = draw;
  return el;
}

async function vpnUpDown(name, up) {
  const r = await api('POST', '/api/vpn/' + encodeURIComponent(name) + '/' + (up ? 'up' : 'down'));
  if (state.status) mergeVpnStatus(state.status.vpns, r);
  toast('VPN ' + name + (up ? ' up' : ' down') + (r && r.error ? ': ' + r.error : ''), r && r.error ? 'warn' : 'ok');
  return r;
}

Pages.dashboard = {
  title: 'Dashboard',
  async mount(root) {
    this.root = root; this.busy = false;
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Dashboard'),
      h('span', { class: 'muted small' }, 'live overview of interception, traffic and your tunnels'),
      h('span', { class: 'spacer' }), btn('Refresh', () => this.refresh())));
    this.body = h('div', { class: 'dash' });
    root.append(this.body);
    this.onTheme = () => { if (this.graph) this.graph.draw(); };
    document.addEventListener('cyberboba:theme', this.onTheme);
    window.addEventListener('resize', this.onTheme);
    await this.refresh();
    if (!root.isConnected) return;
    this.timer = setInterval(() => this.refresh(true), 10000);
  },
  unmount() {
    clearInterval(this.timer); this.root = null; this.body = null; this.graph = null;
    document.removeEventListener('cyberboba:theme', this.onTheme); window.removeEventListener('resize', this.onTheme);
  },
  async refresh(silent) {
    let s;
    try { s = await api('GET', '/api/status', undefined, { silent }); } catch (_) { return; }
    state.status = s; state.stats = s.stats || state.stats;
    updateHeader();
    this.render();
  },
  async toggle(on) {
    if (this.busy) return;
    this.busy = true;
    try {
      const s = await api('POST', '/api/proxify/' + (on ? 'enable' : 'disable'));
      if (s && s.proxify) state.status = s;
      updateHeader(); this.render();
      toast('Proxify ' + (on ? 'enabled' : 'disabled'), 'ok');
    } catch (_) { /* toast shown */ }
    finally { this.busy = false; }
  },
  render() {
    const s = state.status;
    if (!s || !this.body) return;
    const p = s.proxify || {};
    const on = !!p.enabled;
    const b = clear(this.body);

    b.append(h('div', { class: 'dash-top' },
      h('div', { class: 'card proxify-card' },
        h('div', { class: 'card-title' }, 'Proxify'),
        h('button', { type: 'button', class: 'toggle-big ' + (on ? 'on' : 'off'), 'aria-pressed': on ? 'true' : 'false',
          title: on ? 'Click to disable interception' : 'Click to enable interception', onClick: () => this.toggle(!on) },
          h('span', { class: 'knob' }), h('span', { class: 'toggle-text' }, on ? 'ON' : 'OFF'),
          h('span', { class: 'toggle-sub' }, p.netfilter_installed ? 'netfilter installed' : 'netfilter not installed')),
        h('div', { class: 'kv' },
          kv('TCP listener', p.listen_tcp), kv('DNS listener', p.listen_dns),
          kv('QUIC', p.block_quic ? 'blocked (UDP/443)' : 'allowed'),
          kv('IPv6', p.ipv6 ? 'intercepted' : 'not intercepted')),
        h('div', { class: 'muted small' }, 'cyberbobad ' + (s.version || '') + ' · uptime ' + fmt.duration(s.uptime_sec))),
      h('div', { class: 'tiles' },
        ...TILES.map(([k, l]) => h('div', { class: 'tile' }, h('div', { class: 'tile-label' }, l), h('div', { class: 'tile-value', dataset: { stat: k } }, '—'))),
        h('div', { class: 'tile', style: { gridColumn: '1 / -1' } }, h('div', { class: 'tile-label' }, 'By action'),
          h('div', { class: 'by-action', dataset: { stat: 'by_action' } })))));

    this.applyStats(s.stats || state.stats);

    this.graph = trafficGraph();
    b.append(h('div', { class: 'card graph-card' }, h('div', { class: 'card-title' }, 'Traffic · last ' + RATE_HIST + ' s'), this.graph));
    requestAnimationFrame(() => this.graph && this.graph.draw());

    if (s.warnings && s.warnings.length) {
      b.append(h('div', { class: 'warn-box' }, h('strong', null, 'Warnings'), h('ul', null, ...s.warnings.map(w => h('li', null, w)))));
    }

    const vpns = s.vpns || [];
    const c = s.caido || {};
    this.cards = h('div', { class: 'cards-row' });
    this.cards.append(this.interceptCard(s.intercept || state.intercept || {}));
    for (const v of vpns) this.cards.append(this.vpnCard(v));
    this.cards.append(this.caidoCard(c));
    b.append(h('div', null, h('h4', null, 'Intercept, VPN & Caido'), this.cards));
  },
  interceptCard(ic) {
    const hold = [ic.hold_requests ? 'requests' : '', ic.hold_responses ? 'responses' : ''].filter(Boolean).join(' + ');
    const pc = state.pendingSeeded ? state.pendingIds.size : num(ic.pending);
    return h('div', { class: 'card intercept-card' },
      h('div', { class: 'card-title' }, h('span', null, 'Intercept'), interceptStateBadge(ic)),
      h('div', { class: 'kv' },
        kv('listen', ic.listen), kv('flows', fmt.num(ic.flows)),
        kv('pending', pc ? h('span', { class: 'warn' }, fmt.num(pc) + ' held') : '0'),
        kv('hold', hold || 'off')),
      h('div', { class: 'card-actions' },
        btn(ic.recording ? 'Pause recording' : 'Start recording', () => this.interceptToggle(!ic.recording), ic.recording ? '' : 'ok', { disabled: !ic.enabled, title: 'POST /api/intercept/toggle' }),
        pc ? h('a', { class: 'btn', href: '#/intercept/queue' }, 'Queue (' + pc + ')') : null,
        h('span', { class: 'spacer' }), h('a', { href: '#/intercept', class: 'small' }, 'open →')));
  },
  async interceptToggle(recording) {
    let r; try { r = await api('POST', '/api/intercept/toggle', { recording }); } catch (_) { return; }
    state.intercept = r;
    if (state.status) state.status.intercept = Object.assign({}, state.status.intercept, { enabled: r.enabled, listen: r.listen, recording: r.recording, hold_requests: r.hold_requests, hold_responses: r.hold_responses, flows: r.flows, pending: r.pending });
    toast('Recording ' + (r.recording ? 'started' : 'paused'), 'ok', 2000);
    this.render();
  },
  applyStats(st) {
    if (!st || !this.body) return;
    for (const [k] of TILES) {
      const el = this.body.querySelector('[data-stat="' + k + '"]');
      if (!el) continue;
      const v = st[k];
      el.textContent = k.startsWith('rate') ? fmt.rate(v) : k.startsWith('bytes') ? fmt.bytes(v) : fmt.num(v);
    }
    const ba = this.body.querySelector('[data-stat="by_action"]');
    if (ba) {
      const m = st.by_action || {};
      const acts = ['direct', 'proxy', 'vpn', 'block'].concat(m.intercept !== undefined ? ['intercept'] : []);
      replace(ba, ...acts.map(a => h('span', { class: 'mono' }, badge(a, ACTION_CLS[a]), fmt.num(m[a]))));
    }
    if (this.graph) this.graph.draw();
  },
  vpnCard(v) {
    const up = v.state === 'up';
    const el = h('div', { class: 'card vpn-card', dataset: { vpn: v.name } },
      h('div', { class: 'card-title' }, h('span', null, 'VPN · ', h('span', { class: 'mono' }, v.name)), h('span', null, v.kill_switch_active ? [badge('kill switch', 'red'), ' '] : null, vpnStateBadge(v))),
      h('div', { class: 'kv' },
        kv('type / mode', (v.type || '') + ' / ' + (v.mode || '')),
        kv('interface', v.interface), kv('endpoint', v.endpoint), kv('local ip', v.local_ip),
        kv('rx / tx', fmt.bytes(v.rx_bytes) + ' / ' + fmt.bytes(v.tx_bytes)),
        kv('handshake', isZeroTime(v.last_handshake) ? 'never' : fmt.ago(v.last_handshake)),
        num(v.reconnects) ? kv('reconnects', fmt.num(v.reconnects)) : null,
        up ? kv('since', fmt.datetime(v.since)) : null),
      v.error ? h('div', { class: 'error-box', style: { marginTop: '6px' } }, v.error) : null,
      h('div', { class: 'card-actions' },
        btn('Up', () => this.vpnAction(v.name, true), 'ok', { disabled: up }),
        btn('Down', () => this.vpnAction(v.name, false), 'danger', { disabled: !up }),
        h('span', { class: 'spacer' }), h('a', { href: '#/vpn', class: 'small' }, 'manage →')));
    return el;
  },
  async vpnAction(name, up) {
    try { await vpnUpDown(name, up); } catch (_) { return; }
    this.render();
  },
  caidoCard(c) {
    const can = c.enabled && c.managed;
    return h('div', { class: 'card caido-card' },
      h('div', { class: 'card-title' }, h('span', null, 'Caido'), caidoStateBadge(c)),
      h('div', { class: 'kv' },
        kv('listen', c.listen), kv('version', c.version), kv('pid', c.running && c.pid ? c.pid : ''),
        kv('managed', c.managed ? 'yes (started by cyberboba)' : 'no (external)'),
        kv('reachable', c.enabled ? (c.reachable ? 'yes' : 'no') : '')),
      c.error ? h('div', { class: 'error-box', style: { marginTop: '6px' } }, c.error) : null,
      h('div', { class: 'card-actions' },
        btn('Start', () => this.caidoAction('start'), 'ok', { disabled: !can || c.running }),
        btn('Stop', () => this.caidoAction('stop'), 'danger', { disabled: !can || !c.running }),
        c.ui_url ? h('a', { class: 'btn', href: c.ui_url, target: '_blank', rel: 'noopener' }, 'Open UI ↗') : null,
        h('span', { class: 'spacer' }), h('a', { href: '#/caido', class: 'small' }, 'configure →')));
  },
  async caidoAction(act) {
    try { await api('POST', '/api/caido/' + act); toast('Caido ' + act + ' requested', 'ok'); } catch (_) { return; }
    this.refresh(true);
  },
  onEvent(type, data) {
    if (type === 'stats') this.applyStats(data);
    else if (type === 'vpn' || type === 'caido' || type === 'intercept' || type === 'pending-sync') this.render();
    else if (type === 'flow' && this.cards) { // keep the pending count on the intercept card fresh
      const ic = (state.status && state.status.intercept) || state.intercept || {};
      const old = this.cards.querySelector('.intercept-card');
      if (old) old.replaceWith(this.interceptCard(ic));
    }
  },
};

/* ================================================================
 * 4b. Connections
 * ================================================================ */
const CONN_MAX = 2000;
const CONN_COLS = [
  { k: 'time', label: 'Time', w: '72px' },
  { k: 'app', label: 'Application', w: '190px' },
  { k: 'user', label: 'User', w: '80px' },
  { k: 'target', label: 'Target', w: 'auto' },
  { k: 'rule', label: 'Rule', w: '160px' },
  { k: 'action', label: 'Action', w: '76px' },
  { k: 'via', label: 'Via', w: '110px' },
  { k: 'in', label: 'In', w: '82px', cls: 'num' },
  { k: 'out', label: 'Out', w: '82px', cls: 'num' },
  { k: 'state', label: 'State', w: '80px' },
  { k: 'x', label: '', w: '34px' },
];

Pages.connections = {
  title: 'Connections',
  async mount(root) {
    this.root = root;
    this.rows = new Map();   // id -> <tr>
    this.filter = '';
    this.showClosed = localStorage.getItem('cyberboba.showClosed') !== '0';

    const filterIn = h('input', { type: 'search', class: 'filter mono', placeholder: 'filter app / host / rule / via…', spellcheck: 'false',
      onInput: debounce(() => { this.filter = filterIn.value.trim().toLowerCase(); this.applyFilter(); }, 120),
      onKeydown: e => { if (e.key === 'Escape') { filterIn.value = ''; this.filter = ''; this.applyFilter(); } } });
    this.filterIn = filterIn;
    const cb = checkbox('show closed', this.showClosed);
    cb.input.addEventListener('change', () => {
      this.showClosed = cb.input.checked;
      localStorage.setItem('cyberboba.showClosed', this.showClosed ? '1' : '0');
      this.reload();
    });
    this.countEl = h('span', { class: 'muted small mono' });
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Connections'),
      h('span', { class: 'muted small' }, 'every connection apps on this machine make, live'),
      filterIn, cb, this.countEl,
      h('span', { class: 'spacer' }),
      btn('Clear history', () => this.clearClosed(), 'danger', { title: 'Remove closed connections from the list (active ones stay)' }),
      btn('Reload', () => this.reload())));

    this.tbody = h('tbody');
    const table = h('table', { class: 'grid conns' },
      h('colgroup', null, ...CONN_COLS.map(c => h('col', { style: c.w === 'auto' ? null : { width: c.w } }))),
      h('thead', null, h('tr', null, ...CONN_COLS.map(c => h('th', { class: c.cls || '' }, c.label)))),
      this.tbody);
    root.append(h('div', { class: 'table-wrap' }, table));
    this.tbody.addEventListener('click', e => {
      const b = e.target.closest('button[data-close]');
      if (b) this.closeConn(Number(b.dataset.close));
    });
    await this.reload();
  },
  unmount() { clearTimeout(this.countTimer); this.rows = null; this.tbody = null; this.root = null; },

  async reload() {
    let r;
    try { r = await api('GET', '/api/connections?limit=' + CONN_MAX + '&closed=' + (this.showClosed ? '1' : '0')); }
    catch (_) { return; }
    if (!this.tbody) return;
    clear(this.tbody); this.rows.clear();
    const list = (r.connections || []).slice().sort((a, b) => num(a.id) - num(b.id)); // ascending; each insert goes on top
    for (const c of list) this.upsert(c);
    this.applyFilter();
  },
  isClosed(c) { return c.state !== 'open'; },
  matches(c) {
    if (!this.showClosed && this.isClosed(c)) return false;
    if (!this.filter) return true;
    const f = this.filter;
    return [c.app, c.host, c.dst_ip, c.rule, c.via, c.vpn, c.user, c.exe].some(v => v && String(v).toLowerCase().includes(f));
  },
  upsert(c) {
    if (!this.tbody || c === null || typeof c !== 'object' || c.id === undefined) return;
    const tr = this.rows.get(c.id);
    if (tr) {
      this.fillRow(tr, c);
      tr.hidden = !this.matches(c);
    } else {
      const row = this.makeRow(c);
      this.rows.set(c.id, row);
      row.hidden = !this.matches(c);
      this.tbody.insertBefore(row, this.tbody.firstChild);
      this.trim();
    }
    this.scheduleCount();
  },
  makeRow(c) {
    const cells = {};
    const tr = h('tr', { dataset: { id: c.id } });
    cells.time = h('td', { class: 'mono' });
    cells.appName = h('span', { class: 'app-name' });
    cells.pid = h('span', { class: 'pid' });
    cells.app = h('td', null, cells.appName, cells.pid);
    cells.user = h('td');
    cells.target = h('td', { class: 'mono' });
    cells.rule = h('td');
    cells.action = h('span', { class: 'badge' });
    cells.via = h('td', { class: 'mono' });
    cells.in = h('td', { class: 'num' });
    cells.out = h('td', { class: 'num' });
    cells.state = h('span', { class: 'badge' });
    cells.close = h('button', { type: 'button', class: 'btn tiny icon danger', dataset: { close: c.id }, title: 'close connection' }, '×');
    tr.append(cells.time, cells.app, cells.user, cells.target, cells.rule, h('td', null, cells.action), cells.via, cells.in, cells.out, h('td', null, cells.state), h('td', null, cells.close));
    tr._c = cells;
    this.fillRow(tr, c);
    return tr;
  },
  fillRow(tr, c) {
    const x = tr._c;
    tr._conn = c;
    x.time.textContent = fmt.time(c.started);
    x.time.title = fmt.datetime(c.started) + (c.ended && !isZeroTime(c.ended) ? ' → ' + fmt.time(c.ended) : '');
    x.appName.textContent = c.app || (c.pid ? 'pid ' + c.pid : '?');
    x.pid.textContent = c.pid ? String(c.pid) : '';
    x.app.title = (c.exe || '') + (c.tag ? '  [' + c.tag + ']' : '');
    x.user.textContent = c.user || '';
    const port = c.dst_port === undefined || c.dst_port === null ? '' : ':' + c.dst_port;
    x.target.textContent = (c.host || c.dst_ip || '?') + port;
    x.target.title = (c.proto || 'tcp') + ' ' + (c.dst_ip || '') + port + (c.host ? '  (' + c.host + ')' : '');
    x.rule.textContent = c.rule || '';
    x.rule.title = c.rule || '';
    setBadge(x.action, c.action || '', ACTION_CLS[c.action] || 'gray');
    x.via.textContent = c.via || c.vpn || '';
    x.in.textContent = fmt.bytes(c.bytes_in);
    x.out.textContent = fmt.bytes(c.bytes_out);
    setBadge(x.state, c.state || '', STATE_CLS[c.state] || 'gray');
    x.state.title = c.error || '';
    x.close.hidden = c.state !== 'open';
    tr.className = 'st-' + (c.state || 'open');
  },
  trim() {
    const tb = this.tbody;
    while (this.rows.size > CONN_MAX) {
      let victim = null, n = 0;
      for (let tr = tb.lastElementChild; tr && n < 300; tr = tr.previousElementSibling, n++) {
        if (tr._conn && tr._conn.state !== 'open') { victim = tr; break; }
      }
      if (!victim) victim = tb.lastElementChild;
      if (!victim) break;
      this.rows.delete(victim._conn.id);
      victim.remove();
    }
  },
  applyFilter() {
    if (!this.tbody) return;
    for (const tr of this.rows.values()) tr.hidden = !this.matches(tr._conn);
    this.updateCount();
  },
  scheduleCount() {
    if (this.countTimer) return;
    this.countTimer = setTimeout(() => { this.countTimer = null; this.updateCount(); }, 300);
  },
  updateCount() {
    if (!this.rows) return;
    let shown = 0, open = 0;
    for (const tr of this.rows.values()) { if (!tr.hidden) shown++; if (tr._conn.state === 'open') open++; }
    this.countEl.textContent = shown + ' shown / ' + this.rows.size + ' loaded / ' + open + ' open';
    this.syncEmpty(shown);
  },
  syncEmpty(shown) {
    if (!this.tbody) return;
    const existing = this.tbody.querySelector('tr.conn-empty');
    if (shown > 0) { if (existing) existing.remove(); return; }
    if (existing) return;
    const filtered = !!this.filter || !this.showClosed;
    const content = filtered
      ? emptyState('Nothing matches', 'No connections match your current filter. Clear it, or turn on “show closed” to include finished connections.', { cls: 'flat' })
      : emptyState('No connections yet',
        'The moment an app opens a network connection, it appears here with its app, destination and the rule that routed it. Make sure Proxify is on so cyberboba can see traffic.',
        { cls: 'flat', actions: [h('a', { class: 'btn', href: '#/dashboard' }, 'Go to Dashboard'), h('a', { class: 'btn', href: '#/rules' }, 'Set up Rules')] });
    this.tbody.append(h('tr', { class: 'conn-empty' }, h('td', { colspan: CONN_COLS.length }, content)));
  },
  async clearClosed() {
    const closed = Array.from(this.rows.values()).filter(tr => tr._conn.state !== 'open').length;
    if (closed && !confirm('Clear ' + closed + ' closed connection' + (closed === 1 ? '' : 's') + ' from the list? Active connections stay, and this only affects the history shown here.')) return;
    try { await api('DELETE', '/api/connections'); } catch (_) { return; }
    for (const [id, tr] of Array.from(this.rows.entries())) {
      if (tr._conn.state !== 'open') { tr.remove(); this.rows.delete(id); }
    }
    this.updateCount();
    toast('Connection history cleared', 'ok');
  },
  async closeConn(id) {
    try { await api('POST', '/api/connections/' + id + '/close'); toast('Connection ' + id + ' closed', 'ok', 2000); } catch (_) { /* shown */ }
  },
  onEvent(type, data) {
    if (type === 'conn') this.upsert(data);
  },
};

/* ================================================================
 * 4c. Rules
 * ================================================================ */
Pages.rules = {
  title: 'Rules',
  async mount(root) {
    this.root = root; this.dirty = false; this.dragEl = null;
    const [rules, proxies, vpns, caido, procs] = await Promise.all([
      api('GET', '/api/rules'),
      api('GET', '/api/proxies', undefined, { silent: true }).catch(() => ({ proxies: [] })),
      api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
      api('GET', '/api/caido', undefined, { silent: true }).catch(() => null),
      api('GET', '/api/processes', undefined, { silent: true }).catch(() => ({ processes: [] })),
    ]);
    if (!root.isConnected) return;
    this.proxyNames = (proxies.proxies || []).map(p => p.name).filter(Boolean);
    const cc = caido && caido.config;
    this.caidoProxy = cc && cc.enabled ? (cc.proxy_name || '') : '';
    if (this.caidoProxy && !this.proxyNames.includes(this.caidoProxy)) this.proxyNames.push(this.caidoProxy);
    this.vpnNames = (vpns.vpns || []).map(v => v.name).filter(Boolean);
    this.procs = procs.processes || [];

    root.append(
      h('datalist', { id: 'dl-apps' }, ...uniq(this.procs.map(p => p.name)).sort().map(n => h('option', { value: n }))),
      h('datalist', { id: 'dl-users' }, ...uniq(this.procs.map(p => p.user)).sort().map(n => h('option', { value: n }))),
      h('datalist', { id: 'dl-proto' }, h('option', { value: 'tcp' }), h('option', { value: 'udp' })),
      h('datalist', { id: 'dl-targets' }, h('option', { value: 'lan' }), h('option', { value: '*' }), h('option', { value: '10.0.0.0/8' }), h('option', { value: '*.example.com' })),
      h('datalist', { id: 'dl-ports' }, h('option', { value: '80' }), h('option', { value: '443' }), h('option', { value: '80,443' }), h('option', { value: '1-1023' })));

    this.saveBtn = btn('Save', () => this.save(), 'primary');
    this.dirtyEl = h('span', { class: 'muted small', hidden: true }, 'unsaved changes');
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Rules'),
      h('span', { class: 'muted small' }, 'evaluated top to bottom, first match wins'),
      h('span', { class: 'spacer' }), this.dirtyEl,
      btn('+ New route', () => routeWizard(() => this.reload()), 'primary', { title: 'guided builder: send traffic through VPN(s) and/or proxies, in order' }),
      btn('+ Add rule', () => this.add(), '', { title: 'add a blank rule to edit by hand' }),
      btn('Reload', () => this.reload()), this.saveBtn));

    root.append(h('div', { class: 'info-box small' },
      'A rule sends matching traffic one way: ', badge('direct', 'gray'), ' ', badge('proxy', 'blue'), ' ', badge('vpn', 'green'), ' ', badge('block', 'red'), ' ', badge('intercept', 'yellow'), '. ',
      'First matching rule wins (top → bottom), so put specific rules above the catch-all ', h('code', null, 'Default'), '. ',
      'To chain hops — e.g. ', h('b', null, 'all traffic → VPN → proxy'), ', or ', h('b', null, 'VPN → VPN → proxy'), ' — press ', h('b', null, '+ New route'), ' and it builds the proxy chain and rule for you.'));

    this.list = h('div', { class: 'rules-list' });
    this.list.addEventListener('input', () => this.setDirty(true));
    this.list.addEventListener('change', () => this.setDirty(true));
    root.append(h('div', { class: 'rules-layout' }, this.list, h('aside', { class: 'rules-side' }, this.testPanel(), this.help())));
    this.fill(rules.rules || []);
  },
  unmount() { this.root = null; this.list = null; },
  fill(rules) {
    clear(this.list);
    for (const r of rules) this.list.append(this.card(r));
    this.renumber();
    this.setDirty(false);
  },
  async reload() {
    if (this.dirty && !confirm('Discard unsaved changes?')) return;
    let r; try { r = await api('GET', '/api/rules'); } catch (_) { return; }
    this.fill(r.rules || []);
  },
  setDirty(d) { this.dirty = d; this.dirtyEl.hidden = !d; this.saveBtn.classList.toggle('dirty', d); },
  cards() { return $$('.rule', this.list); },
  renumber() {
    const cards = this.cards();
    cards.forEach((c, i) => {
      c._idx.textContent = String(i + 1);
      c._up.disabled = i === 0; c._down.disabled = i === cards.length - 1;
    });
    const empty = $('.empty', this.list);
    if (!cards.length && !empty) this.list.append(emptyState('No rules yet',
      ['Without rules, every connection goes out ', badge('direct', 'gray'), ' — straight to the internet, untouched. Add a rule to send specific apps or sites through a VPN, a proxy, or the interceptor.'],
      { actions: [btn('+ New route', () => routeWizard(() => this.reload()), 'primary'), btn('+ Add rule', () => this.add())] }));
    else if (cards.length && empty) empty.remove();
  },
  card(r) {
    const el = h('div', { class: 'rule' + (r.enabled === false ? ' disabled' : '') });
    const idx = h('span', { class: 'rule-idx' });
    const enabled = h('input', { type: 'checkbox', checked: r.enabled !== false, title: 'enabled',
      onChange: () => el.classList.toggle('disabled', !enabled.checked) });
    const name = textInput(r.name, { class: 'rule-name', placeholder: 'rule name', spellcheck: 'false' });
    const action = sel(['direct', 'proxy', 'vpn', 'block', 'intercept'], r.action || 'direct', { class: 'rule-action', title: 'action' });
    const proxy = sel([{ value: '', label: '(choose proxy)' }, ...this.proxyNames], r.proxy || '', { class: 'mono', title: 'proxy' });
    const vpn = sel([{ value: '', label: '(choose vpn)' }, ...this.vpnNames], r.vpn || '', { class: 'mono', title: 'vpn' });
    const syncAction = () => {
      proxy.hidden = action.value !== 'proxy';
      vpn.hidden = action.value !== 'vpn';
      action.className = 'rule-action act-' + action.value;
    };
    action.addEventListener('change', syncAction);
    syncAction();
    const apps = tagsInput({ values: r.apps, placeholder: 'name, /path/to/exe, tag:x', list: 'dl-apps' });
    const appsPick = btn('Choose…', () => pickAppModal(n => { const cur = apps.getValues(); if (!cur.includes(n)) { apps.setValues(cur.concat(n)); this.setDirty(true); } }), 'tiny', { title: 'pick from installed apps or running processes' });
    const appsCtl = h('div', { class: 'rb-apps' }, apps, appsPick);
    const users = tagsInput({ values: r.users, placeholder: 'any user', list: 'dl-users' });
    const targets = tagsInput({ values: r.targets, placeholder: 'host, *.domain, cidr, lan', list: 'dl-targets' });
    const ports = tagsInput({ values: r.ports, placeholder: '443, 8000-8100', list: 'dl-ports' });
    const protos = tagsInput({ values: r.protocols, placeholder: 'tcp, udp', list: 'dl-proto' });
    const comment = textInput(r.comment, { placeholder: 'comment' });
    const handle = h('span', { class: 'drag-handle', title: 'drag to reorder', 'aria-hidden': 'true' }, '⋮⋮');

    // drag & drop reordering (initiated from the handle only, so inputs stay selectable)
    handle.addEventListener('mousedown', () => { el.draggable = true; });
    handle.addEventListener('mouseup', () => { el.draggable = false; });
    el.addEventListener('dragstart', e => {
      if (!el.draggable) { e.preventDefault(); return; }
      this.dragEl = el; el.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', 'rule'); } catch (_) { /* ignore */ }
    });
    el.addEventListener('dragend', () => {
      el.draggable = false; el.classList.remove('dragging'); this.dragEl = null;
      $$('.rule.drop-before,.rule.drop-after', this.list).forEach(x => x.classList.remove('drop-before', 'drop-after'));
    });
    el.addEventListener('dragover', e => {
      if (!this.dragEl || this.dragEl === el) return;
      e.preventDefault(); e.dataTransfer.dropEffect = 'move';
      const rc = el.getBoundingClientRect();
      const before = e.clientY < rc.top + rc.height / 2;
      el.classList.toggle('drop-before', before); el.classList.toggle('drop-after', !before);
    });
    el.addEventListener('dragleave', () => el.classList.remove('drop-before', 'drop-after'));
    el.addEventListener('drop', e => {
      if (!this.dragEl || this.dragEl === el) return;
      e.preventDefault();
      const rc = el.getBoundingClientRect();
      const before = e.clientY < rc.top + rc.height / 2;
      this.list.insertBefore(this.dragEl, before ? el : el.nextSibling);
      el.classList.remove('drop-before', 'drop-after');
      this.setDirty(true); this.renumber();
    });

    const up = btn('↑', () => this.move(el, -1), 'icon', { title: 'move up' });
    const down = btn('↓', () => this.move(el, 1), 'icon', { title: 'move down' });
    el.append(
      h('div', { class: 'rule-row1' }, handle, idx, enabled, name, action, proxy, vpn, h('span', { class: 'spacer' }),
        up, down, btn('⎘', () => this.dup(el), 'icon', { title: 'duplicate' }), btn('×', () => this.del(el), 'icon danger', { title: 'delete rule' })),
      h('div', { class: 'rule-grid' },
        field('Apps', appsCtl, null), field('Users', users), field('Targets', targets), field('Ports', ports), field('Protocols', protos),
        field('Comment', comment, null, 'field-comment')));
    el._idx = idx; el._up = up; el._down = down;
    el.read = () => ({
      name: name.value.trim(), enabled: enabled.checked, comment: comment.value.trim(),
      apps: apps.getValues(), users: users.getValues(), targets: targets.getValues(), ports: ports.getValues(), protocols: protos.getValues(),
      action: action.value,
      proxy: action.value === 'proxy' ? proxy.value : '',
      vpn: action.value === 'vpn' ? vpn.value : '',
    });
    el.focusName = () => name.focus();
    return el;
  },
  move(el, dir) {
    const sib = dir < 0 ? el.previousElementSibling : el.nextElementSibling;
    if (!sib || !sib.classList.contains('rule')) return;
    if (dir < 0) this.list.insertBefore(el, sib); else this.list.insertBefore(sib, el);
    this.setDirty(true); this.renumber();
    el.scrollIntoView({ block: 'nearest' });
  },
  add() {
    const c = this.card({ name: 'New rule', enabled: true, apps: [], users: [], targets: [], ports: [], protocols: [], action: 'direct' });
    this.list.append(c); this.renumber(); this.setDirty(true);
    c.scrollIntoView({ block: 'nearest' }); c.focusName();
  },
  dup(el) {
    const r = el.read(); r.name = r.name + ' (copy)';
    const c = this.card(r);
    this.list.insertBefore(c, el.nextSibling); this.renumber(); this.setDirty(true); c.focusName();
  },
  del(el) {
    const r = el.read();
    if (!confirm('Delete the rule "' + (r.name || '(unnamed)') + '"? Traffic it handled will fall through to the next matching rule. Nothing is removed until you press Save.')) return;
    el.remove(); this.renumber(); this.setDirty(true);
  },
  async save() {
    const rules = this.cards().map(c => c.read());
    for (const r of rules) {
      if (r.action === 'proxy' && !r.proxy) { toast('Rule "' + r.name + '": action proxy needs a proxy', 'error'); return; }
      if (r.action === 'vpn' && !r.vpn) { toast('Rule "' + r.name + '": action vpn needs a VPN', 'error'); return; }
    }
    this.saveBtn.disabled = true;
    try {
      const r = await api('PUT', '/api/rules', { rules });
      toast('Rules saved (' + rules.length + ')', 'ok');
      this.fill((r && r.rules) || rules);
    } catch (_) { /* shown */ }
    finally { this.saveBtn.disabled = false; }
  },
  testPanel() {
    const app = textInput('', { placeholder: 'firefox', list: 'dl-apps', class: 'mono' });
    const user = textInput('', { placeholder: 'user', list: 'dl-users', class: 'mono' });
    const host = textInput('', { placeholder: 'example.com', class: 'mono' });
    const ip = textInput('', { placeholder: '1.2.3.4', class: 'mono' });
    const port = h('input', { type: 'number', value: '443', min: 0, max: 65535, class: 'mono' });
    const proto = sel(['tcp', 'udp'], 'tcp');
    const exe = textInput('', { placeholder: '/usr/bin/app (for path rules)', class: 'mono' });
    const cmdl = textInput('', { placeholder: 'command line (for cmd: rules)', class: 'mono' });
    const result = h('div', { class: 'test-result' });
    const run = async () => {
      const body = { app: app.value.trim(), exe: exe.value.trim(), cmd: cmdl.value.trim(), user: user.value.trim(), host: host.value.trim(), ip: ip.value.trim(), port: num(port.value), protocol: proto.value };
      let r;
      try { r = await api('POST', '/api/rules/test', body); } catch (e) { replace(result, h('div', { class: 'error-box' }, e.message)); return; }
      if (r.matched) {
        replace(result, h('div', { class: 'ok-box' },
          h('div', null, 'Matched rule #', num(r.index) + 1, ' ', h('strong', null, r.rule || '(unnamed)')),
          h('div', { style: { marginTop: '4px' } }, badge(r.action, ACTION_CLS[r.action]), ' ',
            r.proxy ? h('span', { class: 'mono' }, 'via proxy ' + r.proxy) : null,
            r.vpn ? h('span', { class: 'mono' }, 'via vpn ' + r.vpn) : null)));
      } else {
        replace(result, h('div', { class: 'info-box' }, 'No rule matched — traffic goes ', badge(r.action || 'direct', ACTION_CLS[r.action] || 'gray'), '.'));
      }
    };
    const liveRun = async () => {
      const body = { app: app.value.trim(), exe: exe.value.trim(), cmd: cmdl.value.trim(), host: host.value.trim(), port: num(port.value) || 443 };
      if (!body.host) { replace(result, h('div', { class: 'info-box' }, 'Enter a host to live-test (e.g. api.ipify.org).')); return; }
      replace(result, h('div', { class: 'muted' }, h('span', { class: 'spinner' }), ' dialing through the matched route…'));
      let r; try { r = await api('POST', '/api/route/test', body, { silent: true }); } catch (e) { replace(result, h('div', { class: 'error-box' }, e.message)); return; }
      const chain = ['this machine', ...(r.vpn ? ['🔒 ' + r.vpn] : (r.via_full_tunnel ? ['🔒 ' + r.via_full_tunnel + ' (full tunnel)'] : [])), ...((r.hops || [])), 'exit'];
      const head = h('div', null, 'Rule ', h('strong', null, r.rule || '(none → direct)'), ' ', badge(r.action || 'direct', ACTION_CLS[r.action] || 'gray'));
      const chainEl = h('div', { class: 'hop-preview mono', style: { marginTop: '6px' } }, chain.join('  →  '));
      let res;
      if (r.blocked) res = h('div', { class: 'warn-box', style: { marginTop: '6px' } }, 'Traffic is ', badge('blocked', 'red'), ' by this rule — nothing leaves.');
      else if (r.ok) res = h('div', { class: 'ok-box', style: { marginTop: '6px' } },
        '✓ reached the internet in ', h('strong', null, fmt.ms(r.latency_ms)), '. Exit IP ', h('strong', { class: 'mono' }, r.exit_ip || '?'),
        (r.flag || r.country) ? [' ', r.flag || '', ' ', r.country || '', r.city ? ', ' + r.city : '', r.isp ? ' · ' + r.isp : ''] : null);
      else res = h('div', { class: 'error-box', style: { marginTop: '6px' } }, '✗ route failed: ', r.error || 'unknown error',
        (r.vpn ? h('div', { class: 'small', style: { marginTop: '4px' } }, 'Is VPN "' + r.vpn + '" up? Bring it up on the VPN page.') : null));
      replace(result, head, chainEl, res);
    };
    const onEnter = e => { if (e.key === 'Enter') run(); };
    [app, user, host, ip, port, exe, cmdl].forEach(i => i.addEventListener('keydown', onEnter));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Test rule'),
      h('div', { class: 'muted small', style: { marginBottom: '6px' } }, h('b', null, 'Test'), ' = which rule matches (instant). ', h('b', null, 'Live test'), ' = actually dial the host through the route and show the real exit IP & country.'),
      h('div', { class: 'form-grid', style: { gridTemplateColumns: '1fr 1fr' } },
        field('App', app), field('User', user), field('Host', host), field('IP', ip), field('Port', port), field('Protocol', proto),
        field('Exe path', exe, 'optional — for /path rules'), field('Command line', cmdl, 'optional — for cmd: rules')),
      h('div', { class: 'form-actions' }, btn('Test', run, 'primary'), btn('Live test', liveRun, '', { title: 'POST /api/route/test — dials through the resolved route' })),
      result);
  },
  help() {
    return h('div', { class: 'card help' },
      h('div', { class: 'card-title' }, 'Syntax'),
      h('ul', null,
        h('li', null, h('code', null, 'apps'), ': process name, full exe path, or ', h('code', null, 'tag:name'), '. Empty = any app.'),
        h('li', null, h('code', null, 'targets'), ': host, ', h('code', null, '*.domain'), ', IP, CIDR, or ', h('code', null, 'lan'), '. Empty = any target.'),
        h('li', null, h('code', null, 'ports'), ': ', h('code', null, '443'), ' or range ', h('code', null, '8000-8100'), '.'),
        h('li', null, 'Press Enter or comma to add a value; Backspace removes the last one.'),
        h('li', null, h('b', null, '+ New route'), ' (top right) is the easy way: pick apps/sites and an ordered list of hops (VPN, then proxy…) and it writes the proxy chain + rule for you.'),
        h('li', null, 'Actions: ', badge('direct', 'gray'), ' ', badge('proxy', 'blue'), ' ', badge('vpn', 'green'), ' ', badge('block', 'red'), ' ', badge('intercept', 'yellow'),
          '. ', h('code', null, 'intercept'), ' terminates HTTP(S) in cyberboba\'s built-in intercepting proxy (TLS is MITMed with cyberboba\'s CA), records the flows and forwards them upstream — no proxy/VPN needed. ',
          h('a', { href: '#/intercept' }, 'Open Intercept →')),
        h('li', null, this.caidoProxy ? ['Caido proxy name: ', h('code', null, this.caidoProxy)] : 'Caido (external) is disabled; enable it on the Caido page to route apps through it.')));
  },
};

/* ================================================================
 * 4d. Intercept (built-in intercepting proxy: history / queue / repeater)
 * ================================================================ */
const FLOW_MAX = 5000;
const FLOW_LIMIT = 2000;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'];
const SEV_BADGE = { high: 'red', medium: 'yellow', low: 'blue', info: 'gray' };
const FLOW_COLS = [
  { k: 'id', label: '#', w: '54px', cls: 'num' },
  { k: 'time', label: 'Time', w: '66px' },
  { k: 'app', label: 'App', w: '96px' },
  { k: 'method', label: 'Method', w: '62px' },
  { k: 'host', label: 'Host', w: '180px' },
  { k: 'path', label: 'Path', w: 'auto' },
  { k: 'status', label: 'Status', w: '54px' },
  { k: 'size', label: 'Size', w: '66px', cls: 'num' },
  { k: 'type', label: 'Type', w: '58px' },
  { k: 'dur', label: 'Time', w: '60px', cls: 'num' },
  { k: 'flags', label: 'Flags', w: '104px' },
];
const REPEATER_KEY = 'cyberboba.repeater';
const CRLF = s => String(s || '').replace(/\r?\n/g, '\r\n');
const LF = s => String(s || '').replace(/\r\n/g, '\n');

/** "text/html; charset=utf-8" → "html", "application/x-www-form-urlencoded" → "form" … */
function ctypeShort(ct) {
  if (!ct) return '';
  const main = String(ct).split(';')[0].trim().toLowerCase();
  const sub = main.includes('/') ? main.split('/')[1] : main;
  const map = { 'javascript': 'js', 'x-javascript': 'js', 'ecmascript': 'js', 'octet-stream': 'bin', 'x-www-form-urlencoded': 'form', 'plain': 'text', 'svg+xml': 'svg', 'x-protobuf': 'proto', 'grpc': 'grpc', 'event-stream': 'sse', 'x-icon': 'ico' };
  if (map[sub]) return map[sub];
  return sub.replace(/^x-/, '').replace(/^vnd\./, '').replace(/\+.*$/, '').slice(0, 10);
}
function statusCls(st) { st = num(st); return st >= 500 ? 'st-5xx' : st >= 400 ? 'st-4xx' : st >= 300 ? 'st-3xx' : st >= 200 ? 'st-2xx' : st > 0 ? 'st-1xx' : ''; }
function flowStateBadge(f) {
  const m = { pending_request: ['held request', 'yellow'], pending_response: ['held response', 'yellow'], sent: ['sent', 'blue'], done: ['done', 'green'], error: ['error', 'red'], dropped: ['dropped', 'gray'] };
  const [t, c] = m[f.state] || [f.state || '', 'gray'];
  return badge(t, c);
}
function b64Bytes(s) { s = String(s || ''); return Math.floor((s.length * 3) / 4) - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0); }
function flowShort(f) { return (f.method || '') + ' ' + (f.url || ((f.tls ? 'https://' : 'http://') + (f.host || '') + (f.path || ''))); }

/** read-only raw text block with copy / select-all. */
function rawBlock(text, label) {
  const ta = h('textarea', { class: 'code raw', readOnly: true, spellcheck: 'false', wrap: 'off', 'aria-label': label });
  const size = h('span', { class: 'muted small mono' });
  const el = h('div', { class: 'raw-block' },
    h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, label), size, h('span', { class: 'spacer' }),
      btn('Select all', () => { ta.focus(); ta.select(); }, 'tiny'),
      btn('Copy', () => copyText(ta.value, label + ' copied'), 'tiny', { title: 'copy raw text to clipboard' })),
    ta);
  el.set = t => { ta.value = t || ''; size.textContent = fmt.bytes((t || '').length); };
  el.set(text);
  el.ta = ta;
  return el;
}
function headersTable(headers) {
  const list = Array.isArray(headers) ? headers : [];
  if (!list.length) return h('div', { class: 'muted small' }, '(no headers)');
  return h('table', { class: 'grid hdrs' },
    h('colgroup', null, h('col', { style: { width: '32%' } }), h('col')),
    h('tbody', null, ...list.map(p => h('tr', null, h('td', { class: 'mono hdr-name' }, p[0]), h('td', { class: 'mono' }, p[1])))));
}
/** body view: JSON pretty-printed, text as-is, base64 shown as <binary> with a data-URL download. */
function bodyView(body, b64, ctype, truncated, filename) {
  if (!body) return h('div', { class: 'muted small' }, '(no body)');
  const trunc = truncated ? h('div', { class: 'warn-box small' }, 'body truncated by the daemon (max_body) — the full payload was forwarded but not recorded') : null;
  if (b64) {
    const mime = (ctype || 'application/octet-stream').split(';')[0].trim() || 'application/octet-stream';
    return h('div', { class: 'body-bin' }, trunc,
      h('span', { class: 'mono' }, '<binary ' + fmt.bytes(b64Bytes(body)) + '>'), ' ',
      h('a', { href: 'data:' + mime + ';base64,' + body, download: filename }, 'download'));
  }
  let text = body, isJson = false;
  if (/json/i.test(ctype || '') || /^\s*[[{]/.test(body)) {
    try { text = JSON.stringify(JSON.parse(body), null, 2); isJson = true; } catch (_) { /* not JSON */ }
  }
  const pre = h('pre', { class: 'body-pre' }, text);
  return h('div', { class: 'body-view' }, trunc,
    h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, isJson ? 'JSON (pretty-printed)' : (ctypeShort(ctype) || 'text') + ' · ' + fmt.bytes(body.length)),
      h('span', { class: 'spacer' }), btn('Copy', () => copyText(text, 'Body copied'), 'tiny')),
    pre);
}
function loadRepeater() {
  let s = null;
  try { s = JSON.parse(localStorage.getItem(REPEATER_KEY) || 'null'); } catch (_) { s = null; }
  if (!s || !Array.isArray(s.tabs)) s = { tabs: [], active: 0 };
  s.tabs = s.tabs.filter(t => t && typeof t === 'object').map((t, i) => Object.assign({ id: i + 1, name: 'tab ' + (i + 1), host: '', port: 443, tls: true, raw: '', follow: false, timeout: 30 }, t));
  s.active = Math.min(Math.max(0, num(s.active)), Math.max(0, s.tabs.length - 1));
  return s;
}

Pages.intercept = {
  title: 'Intercept',
  async mount(root) {
    this.root = root;
    this.rows = new Map(); this.total = 0; this.selectedId = null; this.detailFlow = null;
    this.pending = new Map(); this.pendingSel = null;
    this.filter = { q: '', body: '', method: '', status: '', scope: false, ids: '' };
    this.repeater = loadRepeater();
    this.detailTab = sessionStorage.getItem('cyberboba.icDetailTab') || 'request';
    this.detailMode = sessionStorage.getItem('cyberboba.icDetailMode') || 'pretty';
    let st = null;
    try { st = await api('GET', '/api/intercept'); } catch (_) { /* toolbar renders in a degraded state */ }
    if (!root.isConnected) return;
    this.status = st || state.intercept || {};
    state.intercept = this.status;

    root.append(this.toolbar());
    this.tabBar = h('div', { class: 'tabs ic-tabs' });
    this.panels = { history: this.historyPanel(), queue: this.queuePanel(), repeater: this.repeaterPanel(), rewrites: this.rewritesPanel() };
    this.queueBadge = h('span', { class: 'badge yellow', hidden: true });
    for (const [id, label] of [['history', 'History'], ['queue', 'Intercept'], ['repeater', 'Repeater'], ['rewrites', 'Rewrites']]) {
      this.tabBar.append(h('button', { type: 'button', dataset: { tab: id }, onClick: () => this.showTab(id) }, label, id === 'queue' ? [' ', this.queueBadge] : null));
    }
    const body = h('div', { class: 'ic-body' }, this.panels.history, this.panels.queue, this.panels.repeater, this.panels.rewrites);
    root.append(this.tabBar, body);
    this.showTab(Router.sub() || sessionStorage.getItem('cyberboba.interceptTab') || 'history', true);
    this.syncToolbar();
    await Promise.all([this.reload(), this.reloadPending()]);
  },
  unmount() {
    clearTimeout(this.detailTimer);
    this.root = null; this.rows = null; this.tbody = null; this.detail = null; this.pending = null; this.queueList = null;
  },
  onHash(sub) { if (sub && this.panels && this.panels[sub]) this.showTab(sub); },
  showTab(id, silent) {
    if (!this.panels[id]) id = 'history';
    this.tab = id;
    sessionStorage.setItem('cyberboba.interceptTab', id);
    $$('button', this.tabBar).forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    for (const k of Object.keys(this.panels)) this.panels[k].hidden = k !== id;
    const want = '#/intercept' + (id === 'history' ? '' : '/' + id);
    if (!silent && location.hash !== want && location.hash !== '#/intercept/history') history.replaceState(null, '', want);
    if (id === 'history' && this.tableWrap) this.tableWrap.focus({ preventScroll: true });
    if (id === 'repeater') this.renderRepeater();
    if (id === 'rewrites') this.loadRewrites();
  },
  focusFilter() { this.showTab('history'); if (this.filterIn) { this.filterIn.focus(); this.filterIn.select(); } },

  /* ---------- toolbar ---------- */
  toolbar() {
    const tog = (label, key, title) => {
      const b = h('button', { type: 'button', class: 'btn toggle', title, 'aria-pressed': 'false', onClick: () => this.toggle(key, b.getAttribute('aria-pressed') !== 'true') },
        h('span', { class: 'tg-dot' }), label);
      b._key = key;
      return b;
    };
    this.togs = [tog('Recording', 'recording', 'record flows (POST /api/intercept/toggle)'),
      tog('Passive scan', 'scan', 'flag secrets, insecure cookies, missing security headers and more on recorded flows'),
      tog('Hold requests', 'hold_requests', 'queue every request for review before it is sent upstream'),
      tog('Hold responses', 'hold_responses', 'queue every response for review before it is returned to the app')];
    this.counters = h('span', { class: 'mono muted small nowrap' });
    this.stateBadge = badge('', 'gray');
    this.caLink = dlLink('CA cert', '/api/intercept/ca', 'cyberboba-ca.crt', { title: 'download the cyberboba CA certificate (PEM)' });
    return h('div', { class: 'page-head ic-toolbar' },
      h('h2', null, 'Intercept'), this.stateBadge,
      h('span', { class: 'ic-toggles' }, ...this.togs),
      this.counters,
      h('span', { class: 'spacer' }),
      btn('Clear', () => this.clearFlows(), 'danger', { title: 'DELETE /api/intercept/flows — remove all recorded flows' }),
      dlLink('Export HAR', () => '/api/intercept/export?format=har' + this.query(false).replace(/^\?/, '&'), 'cyberboba-flows.har', { title: 'download all flows matching the current filter as HAR' }),
      this.caLink,
      btn('Install CA', () => this.installCA(), '', { title: 'POST /api/intercept/ca/install — trust the CA in the system store and browser NSS dbs' }),
      btn('Record app…', () => this.recordDialog(), '', { title: 'capture only specific programs (e.g. just Chromium or just Claude)' }),
      this.findingsBtn = btn('Findings', () => this.findingsDialog(), '', { title: 'passive security scan results across all recorded flows' }),
      btn('Sessions…', () => this.sessionsDialog(), '', { title: 'save / load captured flow sessions' }),
      btn('Settings…', () => this.settingsDialog(), '', { title: 'PUT /api/intercept' }));
  },
  syncToolbar() {
    const s = this.status || {};
    for (const b of this.togs) { const on = !!s[b._key]; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); }
    const pc = pendingCount();
    const flows = this.total || num(s.flows);
    this.counters.textContent = fmt.num(flows) + ' flows · ' + pc + ' pending';
    this.counters.title = 'listen ' + (s.listen || '?') + (s.enabled ? '' : ' (disabled)');
    const sb = interceptStateBadge(s); this.stateBadge.replaceWith(sb); this.stateBadge = sb;
    this.stateBadge.title = s.enabled ? 'listening on ' + (s.listen || '') : 'the interceptor is disabled — enable it in Settings…';
    if (this.caLink) this.caLink.title = 'download the cyberboba CA certificate (PEM)' + (s.ca_fingerprint ? '\n' + s.ca_fingerprint : '') + (s.ca_installed ? '\ninstalled in the system trust store' : '\nnot yet installed');
    if (this.queueBadge) { this.queueBadge.hidden = pc <= 0; this.queueBadge.textContent = String(pc); }
    if (this.holdHint) this.holdHint.hidden = !!(s.hold_requests || s.hold_responses);
  },
  applyStatus(s) {
    if (!s) return;
    this.status = Object.assign({}, this.status, s);
    state.intercept = this.status;
    if (state.status) state.status.intercept = Object.assign({}, state.status.intercept, { enabled: s.enabled, listen: s.listen, recording: s.recording, hold_requests: s.hold_requests, hold_responses: s.hold_responses, flows: s.flows, pending: s.pending });
    if (s.flows !== undefined) this.total = num(s.flows);
    this.syncToolbar(); updateHeader();
  },
  async toggle(key, on) {
    let r; try { r = await api('POST', '/api/intercept/toggle', { [key]: on }); } catch (_) { return; }
    this.applyStatus(r);
    toast(key.replace('_', ' ') + (on ? ' on' : ' off'), 'ok', 1500);
  },
  async clearFlows() {
    if (!confirm('Clear all ' + fmt.num(this.total || this.rows.size) + ' recorded flows from History? This only wipes what is shown here — tip: use Sessions to save them first if you might need them.')) return;
    try { await api('DELETE', '/api/intercept/flows'); } catch (_) { return; }
    clear(this.tbody); this.rows.clear(); this.total = 0; this.closeDetail(); this.updateCount(); this.syncToolbar();
    toast('Flow history cleared', 'ok');
  },
  async installCA() {
    const out = h('div', null, h('span', { class: 'muted' }, h('span', { class: 'spinner' }), ' installing CA…'));
    const m = openModal({ title: 'Install cyberboba CA', width: '620px', body: out, buttons: [{ label: 'Close' }] });
    let r;
    try { r = await api('POST', '/api/intercept/ca/install', {}, { silent: true }); }
    catch (e) { replace(out, h('div', { class: 'error-box' }, e.message)); return; }
    replace(out, h('div', { class: r.ok ? 'ok-box' : 'warn-box' },
      h('div', null, r.ok ? 'CA installed into:' : 'CA installation finished with errors'),
      r.installed_into && r.installed_into.length ? h('ul', { class: 'mono', style: { margin: '4px 0', paddingLeft: '18px' } }, ...r.installed_into.map(p => h('li', null, p))) : h('div', { class: 'muted small' }, '(nothing installed)'),
      r.errors && r.errors.length ? h('ul', { class: 'mono bad', style: { margin: '4px 0', paddingLeft: '18px' } }, ...r.errors.map(e => h('li', null, e))) : null,
      h('div', { class: 'muted small' }, 'Restart browsers for the new CA to take effect. Apps with certificate pinning should be added to the passthrough list.')));
    if (r.ok) { this.status.ca_installed = true; this.syncToolbar(); }
    return m;
  },
  interceptConfig() {
    const s = this.status || {};
    const c = Object.assign({ enabled: !!s.enabled, listen: s.listen || '127.0.0.1:8080', hold_requests: !!s.hold_requests, hold_responses: !!s.hold_responses,
      record_only_scope: false, scope: s.scope, passthrough: s.passthrough, upstream: s.upstream, verify_upstream_tls: !!s.verify_upstream_tls,
      max_flows: num(s.max_flows, 10000), max_body: num(s.max_body, 1048576) }, s.config || {});
    c.scope = Object.assign({ include: [], exclude: [] }, c.scope || {});
    c.scope.include = (c.scope.include || []).slice(); c.scope.exclude = (c.scope.exclude || []).slice();
    c.passthrough = (c.passthrough || []).slice();
    c.upstream = Object.assign({ action: 'direct', proxy: '', vpn: '' }, c.upstream || {});
    return c;
  },
  async settingsDialog() {
    const [pr, vp] = await Promise.all([
      api('GET', '/api/proxies', undefined, { silent: true }).catch(() => ({ proxies: [] })),
      api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
    ]);
    const proxyNames = (pr.proxies || []).map(p => p.name).filter(Boolean);
    const vpnNames = (vp.vpns || []).map(v => v.name).filter(Boolean);
    const c = this.interceptConfig();
    const enabled = checkbox('Enabled (start the intercepting proxy listener)', c.enabled); bind(enabled.input, c, 'enabled');
    const listen = bind(textInput(c.listen, { class: 'mono', placeholder: '127.0.0.1:8080' }), c, 'listen', null, s => s.trim());
    const holdReq = checkbox('Hold requests at start', c.hold_requests); bind(holdReq.input, c, 'hold_requests');
    const holdResp = checkbox('Hold responses at start', c.hold_responses); bind(holdResp.input, c, 'hold_responses');
    const onlyScope = checkbox('Record only in-scope flows (record_only_scope)', c.record_only_scope); bind(onlyScope.input, c, 'record_only_scope');
    const verify = checkbox('Verify upstream TLS certificates', c.verify_upstream_tls); bind(verify.input, c, 'verify_upstream_tls');
    const inc = tagsInput({ values: c.scope.include, placeholder: '*.example.com, api.foo', onChange: v => { c.scope.include = v; } });
    const exc = tagsInput({ values: c.scope.exclude, placeholder: '*.google.com', onChange: v => { c.scope.exclude = v; } });
    const pass = tagsInput({ values: c.passthrough, placeholder: '*.bank.com (no MITM, tunnelled as-is)', onChange: v => { c.passthrough = v; } });
    const upAction = bind(sel(['direct', 'proxy', 'vpn'], c.upstream.action || 'direct'), c.upstream, 'action', () => syncUp());
    const upProxy = bind(sel([{ value: '', label: '(choose proxy)' }, ...proxyNames], c.upstream.proxy || '', { class: 'mono' }), c.upstream, 'proxy');
    const upVpn = bind(sel([{ value: '', label: '(choose vpn)' }, ...vpnNames], c.upstream.vpn || '', { class: 'mono' }), c.upstream, 'vpn');
    const upProxyF = field('Upstream proxy', upProxy), upVpnF = field('Upstream VPN', upVpn);
    const syncUp = () => { upProxyF.hidden = upAction.value !== 'proxy'; upVpnF.hidden = upAction.value !== 'vpn'; };
    syncUp();
    const maxFlows = bind(h('input', { type: 'number', min: 100, step: 100, class: 'mono', value: c.max_flows }), c, 'max_flows');
    const maxBody = bind(h('input', { type: 'number', min: 0, step: 1024, class: 'mono', value: c.max_body }), c, 'max_body');
    const s = this.status || {};
    const caRow = h('div', { class: 'kv' },
      kv('CA certificate', s.ca_cert), kv('fingerprint', s.ca_fingerprint),
      kv('installed', s.ca_installed ? h('span', { class: 'ok' }, 'yes') : h('span', { class: 'warn' }, 'no — use "Install CA"')));
    const regen = btn('Regenerate CA', async () => {
      if (!confirm('Generate a new CA? All previously issued leaf certificates become invalid and the new CA must be installed again.')) return;
      regen.disabled = true;
      try { const r = await api('POST', '/api/intercept/ca/regenerate'); this.applyStatus(r); toast('New CA generated — install it again', 'warn', 6000); }
      catch (_) { /* shown */ }
      finally { regen.disabled = false; }
      close();
    }, 'danger tiny');
    let close = () => {};
    const m = openModal({ title: 'Intercept settings', width: '680px',
      body: h('div', { class: 'tab-panel' },
        enabled,
        h('div', { class: 'form-grid' }, field('Listen address', listen, 'explicit HTTP proxy listener; transparent traffic arrives via rules with action "intercept"'),
          field('Upstream', upAction, 'where intercepted traffic is forwarded'), upProxyF, upVpnF),
        h('div', { class: 'form-grid' }, holdReq, holdResp, onlyScope, verify),
        h('div', { class: 'form-grid' },
          field('Scope include', inc, 'host patterns; empty = everything is in scope'), field('Scope exclude', exc),
          field('Passthrough', pass, 'hosts never MITMed (e.g. certificate-pinned apps)', 'wide'),
          field('Max flows kept', maxFlows), field('Max recorded body (bytes)', maxBody)),
        h('h4', null, 'Certificate authority'), caRow, h('div', null, regen),
        h('div', { class: 'muted small' }, 'Runtime toggles in the toolbar are not persisted; these settings are saved to the configuration file.')),
      buttons: [{ label: 'Cancel' }, { label: 'Save', cls: 'primary', onClick: async cl => {
        c.max_flows = num(c.max_flows); c.max_body = num(c.max_body);
        c.scope.include = inc.getValues(); c.scope.exclude = exc.getValues(); c.passthrough = pass.getValues();
        if (c.upstream.action !== 'proxy') c.upstream.proxy = '';
        if (c.upstream.action !== 'vpn') c.upstream.vpn = '';
        if (c.upstream.action === 'proxy' && !c.upstream.proxy) { toast('Choose an upstream proxy', 'error'); return; }
        if (c.upstream.action === 'vpn' && !c.upstream.vpn) { toast('Choose an upstream VPN', 'error'); return; }
        let r; try { r = await api('PUT', '/api/intercept', c); } catch (_) { return; }
        this.applyStatus(r);
        toast('Intercept settings saved', 'ok');
        cl();
      } }] });
    close = m.close;
  },

  /* ---------- history ---------- */
  historyPanel() {
    const refetch = debounce(() => this.reload(), 250);
    this.filterIn = h('input', { type: 'search', class: 'filter mono', placeholder: 'filter host / path / app / url…  ( / )', spellcheck: 'false',
      onInput: () => { this.filter.q = this.filterIn.value.trim(); this.filter.ids = ''; refetch(); },
      onKeydown: e => { if (e.key === 'Escape') { this.filterIn.value = ''; this.filter.q = ''; this.filter.ids = ''; refetch(); } } });
    this.bodyIn = h('input', { type: 'search', class: 'filter mono', placeholder: 'search bodies…', title: 'case-insensitive substring match on request/response bodies (body= query param)', spellcheck: 'false',
      onInput: () => { this.filter.body = this.bodyIn.value.trim(); refetch(); },
      onKeydown: e => { if (e.key === 'Escape') { this.bodyIn.value = ''; this.filter.body = ''; refetch(); } } });
    const method = sel([{ value: '', label: 'any method' }, ...METHODS], '', { title: 'method' });
    method.addEventListener('change', () => { this.filter.method = method.value; refetch(); });
    const status = h('input', { type: 'text', class: 'mono', placeholder: 'status', title: 'status code or prefix, e.g. 2, 30, 404', style: { width: '64px' }, spellcheck: 'false',
      onInput: () => { this.filter.status = status.value.trim(); refetch(); } });
    const scope = checkbox('in scope only', false);
    scope.input.addEventListener('change', () => { this.filter.scope = scope.input.checked; refetch(); });
    this.countEl = h('span', { class: 'muted small mono nowrap' });

    this.tbody = h('tbody');
    const table = h('table', { class: 'grid flows' },
      h('colgroup', null, ...FLOW_COLS.map(c => h('col', { class: 'c-' + c.k, style: c.w === 'auto' ? null : { width: c.w } }))),
      h('thead', null, h('tr', null, ...FLOW_COLS.map(c => h('th', { class: 'c-' + c.k + ' ' + (c.cls || '') }, c.label)))),
      this.tbody);
    this.histEmpty = h('div', { class: 'hist-empty', hidden: true },
      h('div', { class: 'hist-empty-title' }, 'No intercepted traffic yet'),
      h('div', { class: 'hist-empty-body muted small' },
        'cyberboba only captures traffic that is ', h('b', null, 'routed to the intercepting proxy'), ' — it does not sniff everything automatically. To see an app’s HTTPS here:'),
      h('ol', { class: 'hist-empty-steps small' },
        h('li', null, 'Trust cyberboba’s CA so TLS can be decrypted — ', h('a', { href: '#', onclick: e => { e.preventDefault(); this.installCA(); } }, 'Install CA'), '.'),
        h('li', null, 'Pick what to capture: ', h('a', { href: '#', onclick: e => { e.preventDefault(); this.recordDialog(); } }, 'Record an app →'), ' (just Chromium, just Claude, …), add an ', h('span', { class: 'badge yellow' }, 'intercept'), ' rule in ', h('a', { href: '#/rules' }, 'Rules'), ', or point an app’s proxy at ', h('code', null, '127.0.0.1:8080'), '.'),
        h('li', null, 'Make sure ', h('b', null, 'Recording'), ' is on (toolbar, top-left).')),
      h('div', { class: 'hist-empty-actions' },
        btn('Record an app…', () => this.recordDialog(), 'primary'),
        btn('Open Rules', () => { location.hash = '#/rules'; }, ''),
        btn('Install CA', () => this.installCA(), '')));
    this.tableWrap = h('div', { class: 'table-wrap', tabindex: 0, 'aria-label': 'flow list (↑/↓ or j/k to move, Enter to open, Delete to remove, Esc to close detail)' }, table, this.histEmpty);
    this.tbody.addEventListener('click', e => { const tr = e.target.closest('tr[data-id]'); if (tr) this.select(num(tr.dataset.id)); });
    this.tableWrap.addEventListener('keydown', e => {
      if (e.target !== this.tableWrap) return;
      if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); this.moveSel(1); }
      else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); this.moveSel(-1); }
      else if (e.key === 'Enter' && this.selectedId !== null) { e.preventDefault(); this.select(this.selectedId); }
      else if (e.key === 'Escape') { this.closeDetail(); }
      else if (e.key === 'Delete' && this.selectedId !== null) { e.preventDefault(); this.deleteFlow(this.selectedId); }
      else if (e.key === 'r' && this.detailFlow) { e.preventDefault(); this.sendToRepeater(this.detailFlow); }
    });

    this.detail = h('div', { class: 'detail', hidden: true });
    const w = num(localStorage.getItem('cyberboba.icDetailW'), 0);
    if (w) this.detail.style.width = w + 'px';
    const splitter = h('div', { class: 'splitter', hidden: true, title: 'drag to resize' });
    splitter.addEventListener('mousedown', e => {
      e.preventDefault();
      const startX = e.clientX, startW = this.detail.getBoundingClientRect().width;
      const move = ev => { const nw = Math.max(320, Math.min(window.innerWidth * 0.8, startW + (startX - ev.clientX))); this.detail.style.width = nw + 'px'; };
      const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); localStorage.setItem('cyberboba.icDetailW', String(Math.round(this.detail.getBoundingClientRect().width))); };
      document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
    });
    this.splitter = splitter;

    return h('div', { class: 'ic-panel' },
      h('div', { class: 'hist-filters' }, this.filterIn, this.bodyIn, method, status, scope, this.countEl, h('span', { class: 'spacer' }), btn('Reload', () => this.reload(), 'tiny')),
      h('div', { class: 'hist-split' }, this.tableWrap, splitter, this.detail));
  },
  query(withLimit = true) {
    const p = new URLSearchParams();
    if (withLimit) p.set('limit', String(FLOW_LIMIT));
    const f = this.filter;
    if (f.q) p.set('q', f.q);
    if (f.body) p.set('body', f.body);
    if (f.method) p.set('method', f.method);
    if (f.status) p.set('status', f.status);
    if (f.scope) p.set('scope', '1');
    if (f.ids) p.set('ids', f.ids);
    const s = p.toString();
    return s ? '?' + s : '';
  },
  async reload() {
    let r; try { r = await api('GET', '/api/intercept/flows' + this.query()); } catch (_) { return; }
    if (!this.tbody) return;
    clear(this.tbody); this.rows.clear();
    const list = (r.flows || []).slice().sort((a, b) => num(a.id) - num(b.id)); // ascending; each insert goes on top
    for (const f of list) this.upsert(f, true);
    this.total = num(r.total, list.length);
    this.updateCount(); this.syncToolbar();
    if (this.selectedId !== null && !this.rows.has(this.selectedId)) this.closeDetail();
  },
  matches(f) {
    const q = this.filter.q.toLowerCase();
    if (q && ![f.host, f.path, f.url, f.app, f.method].some(v => v && String(v).toLowerCase().includes(q))) return false;
    if (this.filter.method && String(f.method || '').toUpperCase() !== this.filter.method) return false;
    if (this.filter.status && !(f.status && String(f.status).startsWith(this.filter.status))) return false;
    if (this.filter.scope && !f.in_scope) return false;
    return true;
  },
  upsert(f, force) {
    if (!this.tbody || !f || typeof f !== 'object' || f.id === undefined) return;
    const tr = this.rows.get(f.id);
    if (tr) { this.fillRow(tr, f); return; }
    if (!force && !this.matches(f)) return;
    const row = this.makeRow(f);
    this.rows.set(f.id, row);
    // keep descending id order: new flows normally go on top
    let ref = this.tbody.firstChild;
    while (ref && num(ref.dataset.id) > num(f.id)) ref = ref.nextSibling;
    this.tbody.insertBefore(row, ref);
    while (this.rows.size > FLOW_MAX) { const last = this.tbody.lastElementChild; if (!last) break; this.rows.delete(num(last.dataset.id)); last.remove(); }
  },
  makeRow(f) {
    const x = {};
    const tr = h('tr', { class: 'clickable', dataset: { id: f.id } });
    x.id = h('td', { class: 'num mono c-id' }); x.time = h('td', { class: 'mono c-time' }); x.app = h('td', { class: 'c-app' }); x.method = h('td', { class: 'mono c-method' });
    x.host = h('td', { class: 'mono c-host' }); x.path = h('td', { class: 'mono c-path' }); x.status = h('td', { class: 'mono c-status' }); x.size = h('td', { class: 'num mono c-size' });
    x.type = h('td', { class: 'mono c-type' }); x.dur = h('td', { class: 'num mono c-dur' }); x.flags = h('td', { class: 'flags c-flags' });
    tr.append(x.id, x.time, x.app, x.method, x.host, x.path, x.status, x.size, x.type, x.dur, x.flags);
    tr._c = x;
    this.fillRow(tr, f);
    return tr;
  },
  fillRow(tr, f) {
    const x = tr._c;
    tr._flow = f;
    x.id.textContent = String(f.id);
    x.time.textContent = fmt.time(f.time); x.time.title = fmt.datetime(f.time);
    x.app.textContent = f.app || (f.source === 'repeater' ? 'repeater' : f.source === 'proxy' ? 'proxy' : f.pid ? 'pid ' + f.pid : '');
    x.app.title = (f.source || '') + (f.pid ? ' pid ' + f.pid : '');
    x.method.textContent = f.method || (f.websocket ? 'WS' : '');
    x.host.textContent = (f.host || '') + (f.port && f.port !== (f.tls ? 443 : 80) ? ':' + f.port : '');
    x.host.title = x.host.textContent;
    x.path.textContent = f.path || '/'; x.path.title = f.url || f.path || '';
    if (f.status) { x.status.textContent = String(f.status); x.status.className = 'mono c-status ' + statusCls(f.status); x.status.title = f.status_text || ''; }
    else {
      const m = { pending_request: ['held', 'warn'], pending_response: ['held', 'warn'], error: ['ERR', 'bad'], dropped: ['drop', 'muted'], sent: ['…', 'muted'] };
      const [t, c] = m[f.state] || ['', 'muted'];
      x.status.textContent = t; x.status.className = 'mono c-status ' + c; x.status.title = f.error || f.state || '';
    }
    x.size.textContent = f.status ? fmt.bytes(f.resp_size) : (f.req_size ? fmt.bytes(f.req_size) : '');
    x.size.title = 'request ' + fmt.bytes(f.req_size) + ' / response ' + fmt.bytes(f.resp_size);
    x.type.textContent = ctypeShort(f.content_type); x.type.title = f.content_type || '';
    x.dur.textContent = f.duration_ms ? fmt.ms(f.duration_ms) : '';
    const topSev = f.findings && f.findings.length ? ['high', 'medium', 'low', 'info'].find(s => f.findings.some(fd => fd.severity === s)) : null;
    replace(x.flags,
      topSev ? h('span', { class: 'flag finding sev-' + topSev, title: f.findings.length + ' passive-scan finding' + (f.findings.length > 1 ? 's' : '') + ' (' + topSev + ')' }, '⚠ ' + f.findings.length) : null,
      f.tls ? h('span', { class: 'flag tls', title: 'TLS (MITM)' }, 'tls') : null,
      f.in_scope ? h('span', { class: 'flag scope', title: 'in scope' }, '●') : null,
      f.intercepted ? h('span', { class: 'flag held', title: 'was held in the intercept queue' }, 'held') : null,
      f.edited ? h('span', { class: 'flag edit', title: 'edited before forwarding' }, 'edit') : null,
      f.rewritten ? h('span', { class: 'flag rewritten', title: 'modified by a match & replace rewrite rule' }, 'R') : null,
      f.websocket ? h('span', { class: 'flag ws', title: 'websocket' }, 'ws') : null);
    tr.className = 'clickable st-' + (f.state || 'done') + (f.id === this.selectedId ? ' selected' : '');
  },
  updateCount() {
    if (!this.countEl) return;
    this.countEl.textContent = fmt.num(this.rows.size) + ' loaded / ' + fmt.num(Math.max(this.total, this.rows.size)) + ' total';
    if (this.histEmpty) this.histEmpty.hidden = this.rows.size > 0;
  },
  moveSel(dir) {
    const trs = $$('tr[data-id]', this.tbody);
    if (!trs.length) return;
    let i = trs.findIndex(t => num(t.dataset.id) === this.selectedId);
    i = i < 0 ? 0 : Math.max(0, Math.min(trs.length - 1, i + dir));
    this.select(num(trs[i].dataset.id));
    trs[i].scrollIntoView({ block: 'nearest' });
  },
  async select(id) {
    this.selectedId = id;
    $$('tr[data-id]', this.tbody).forEach(tr => tr.classList.toggle('selected', num(tr.dataset.id) === id));
    this.detail.hidden = false; this.splitter.hidden = false;
    this.detail.parentElement.classList.add('detail-open');
    await this.loadDetail(id);
  },
  async loadDetail(id) {
    let f;
    try { f = await api('GET', '/api/intercept/flows/' + id + '?max_body=200000', undefined, { silent: true }); }
    catch (e) { if (this.detail) replace(this.detail, h('div', { class: 'detail-head' }, h('span', { class: 'detail-title' }, '#' + id), h('span', { class: 'spacer' }), btn('×', () => this.closeDetail(), 'icon tiny')), h('div', { class: 'error-box', style: { margin: '8px' } }, e.message)); return; }
    if (!this.detail || this.selectedId !== id) return;
    this.detailFlow = f;
    this.renderDetail(f);
  },
  closeDetail() {
    this.selectedId = null; this.detailFlow = null;
    if (this.detail) { this.detail.hidden = true; this.splitter.hidden = true; clear(this.detail); this.detail.parentElement.classList.remove('detail-open'); }
    $$('tr.selected', this.tbody).forEach(tr => tr.classList.remove('selected'));
  },
  findingsBlock(list) {
    const wrap = h('div', { class: 'flow-findings' });
    for (const fd of list) {
      wrap.append(h('div', { class: 'finding sev-' + fd.severity },
        badge(fd.severity, SEV_BADGE[fd.severity] || 'gray'),
        h('span', { class: 'finding-title' }, fd.title),
        fd.where ? h('span', { class: 'finding-where muted small mono' }, fd.where) : null,
        fd.detail ? h('div', { class: 'finding-detail muted small' }, fd.detail) : null));
    }
    return wrap;
  },
  async findingsDialog() {
    const box = h('div', null, h('div', { class: 'muted small' }, h('span', { class: 'spinner' }), ' scanning…'));
    openModal({ title: 'Passive scan findings', width: '660px', body: box, buttons: [{ label: 'Close' }] });
    let r; try { r = await api('GET', '/api/intercept/findings', undefined, { silent: true }); }
    catch (e) { replace(box, h('div', { class: 'error-box' }, e.message)); return; }
    const groups = r.groups || [], sev = r.severity || {};
    clear(box);
    box.append(h('div', { class: 'find-summary' },
      h('span', { class: 'muted small' }, 'scanned ' + fmt.num(r.scanned_flows || 0) + ' flows'),
      h('span', { class: 'spacer' }),
      ...['high', 'medium', 'low', 'info'].map(s => sev[s] ? h('span', { class: 'find-sevcount' }, badge(s, SEV_BADGE[s]), ' ' + sev[s]) : null)));
    if (!groups.length) {
      box.append(emptyState('Nothing flagged', 'No passive-scan findings in the recorded flows. Keep the Passive scan toggle on and browse through the interceptor to surface issues.', { cls: 'flat' }));
      return;
    }
    for (const g of groups) {
      box.append(h('div', { class: 'find-group sev-' + g.severity },
        h('div', { class: 'find-group-head' },
          badge(g.severity, SEV_BADGE[g.severity] || 'gray'),
          h('span', { class: 'finding-title' }, g.title),
          h('span', { class: 'muted small' }, '×' + g.count),
          h('span', { class: 'spacer' }),
          btn('Show flows', () => { this.filterByIds(g.flows); const m = document.querySelector('.modal-close,[aria-label="Close"]'); if (m) m.click(); }, 'tiny', { title: 'filter History to the affected flows' })),
        g.sample ? h('div', { class: 'finding-detail muted small' }, g.sample) : null,
        h('div', { class: 'find-rule mono muted small' }, g.rule)));
    }
  },
  filterByIds(ids) {
    if (!ids || !ids.length) return;
    this.showTab('history');
    this.filter = this.filter || {};
    this.filter.ids = ids.join(',');
    if (this.filterIn) this.filterIn.value = '';
    this.reload();
    toast('Showing ' + ids.length + ' flagged flow' + (ids.length > 1 ? 's' : ''), 'ok', 2500);
  },
  renderDetail(f) {
    const d = clear(this.detail);
    const modeBtn = (label, key, val) => {
      const b = btn(label, () => { this[key] = val; sessionStorage.setItem(key === 'detailTab' ? 'cyberboba.icDetailTab' : 'cyberboba.icDetailMode', val); this.renderDetail(f); }, 'tiny' + (this[key] === val ? ' primary' : ''));
      return b;
    };
    d.append(
      h('div', { class: 'detail-head' },
        h('span', { class: 'detail-title', title: flowShort(f) }, h('b', null, '#' + f.id), ' ', h('span', { class: 'mono' }, flowShort(f))),
        flowStateBadge(f),
        btn('×', () => this.closeDetail(), 'icon tiny', { title: 'close (Esc)' })),
      h('div', { class: 'detail-meta small muted mono' },
        [f.app ? f.app + (f.pid ? '[' + f.pid + ']' : '') : f.source, fmt.datetime(f.time), f.duration_ms ? fmt.ms(f.duration_ms) : null,
          'req ' + fmt.bytes(f.req_size), f.status ? 'resp ' + fmt.bytes(f.resp_size) : null, f.proto, f.tls ? 'tls' : 'plain', f.in_scope ? 'in-scope' : 'out-of-scope'].filter(Boolean).join(' · '),
        f.error ? h('div', { class: 'bad' }, f.error) : null),
      h('div', { class: 'detail-actions' },
        btn('Send to Repeater', () => this.sendToRepeater(f), '', { title: 'open the request in a new Repeater tab (r)' }),
        btn('Copy as curl', () => this.copyCurl(f.id), '', { title: 'GET /api/intercept/flows/{id}/export?format=curl' }),
        dlLink('Raw ↓', '/api/intercept/flows/' + f.id + '/export?format=raw', 'flow-' + f.id + '.txt', { class: 'btn', title: 'download request+response raw' }),
        dlLink('HAR ↓', '/api/intercept/flows/' + f.id + '/export?format=har', 'flow-' + f.id + '.har', { class: 'btn', title: 'download this flow as HAR' }),
        h('span', { class: 'spacer' }),
        btn('Delete', () => this.deleteFlow(f.id), 'danger', { title: 'DELETE /api/intercept/flows/{id}' })),
      h('div', { class: 'detail-tabs' },
        h('span', { class: 'btn-group' }, modeBtn('Request', 'detailTab', 'request'), modeBtn('Response', 'detailTab', 'response')),
        h('span', { class: 'spacer' }),
        h('span', { class: 'btn-group' }, modeBtn('Pretty', 'detailMode', 'pretty'), modeBtn('Raw', 'detailMode', 'raw'))));
    if (f.findings && f.findings.length) d.append(this.findingsBlock(f.findings));
    const body = h('div', { class: 'detail-body' });
    const isReq = this.detailTab === 'request';
    if (!isReq && !f.status && !f.resp_raw) {
      body.append(h('div', { class: 'info-box' }, f.state === 'pending_request' ? 'Request is held in the intercept queue; no response yet.' : f.state === 'error' ? 'No response: ' + (f.error || 'error') : f.state === 'dropped' ? 'Request was dropped.' : 'No response recorded yet.'));
    } else if (this.detailMode === 'raw') {
      body.append(rawBlock(isReq ? f.req_raw : f.resp_raw, isReq ? 'request' : 'response'));
    } else {
      const firstLine = isReq ? (f.method || '') + ' ' + (f.path || '/') + ' ' + (f.proto || '') : (f.proto || '') + ' ' + (f.status_text || f.status || '');
      const reqCt = (f.req_headers || []).find(p => /^content-type$/i.test(p[0]));
      body.append(
        h('div', { class: 'first-line mono ' + (isReq ? '' : statusCls(f.status)) }, firstLine),
        headersTable(isReq ? f.req_headers : f.resp_headers),
        h('h4', { style: { marginTop: '6px' } }, 'Body'),
        bodyView(isReq ? f.req_body : f.resp_body, isReq ? f.req_body_b64 : f.resp_body_b64, isReq ? (reqCt ? reqCt[1] : '') : f.content_type,
          isReq ? f.req_body_truncated : f.resp_body_truncated, 'flow-' + f.id + (isReq ? '-request' : '-response') + '.bin'));
    }
    if (isReq ? f.req_body_cut : f.resp_body_cut) {
      body.insertBefore(h('div', { class: 'warn-box small' },
        'body truncated for display (first 200 kB) — ',
        dlLink('download full', '/api/intercept/flows/' + f.id + '/export?format=raw', 'flow-' + f.id + '.txt', { class: 'inline' }),
        ' (raw export)'), body.firstChild);
    }
    d.append(body);
  },
  async copyCurl(id) {
    let t; try { t = await api('GET', '/api/intercept/flows/' + id + '/export?format=curl', undefined, { raw: true }); } catch (_) { return; }
    copyText(typeof t === 'string' ? t : JSON.stringify(t), 'curl command copied');
  },
  async deleteFlow(id) {
    try { await api('DELETE', '/api/intercept/flows/' + id); } catch (_) { return; }
    const tr = this.rows.get(id);
    const next = tr && (tr.nextElementSibling || tr.previousElementSibling);
    if (tr) { tr.remove(); this.rows.delete(id); }
    if (this.total > 0) this.total--;
    if (this.selectedId === id) { if (next) this.select(num(next.dataset.id)); else this.closeDetail(); }
    this.updateCount(); this.syncToolbar();
    toast('Flow #' + id + ' deleted', 'ok', 1500);
  },

  /* ---------- intercept queue ---------- */
  queuePanel() {
    this.holdHint = h('div', { class: 'info-box', hidden: true }, 'Hold requests / Hold responses are both off — nothing will be queued. Turn one on in the toolbar to review and edit traffic before it is forwarded.');
    this.queueList = h('div', { class: 'queue-list', tabindex: 0, 'aria-label': 'held flows' });
    this.queueList.addEventListener('click', e => { const it = e.target.closest('[data-id]'); if (it) this.selectPending(num(it.dataset.id)); });
    this.queueList.addEventListener('keydown', e => {
      if (e.target !== this.queueList) return;
      const ids = Array.from(this.pending.keys());
      let i = ids.indexOf(this.pendingSel);
      if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); this.selectPending(ids[Math.min(ids.length - 1, i + 1)]); }
      else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); this.selectPending(ids[Math.max(0, i - 1)]); }
    });
    this.queueEdit = h('div', { class: 'queue-edit' });
    this.queueCount = h('span', { class: 'muted small mono' });
    return h('div', { class: 'ic-panel' },
      this.holdHint,
      h('div', { class: 'hist-filters' }, this.queueCount, h('span', { class: 'spacer' }),
        btn('Forward all', () => this.forwardAll(), '', { title: 'POST /api/intercept/pending/forward-all' }), btn('Reload', () => this.reloadPending(), 'tiny')),
      h('div', { class: 'queue-split' }, this.queueList, this.queueEdit));
  },
  async reloadPending() {
    let r; try { r = await api('GET', '/api/intercept/pending', undefined, { silent: true }); } catch (_) { return; }
    this.setPending(r.pending || []);
  },
  setPending(list) {
    if (!this.pending) return;
    this.pending = new Map(list.map(f => [f.id, f]));
    state.pendingIds = new Set(this.pending.keys()); state.pendingSeeded = true;
    updateHeader();
    if (this.pendingSel !== null && !this.pending.has(this.pendingSel)) this.pendingSel = null;
    if (this.pendingSel === null && this.pending.size) this.pendingSel = this.pending.keys().next().value;
    this.renderQueue();
    this.syncToolbar();
  },
  renderQueue() {
    const l = clear(this.queueList);
    this.queueCount.textContent = this.pending.size + ' held';
    if (!this.pending.size) l.append(emptyState('Nothing held',
      ['With ', h('b', null, 'Hold requests'), ' or ', h('b', null, 'Hold responses'), ' on (toolbar), each intercepted message pauses here so you can read or edit it before it continues.'],
      { cls: 'small flat' }));
    for (const f of this.pending.values()) {
      const resp = f.state === 'pending_response';
      l.append(h('div', { class: 'queue-item' + (f.id === this.pendingSel ? ' selected' : ''), dataset: { id: f.id } },
        h('div', { class: 'qi-row' }, h('b', { class: 'mono' }, '#' + f.id), badge(resp ? 'response' : 'request', resp ? 'blue' : 'yellow'),
          resp && f.status ? h('span', { class: 'mono ' + statusCls(f.status) }, String(f.status)) : null,
          h('span', { class: 'spacer' }), h('span', { class: 'muted small mono' }, fmt.time(f.time))),
        h('div', { class: 'qi-url mono', title: flowShort(f) }, (f.method || '') + ' ' + (f.host || '') + (f.path || '')),
        h('div', { class: 'muted small' }, (f.app || f.source || '') + (f.tls ? ' · tls' : ''))));
    }
    this.renderQueueEdit();
  },
  selectPending(id) {
    if (id === undefined || !this.pending.has(id)) return;
    this.pendingSel = id;
    $$('.queue-item', this.queueList).forEach(it => it.classList.toggle('selected', num(it.dataset.id) === id));
    this.renderQueueEdit();
  },
  renderQueueEdit() {
    const box = clear(this.queueEdit);
    const f = this.pending.get(this.pendingSel);
    if (!f) { box.append(this.pending.size
      ? emptyState('Pick a held flow', 'Select a request or response on the left to review and edit it.', { cls: 'small flat' })
      : emptyState('Nothing waiting', 'Held requests and responses will show up here as apps make them.', { cls: 'small flat' })); return; }
    const resp = f.state === 'pending_response';
    const raw = resp ? f.resp_raw : f.req_raw;
    const ta = h('textarea', { class: 'code raw edit', spellcheck: 'false', wrap: 'off', 'aria-label': 'raw ' + (resp ? 'response' : 'request') });
    ta.value = LF(raw);
    const orig = LF(raw);
    const edited = () => ta.value !== orig;
    const fwd = btn('Forward', () => this.forward(f.id, edited() ? ta.value : null), 'primary', { title: 'Ctrl+Enter — send ' + (resp ? 'the response to the app' : 'the request upstream') + ' (edited text is used if changed)' });
    ta.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); fwd.click(); } });
    if (raw === undefined || raw === null) {
      // the SSE flow object has no raw text; fetch the detail
      api('GET', '/api/intercept/flows/' + f.id, undefined, { silent: true }).then(d => {
        if (this.pendingSel !== f.id || !d) return;
        Object.assign(f, { req_raw: d.req_raw, resp_raw: d.resp_raw });
        this.renderQueueEdit();
      }).catch(() => {});
    }
    box.append(
      h('div', { class: 'detail-head' },
        h('span', { class: 'detail-title', title: flowShort(f) }, h('b', null, '#' + f.id), ' ', h('span', { class: 'mono' }, flowShort(f))),
        flowStateBadge(f)),
      h('div', { class: 'detail-meta small muted mono' }, [f.app ? f.app + (f.pid ? '[' + f.pid + ']' : '') : f.source, fmt.datetime(f.time), f.tls ? 'tls' : 'plain', resp ? 'editing the response before it reaches the app' : 'editing the request before it goes upstream'].filter(Boolean).join(' · ')),
      ta,
      h('div', { class: 'form-actions' }, fwd,
        btn('Drop', () => this.drop(f.id), 'danger', { title: 'POST /api/intercept/pending/{id}/drop — abort the connection' }),
        btn('Reset edits', () => { ta.value = orig; ta.focus(); }, 'tiny'),
        btn('Copy', () => copyText(ta.value, 'Raw copied'), 'tiny'),
        h('span', { class: 'spacer' }),
        h('span', { class: 'muted small' }, 'Line endings are sent as CRLF.')));
    ta.focus();
  },
  removePending(id) {
    if (!this.pending || !this.pending.has(id)) return;
    const ids = Array.from(this.pending.keys());
    const i = ids.indexOf(id);
    this.pending.delete(id); state.pendingIds.delete(id);
    if (this.pendingSel === id) { const rest = Array.from(this.pending.keys()); this.pendingSel = rest.length ? rest[Math.min(i, rest.length - 1)] : null; }
    updateHeader(); this.renderQueue(); this.syncToolbar();
  },
  async forward(id, raw) {
    const body = raw === null || raw === undefined ? {} : { raw: CRLF(raw) };
    try { await api('POST', '/api/intercept/pending/' + id + '/forward', body); } catch (_) { return; }
    this.removePending(id);
    toast('#' + id + (body.raw ? ' forwarded (edited)' : ' forwarded'), 'ok', 1500);
  },
  async drop(id) {
    try { await api('POST', '/api/intercept/pending/' + id + '/drop'); } catch (_) { return; }
    this.removePending(id);
    toast('#' + id + ' dropped', 'warn', 1500);
  },
  async forwardAll() {
    try { await api('POST', '/api/intercept/pending/forward-all'); } catch (_) { return; }
    toast('All held flows forwarded', 'ok', 1500);
    this.setPending([]);
  },

  /* ---------- repeater ---------- */
  repeaterPanel() {
    this.repBar = h('div', { class: 'tabs rep-tabs' });
    this.repBody = h('div', { class: 'rep-body' });
    return h('div', { class: 'ic-panel' }, this.repBar, this.repBody);
  },
  saveRepeater() {
    const s = { tabs: this.repeater.tabs.map(t => ({ id: t.id, name: t.name, host: t.host, port: t.port, tls: t.tls, raw: t.raw, follow: t.follow, timeout: t.timeout })), active: this.repeater.active };
    try { localStorage.setItem(REPEATER_KEY, JSON.stringify(s)); } catch (_) { /* quota */ }
  },
  newTab(init) {
    const id = Math.max(0, ...this.repeater.tabs.map(t => num(t.id))) + 1;
    const t = Object.assign({ id, name: 'tab ' + id, host: '', port: 443, tls: true, raw: 'GET / HTTP/1.1\nHost: \nUser-Agent: cyberboba-repeater\nAccept: */*\n\n', follow: false, timeout: 30 }, init || {}, { id });
    this.repeater.tabs.push(t);
    this.repeater.active = this.repeater.tabs.length - 1;
    this.saveRepeater();
    return t;
  },
  sendToRepeater(f) {
    const t = this.newTab({ name: (f.method || 'GET') + ' ' + (f.host || ''), host: f.host || '', port: num(f.port, f.tls ? 443 : 80), tls: !!f.tls, raw: LF(f.req_raw || '') });
    this.showTab('repeater');
    toast('Opened in Repeater tab "' + t.name + '"', 'ok', 1500);
  },
  closeTab(i) {
    this.repeater.tabs.splice(i, 1);
    this.repeater.active = Math.max(0, Math.min(this.repeater.active, this.repeater.tabs.length - 1));
    this.saveRepeater(); this.renderRepeater();
  },
  renderRepeater() {
    if (!this.repBar) return;
    const R = this.repeater;
    const bar = clear(this.repBar);
    R.tabs.forEach((t, i) => {
      const b = h('button', { type: 'button', class: i === R.active ? 'active' : '', title: 'double-click to rename', onClick: () => { R.active = i; this.saveRepeater(); this.renderRepeater(); },
        onDblclick: () => { const n = prompt('Tab name', t.name); if (n !== null && n.trim()) { t.name = n.trim(); this.saveRepeater(); this.renderRepeater(); } } },
        t.name, h('span', { class: 'tab-x', title: 'close tab', onClick: e => { e.stopPropagation(); this.closeTab(i); } }, '×'));
      bar.append(b);
    });
    bar.append(h('button', { type: 'button', title: 'new tab', onClick: () => { this.newTab(); this.renderRepeater(); } }, '+'));
    const body = clear(this.repBody);
    const t = R.tabs[R.active];
    if (!t) { body.append(emptyState('No repeater tabs',
      ['Repeater lets you resend and tweak a request by hand — great for probing an endpoint. Press ', h('b', null, '+'), ' to craft one from scratch, or open a flow in ', h('b', null, 'History'), ' and choose ', h('b', null, 'Send to Repeater'), '.'],
      { actions: [btn('+ New tab', () => { this.newTab(); this.renderRepeater(); }, 'primary'), h('a', { class: 'btn', href: '#/intercept' }, 'Open History')] })); return; }
    const host = bind(textInput(t.host, { class: 'mono', placeholder: 'example.com', spellcheck: 'false' }), t, 'host', () => this.saveRepeater(), s => s.trim());
    const port = bind(h('input', { type: 'number', class: 'mono', value: t.port, min: 1, max: 65535, style: { width: '76px' } }), t, 'port', () => this.saveRepeater());
    const tls = checkbox('TLS', t.tls); bind(tls.input, t, 'tls', () => this.saveRepeater());
    const follow = checkbox('Follow redirects', t.follow); bind(follow.input, t, 'follow', () => this.saveRepeater());
    const timeout = bind(h('input', { type: 'number', class: 'mono', value: t.timeout, min: 1, max: 600, style: { width: '64px' }, title: 'timeout (seconds)' }), t, 'timeout', () => this.saveRepeater());
    const ta = h('textarea', { class: 'code raw edit', spellcheck: 'false', wrap: 'off', 'aria-label': 'raw request' });
    ta.value = t.raw || '';
    ta.addEventListener('input', debounce(() => { t.raw = ta.value; this.saveRepeater(); }, 300));
    const send = btn('Send', () => this.repeaterSend(t, ta), 'primary', { title: 'POST /api/intercept/send (Ctrl+Enter)' });
    ta.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); send.click(); } });
    [host, port].forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') send.click(); }));
    tls.input.addEventListener('change', () => { if (port.value === '443' && !tls.input.checked) { port.value = '80'; t.port = 80; } else if (port.value === '80' && tls.input.checked) { port.value = '443'; t.port = 443; } this.saveRepeater(); });
    this.repResp = h('div', { class: 'rep-col rep-resp' });
    this.repTab = t;
    body.append(
      h('div', { class: 'form-row rep-form' }, field('Host', host), field('Port', port), tls, follow, field('Timeout (s)', timeout), h('span', { class: 'spacer' }),
        btn('Copy', () => copyText(CRLF(ta.value), 'Request copied'), 'tiny', { title: 'copy request (CRLF)' }), send),
      h('div', { class: 'rep-split' },
        h('div', { class: 'rep-col' }, h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, 'request'), h('span', { class: 'spacer' }), h('span', { class: 'muted small' }, 'Ctrl+Enter sends')), ta),
        this.repResp));
    this.renderRepResponse(t);
  },
  async repeaterSend(t, ta) {
    t.raw = ta.value; this.saveRepeater();
    if (!t.host) { toast('Host is required', 'error'); return; }
    if (!t.raw.trim()) { toast('Request is empty', 'error'); return; }
    const req = { host: t.host, port: num(t.port, t.tls ? 443 : 80), tls: !!t.tls, raw: CRLF(t.raw.replace(/\n*$/, '\n\n')), follow_redirects: !!t.follow, timeout_sec: num(t.timeout, 30) };
    t._busy = true; t._err = ''; this.renderRepResponse(t);
    const t0 = performance.now();
    try {
      const r = await api('POST', '/api/intercept/send', req, { silent: true });
      t._resp = r.flow || r; t._rtt = performance.now() - t0; t._err = '';
    } catch (e) { t._err = e.message; t._rtt = performance.now() - t0; }
    finally { t._busy = false; }
    if (this.repTab === t) this.renderRepResponse(t);
  },
  renderRepResponse(t) {
    const box = clear(this.repResp);
    if (t._busy) { box.append(h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, 'response'), h('span', { class: 'spacer' })), h('div', { class: 'empty' }, h('span', { class: 'spinner' }), ' sending…')); return; }
    if (t._err) { box.append(h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, 'response')), h('div', { class: 'error-box' }, t._err)); return; }
    const f = t._resp;
    if (!f) { box.append(h('div', { class: 'raw-bar' }, h('span', { class: 'muted small' }, 'response')), h('div', { class: 'empty' }, 'No response yet — press Send (Ctrl+Enter).')); return; }
    const mode = sessionStorage.getItem('cyberboba.repMode') || 'pretty';
    const mb = (label, v) => btn(label, () => { sessionStorage.setItem('cyberboba.repMode', v); this.renderRepResponse(t); }, 'tiny' + (mode === v ? ' primary' : ''));
    const timing = [f.status_text || (f.status ? String(f.status) : f.state), f.duration_ms !== undefined ? fmt.ms(f.duration_ms) : null, 'rtt ' + fmt.ms(t._rtt), f.resp_size !== undefined ? fmt.bytes(f.resp_size) : null, f.id ? 'flow #' + f.id : null].filter(Boolean).join(' · ');
    box.append(h('div', { class: 'raw-bar' },
      h('span', { class: 'mono ' + statusCls(f.status) }, timing),
      h('span', { class: 'spacer' }), h('span', { class: 'btn-group' }, mb('Pretty', 'pretty'), mb('Raw', 'raw'))));
    if (f.error && !f.status) { box.append(h('div', { class: 'error-box' }, f.error)); return; }
    if (mode === 'raw') box.append(rawBlock(f.resp_raw, 'response'));
    else box.append(h('div', { class: 'detail-body' },
      h('div', { class: 'first-line mono ' + statusCls(f.status) }, (f.proto || '') + ' ' + (f.status_text || f.status || '')),
      headersTable(f.resp_headers),
      h('h4', { style: { marginTop: '6px' } }, 'Body'),
      bodyView(f.resp_body, f.resp_body_b64, f.content_type, f.resp_body_truncated, 'repeater-' + (f.id || 'response') + '.bin')));
  },

  /* ---------- sessions ---------- */
  async recordDialog() {
    const listBox = h('div', { class: 'rec-list' });
    const appIn = textInput('', { class: 'mono', placeholder: 'process name, path or glob — e.g. chromium, claude, *telegram*', spellcheck: 'false' });
    const sugg = h('datalist', { id: 'rec-apps-sugg' });
    appIn.setAttribute('list', 'rec-apps-sugg');
    const refresh = async () => {
      let r; try { r = await api('GET', '/api/intercept/record', undefined, { silent: true }); }
      catch (e) { replace(listBox, h('div', { class: 'error-box' }, e.message)); return; }
      const apps = r.apps || [];
      if (!apps.length) {
        replace(listBox, emptyState('Capturing nothing specific yet',
          'Add an app below to record just its traffic. Everything else is left untouched.', { cls: 'small flat' }));
      } else {
        clear(listBox);
        for (const a of apps) {
          listBox.append(h('div', { class: 'rec-item' },
            h('span', { class: 'mono rec-app' }, a),
            h('span', { class: 'spacer' }),
            btn('Stop', () => doRemove(a), 'tiny danger', { title: 'stop recording this app (removes its intercept rule)' })));
        }
      }
      if (!r.recording && apps.length) listBox.append(h('div', { class: 'muted small', style: { marginTop: '6px' } }, 'Recording is paused — turn it on in the toolbar to capture.'));
    };
    const doAdd = async () => {
      const app = appIn.value.trim();
      if (!app) return;
      try { await api('POST', '/api/intercept/record', { app }); } catch (_) { return; }
      toast('Recording ' + app, 'ok', 2500);
      appIn.value = '';
      await refresh(); this.reload();
    };
    const doRemove = async (app) => {
      try { await api('DELETE', '/api/intercept/record?app=' + encodeURIComponent(app)); } catch (_) { return; }
      toast('Stopped recording ' + app, 'ok', 2500);
      await refresh();
    };
    appIn.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); doAdd(); } });
    // suggestions: running processes + installed apps
    Promise.all([
      api('GET', '/api/procmon', undefined, { silent: true }).catch(() => ({ processes: [] })),
      api('GET', '/api/apps/installed', undefined, { silent: true }).catch(() => ({ apps: [] })),
    ]).then(([pm, ins]) => {
      const names = new Set();
      for (const p of (pm.processes || [])) if (p.name && !p.system) names.add(p.name);
      for (const a of (ins.apps || [])) if (a.match) names.add(a.match.replace(/^cmd:/, ''));
      clear(sugg);
      [...names].sort().forEach(n => sugg.append(h('option', { value: n })));
    });
    const body = h('div', { class: 'tab-panel' },
      h('div', { class: 'muted small', style: { marginBottom: '8px' } },
        'Recording captures only traffic routed through the interceptor. Add a program here to capture ', h('b', null, 'just that app'), '’s HTTP/HTTPS — the rest of the system stays untouched. For HTTPS the app must trust cyberboba’s CA.'),
      h('div', { class: 'row', style: { gap: '8px', marginBottom: '10px' } }, appIn, sugg, btn('Add', doAdd, 'primary')),
      listBox);
    openModal({ title: 'Record specific apps', width: '560px', body, buttons: [{ label: 'Done' }] });
    refresh();
  },

  async sessionsDialog() {
    const pathIn = textInput('', { class: 'mono', placeholder: '(optional) /var/lib/cyberboba/sessions/name.json', spellcheck: 'false' });
    const replaceCb = checkbox('replace current flows on load (otherwise merge)', false);
    const listBox = h('div', { class: 'sess-list' }, h('div', { class: 'muted small' }, h('span', { class: 'spinner' }), ' loading…'));
    const loadList = async () => {
      let r; try { r = await api('GET', '/api/intercept/sessions', undefined, { silent: true }); }
      catch (e) { replace(listBox, h('div', { class: 'error-box' }, e.message)); return; }
      const list = (r.sessions || []).slice();
      if (!list.length) { replace(listBox, emptyState('No saved sessions',
        ['Save the flows you have captured as a session and reload them later. They live in ', h('code', null, '/var/lib/cyberboba/sessions'), '.'],
        { cls: 'small flat' })); return; }
      clear(listBox);
      for (const s of list) {
        listBox.append(h('div', { class: 'sess-item' },
          h('div', { class: 'sess-info' },
            h('div', { class: 'mono sess-path', title: s.path }, s.path),
            h('div', { class: 'muted small mono' }, fmt.bytes(s.size) + ' · ' + fmt.datetime(s.modified))),
          btn('Load', () => doLoad(s.path), 'tiny', { title: 'POST /api/intercept/session/load' })));
      }
    };
    const doSave = async () => {
      const body = {}; const p = pathIn.value.trim(); if (p) body.path = p;
      let r; try { r = await api('POST', '/api/intercept/session/save', body); } catch (_) { return; }
      toast('Saved ' + fmt.num(num(r.flows)) + ' flows → ' + (r.path || '?'), 'ok', 6000);
      loadList();
    };
    const doLoad = async path => {
      let r; try { r = await api('POST', '/api/intercept/session/load', { path, replace: replaceCb.input.checked }); } catch (_) { return; }
      toast('Loaded ' + fmt.num(num(r.loaded)) + ' flows (' + fmt.num(num(r.flows)) + ' total)', 'ok', 6000);
      await this.reload();
    };
    loadList();
    openModal({ title: 'Intercept sessions', width: '660px',
      body: h('div', { class: 'tab-panel' },
        h('h4', null, 'Save current flows'),
        h('div', { class: 'form-row' }, field('Path', pathIn, 'empty → timestamped file in /var/lib/cyberboba/sessions'), btn('Save current flows', doSave, 'primary', { title: 'POST /api/intercept/session/save' })),
        h('h4', null, 'Saved sessions'),
        replaceCb,
        listBox,
        h('div', { class: 'form-actions' }, btn('Refresh list', loadList, 'tiny'),
          h('span', { class: 'muted small' }, 'Loading re-reads flows into the history.'))),
      buttons: [{ label: 'Close' }] });
  },

  /* ---------- rewrites (match & replace) ---------- */
  rewritesPanel() {
    this.rwList = h('div', { class: 'rw-list' });
    this.rwList.addEventListener('input', () => this.setRwDirty(true));
    this.rwList.addEventListener('change', () => this.setRwDirty(true));
    this.rwSaveBtn = btn('Save rewrites', () => this.saveRewrites(), 'primary');
    this.rwDirtyEl = h('span', { class: 'muted small', hidden: true }, 'unsaved changes');
    const head = h('div', { class: 'hist-filters' },
      h('span', { class: 'muted small' }, 'applied top to bottom to every intercepted flow'),
      h('span', { class: 'spacer' }), this.rwDirtyEl,
      btn('+ Add rewrite', () => this.addRewrite()),
      btn('Reload', () => this.loadRewrites(true), 'tiny'),
      this.rwSaveBtn);
    const help = h('div', { class: 'info-box small' },
      'Rewrites apply only to flows going through the intercepting proxy — not to the Repeater. A flow changed by a rewrite is flagged ',
      h('span', { class: 'flag rewritten' }, 'R'), ' in History. Saving replaces the whole ordered list (PUT /api/intercept/rewrites).');
    return h('div', { class: 'ic-panel rw-panel' }, head, help, h('div', { class: 'rw-scroll' }, this.rwList));
  },
  async loadRewrites(force) {
    if (this.rwLoaded && !force) return;
    let r; try { r = await api('GET', '/api/intercept/rewrites'); } catch (_) { return; }
    if (!this.rwList) return;
    this.rwLoaded = true;
    this.fillRewrites(r.rewrites || []);
  },
  fillRewrites(list) {
    clear(this.rwList);
    for (const rw of list) this.rwList.append(this.rewriteCard(rw));
    this.renumberRewrites();
    this.setRwDirty(false);
  },
  setRwDirty(d) { this.rwDirty = d; if (this.rwDirtyEl) this.rwDirtyEl.hidden = !d; if (this.rwSaveBtn) this.rwSaveBtn.classList.toggle('dirty', d); },
  rwCards() { return $$('.rw-card', this.rwList); },
  renumberRewrites() {
    const cards = this.rwCards();
    cards.forEach((c, i) => { c._idx.textContent = String(i + 1); c._up.disabled = i === 0; c._down.disabled = i === cards.length - 1; });
    const empty = $('.empty', this.rwList);
    if (!cards.length && !empty) this.rwList.append(emptyState('No rewrites yet',
      'Rewrites automatically patch intercepted traffic on the fly — swap a header, edit a response body, or redirect a URL. Add one to get started.',
      { actions: [btn('+ Add rewrite', () => this.addRewrite(), 'primary')] }));
    else if (cards.length && empty) empty.remove();
  },
  rewriteCard(rw) {
    const el = h('div', { class: 'rw-card' + (rw.enabled === false ? ' disabled' : '') });
    const idx = h('span', { class: 'rw-idx' });
    const enabled = h('input', { type: 'checkbox', checked: rw.enabled !== false, title: 'enabled', onChange: () => el.classList.toggle('disabled', !enabled.checked) });
    const name = textInput(rw.name, { class: 'rw-name', placeholder: 'rewrite name', spellcheck: 'false' });
    const target = sel(['request', 'response'], rw.target || 'request', { title: 'target: request or response' });
    const part = sel(['header', 'body', 'url'], rw.part || 'header', { title: 'part to rewrite' });
    const header = textInput(rw.header, { class: 'mono', placeholder: 'Header-Name', spellcheck: 'false' });
    const headerF = field('Header name', header);
    const match = textInput(rw.match, { class: 'mono', placeholder: 'regex (match)', spellcheck: 'false' });
    const matchF = field('Match', match, 'empty match + part=header sets the header to the replacement value; body/url need a match');
    const replaceTa = h('textarea', { class: 'code rw-replace', rows: 2, spellcheck: 'false', placeholder: 'replacement — $1 capture groups allowed' });
    replaceTa.value = rw.replace || '';
    const replaceF = field('Replace', replaceTa, null, 'wide');
    const remove = checkbox('remove (delete the header / matched text instead of replacing)', !!rw.remove);
    const hosts = tagsInput({ values: rw.hosts, placeholder: '*.example.com (optional host scope)' });
    const hostsF = field('Hosts', hosts, 'empty = all hosts', 'wide');
    const syncPart = () => { headerF.hidden = part.value !== 'header'; };
    part.addEventListener('change', syncPart); syncPart();
    const up = btn('↑', () => this.moveRewrite(el, -1), 'icon', { title: 'move up' });
    const down = btn('↓', () => this.moveRewrite(el, 1), 'icon', { title: 'move down' });
    el.append(
      h('div', { class: 'rw-row1' }, idx, enabled, name, target, part, h('span', { class: 'spacer' }),
        up, down, btn('⎘', () => this.dupRewrite(el), 'icon', { title: 'duplicate' }), btn('×', () => this.delRewrite(el), 'icon danger', { title: 'delete rewrite' })),
      h('div', { class: 'form-grid rw-grid' }, headerF, matchF, replaceF, remove, hostsF));
    el._idx = idx; el._up = up; el._down = down;
    el.read = () => {
      const p = part.value;
      return {
        name: name.value.trim(), enabled: enabled.checked, target: target.value, part: p,
        header: p === 'header' ? header.value.trim() : '',
        match: match.value, replace: replaceTa.value, remove: remove.input.checked,
        hosts: hosts.getValues(),
      };
    };
    el.focusName = () => name.focus();
    return el;
  },
  moveRewrite(el, dir) {
    const sib = dir < 0 ? el.previousElementSibling : el.nextElementSibling;
    if (!sib || !sib.classList.contains('rw-card')) return;
    if (dir < 0) this.rwList.insertBefore(el, sib); else this.rwList.insertBefore(sib, el);
    this.setRwDirty(true); this.renumberRewrites();
    el.scrollIntoView({ block: 'nearest' });
  },
  addRewrite() {
    const c = this.rewriteCard({ name: 'New rewrite', enabled: true, target: 'request', part: 'header', header: '', match: '', replace: '', remove: false, hosts: [] });
    this.rwList.append(c); this.renumberRewrites(); this.setRwDirty(true);
    c.scrollIntoView({ block: 'nearest' }); c.focusName();
  },
  dupRewrite(el) {
    const r = el.read(); r.name = (r.name || 'rewrite') + ' (copy)';
    const c = this.rewriteCard(r);
    this.rwList.insertBefore(c, el.nextSibling); this.renumberRewrites(); this.setRwDirty(true); c.focusName();
  },
  delRewrite(el) {
    const r = el.read();
    if (!confirm('Delete rewrite "' + (r.name || '(unnamed)') + '"?')) return;
    el.remove(); this.renumberRewrites(); this.setRwDirty(true);
  },
  async saveRewrites() {
    const rewrites = this.rwCards().map(c => c.read());
    this.rwSaveBtn.disabled = true;
    try {
      const r = await api('PUT', '/api/intercept/rewrites', { rewrites });
      toast('Rewrites saved (' + rewrites.length + ')', 'ok');
      this.fillRewrites((r && r.rewrites) || rewrites);
    } catch (_) { /* shown */ }
    finally { this.rwSaveBtn.disabled = false; }
  },

  /* ---------- events ---------- */
  onEvent(type, data) {
    if (type === 'flow' && data && data.id !== undefined) {
      const existed = this.rows.has(data.id);
      this.upsert(data);
      if (!existed && this.rows.has(data.id)) this.total++;
      this.updateCount();
      const held = data.state === 'pending_request' || data.state === 'pending_response';
      if (held) {
        const cur = this.pending.get(data.id);
        if (cur && cur.state === data.state) Object.assign(cur, data);
        else { this.pending.set(data.id, Object.assign({}, cur, data)); if (this.pendingSel === null) this.pendingSel = data.id; this.renderQueue(); }
        state.pendingIds.add(data.id); updateHeader();
      } else if (this.pending.has(data.id)) this.removePending(data.id);
      this.syncToolbar();
      if (this.selectedId === data.id && this.detailFlow && this.detailFlow.state !== data.state) {
        clearTimeout(this.detailTimer);
        this.detailTimer = setTimeout(() => this.loadDetail(data.id), 150);
      }
    } else if (type === 'intercept') {
      this.applyStatus(data);
    } else if (type === 'pending-sync') {
      this.setPending(data || []);
    }
  },
};

/* ================================================================
 * 4e. Proxies
 * ================================================================ */
const PROXY_TYPES = ['socks5', 'socks4', 'http', 'chain', 'failover', 'balance', 'rotate'];
const PROXY_MULTI = new Set(['chain', 'failover', 'balance', 'rotate']); // types made of hops instead of an address
const PROXY_HOP_HINT = {
  rotate: 'one member is active at a time; it switches on the timer below',
  chain: 'traffic enters the first hop and exits the last',
  failover: 'hops are tried in order until one connects; each hop must be a single proxy (not a chain)',
  balance: 'a random hop is picked per connection; each hop must be a single proxy (not a chain)',
};
/* ---- shared helpers for proxy/route editing ---- */
function uniqueName(base, taken) {
  base = (base || 'route').replace(/[^a-zA-Z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'route';
  const set = new Set(taken || []);
  let n = base, i = 2;
  while (set.has(n)) { n = base + '-' + i; i++; }
  return n;
}
function insertRuleBeforeCatchAll(rules, rule) {
  const next = (rules || []).slice();
  const isCatchAll = r => !((r.apps && r.apps.length) || (r.users && r.users.length) || (r.targets && r.targets.length) || (r.ports && r.ports.length));
  let idx = next.findIndex(isCatchAll);
  if (idx < 0) idx = next.length;
  next.splice(idx, 0, rule);
  return next;
}

/* openProxyForm — a modal to create or edit one proxy. candidates: other
 * proxies usable as hops. onSubmit(proxyObj) returns '' to close or an error
 * string / rejected promise to keep the dialog open. */
function openProxyForm({ proxy, candidates, vpnNames, title, submitLabel, onSubmit }) {
  const p = Object.assign({ name: '', type: 'socks5', addr: '', username: '', password: '', hops: [], via_vpn: '', remote_dns: true, comment: '' },
    JSON.parse(JSON.stringify(proxy || {})));
  const singles = (candidates || []).filter(q => q.name && !PROXY_MULTI.has(q.type));

  const name = textInput(p.name, { class: 'mono', placeholder: 'my-proxy', spellcheck: 'false' });
  const type = sel(PROXY_TYPES, p.type || 'socks5');
  const addr = textInput(p.addr, { class: 'mono', placeholder: 'host:port  (e.g. 10.0.0.1:1080)', spellcheck: 'false' });
  const user = textInput(p.username, { class: 'mono', autocomplete: 'off' });
  const pass = h('input', { type: 'password', class: 'mono', value: p.password || '', autocomplete: 'new-password' });
  const showPw = btn('show', () => { pass.type = pass.type === 'password' ? 'text' : 'password'; }, 'tiny', { tabindex: -1, title: 'show/hide' });
  const viaVpn = sel([{ value: '', label: '(none)' }, ...(vpnNames || [])], p.via_vpn || '', { class: 'mono' });
  const rdns = checkbox('Remote DNS — resolve hostnames on the proxy side', p.remote_dns !== false);
  const comment = textInput(p.comment, { placeholder: 'optional note' });

  const hops = h('select', { multiple: true, class: 'mono' });
  const buildHops = () => {
    hops.size = Math.min(8, Math.max(3, singles.length || 3));
    replace(hops, ...singles.map(q => h('option', { value: q.name, selected: (p.hops || []).includes(q.name) }, q.name + '  (' + (q.type || 'socks5') + ')')));
    if (!singles.length) hops.append(h('option', { value: '', disabled: true }, '(no single proxies yet — add some first)'));
  };
  buildHops();
  hops.addEventListener('change', () => { p.hops = Array.from(hops.selectedOptions).map(o => o.value).filter(Boolean); });

  const addrField = field('Address', addr, 'host:port of the proxy server');
  const userField = field('Username', user);
  const passField = field('Password', h('div', { class: 'form-row', style: { flexWrap: 'nowrap' } }, pass, showPw));
  const authFields = h('div', { class: 'form-grid' }, userField, passField);
  const hopsField = field('Hops (click in the order traffic should take; Ctrl/⌘-click for several)', hops, PROXY_HOP_HINT.chain);
  const hopsHint = $('.hint', hopsField);
  const rotEvery = h('input', { type: 'number', min: 1, value: p.rotate_every_sec || 300, class: 'mono', style: { width: '110px' } });
  const rotMode = sel([{ value: 'random', label: 'random' }, { value: 'sequential', label: 'sequential' }], p.rotate_mode || 'random');
  const rotField = h('div', { class: 'form-grid' }, field('Rotate every (seconds)', rotEvery, 'how often the active member switches'), field('Rotate mode', rotMode));
  const viaField = field('Via VPN', viaVpn, 'reach this proxy through a VPN tunnel first (optional)');
  const sync = () => {
    const multi = PROXY_MULTI.has(type.value);
    hopsField.hidden = !multi; addrField.hidden = multi; authFields.hidden = multi;
    passField.hidden = type.value === 'socks4';
    rotField.hidden = type.value !== 'rotate';
    viaField.hidden = type.value === 'failover' || type.value === 'balance' || type.value === 'rotate';
    $('.field-label', userField).textContent = type.value === 'socks4' ? 'User ID (optional)' : 'Username';
    if (multi) { hopsHint.textContent = PROXY_HOP_HINT[type.value] || ''; buildHops(); }
  };
  type.addEventListener('change', sync); sync();

  const body = h('div', null,
    h('div', { class: 'form-grid' }, field('Name', name, 'a label you choose'), field('Type', type)),
    addrField, authFields, hopsField, rotField, viaField,
    h('div', { style: { marginTop: '4px' } }, rdns),
    field('Comment', comment));

  openModal({
    title: title || 'Proxy', width: '560px', body, buttons: [
      { label: 'Cancel' },
      {
        label: submitLabel || 'Save', cls: 'primary', onClick: async (close) => {
          p.name = name.value.trim(); p.type = type.value; p.addr = addr.value.trim();
          p.username = user.value; p.password = pass.value;
          p.via_vpn = viaField.hidden ? '' : viaVpn.value;
          p.remote_dns = rdns.input.checked; p.comment = comment.value.trim();
          if (p.type === 'rotate') { p.rotate_every_sec = num(rotEvery.value) || 300; p.rotate_mode = rotMode.value; }
          if (!p.name) { toast('Name is required', 'error'); return; }
          if (PROXY_MULTI.has(p.type)) { if (!(p.hops && p.hops.length)) { toast('Pick at least one hop', 'error'); return; } }
          else if (!p.addr) { toast('Address (host:port) is required', 'error'); return; }
          try { const err = await onSubmit(p); if (err) { toast(err, 'error'); return; } close(); }
          catch (e) { /* api already toasted */ }
        }
      },
    ],
  });
}

const PROXY_HELP = 'A proxy is one upstream server (SOCKS5 / SOCKS4 / HTTP). A chain sends traffic through several in order. "Via VPN" reaches a proxy through a tunnel first.';

Pages.proxies = {
  title: 'Proxies',
  async mount(root) {
    this.root = root; this.checks = {};
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Proxies'),
      h('span', { class: 'muted small' }, 'upstream servers and chains'),
      h('span', { class: 'spacer' }),
      btn('+ Add proxy', () => this.edit(-1), 'primary'),
      btn('Reload', () => this.reload())));
    root.append(h('div', { class: 'info-box small' },
      PROXY_HELP, ' To actually send apps through one, add a rule on the ',
      h('a', { href: '#/rules' }, 'Rules'), ' page — the ', h('b', null, '+ New route'), ' button there builds VPN→proxy chains for you.'));
    this.tbody = h('tbody');
    root.append(h('div', { class: 'table-wrap', style: { maxHeight: 'calc(100vh - 180px)' } },
      h('table', { class: 'grid' },
        h('colgroup', null, h('col', { style: { width: '150px' } }), h('col', { style: { width: '80px' } }), h('col'),
          h('col', { style: { width: '110px' } }), h('col', { style: { width: '54px' } }), h('col', { style: { width: '170px' } }), h('col', { style: { width: '150px' } })),
        h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', null, 'Type'), h('th', null, 'Address / hops'),
          h('th', null, 'Via VPN'), h('th', null, 'rDNS'), h('th', null, 'Check'), h('th'))),
        this.tbody)));
    await this.reload(true);
    this.rotTimer = setInterval(() => this.loadRotation(), 2000);
    this.loadRotation();
  },
  unmount() { clearInterval(this.rotTimer); this.root = null; this.tbody = null; },
  async loadRotation() {
    const r = await api('GET', '/api/proxies/rotation', undefined, { silent: true }).catch(() => null);
    if (!r || !this.tbody) return;
    this.rotation = {};
    for (const rs of (r.rotations || [])) this.rotation[rs.name] = rs;
    this.render();
  },
  async reload(silent) {
    const [pr, vp] = await Promise.all([
      api('GET', '/api/proxies', undefined, { silent }).catch(() => ({ proxies: [] })),
      api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
    ]);
    if (!this.tbody) return;
    this.list = (pr.proxies || []).map(p => Object.assign({ hops: [], remote_dns: true }, p));
    this.vpnNames = (vp.vpns || []).map(v => v.name).filter(Boolean);
    this.render();
  },
  render() {
    clear(this.tbody);
    if (!this.list.length) { this.tbody.append(h('tr', null, h('td', { colspan: 7 },
      emptyState('No proxies yet',
        'Add a SOCKS5, SOCKS4 or HTTP proxy server here, then point traffic at it with a rule. You can also chain several proxies or rotate between them.',
        { actions: [btn('+ Add proxy', () => this.edit(-1), 'primary')] })))); return; }
    this.list.forEach((p, i) => {
      const multi = PROXY_MULTI.has(p.type);
      const rs = p.type === 'rotate' && this.rotation ? this.rotation[p.name] : null;
      let hopsText = (p.hops || []).join(p.type === 'chain' ? ' → ' : ' | ');
      let hopsCell = multi ? hopsText : (p.addr || '');
      if (rs) hopsCell = h('span', null, h('span', { class: 'rot-active' }, '▶ ' + (rs.current || '?')),
        h('span', { class: 'muted small' }, '  of ' + (rs.members || []).length + ' · every ' + rs.every_sec + 's · next ' + rs.next_in_sec + 's'));
      const chk = this.checks[p.name];
      this.tbody.append(h('tr', { class: 'clickable', onClick: () => this.edit(i) },
        h('td', { class: 'mono' }, p.name || h('span', { class: 'muted' }, '(unnamed)')),
        h('td', null, badge(p.type || 'socks5', multi ? 'yellow' : 'blue')),
        h('td', { class: 'mono', title: hopsText }, hopsCell),
        h('td', { class: 'mono' }, p.via_vpn || ''),
        h('td', null, p.remote_dns ? 'yes' : 'no'),
        h('td', { class: 'check-result' }, this.checkText(chk)),
        h('td', { onClick: e => e.stopPropagation() },
          btn('Check', () => this.check(p.name), 'tiny', { disabled: !p.name }),
          btn('Edit', () => this.edit(i), 'tiny'),
          btn('✕', () => this.del(i), 'tiny danger', { title: 'delete' }))));
    });
  },
  checkText(chk) {
    if (!chk) return '';
    if (chk.pending) return h('span', { class: 'muted' }, h('span', { class: 'spinner' }), ' checking…');
    if (chk.ok) return h('span', { class: 'ok', title: 'HTTP ' + (chk.status || '') }, '✓ ' + fmt.ms(chk.latency_ms) + (chk.exit_ip ? ' · ' + chk.exit_ip : ''));
    return h('span', { class: 'bad', title: chk.error || '' }, '✗ ' + (chk.error || 'failed'));
  },
  edit(i) {
    const isNew = i < 0;
    const candidates = this.list.filter((q, j) => j !== i);
    openProxyForm({
      proxy: isNew ? null : this.list[i],
      candidates, vpnNames: this.vpnNames,
      title: isNew ? 'Add proxy' : 'Edit proxy', submitLabel: isNew ? 'Add' : 'Save',
      onSubmit: async (p) => {
        if (this.list.some((q, j) => j !== i && q.name === p.name)) return 'A proxy named "' + p.name + '" already exists';
        const next = this.list.slice();
        if (isNew) next.push(p); else next[i] = p;
        const ok = await this.persist(next);
        return ok ? '' : 'save failed';
      },
    });
  },
  del(i) {
    const p = this.list[i];
    if (!confirm('Delete proxy "' + p.name + '"? Rules or chains referencing it will fail to save.')) return;
    const next = this.list.slice(); next.splice(i, 1);
    this.persist(next);
  },
  async persist(list) {
    try {
      const r = await api('PUT', '/api/proxies', { proxies: list });
      this.list = ((r && r.proxies) || list).map(p => Object.assign({ hops: [], remote_dns: true }, p));
      this.render();
      toast('Proxies saved', 'ok');
      return true;
    } catch (_) { return false; }
  },
  async check(name) {
    if (!name) return;
    this.checks[name] = { pending: true }; this.render();
    let r;
    try { r = await api('POST', '/api/proxies/' + encodeURIComponent(name) + '/check', {}, { silent: true }); }
    catch (e) { r = { ok: false, error: e.message }; }
    this.checks[name] = r; this.render();
  },
};

/* routeWizard — a guided builder: pick traffic + an ordered list of hops
 * (VPNs and proxies), and it assembles the proxy chain / via_vpn / rule. */
/* pickAppModal — a tabbed picker to add an app to a route/rule scope:
 *  • Installed apps — human-friendly names from .desktop files; adds a
 *    forgiving `cmd:<keyword>` match (matches the process command line).
 *  • Running processes — live processes, with the ones currently using the
 *    network flagged first. onPick(value) receives the string to add. */
async function pickAppModal(onPick) {
  let tab = 'installed';
  const added = new Set();
  let installed = null, procRows = null;
  const search = textInput('', { placeholder: 'filter by name or path…', class: 'mono' });
  const netOnly = checkbox('only apps with network activity', false);
  const listEl = h('div', { class: 'app-picker-list' });
  const countEl = h('span', { class: 'muted small' });
  const hint = h('div', { class: 'muted small', style: { marginBottom: '8px' } });

  const tabI = h('button', { class: 'tg-tab active', type: 'button' }, 'Installed apps');
  const tabR = h('button', { class: 'tg-tab', type: 'button' }, 'Running processes');
  tabI.addEventListener('click', () => { tab = 'installed'; tabI.classList.add('active'); tabR.classList.remove('active'); render(); });
  tabR.addEventListener('click', () => { tab = 'running'; tabR.classList.add('active'); tabI.classList.remove('active'); render(); });

  async function loadInstalled() {
    if (installed) return;
    const r = await api('GET', '/api/apps/installed', undefined, { silent: true }).catch(() => ({ apps: [] }));
    installed = r.apps || [];
  }
  async function loadRunning() {
    if (procRows) return;
    const [pr, cn] = await Promise.all([
      api('GET', '/api/processes', undefined, { silent: true }).catch(() => ({ processes: [] })),
      api('GET', '/api/connections?limit=500', undefined, { silent: true }).catch(() => ({ connections: [] })),
    ]);
    const netNames = new Set((cn.connections || []).map(c => c.app).filter(Boolean));
    const byName = new Map();
    for (const p of (pr.processes || [])) {
      if (!p.name) continue;
      let g = byName.get(p.name);
      if (!g) { g = { name: p.name, pids: [], user: p.user, exe: p.exe, net: netNames.has(p.name) }; byName.set(p.name, g); }
      g.pids.push(p.pid);
    }
    procRows = [...byName.values()].sort((a, b) => (Number(b.net) - Number(a.net)) || a.name.localeCompare(b.name));
  }

  function rowEl(value, labelNodes, subText, addedMark) {
    const isAdded = added.has(value);
    return h('div', { class: 'app-row' + (isAdded ? ' added' : ''), onClick: () => { if (added.has(value)) return; added.add(value); onPick(value); render(); } },
      h('div', { class: 'app-row-top' }, ...labelNodes, h('span', { class: 'spacer' }),
        isAdded ? h('span', { class: 'ok small' }, '\u2713 added') : btn('Add', null, 'tiny')),
      subText ? h('div', { class: 'app-exe muted small mono', title: subText }, subText) : null);
  }

  async function render() {
    netOnly.style.display = tab === 'running' ? '' : 'none';
    const q = search.value.trim().toLowerCase();
    clear(listEl);
    if (tab === 'installed') {
      hint.textContent = 'Pick your app by its normal name — it adds a cmd: match on the command line, which is the most reliable way to catch all of the app\u2019s processes.';
      await loadInstalled();
      let rows = installed.filter(a => !q || a.name.toLowerCase().includes(q) || (a.binary || '').toLowerCase().includes(q) || (a.keyword || '').includes(q));
      countEl.textContent = rows.length + ' of ' + installed.length;
      if (!rows.length) { listEl.append(installed.length
        ? emptyState('No matching apps', 'Nothing matches your search. Try a shorter term, or switch to Running processes.', { cls: 'small flat' })
        : emptyState('No installed apps found', 'cyberboba could not read any .desktop entries. Switch to Running processes to pick from what is live right now.', { cls: 'small flat' })); return; }
      for (const a of rows.slice(0, 500)) {
        listEl.append(rowEl('cmd:' + a.keyword,
          [h('span', { class: 'app-name' }, a.name), h('span', { class: 'muted small mono' }, 'cmd:' + a.keyword)],
          a.comment || a.binary || ''));
      }
    } else {
      hint.textContent = 'Live processes. Toggle network activity to find the app that is actually connecting right now.';
      await loadRunning();
      let rows = procRows.filter(r => (!netOnly.input.checked || r.net) && (!q || r.name.toLowerCase().includes(q) || (r.exe || '').toLowerCase().includes(q)));
      countEl.textContent = rows.length + ' of ' + procRows.length;
      if (!rows.length) { listEl.append(emptyState('No matching processes',
        netOnly.input.checked ? 'Nothing is using the network right now. Turn off the network filter to see all running processes.' : 'No running process matches your search.',
        { cls: 'small flat' })); return; }
      for (const r of rows.slice(0, 400)) {
        listEl.append(rowEl(r.name,
          [h('span', { class: 'app-name mono' }, r.name), r.net ? badge('network', 'green') : null],
          r.pids.length + ' proc \u00b7 ' + (r.user || '') + '  ' + (r.exe || '')));
      }
    }
  }
  search.addEventListener('input', render);
  netOnly.input.addEventListener('change', render);
  render();
  openModal({
    title: 'Choose an app', width: '680px',
    body: h('div', null,
      h('div', { class: 'tg-tabs' }, tabI, tabR),
      hint,
      h('div', { class: 'form-row', style: { gap: '12px', marginBottom: '8px', alignItems: 'center' } }, search, netOnly, h('span', { class: 'spacer' }), countEl),
      listEl),
    buttons: [{ label: 'Done' }],
  });
}

/* assembleAndSaveRoute — turn (scope + ordered hops) into cyberboba config:
 * builds a proxy chain when needed, sets via_vpn (one VPN) or full-mode nesting
 * (two+ VPNs), and inserts the rule before the catch-all. Shared by the route
 * wizard and the RouteBuilder tab. Returns {rname, rule, nested}. */
async function assembleAndSaveRoute({ name, apps, targets, hops, proxies, vpns, rules }) {
  const rname = (name || '').trim() || uniqueName('route', (rules || []).map(r => r.name));
  const vpnHops = hops.filter(x => x.kind === 'vpn').map(x => x.name);
  const proxyHops = hops.filter(x => x.kind === 'proxy').map(x => x.name);
  const nested = vpnHops.length >= 2;
  let newProxies = proxies.slice();
  let proxyRef = '';
  if (proxyHops.length) {
    if (proxyHops.length === 1 && !nested && !vpnHops.length) {
      proxyRef = proxyHops[0];
    } else {
      const chainName = uniqueName(rname + '-chain', newProxies.map(p => p.name));
      newProxies.push({ name: chainName, type: 'chain', hops: proxyHops, via_vpn: nested ? '' : (vpnHops[0] || ''), remote_dns: true, comment: 'auto: route ' + rname });
      proxyRef = chainName;
    }
  }
  let vpnUpdate = null;
  if (nested) vpnUpdate = vpns.map(v => vpnHops.includes(v.name) ? Object.assign({}, v, { mode: 'full' }) : v);
  let rule = null;
  if (proxyRef) rule = { name: rname, enabled: true, apps: apps || [], targets: targets || [], action: 'proxy', proxy: proxyRef };
  else if (vpnHops.length === 1) rule = { name: rname, enabled: true, apps: apps || [], targets: targets || [], action: 'vpn', vpn: vpnHops[0] };
  if (newProxies.length !== proxies.length) await api('PUT', '/api/proxies', { proxies: newProxies });
  if (vpnUpdate) await api('PUT', '/api/vpn', { vpns: vpnUpdate });
  if (rule) await api('PUT', '/api/rules', { rules: insertRuleBeforeCatchAll(rules, rule) });
  return { rname, rule, nested };
}

function routeWizard(onDone) {
  Promise.all([
    api('GET', '/api/proxies', undefined, { silent: true }).catch(() => ({ proxies: [] })),
    api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
    api('GET', '/api/rules', undefined, { silent: true }).catch(() => ({ rules: [] })),
  ]).then(([pr, vp, ru]) => {
    const proxies = (pr.proxies || []);
    // GET /api/vpn returns status views; the editable profile is under .config
    const vpns = (vp.vpns || []).map(v => (v && v.config) ? v.config : v);
    const rules = (ru.rules || []);
    const proxyNames = proxies.map(p => p.name).filter(Boolean);
    const vpnNames = vpns.map(v => v.name).filter(Boolean);
    let hops = [];

    const name = textInput('', { placeholder: 'route name, e.g. “work via NL”' });
    const apps = tagsInput({ placeholder: 'firefox, tag:work — empty = all apps', list: 'dl-apps' });
    const targets = tagsInput({ placeholder: '*.example.com, lan — empty = all sites', list: 'dl-targets' });
    const hopBox = h('div', { class: 'hopbuilder' });
    const preview = h('div', { class: 'hop-preview mono' });
    const note = h('div', { class: 'info-box small' });

    const addVpn = sel([{ value: '', label: '+ VPN hop…' }, ...vpnNames]);
    const addProxy = sel([{ value: '', label: '+ Proxy hop…' }, ...proxyNames, { value: '__new__', label: '＋ new proxy…' }]);
    addVpn.addEventListener('change', () => { if (addVpn.value) { hops.push({ kind: 'vpn', name: addVpn.value }); addVpn.value = ''; render(); } });
    addProxy.addEventListener('change', () => {
      const v = addProxy.value; addProxy.value = '';
      if (!v) return;
      if (v === '__new__') {
        openProxyForm({
          proxy: null, candidates: proxies, vpnNames, title: 'Add proxy', submitLabel: 'Add',
          onSubmit: (np) => {
            if (proxies.some(q => q.name === np.name)) return 'A proxy named "' + np.name + '" already exists';
            proxies.push(np); proxyNames.push(np.name);
            addProxy.insertBefore(h('option', { value: np.name }, np.name), addProxy.lastChild);
            hops.push({ kind: 'proxy', name: np.name }); render();
            toast('Proxy added to the route (saved when you create it)', 'ok');
            return '';
          },
        });
        return;
      }
      hops.push({ kind: 'proxy', name: v }); render();
    });
    function moveHop(i, d) { const j = i + d; if (j < 0 || j >= hops.length) return; const t = hops[i]; hops[i] = hops[j]; hops[j] = t; render(); }
    function render() {
      clear(hopBox);
      if (!hops.length) hopBox.append(h('div', { class: 'muted small' }, 'No hops yet — pick a VPN and/or proxy below.'));
      hops.forEach((hp, i) => {
        hopBox.append(h('div', { class: 'hoprow' },
          h('span', { class: 'hop-n' }, (i + 1) + '.'),
          badge(hp.kind, hp.kind === 'vpn' ? 'green' : 'blue'),
          h('span', { class: 'mono hop-name' }, hp.name),
          h('span', { class: 'spacer' }),
          btn('↑', () => moveHop(i, -1), 'icon', { disabled: i === 0 }),
          btn('↓', () => moveHop(i, 1), 'icon', { disabled: i === hops.length - 1 }),
          btn('✕', () => { hops.splice(i, 1); render(); }, 'icon danger')));
      });
      replace(preview, ['this machine', ...hops.map(x => x.name), 'internet'].join('  →  '));
      const nVpn = hops.filter(x => x.kind === 'vpn').length;
      const hasProxy = hops.some(x => x.kind === 'proxy');
      clear(note);
      if (nVpn >= 2) {
        note.className = 'warn-box small';
        note.append('A single connection can only pass through one VPN (routing is done per packet mark). ',
          'To chain two VPNs back-to-back, the wizard switches the chosen tunnels to ', h('b', null, 'full'),
          ' mode — they come up in order, the second running inside the first (nested), with any proxy on top of the last. ',
          'After creating the route, bring these VPNs up in that order on the ', h('a', { href: '#/vpn' }, 'VPN'), ' page.');
      } else {
        note.className = 'info-box small';
        note.append('Traffic flows left to right: ',
          nVpn ? 'first through the VPN tunnel' : 'straight out', hasProxy ? ', then through the proxy' : '', ', then on to the site.');
      }
    }
    render();

    const body = h('div', null,
      field('Route name', name),
      h('div', { class: 'form-grid' },
        field('Apps (optional)', apps, 'empty = all apps'),
        field('Sites / targets (optional)', targets, 'empty = all sites')),
      h('div', { class: 'field' },
        h('label', { class: 'field-label' }, 'Route through (in order)'), hopBox,
        h('div', { class: 'form-row', style: { marginTop: '6px' } }, addVpn, addProxy)),
      h('div', { class: 'field-label', style: { marginTop: '8px' } }, 'Preview'), preview, note);

    openModal({
      title: 'New route (guided)', width: '640px', body, buttons: [
        { label: 'Cancel' },
        {
          label: 'Create route', cls: 'primary', onClick: async (close) => {
            if (!hops.length) { toast('Add at least one hop (VPN or proxy)', 'error'); return; }
            try {
              const r = await assembleAndSaveRoute({ name: name.value, apps: apps.getValues(), targets: targets.getValues(), hops, proxies, vpns, rules });
              toast(r.rule ? 'Route "' + r.rname + '" created' : 'VPNs set to full (nested) — bring them up in order on the VPN page', 'ok');
              close();
              if (onDone) onDone();
            } catch (e) { /* api toasted */ }
          },
        },
      ],
    });
  });
}

/* ================================================================
 * 4e-bis. RouteBuilder — visual drag-free chain builder: start from
 *          "this machine", add VPN/proxy hops one by one, pick scope,
 *          and create the route (proxy chain + rule) in one click.
 * ================================================================ */
function hostOnlyJS(addr) { const a = String(addr || ''); const i = a.lastIndexOf(':'); return i > 0 && !a.endsWith(']') ? a.slice(0, i).replace(/^\[|\]$/g, '') : a; }

Pages.routebuilder = {
  title: 'RouteBuilder',
  hops: [],
  scope: 'all',
  async mount(root) {
    this.root = root;
    this.hops = [];
    this.scope = 'all';
    const [pr, vp, ru, pc] = await Promise.all([
      api('GET', '/api/proxies', undefined, { silent: true }).catch(() => ({ proxies: [] })),
      api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
      api('GET', '/api/rules', undefined, { silent: true }).catch(() => ({ rules: [] })),
      api('GET', '/api/processes', undefined, { silent: true }).catch(() => ({ processes: [] })),
    ]);
    if (!root.isConnected) return;
    this.proxies = pr.proxies || [];
    this.vpns = (vp.vpns || []).map(v => (v && v.config) ? v.config : v);
    this.rules = ru.rules || [];
    this.proxyNames = this.proxies.map(p => p.name).filter(Boolean);
    this.vpnNames = this.vpns.map(v => v.name).filter(Boolean);
    this.vpnEndpoints = {};
    (vp.vpns || []).forEach(v => { if (v && v.endpoint) this.vpnEndpoints[v.name] = v.endpoint; });
    this.setFullTunnel(vp.vpns);
    this.geo = {};
    this.procs = pc.processes || [];

    root.append(h('div', { class: 'page-head' }, h('h2', null, 'RouteBuilder'),
      h('span', { class: 'muted small' }, 'build a traffic path visually: this machine → hop → hop → internet'),
      h('span', { class: 'spacer' }),
      btn('Clear', () => { this.hops = []; this.render(); }),
      this.liveBtn = btn('Live test', () => this.liveTest(), '', { title: 'dial a sample host through this chain now and show the real exit IP' }),
      this.createBtn = btn('Create route', () => this.create(), 'primary')));

    // scope
    this.nameIn = textInput('', { placeholder: 'route name (optional)' });
    this.appsIn = tagsInput({ placeholder: 'firefox, tag:work', list: 'dl-apps' });
    this.targetsIn = tagsInput({ placeholder: '*.example.com, lan', list: 'dl-targets' });
    root.append(
      h('datalist', { id: 'dl-apps' }, ...uniq(this.procs.map(p => p.name)).sort().map(n => h('option', { value: n }))),
      h('datalist', { id: 'dl-targets' }, h('option', { value: 'lan' }), h('option', { value: '*' })));
    const allRadio = h('input', { type: 'radio', name: 'rb-scope', checked: true });
    const appRadio = h('input', { type: 'radio', name: 'rb-scope' });
    allRadio.addEventListener('change', () => { this.scope = 'all'; this.syncScope(); });
    appRadio.addEventListener('change', () => { this.scope = 'app'; this.syncScope(); });
    const addApp = n => { const cur = this.appsIn.getValues(); if (!cur.includes(n)) this.appsIn.setValues(cur.concat(n)); };
    const pickBtn = btn('Choose app…', () => pickAppModal(addApp), 'tiny', { title: 'pick from installed apps or running processes' });
    const appsControl = h('div', { class: 'rb-apps' }, this.appsIn, pickBtn);
    this.scopeFields = h('div', { class: 'rb-scope-fields', hidden: true },
      h('div', { class: 'form-grid' },
        field('Apps', appsControl, 'don\u2019t know the name? press “Choose app” — lists your installed apps'),
        field('Sites / targets', this.targetsIn, 'empty = any site')));
    root.append(h('div', { class: 'card rb-scope-card' },
      h('div', { class: 'card-title' }, 'Apply to'),
      h('div', { class: 'form-row', style: { gap: '18px' } },
        h('label', { class: 'check' }, allRadio, h('span', null, 'All traffic')),
        h('label', { class: 'check' }, appRadio, h('span', null, 'Specific apps / sites'))),
      this.scopeFields,
      h('div', { class: 'form-row', style: { marginTop: '8px' } }, field('Route name', this.nameIn))));

    this.canvas = h('div', { class: 'rb-canvas' });
    root.append(h('div', { class: 'rb-canvas-wrap' }, this.canvas));
    this.note = h('div', { class: 'info-box small' });
    root.append(this.note);
    this.probeBox = h('div', { class: 'rb-probe' });
    root.append(this.probeBox);
    this.render();
  },
  unmount() { this.root = null; this.canvas = null; },
  syncScope() { this.scopeFields.hidden = this.scope !== 'app'; },
  // The full-mode VPN that is up right now (owns the default route). Every
  // chain without its own VPN hop physically leaves through it, so the canvas
  // shows it as an implicit first hop instead of lying "straight out".
  setFullTunnel(vpns) {
    const ft = (vpns || []).find(v => v && v.state === 'up' && (v.mode || (v.config && v.config.mode)) === 'full');
    this.fullTunnel = ft ? { name: ft.name, endpoint: ft.endpoint, external: !!ft.external } : null;
  },
  onEvent(type) {
    if (type !== 'vpn' || !this.root) return;
    api('GET', '/api/vpn', undefined, { silent: true }).then(vp => {
      const before = this.fullTunnel && this.fullTunnel.name;
      this.setFullTunnel(vp.vpns);
      if ((this.fullTunnel && this.fullTunnel.name) !== before && this.canvas) this.render();
    }).catch(() => {});
  },

  render() {
    clear(this.canvas);
    // start node — clickable to add the first/next hop
    this.canvas.append(this.nodeEl({ kind: 'client', label: 'this machine', sub: 'start here' }, () => this.addHop()));
    const explicitVpn = this.hops.some(x => x.kind === 'vpn');
    if (this.fullTunnel && !explicitVpn) {
      this.canvas.append(this.arrow());
      const g = this.fullTunnel.endpoint ? this.geo[hostOnlyJS(this.fullTunnel.endpoint)] : null;
      const flag = (g && g.flag) ? g.flag + ' ' : '';
      const el = this.nodeEl({ kind: 'vpn', label: flag + '🔒 ' + this.fullTunnel.name, sub: 'full tunnel · active — all traffic exits here' + (this.fullTunnel.external ? ' (external)' : '') });
      el.classList.add('rb-implicit');
      el.title = 'Implicit hop: this VPN is up in full mode and owns the default route, so every route without its own VPN hop goes through it. Add an explicit VPN hop to bypass it, or bring it down on the VPN page.';
      this.canvas.append(el);
    }
    this.hops.forEach((hp, i) => {
      this.canvas.append(this.arrow());
      const meta = hp.kind === 'vpn'
        ? this.vpns.find(v => v.name === hp.name)
        : this.proxies.find(p => p.name === hp.name);
      const baseSub = hp.kind === 'vpn' ? (meta ? (meta.type || 'vpn') + ' · ' + (meta.mode || '') : 'vpn')
        : (meta ? (meta.type || 'proxy') + (meta.addr ? ' · ' + meta.addr : '') : 'proxy');
      const host = this.geoHostFor(hp);
      const g = host ? this.geo[host] : null;
      const flag = (g && g.flag) ? g.flag + ' ' : '';
      const sub = (g && g.country) ? (g.flag ? '' : '') + g.country + (g.city ? ', ' + g.city : '') : baseSub;
      this.canvas.append(this.nodeEl({ kind: hp.kind, label: flag + hp.name, sub }, null, i));
    });
    // add box
    this.canvas.append(this.arrow());
    this.canvas.append(h('div', { class: 'rb-add', onClick: () => this.addHop() },
      h('div', { class: 'rb-add-plus' }, '+'), h('div', { class: 'rb-add-t' }, 'Add proxy / VPN')));
    this.canvas.append(this.arrow());
    this.canvas.append(this.nodeEl({ kind: 'internet', label: 'internet', sub: 'destination' }));
    this.renderNote();
    this.ensureGeo();
  },
  arrow() { return h('div', { class: 'rb-arrow', 'aria-hidden': 'true' }, '→'); },
  nodeEl(n, onClick, hopIdx) {
    const glyph = { client: '◉', vpn: '⦿', proxy: '▸', internet: '☁' }[n.kind] || '●';
    const el = h('div', { class: 'rb-node rb-' + n.kind + (onClick ? ' clickable' : '') },
      h('div', { class: 'rb-node-ico' }, glyph),
      h('div', { class: 'rb-node-body' },
        h('div', { class: 'rb-node-label' }, n.label),
        h('div', { class: 'rb-node-sub muted' }, n.sub || '')));
    if (onClick) el.addEventListener('click', onClick);
    if (hopIdx !== undefined) {
      el.append(h('div', { class: 'rb-node-ctl' },
        btn('←', () => this.moveHop(hopIdx, -1), 'icon', { disabled: hopIdx === 0, title: 'move left' }),
        btn('→', () => this.moveHop(hopIdx, 1), 'icon', { disabled: hopIdx === this.hops.length - 1, title: 'move right' }),
        btn('✕', () => { this.hops.splice(hopIdx, 1); this.render(); }, 'icon danger', { title: 'remove' })));
    }
    return el;
  },
  moveHop(i, d) { const j = i + d; if (j < 0 || j >= this.hops.length) return; const t = this.hops[i]; this.hops[i] = this.hops[j]; this.hops[j] = t; this.render(); },

  renderNote() {
    const nVpn = this.hops.filter(x => x.kind === 'vpn').length;
    const hasProxy = this.hops.some(x => x.kind === 'proxy');
    clear(this.note);
    if (!this.hops.length) {
      this.note.className = 'info-box small';
      if (this.fullTunnel) this.note.append('With no hops of its own, this route still leaves through ', h('b', null, this.fullTunnel.name), ' — it is up as a ', h('b', null, 'full tunnel'), ' (default route). Add a different VPN hop to bypass it, or bring it down on the ', h('a', { href: '#/vpn' }, 'VPN'), ' page. Click ', h('b', null, 'Add proxy / VPN'), ' to chain more hops after it.');
      else this.note.append('Click ', h('b', null, 'this machine'), ' or ', h('b', null, 'Add proxy / VPN'), ' to drop in your first hop. With no hops, traffic just goes out directly.');
      return;
    }
    if (nVpn >= 2) {
      this.note.className = 'warn-box small';
      this.note.append('Two or more VPNs in one chain: the builder switches them to ', h('b', null, 'full'), ' mode (nested tunnels — the second runs inside the first). After creating the route, bring these VPNs up in order on the ', h('a', { href: '#/vpn' }, 'VPN'), ' page.');
    } else {
      this.note.className = 'info-box small';
      this.note.append('Traffic will go ', nVpn ? 'through the VPN' : (this.fullTunnel ? 'through ' + this.fullTunnel.name + ' (full tunnel)' : 'straight out'), hasProxy ? ', then through the proxy' : '', ', then on to the site. Press ', h('b', null, 'Create route'), ' when it looks right.');
    }
  },

  addHop() {
    const vpnSel = sel([{ value: '', label: '— choose VPN —' }, ...this.vpnNames]);
    const proxySel = sel([{ value: '', label: '— choose proxy —' }, ...this.proxyNames]);
    let kind = 'vpn';
    const vpnRadio = h('input', { type: 'radio', name: 'rb-add', checked: true });
    const proxyRadio = h('input', { type: 'radio', name: 'rb-add' });
    const vpnField = field('VPN', vpnSel);
    const proxyField = field('Proxy', h('div', { class: 'form-row', style: { flexWrap: 'nowrap' } }, proxySel,
      btn('+ new', () => {
        openProxyForm({
          proxy: null, candidates: this.proxies, vpnNames: this.vpnNames, title: 'Add proxy', submitLabel: 'Add',
          onSubmit: (np) => {
            if (this.proxies.some(q => q.name === np.name)) return 'A proxy named "' + np.name + '" already exists';
            this.proxies.push(np); this.proxyNames.push(np.name);
            proxySel.append(h('option', { value: np.name }, np.name)); proxySel.value = np.name;
            return '';
          },
        });
      }, 'tiny')));
    const syncKind = () => { vpnField.hidden = kind !== 'vpn'; proxyField.hidden = kind !== 'proxy'; };
    vpnRadio.addEventListener('change', () => { kind = 'vpn'; syncKind(); });
    proxyRadio.addEventListener('change', () => { kind = 'proxy'; syncKind(); });
    syncKind();
    const noVpns = !this.vpnNames.length, noProxies = !this.proxyNames.length;
    const body = h('div', null,
      h('div', { class: 'form-row', style: { gap: '18px', marginBottom: '8px' } },
        h('label', { class: 'check' }, vpnRadio, h('span', null, 'VPN')),
        h('label', { class: 'check' }, proxyRadio, h('span', null, 'Proxy'))),
      vpnField, proxyField,
      (noVpns || noProxies) ? h('div', { class: 'muted small', style: { marginTop: '6px' } },
        noVpns ? 'No VPNs yet — import one on the VPN page. ' : '', noProxies ? 'No proxies yet — use “+ new”.' : '') : null);
    openModal({
      title: 'Add hop', width: '460px', body, buttons: [
        { label: 'Cancel' },
        {
          label: 'Add', cls: 'primary', onClick: (close) => {
            if (kind === 'vpn') {
              if (!vpnSel.value) { toast('Choose a VPN', 'error'); return; }
              this.hops.push({ kind: 'vpn', name: vpnSel.value });
            } else {
              if (!proxySel.value) { toast('Choose a proxy', 'error'); return; }
              this.hops.push({ kind: 'proxy', name: proxySel.value });
            }
            this.render(); close();
          },
        },
      ],
    });
  },

  geoHostFor(hp) {
    const strip = a => String(a || '').replace(/:\d+$/, '');
    if (hp.kind === 'proxy') { const p = this.proxies.find(x => x.name === hp.name); return p ? strip(p.addr) : ''; }
    return strip(this.vpnEndpoints[hp.name] || '');
  },
  async ensureGeo() {
    const hosts = uniq(this.hops.map(h => this.geoHostFor(h)).filter(Boolean)).filter(h => !(h in this.geo));
    if (!hosts.length) return;
    hosts.forEach(h => { this.geo[h] = null; }); // mark in-flight
    await Promise.all(hosts.map(async h => {
      try { this.geo[h] = await api('GET', '/api/geo/' + encodeURIComponent(h), undefined, { silent: true }); }
      catch (_) { this.geo[h] = {}; }
    }));
    if (this.canvas && this.root && this.root.isConnected) this.render();
  },
  async liveTest() {
    if (!this.hops.length) { toast('Add at least one hop first', 'error'); return; }
    const host = (this.scope === 'app' && this.targetsIn.getValues()[0]) || 'api.ipify.org';
    replace(this.probeBox, h('div', { class: 'muted', style: { padding: '8px 0' } }, h('span', { class: 'spinner' }), ' dialing ' + host + ' through the chain…'));
    this.liveBtn.disabled = true;
    let r;
    try { r = await api('POST', '/api/route/probe', { hops: this.hops, host }, { silent: true }); }
    catch (e) { replace(this.probeBox, h('div', { class: 'error-box' }, e.message)); this.liveBtn.disabled = false; return; }
    this.liveBtn.disabled = false;
    const chain = ['this machine', ...(r.vpn ? ['\uD83D\uDD12 ' + r.vpn] : []), ...((r.hops || [])), 'exit'];
    let res;
    if (r.ok) res = h('div', { class: 'ok-box', style: { marginTop: '6px' } },
      '\u2713 reached the internet in ', h('strong', null, fmt.ms(r.latency_ms)), '. Exit IP ', h('strong', { class: 'mono' }, r.exit_ip || '?'),
      (r.flag || r.country) ? [' ', r.flag || '', ' ', r.country || '', r.city ? ', ' + r.city : '', r.isp ? ' \u00b7 ' + r.isp : ''] : null);
    else res = h('div', { class: 'error-box', style: { marginTop: '6px' } }, '\u2717 ' + (r.error || 'route failed'));
    replace(this.probeBox, h('div', { class: 'hop-preview mono' }, chain.join('  \u2192  ')), res);
  },
  async create() {
    if (!this.hops.length) { toast('Add at least one hop first', 'error'); return; }
    this.createBtn.disabled = true;
    try {
      const r = await assembleAndSaveRoute({
        name: this.nameIn.value,
        apps: this.scope === 'app' ? this.appsIn.getValues() : [],
        targets: this.scope === 'app' ? this.targetsIn.getValues() : [],
        hops: this.hops, proxies: this.proxies, vpns: this.vpns, rules: this.rules,
      });
      toast(r.rule ? 'Route "' + r.rname + '" created — see it on the Rules page' : 'VPNs set to full (nested) — bring them up in order on the VPN page', 'ok');
      // refresh local state so further edits build on the new config
      const [pr, ru] = await Promise.all([api('GET', '/api/proxies', undefined, { silent: true }), api('GET', '/api/rules', undefined, { silent: true })]);
      this.proxies = pr.proxies || []; this.proxyNames = this.proxies.map(p => p.name).filter(Boolean);
      this.rules = ru.rules || [];
      this.hops = []; this.render();
    } catch (_) { /* toasted */ }
    finally { this.createBtn.disabled = false; }
  },
};

/* ================================================================
 * 4f. VPN
 * ================================================================ */
/* vpnModal — create or edit one VPN profile in a window. Persists immediately. */
function vpnModal({ page, profile, index }) {
  const isNew = index < 0;
  const base = { name: '', type: 'wireguard', config: '', mode: 'full', autostart: false, auth_file: '',
    extra_args: [], interface: '', comment: '', kill_switch: false, reconnect: false, username: '', password: '' };
  const c = Object.assign({}, base, JSON.parse(JSON.stringify((profile && profile.config) || {})));
  if (!Array.isArray(c.extra_args)) c.extra_args = [];
  if (isNew && !c.name) c.name = 'vpn' + (page.list.length + 1);
  if (isNew && !c.config) c.config = '/etc/cyberboba/vpn/' + c.name + '.conf';

  const name = textInput(c.name, { class: 'mono' });
  const type = sel(['wireguard', 'openvpn'], c.type || 'wireguard');
  const mode = sel([{ value: 'full', label: 'full — classic VPN: becomes the default route for everything' }, { value: 'selective', label: 'selective — only traffic sent here by a rule (needs rules!)' }], c.mode || 'full');
  const cfgPath = textInput(c.config, { class: 'mono', placeholder: '/etc/cyberboba/vpn/name.conf' });
  const iface = textInput(c.interface, { class: 'mono', placeholder: 'override interface name (optional)' });
  const comment = textInput(c.comment, { placeholder: 'optional note' });
  const auto = checkbox('Autostart with the daemon', !!c.autostart);
  const killSw = checkbox('Kill switch — block all outbound traffic when the tunnel drops (full mode)', !!c.kill_switch);
  const reconnect = checkbox('Reconnect automatically if the backend exits', !!c.reconnect);
  const authFile = textInput(c.auth_file, { class: 'mono', placeholder: 'OpenVPN auth-user-pass file (optional)' });
  const username = textInput(c.username, { class: 'mono', placeholder: 'OpenVPN username', autocomplete: 'off' });
  const password = h('input', { type: 'password', class: 'mono', value: c.password || '', placeholder: 'OpenVPN password', autocomplete: 'new-password' });
  const showPw = btn('show', () => { password.type = password.type === 'password' ? 'text' : 'password'; }, 'tiny', { tabindex: -1 });

  const ovOnly = h('div', null,
    field('Auth file', authFile, 'OpenVPN auth-user-pass file; username/password below take precedence'),
    h('div', { class: 'form-grid' },
      field('Username', username, 'written to a 0600 auth file at start'),
      field('Password', h('div', { class: 'form-row', style: { flexWrap: 'nowrap' } }, password, showPw))));
  const cfgHint = h('div', { class: 'hint' });
  const syncType = () => {
    ovOnly.hidden = type.value !== 'openvpn';
    cfgHint.textContent = type.value === 'wireguard' ? 'WireGuard .conf (wg-quick). Tip: use Import to paste the config and create the file for you.' : 'OpenVPN .ovpn/.conf path.';
  };
  type.addEventListener('change', syncType); syncType();

  const body = h('div', null,
    isNew ? h('div', { class: 'info-box small' }, 'This creates a profile that points at a config file already on disk. To paste a new WireGuard/OpenVPN config, use ', h('b', null, 'Import…'), ' instead.') : null,
    h('div', { class: 'form-grid' }, field('Name', name, 'a label you choose'), field('Type', type)),
    field('Mode', mode),
    h('div', { class: 'field' }, h('label', { class: 'field-label' }, 'Config file'), cfgPath, cfgHint),
    h('div', { class: 'form-grid' }, field('Interface', iface), field('Comment', comment)),
    ovOnly,
    h('div', { class: 'form-row', style: { marginTop: '6px', flexWrap: 'wrap', gap: '10px' } }, auto, killSw, reconnect));

  openModal({
    title: isNew ? 'Add VPN profile' : 'Edit VPN profile', width: '600px', body, buttons: [
      { label: 'Cancel' },
      {
        label: isNew ? 'Add' : 'Save', cls: 'primary', onClick: async (close) => {
          const nv = name.value.trim();
          if (!nv) { toast('Name is required', 'error'); return; }
          if (type.value === 'wireguard' && !/\.conf$/.test(cfgPath.value.trim())) { toast('WireGuard config file must end with .conf', 'error'); return; }
          if (page.list.some((v, j) => j !== index && v.name === nv)) { toast('A VPN named "' + nv + '" already exists', 'error'); return; }
          const out = { name: nv, type: type.value, config: cfgPath.value.trim(), mode: mode.value,
            autostart: auto.input.checked, auth_file: authFile.value.trim(), extra_args: c.extra_args,
            interface: iface.value.trim(), comment: comment.value.trim(), kill_switch: killSw.input.checked,
            reconnect: reconnect.input.checked, username: username.value, password: password.value };
          const ok = await page.persistProfile(out, index);
          if (ok) close();
        },
      },
    ],
  });
}

/* vpnRotationManager — manage VPN rotations (cycle the active tunnel). */
async function vpnRotationManager(onDone) {
  const [vr, vp] = await Promise.all([
    api('GET', '/api/vpn/rotations', undefined, { silent: true }).catch(() => ({ rotations: [] })),
    api('GET', '/api/vpn', undefined, { silent: true }).catch(() => ({ vpns: [] })),
  ]);
  const vpnNames = (vp.vpns || []).map(v => v.name).filter(Boolean);
  let rots = JSON.parse(JSON.stringify(vr.rotations || []));
  const listEl = h('div', { class: 'rot-list' });
  function render() {
    clear(listEl);
    if (!rots.length) listEl.append(h('div', { class: 'muted small' }, 'No rotations. Add one below.'));
    rots.forEach((r, i) => {
      const name = textInput(r.name, { class: 'mono', placeholder: 'rotation name' }); name.addEventListener('input', () => r.name = name.value.trim());
      const en = checkbox('on', r.enabled !== false); en.input.addEventListener('change', () => r.enabled = en.input.checked);
      const members = h('select', { multiple: true, class: 'mono', size: Math.min(6, Math.max(3, vpnNames.length || 3)) });
      replace(members, ...vpnNames.map(n => h('option', { value: n, selected: (r.vpns || []).includes(n) }, n)));
      if (!vpnNames.length) members.append(h('option', { value: '', disabled: true }, '(no VPN profiles)'));
      members.addEventListener('change', () => r.vpns = Array.from(members.selectedOptions).map(o => o.value).filter(Boolean));
      const every = h('input', { type: 'number', min: 1, value: r.every_sec || 300, class: 'mono', style: { width: '90px' } }); every.addEventListener('input', () => r.every_sec = num(every.value) || 300);
      const mode = sel([{ value: 'random', label: 'random' }, { value: 'sequential', label: 'sequential' }], r.mode || 'random'); mode.addEventListener('change', () => r.mode = mode.value);
      listEl.append(h('div', { class: 'rot-card' },
        h('div', { class: 'form-row', style: { gap: '10px', alignItems: 'center' } }, en, field('Name', name), btn('✕', () => { rots.splice(i, 1); render(); }, 'tiny danger', { title: 'delete' })),
        field('Members (Ctrl/⌘-click several)', members),
        h('div', { class: 'form-grid' }, field('Rotate every (s)', every), field('Mode', mode))));
    });
  }
  render();
  openModal({
    title: 'VPN rotations', width: '560px',
    body: h('div', null,
      h('div', { class: 'info-box small', style: { marginBottom: '8px' } }, 'A rotation cycles the ', h('b', null, 'active tunnel'), ' among its members every interval. Point a rule (action VPN) at the rotation name. Switching re-handshakes, so keep the interval reasonable (tens of seconds+).'),
      listEl,
      h('div', { style: { marginTop: '8px' } }, btn('+ Add rotation', () => { rots.push({ name: 'rotation' + (rots.length + 1), enabled: true, vpns: [], every_sec: 300, mode: 'random' }); render(); }, 'tiny'))),
    buttons: [
      { label: 'Cancel' },
      { label: 'Save', cls: 'primary', onClick: async (close) => {
        for (const r of rots) { if (!r.name) { toast('Every rotation needs a name', 'error'); return; } if (!(r.vpns && r.vpns.length)) { toast('Rotation "' + r.name + '" needs members', 'error'); return; } }
        try { await api('PUT', '/api/vpn/rotations', { rotations: rots }); toast('VPN rotations saved', 'ok'); close(); if (onDone) onDone(); }
        catch (_) { /* shown */ }
      } },
    ],
  });
}

Pages.vpn = {
  title: 'VPN',
  async mount(root) {
    this.root = root;
    let r; try { r = await api('GET', '/api/vpn'); } catch (_) { return; }
    if (!root.isConnected) return;
    this.list = this.normalize(r.vpns);
    await this.loadRuleRefs();
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'VPN'),
      h('span', { class: 'muted small' }, 'WireGuard & OpenVPN tunnels'),
      h('span', { class: 'spacer' }),
      btn('Import…', () => this.importDialog(), 'primary'),
      btn('+ Add profile', () => vpnModal({ page: this, index: -1 })),
      btn('Rotations…', () => vpnRotationManager(() => this.reload())),
      btn('Reload', () => this.reload())));
    root.append(h('div', { class: 'info-box small' },
      h('b', null, 'Import…'), ' pastes a .conf/.ovpn and creates the profile. ',
      h('b', null, 'selective'), ' = only traffic a rule sends here uses the tunnel; ',
      h('b', null, 'full'), ' = the tunnel becomes the default route for everything. ',
      'To send specific apps/sites through a VPN, use ', h('b', null, '+ New route'), ' on the ', h('a', { href: '#/rules' }, 'Rules'), ' page.'));
    this.rotEl = h('div', { class: 'vpn-rot-strip' });
    root.append(this.rotEl);
    this.loadRotations();
    this.rotTimer = setInterval(() => this.loadRotations(), 3000);
    this.listEl = h('div', { class: 'vpn-list' });
    root.append(this.listEl);
    this.renderAll();
    this.timer = setInterval(() => this.poll(), 5000);
  },
  unmount() { clearInterval(this.timer); clearInterval(this.logTimer); clearInterval(this.rotTimer); this.root = null; this.listEl = null; },
  async loadRotations() {
    const r = await api('GET', '/api/vpn/rotations', undefined, { silent: true }).catch(() => null);
    if (!r || !this.rotEl) return;
    const st = r.status || [];
    clear(this.rotEl);
    if (!st.length) return;
    this.rotEl.append(h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'VPN rotations', h('span', { class: 'spacer' }), btn('Manage…', () => vpnRotationManager(() => this.reload()), 'tiny')),
      ...st.map(rs => h('div', { class: 'vpn-rot-row' },
        rs.enabled ? badge('on', 'green') : badge('off', 'gray'),
        h('b', null, rs.name), ' → ', h('span', { class: 'rot-active mono' }, rs.current || '(starting)'),
        h('span', { class: 'muted small' }, '  ' + (rs.members || []).join(', ') + ' · every ' + rs.every_sec + 's · ' + rs.mode + (rs.enabled ? ' · next ' + rs.next_in_sec + 's' : ''))))));
  },
  normalize(vpns) {
    return (vpns || []).map(v => {
      const cfg = Object.assign({ name: v.name, type: v.type || 'wireguard', config: '', mode: v.mode || 'full', autostart: false, auth_file: '', extra_args: [], interface: '', comment: '',
        kill_switch: false, reconnect: false, username: '', password: '' }, v.config || {});
      if (!Array.isArray(cfg.extra_args)) cfg.extra_args = [];
      return Object.assign({}, v, { config: cfg });
    });
  },
  async reload() {
    let r; try { r = await api('GET', '/api/vpn'); } catch (_) { return; }
    this.list = this.normalize(r.vpns); await this.loadRuleRefs(); this.renderAll();
  },
  // Names of VPNs some enabled rule (or rotation) actually routes traffic to.
  async loadRuleRefs() {
    this.ruleRefs = new Set();
    try {
      const rr = await api('GET', '/api/rules', undefined, { silent: true });
      for (const rule of (rr && rr.rules) || []) if (rule.action === 'vpn' && rule.vpn && rule.enabled !== false) this.ruleRefs.add(rule.vpn);
      const rot = await api('GET', '/api/vpn/rotations', undefined, { silent: true }).catch(() => null);
      for (const rs of (rot && rot.status) || []) if (this.ruleRefs.has(rs.name)) for (const m of rs.members || []) this.ruleRefs.add(m);
    } catch (_) { /* ignore */ }
  },
  // Switch a profile to full mode in place (re-up if it was up).
  async switchToFull(v) {
    const profiles = this.list.map(x => x === v ? Object.assign({}, x.config, { mode: 'full' }) : x.config);
    try {
      await api('PUT', '/api/vpn', { vpns: profiles });
      if (v.state === 'up' && !v.external) { await vpnUpDown(v.name, false).catch(() => {}); await vpnUpDown(v.name, true).catch(() => {}); }
      toast(v.name + ' is now a full tunnel — all traffic goes through it while it is up', 'ok');
      await this.reload();
    } catch (_) { /* shown */ }
  },
  async persistProfile(cfg, index) {
    const profiles = this.list.map(v => v.config);
    if (index < 0) profiles.push(cfg); else profiles[index] = cfg;
    try {
      await api('PUT', '/api/vpn', { vpns: profiles });
      toast('VPN profile saved', 'ok');
      await this.reload();
      return true;
    } catch (_) { return false; }
  },
  async poll() {
    let r; try { r = await api('GET', '/api/vpn', undefined, { silent: true }); } catch (_) { return; }
    if (!this.listEl) return;
    for (const v of r.vpns || []) this.updateStatus(v);
  },
  updateStatus(v) {
    const cur = this.list.find(x => x.name === v.name);
    if (!cur) return;
    const cfg = cur.config;
    Object.assign(cur, v); cur.config = cfg;
    const card = this.listEl.querySelector('[data-vpn="' + CSS.escape(v.name) + '"]');
    if (card) {
      const st = this.statusBlock(cur), bd = vpnStateBadge(cur), bt = this.actionBtns(cur);
      card._status.replaceWith(st); card._status = st;
      card._badge.replaceWith(bd); card._badge = bd;
      card._btns.replaceWith(bt); card._btns = bt;
    }
  },
  renderAll() {
    clear(this.listEl);
    if (!this.list.length) this.listEl.append(emptyState('No VPN profiles yet',
      ['Add a WireGuard or OpenVPN tunnel. The quickest way is ', h('b', null, 'Import'), ' — paste a ', h('code', null, '.conf'), '/', h('code', null, '.ovpn'), ' and cyberboba creates the profile for you.'],
      { actions: [btn('Import…', () => this.importDialog(), 'primary'), btn('+ Add profile', () => vpnModal({ page: this, index: -1 }))] }));
    for (const v of this.list) this.listEl.append(this.card(v));
  },
  card(v) {
    const el = h('div', { class: 'card vpn-card', dataset: { vpn: v.name } });
    const badgeEl = vpnStateBadge(v);
    const idx = this.list.indexOf(v);
    el.append(h('div', { class: 'vpn-head' }, h('span', { class: 'vpn-name mono' }, v.name), badge(v.config.type || v.type, 'gray'), badge(v.config.mode || v.mode, 'gray'), badgeEl,
      v.config.comment ? h('span', { class: 'muted small' }, v.config.comment) : null,
      h('span', { class: 'spacer' }),
      btn('Log', () => this.showLog(v.name), 'tiny'),
      btn('Edit', () => vpnModal({ page: this, profile: v, index: this.list.indexOf(v) }), 'tiny'),
      btn('Delete', () => this.del(v), 'tiny danger')));
    const st = this.statusBlock(v); el.append(st);
    const btns = this.actionBtns(v); el.append(btns);
    el._status = st; el._badge = badgeEl; el._btns = btns;
    return el;
  },
  statusBlock(v) {
    const c = v.config || {};
    const mode = c.mode || v.mode || 'full';
    const unrouted = mode === 'selective' && !(this.ruleRefs && this.ruleRefs.has(v.name));
    return h('div', { class: 'vpn-status' },
      v.kill_switch_active ? h('div', { class: 'warn-box', style: { marginBottom: '6px' } }, badge('kill switch active', 'red'), ' outbound traffic is blocked until the tunnel is back up (loopback, LAN and the VPN endpoint stay reachable).') : null,
      unrouted ? h('div', { class: 'warn-box', style: { marginBottom: '6px' } }, badge('nothing uses this VPN', 'yellow'),
        ' it is in ', h('b', null, 'selective'), ' mode but no rule sends traffic to it, so bringing it up changes nothing (your IP stays the same). ',
        btn('Make it a full tunnel', () => this.switchToFull(v), 'tiny primary'), ' ',
        btn('Add a route…', () => { location.hash = '#/rules'; }, 'tiny'),
        ' (full = classic VPN for everything; a route = only chosen apps/sites)') : null,
      v.external ? h('div', { class: 'info-box small', style: { marginBottom: '6px' } }, 'This tunnel was brought up outside cyberboba (wg-quick by hand, a tray helper or NetworkManager). It is shown live here and ', h('b', null, 'Down'), ' takes it down.') : null,
      h('div', { class: 'kv' },
        kv('interface', v.interface), kv('endpoint', v.endpoint),
        kv('local ip', v.local_ip), kv('handshake', isZeroTime(v.last_handshake) ? 'never' : fmt.ago(v.last_handshake)),
        kv('rx / tx', fmt.bytes(v.rx_bytes) + ' / ' + fmt.bytes(v.tx_bytes)), kv('since', v.state === 'up' ? fmt.datetime(v.since) : ''),
        kv('config', c.config), kv('autostart', c.autostart ? 'yes' : 'no'),
        kv('kill switch', c.kill_switch ? (v.kill_switch_active ? h('span', { class: 'bad' }, 'ACTIVE (blocking)') : 'armed') : 'off'),
        kv('reconnects', (c.reconnect ? 'auto · ' : '') + fmt.num(v.reconnects))),
      v.error ? h('div', { class: 'error-box', style: { marginTop: '6px' } }, v.error) : null);
  },
  actionBtns(v) {
    const up = v.state === 'up';
    const busy = v.state === 'connecting' || v.state === 'starting' || v.state === 'stopping';
    return h('div', { class: 'card-actions' },
      btn('Up', () => this.updown(v.name, true), 'ok', { disabled: up || busy }),
      btn('Down', () => this.updown(v.name, false), 'danger', { disabled: !up && !busy }));
  },
  async updown(name, up) {
    let r; try { r = await vpnUpDown(name, up); } catch (_) { return; }
    if (r && r.name) this.updateStatus(r);
    setTimeout(() => this.poll(), 1500);
  },
  async del(v) {
    if (!confirm('Remove VPN profile "' + v.name + '"? (the config file is not deleted)')) return;
    const profiles = this.list.filter(x => x !== v).map(x => x.config);
    try { await api('PUT', '/api/vpn', { vpns: profiles }); toast('VPN profile removed', 'ok'); await this.reload(); }
    catch (_) { /* shown */ }
  },
  showLog(name) {
    const pre = h('div', { class: 'log tall' });
    const auto = checkbox('auto-refresh', true);
    const load = async () => {
      let r; try { r = await api('GET', '/api/vpn/' + encodeURIComponent(name) + '/log', undefined, { silent: true }); }
      catch (e) { replace(pre, h('span', { class: 'bad' }, e.message)); return; }
      const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 20;
      pre.textContent = (r.lines || []).join('\n') || '(empty)';
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    };
    clearInterval(this.logTimer);
    this.logTimer = setInterval(() => { if (auto.input.checked) load(); }, 2000);
    load();
    openModal({ title: 'VPN log · ' + name, width: '760px',
      body: h('div', null, h('div', { class: 'log-toolbar' }, auto, btn('Refresh', load, 'tiny')), pre),
      buttons: [{ label: 'Close' }],
      onClose: () => clearInterval(this.logTimer) });
  },
  importDialog() {
    const name = textInput('', { class: 'mono', placeholder: 'office' });
    const type = sel(['wireguard', 'openvpn'], 'wireguard');
    const mode = sel([{ value: 'full', label: 'full (classic VPN — default route for everything)' }, { value: 'selective', label: 'selective (only rule-routed traffic — needs rules)' }], 'full');
    const content = h('textarea', { class: 'code', rows: 14, placeholder: '[Interface]\nPrivateKey = ...\n\n[Peer]\n...', spellcheck: 'false' });
    const file = h('input', { type: 'file', accept: '.conf,.ovpn,.txt,text/plain' });
    file.addEventListener('change', () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const rd = new FileReader();
      rd.onload = () => {
        content.value = String(rd.result || '');
        if (!name.value) name.value = f.name.replace(/\.(conf|ovpn|txt)$/i, '').replace(/[^A-Za-z0-9_.-]/g, '_');
        if (/\.ovpn$/i.test(f.name) || /^(client|remote |dev tun)/m.test(content.value)) type.value = 'openvpn';
      };
      rd.onerror = () => toast('Could not read file', 'error');
      rd.readAsText(f);
    });
    openModal({ title: 'Import VPN configuration', width: '640px',
      body: h('div', { class: 'tab-panel' },
        h('div', { class: 'form-grid' }, field('Name', name), field('Type', type), field('Mode', mode), field('Config file', file)),
        field('Configuration', content, 'paste the .conf / .ovpn text or choose a file')),
      buttons: [{ label: 'Cancel' }, { label: 'Import', cls: 'primary', onClick: async close => {
        const n = name.value.trim();
        if (!n) { toast('Name is required', 'error'); return; }
        if (!content.value.trim()) { toast('Configuration content is empty', 'error'); return; }
        try { await api('POST', '/api/vpn/import', { name: n, type: type.value, mode: mode.value, content: content.value }); }
        catch (_) { return; }
        toast('Imported VPN profile ' + n, 'ok');
        close();
        this.reload();
      } }] });
  },
  onEvent(type, data) {
    if (type === 'vpn' && data && data.name && this.listEl) {
      if (!this.list.find(x => x.name === data.name)) { this.poll(); return; }
      this.updateStatus(data);
    }
  },
};

/* ================================================================
 * 4f2. Tags (cgroup groups from `cyberboba run -tag`)
 * ================================================================ */
Pages.tags = {
  title: 'Tags',
  async mount(root) {
    this.root = root;
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Tags'),
      h('span', { class: 'muted small' }, 'net_cls cgroup members · refreshed every 3 s'),
      h('span', { class: 'spacer' }), this.countEl = h('span', { class: 'muted small mono' }), btn('Reload', () => this.load(true), 'tiny')));
    root.append(h('div', { class: 'info-box small' },
      'Processes started with ', h('code', null, 'cyberboba run -tag NAME'), ' join a per-tag net_cls cgroup. A rule whose ',
      h('code', null, 'apps'), ' are only ', h('code', null, 'tag:NAME'), ' with action ', badge('vpn', 'green'), ' or ', badge('block', 'red'),
      ' also governs that tag’s UDP traffic (QUIC, games, VoIP), which the transparent TCP proxy cannot see. DNS (UDP/53) keeps going through the forwarder.'));
    this.note = h('div', { class: 'warn-box', hidden: true });
    root.append(this.note);
    this.tbody = h('tbody');
    const table = h('table', { class: 'grid tagsgrid' },
      h('colgroup', null, h('col', { style: { width: '22%' } }), h('col', { style: { width: '22%' } }), h('col', { style: { width: '18%' } }), h('col', { style: { width: '10%' } }), h('col')),
      h('thead', null, h('tr', null, h('th', null, 'Tag'), h('th', null, 'classid'), h('th', null, 'UDP action'), h('th', { class: 'num' }, 'PIDs'), h('th', null, 'PID list'))),
      this.tbody);
    root.append(h('div', { class: 'table-wrap' }, table));
    await this.load();
    if (!root.isConnected) return;
    this.timer = setInterval(() => this.load(true), 3000);
  },
  unmount() { clearInterval(this.timer); this.root = null; this.tbody = null; },
  async load(silent) {
    let r; try { r = await api('GET', '/api/tags', undefined, { silent }); } catch (_) { return; }
    if (!this.tbody) return;
    this.render(r);
  },
  udpBadge(a) {
    if (!a || a === 'none') return badge('none', 'gray');
    return badge(a, ACTION_CLS[String(a).split(':')[0]] || 'gray');
  },
  render(r) {
    const avail = r.available !== false;
    this.note.hidden = avail;
    if (!avail) replace(this.note, 'Tag routing is unavailable — a net_cls cgroup (root privileges) is required. Run cyberbobad as root to enable tag-based UDP routing.');
    const tags = (r.tags || []).slice();
    clear(this.tbody);
    if (!tags.length) {
      this.tbody.append(h('tr', null, h('td', { colspan: 5 }, avail
        ? emptyState('No active tags',
          ['Launch a program with ', h('code', null, 'cyberboba run -tag NAME'), ' to drop it into a tagged group. Rules targeting ', h('code', null, 'tag:NAME'), ' can then govern its UDP traffic too — handy for games, VoIP and QUIC.'],
          { cls: 'small' })
        : emptyState('Tag routing needs root',
          'A net_cls cgroup requires root privileges. Run cyberbobad as root to enable tag-based UDP routing.',
          { cls: 'small' }))));
    }
    for (const t of tags) {
      const pids = Array.isArray(t.pids) ? t.pids : [];
      const shown = pids.slice(0, 16).join(', ') + (pids.length > 16 ? ' … (+' + (pids.length - 16) + ')' : '');
      this.tbody.append(h('tr', null,
        h('td', { class: 'mono' }, t.tag || ''),
        h('td', { class: 'mono' }, t.classid || ''),
        h('td', null, this.udpBadge(t.udp_action)),
        h('td', { class: 'num mono' }, String(pids.length)),
        h('td', { class: 'mono', title: pids.length ? pids.join(', ') : 'no live processes' }, pids.length ? shown : '—')));
    }
    this.countEl.textContent = tags.length + (avail ? '' : ' (unavailable)');
  },
};

/* ================================================================
 * 4f-bis. Traffic map — visual model of how traffic flows through
 *          chained VPNs/proxies to its destination (with geo).
 * ================================================================ */
const TG_KIND = {
  client:   { glyph: '◉', label: 'this machine' },
  intercept:{ glyph: '▣', label: 'intercept' },
  vpn:      { glyph: '⦿', label: 'VPN' },
  proxy:    { glyph: '▸', label: 'proxy' },
  dest:     { glyph: '◆', label: 'destination' },
  internet: { glyph: '☁', label: 'internet' },
  blocked:  { glyph: '⊘', label: 'blocked' },
};
const TG_COLW = 210, TG_BOXW = 158, TG_BOXH = 58, TG_GAPY = 20, TG_PADX = 24, TG_PADY = 24;

Pages.traffic = {
  title: 'Traffic',
  view: 'live',
  sel: null,
  graph: null,
  async mount(root) {
    this.root = root;
    this.reload = debounce(() => this.load(true), 700);
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'Traffic'),
      h('span', { class: 'muted small' }, 'how traffic flows: this machine → VPNs → proxies → destination'),
      h('span', { class: 'spacer' }),
      this.geoNote = h('span', { class: 'muted small' }),
      btn('Reload', () => this.load(), 'tiny')));
    this.legend = h('div', { class: 'tg-legend small muted' });
    root.append(this.legend);
    this.renderLegend();
    this.ftNote = h('div', { class: 'info-box small', hidden: true });
    root.append(this.ftNote);
    this.mapWrap = h('div', { class: 'tg-map' });
    this.side = h('div', { class: 'tg-side' });
    root.append(h('div', { class: 'tg-layout' }, this.mapWrap, this.side));
    await this.load();
    if (!root.isConnected) return;
    this.timer = setInterval(() => this.load(true), 4000);
    // quick follow-up polls so async geo lookups fill in promptly
    setTimeout(() => root.isConnected && this.load(true), 1500);
    setTimeout(() => root.isConnected && this.load(true), 3200);
  },
  unmount() { clearInterval(this.timer); this.root = this.mapWrap = this.side = null; },
  onEvent(type) { if (type === 'conn' || type === 'vpn' || type === 'stats') this.reload && this.reload(); },

  renderLegend() {
    const item = (kind, text) => h('span', { class: 'tg-leg' },
      h('span', { class: 'tg-dot tg-' + kind }), text);
    replace(this.legend,
      item('client', 'this machine'), item('vpn', 'VPN'), item('proxy', 'proxy'),
      item('intercept', 'intercept'), item('dest', 'destination'), item('blocked', 'blocked'),
      h('span', { class: 'tg-leg' }, h('span', { class: 'tg-flow-leg' }), 'live flow'));
  },

  async load(silent) {
    let g; try { g = await api('GET', '/api/topology', undefined, { silent }); } catch (_) { return; }
    if (!this.mapWrap) return;
    this.graph = g;
    if (this.ftNote) {
      if (g.full_tunnel) { replace(this.ftNote, '\uD83D\uDD12 All traffic that is not pinned to another VPN currently leaves through ', h('b', null, g.full_tunnel), ' (full tunnel, default route) \u2014 it is drawn as the first hop of every such chain.'); this.ftNote.hidden = false; }
      else this.ftNote.hidden = true;
    }
    this.geoNote.textContent = g.geo_enabled ? '' : 'geo lookups off (geo.enabled)';
    this.renderMap();
    this.renderSide();
  },

  /* assign each node a column (depth from "this") and a row within it */
  layout(g) {
    const byId = {}; (g.nodes || []).forEach(n => byId[n.id] = n);
    const depth = {}; Object.keys(byId).forEach(id => depth[id] = (id === 'this') ? 0 : -1);
    const out = {}; (g.edges || []).forEach(e => { (out[e.from] = out[e.from] || []).push(e.to); });
    // longest-path relaxation (graph is a DAG from "this" to terminals)
    for (let pass = 0; pass < (g.nodes || []).length + 2; pass++) {
      (g.edges || []).forEach(e => {
        if (depth[e.from] >= 0 && depth[e.to] < depth[e.from] + 1) depth[e.to] = depth[e.from] + 1;
      });
    }
    let maxD = 0;
    Object.keys(depth).forEach(id => { if (depth[id] > maxD) maxD = depth[id]; });
    // unreached nodes (e.g. an up VPN not yet routed) sit one step from client
    Object.keys(depth).forEach(id => { if (depth[id] < 0) depth[id] = 1; });
    // terminals always in the rightmost column
    (g.nodes || []).forEach(n => { if (n.kind === 'dest' || n.kind === 'internet' || n.kind === 'blocked') depth[n.id] = Math.max(maxD, 1); });
    maxD = 0; Object.keys(depth).forEach(id => { if (depth[id] > maxD) maxD = depth[id]; });
    const cols = [];
    for (let i = 0; i <= maxD; i++) cols.push([]);
    (g.nodes || []).forEach(n => cols[depth[n.id]].push(n));
    const pos = {};
    cols.forEach((col, ci) => {
      col.sort((a, b) => (b.conns || 0) - (a.conns || 0) || String(a.label).localeCompare(String(b.label)));
      col.forEach((n, ri) => {
        pos[n.id] = { x: TG_PADX + ci * TG_COLW, y: TG_PADY + ri * (TG_BOXH + TG_GAPY), col: ci, row: ri };
      });
    });
    const rows = Math.max(1, ...cols.map(c => c.length));
    const width = TG_PADX * 2 + maxD * TG_COLW + TG_BOXW;
    const height = TG_PADY * 2 + rows * (TG_BOXH + TG_GAPY);
    return { pos, width, height, byId };
  },

  renderMap() {
    const g = this.graph || {};
    clear(this.mapWrap);
    if (!g.nodes || !g.nodes.length) { this.mapWrap.append(emptyState('Nothing to map yet',
      'This diagram draws itself from your live connections and enabled rules — this machine on the left, hops in the middle, destinations on the right. It appears as soon as traffic flows or a rule is enabled.',
      { actions: [h('a', { class: 'btn', href: '#/rules' }, 'Set up Rules')] })); return; }
    const L = this.layout(g);
    const root = svg('svg', { class: 'tg-svg', viewBox: '0 0 ' + L.width + ' ' + L.height,
      preserveAspectRatio: 'xMinYMin meet', width: L.width, height: L.height });
    const defs = svg('defs', null,
      (function () { const m = svg('marker', { id: 'tg-arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
        m.appendChild(svg('path', { d: 'M0,0 L10,5 L0,10 z', class: 'tg-arrowhead' })); return m; })());
    root.appendChild(defs);
    const gEdges = svg('g', { class: 'tg-edges' });
    const gDots = svg('g', { class: 'tg-dots' });
    const gNodes = svg('g', { class: 'tg-nodes' });
    root.appendChild(gEdges); root.appendChild(gDots); root.appendChild(gNodes);

    const sel = this.sel;
    const near = id => !sel || sel === id || (g.edges || []).some(e => (e.from === sel && e.to === id) || (e.to === sel && e.from === id));

    (g.edges || []).forEach(e => {
      const a = L.pos[e.from], b = L.pos[e.to];
      if (!a || !b) return;
      const x1 = a.x + TG_BOXW, y1 = a.y + TG_BOXH / 2, x2 = b.x, y2 = b.y + TG_BOXH / 2;
      const d = this.edgePath(x1, y1, x2, y2);
      const dim = sel && !(e.from === sel || e.to === sel);
      const cls = 'tg-edge' + (e.active ? ' active' : '') + (dim ? ' dim' : '');
      gEdges.appendChild(svg('path', { d, class: cls, 'marker-end': 'url(#tg-arrow)',
        'stroke-width': e.active ? Math.min(5, 1.5 + (e.active_conns || 1)) : 1.2 }));
      if (e.active && !dim) {
        const n = Math.min(3, e.active_conns || 1);
        for (let i = 0; i < n; i++) {
          const dot = svg('circle', { r: 3.2, class: 'tg-flow' });
          const anim = svg('animateMotion', { dur: (1.6 + i * 0.25) + 's', repeatCount: 'indefinite', path: d, begin: (i * 0.4) + 's' });
          dot.appendChild(anim);
          gDots.appendChild(dot);
        }
      }
    });

    (g.nodes || []).forEach(n => {
      const p = L.pos[n.id]; if (!p) return;
      const dim = sel && !near(n.id);
      const gg = svg('g', { class: 'tg-node tg-' + n.kind + (sel === n.id ? ' sel' : '') + (dim ? ' dim' : ''),
        transform: 'translate(' + p.x + ',' + p.y + ')', style: 'cursor:pointer' });
      gg.addEventListener('click', () => { this.sel = (this.sel === n.id) ? null : n.id; this.renderMap(); this.renderSide(); });
      gg.appendChild(svg('rect', { class: 'tg-box', width: TG_BOXW, height: TG_BOXH, rx: 8, ry: 8 }));
      const title = (TG_KIND[n.kind] ? TG_KIND[n.kind].glyph : '') + ' ' + (n.label || n.id);
      gg.appendChild(svg('text', { x: 10, y: 20, class: 'tg-t1' }, this.clip(title, 20)));
      let line2 = '';
      if (n.kind === 'vpn') line2 = (n.type || '') + (n.state ? ' · ' + n.state : '');
      else if (n.kind === 'proxy') line2 = (n.type || '') + (n.addr ? ' · ' + n.addr : '');
      else if (n.kind === 'dest') line2 = n.addr || '';
      const geo = (n.flag ? n.flag + ' ' : '') + (n.country || '') + (n.city ? ', ' + n.city : '');
      if (geo.trim()) gg.appendChild(svg('text', { x: 10, y: 36, class: 'tg-t2' }, this.clip(geo, 22)));
      else if (line2) gg.appendChild(svg('text', { x: 10, y: 36, class: 'tg-t2' }, this.clip(line2, 24)));
      const stat = [];
      if (n.conns) stat.push(n.conns + ' conn');
      if (n.bytes_out || n.bytes_in) stat.push('↑' + fmt.bytes(n.bytes_out) + ' ↓' + fmt.bytes(n.bytes_in));
      if (stat.length) gg.appendChild(svg('text', { x: 10, y: 51, class: 'tg-t3' }, this.clip(stat.join('  '), 26)));
      else if (geo.trim() && line2) gg.appendChild(svg('text', { x: 10, y: 51, class: 'tg-t3' }, this.clip(line2, 26)));
      gNodes.appendChild(gg);
    });
    this.mapWrap.append(root);
  },

  edgePath(x1, y1, x2, y2) {
    const dx = Math.max(36, (x2 - x1) / 2);
    return 'M' + x1 + ',' + y1 + ' C' + (x1 + dx) + ',' + y1 + ' ' + (x2 - dx) + ',' + y2 + ' ' + x2 + ',' + y2;
  },
  clip(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; },

  chainPills(ids) {
    const map = {}; (this.graph.nodes || []).forEach(n => map[n.id] = n);
    const parts = [];
    (ids || []).forEach((id, i) => {
      if (i) parts.push(h('span', { class: 'tg-arrow' }, '→'));
      const n = map[id];
      const kind = n ? n.kind : (id === 'internet' ? 'internet' : id === 'blocked' ? 'blocked' : 'dest');
      let label = n ? n.label : id.replace(/^(dst:|vpn:|proxy:)/, '');
      if (n && n.flag) label = n.flag + ' ' + label;
      parts.push(h('span', { class: 'tg-pill tg-' + kind }, label));
    });
    return h('span', { class: 'tg-chain' }, parts);
  },

  renderSide() {
    const g = this.graph || {};
    clear(this.side);
    const tabs = h('div', { class: 'tg-tabs' },
      this.tabBtn('live', 'Live (' + ((g.live || []).length) + ')'),
      this.tabBtn('model', 'Model (' + ((g.paths || []).filter(p => p.enabled).length) + ')'));
    this.side.append(tabs);
    if (this.sel) {
      const n = (g.nodes || []).find(x => x.id === this.sel);
      this.side.append(h('div', { class: 'tg-selnote small' },
        'focused: ', h('b', null, n ? n.label : this.sel),
        ' ', h('a', { href: '#', onclick: e => { e.preventDefault(); this.sel = null; this.renderMap(); this.renderSide(); } }, 'clear')));
    }
    const list = h('div', { class: 'tg-list' });
    this.side.append(list);
    if (this.view === 'live') this.renderLive(list);
    else this.renderModel(list);
  },
  tabBtn(v, label) {
    return h('button', { class: 'tg-tab' + (this.view === v ? ' active' : ''), type: 'button',
      onclick: () => { this.view = v; this.renderSide(); } }, label);
  },
  renderLive(list) {
    const g = this.graph || {};
    let live = (g.live || []).filter(l => l.state === 'open');
    if (this.sel) live = live.filter(l => (l.nodes || []).includes(this.sel));
    if (!live.length) { list.append(emptyState(this.sel ? 'Nothing through this hop' : 'No live connections',
      this.sel ? 'No open connection is routed through the selected node right now.' : 'Open connections and the path each one takes will list here as apps start talking to the network.',
      { cls: 'small flat' })); return; }
    live.sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out));
    live.slice(0, 80).forEach(l => {
      list.append(h('div', { class: 'tg-row' },
        h('div', { class: 'tg-row-head' },
          h('span', { class: 'tg-app mono' }, l.app || '?'),
          badge(l.action, ACTION_CLS[l.action] || 'gray'),
          l.flag ? h('span', { class: 'tg-cc', title: l.country || '' }, l.flag + ' ' + (l.country || '')) : null,
          h('span', { class: 'spacer' }),
          h('span', { class: 'muted small mono' }, '↑' + fmt.bytes(l.bytes_out) + ' ↓' + fmt.bytes(l.bytes_in))),
        this.chainPills(l.nodes),
        h('div', { class: 'muted small mono' }, (l.host || l.dst_ip || '') + (l.dst_port ? ':' + l.dst_port : ''))));
    });
  },
  renderModel(list) {
    const g = this.graph || {};
    const paths = (g.paths || []).filter(p => p.enabled);
    if (!paths.length) { list.append(emptyState('No enabled rules',
      ['The model view shows the path each rule would send traffic down. Add or enable a rule on the ', h('a', { href: '#/rules' }, 'Rules'), ' page to see it here.'],
      { cls: 'small flat' })); return; }
    paths.forEach(p => {
      list.append(h('div', { class: 'tg-row' },
        h('div', { class: 'tg-row-head' },
          h('span', { class: 'tg-app' }, p.rule),
          badge(p.action, ACTION_CLS[p.action] || 'gray')),
        this.chainPills(p.nodes),
        p.match && p.match !== 'any' ? h('div', { class: 'muted small mono' }, p.match) : null));
    });
  },
};

/* ================================================================
 * 4g. Live Map — a geographic, real-time view of where each
 *      application is connecting (one point per app → host, with
 *      the host name on the map and one-click blocking).
 * ================================================================ */
const MAP_W = 1000, MAP_H = 500;
function mapProject(lon, lat) {
  return [(lon + 180) / 360 * MAP_W, (90 - lat) / 180 * MAP_H];
}
const APP_PALETTE = ['#4c8dff', '#e8893a', '#3fb950', '#c792ea', '#d9a62e', '#f0505a', '#2bb5c0', '#e26fb0', '#8bc34a', '#9c8cff', '#ff8f6b', '#5bd6a6', '#f2c14e', '#6ac4ff'];
function appHash(s) { let h = 0; s = String(s || '?'); for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) >>> 0; } return h; }
function appColor(name) { return APP_PALETTE[appHash(name) % APP_PALETTE.length]; }
function appJitter(name) { const a = appHash(name) % 360, r = 5.5; return [Math.cos(a * Math.PI / 180) * r, Math.sin(a * Math.PI / 180) * r]; }

Pages.map = {
  title: 'Live Map',
  sel: null,
  appFilter: null,
  showLabels: true,
  async mount(root) {
    this.root = root;
    this.reload = debounce(() => this.load(true), 700);
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'Live Map'),
      h('span', { class: 'muted small' }, 'which app is connecting where, right now'),
      h('span', { class: 'spacer' }),
      this.geoNote = h('span', { class: 'muted small' }),
      this.labelBtn = btn('Labels: on', () => { this.showLabels = !this.showLabels; this.labelBtn.textContent = 'Labels: ' + (this.showLabels ? 'on' : 'off'); this.renderOverlay(); }, 'tiny', { title: 'show/hide host names on the map' }),
      this.blockedBtn = btn('Blocked', () => this.openBlocklist(), 'tiny', { title: 'manage blocked hosts' }),
      btn('Reload', () => this.load(), 'tiny')));
    this.legend = h('div', { class: 'map-legend small' });
    root.append(this.legend);
    this.mapWrap = h('div', { class: 'map-wrap' });
    this.side = h('div', { class: 'map-side' });
    root.append(h('div', { class: 'map-layout' }, this.mapWrap, this.side));
    this.renderBase();
    await this.load();
    if (!root.isConnected) return;
    this.timer = setInterval(() => this.load(true), 4000);
    setTimeout(() => root.isConnected && this.load(true), 1500);
    setTimeout(() => root.isConnected && this.load(true), 3200);
  },
  unmount() { clearInterval(this.timer); this.root = this.mapWrap = this.side = this.overlay = null; },
  onEvent(type) { if (type === 'conn' || type === 'vpn' || type === 'stats' || type === 'fw_resolved') this.reload && this.reload(); },

  /* static base: ocean + graticule + landmasses (built once) */
  renderBase() {
    clear(this.mapWrap);
    const s = svg('svg', { class: 'map-svg', viewBox: '0 0 ' + MAP_W + ' ' + MAP_H, preserveAspectRatio: 'xMidYMid meet' });
    s.appendChild(svg('rect', { class: 'map-ocean', x: 0, y: 0, width: MAP_W, height: MAP_H }));
    const grat = svg('g', { class: 'map-grat' });
    for (let lon = -150; lon <= 150; lon += 30) { const [x] = mapProject(lon, 0); grat.appendChild(svg('line', { x1: x, y1: 0, x2: x, y2: MAP_H })); }
    for (let lat = -60; lat <= 60; lat += 30) { const [, y] = mapProject(0, lat); grat.appendChild(svg('line', { x1: 0, y1: y, x2: MAP_W, y2: y })); }
    s.appendChild(grat);
    const land = svg('g', { class: 'map-land' });
    const polys = (typeof WORLD_LAND !== 'undefined') ? WORLD_LAND : [];
    polys.forEach(ring => {
      let d = '';
      for (let i = 0; i < ring.length; i++) { const [x, y] = mapProject(ring[i][0], ring[i][1]); d += (i ? 'L' : 'M') + x.toFixed(1) + ',' + y.toFixed(1); }
      d += 'Z';
      land.appendChild(svg('path', { d }));
    });
    s.appendChild(land);
    this.overlay = svg('g', { class: 'map-overlay' });
    s.appendChild(this.overlay);
    this.mapWrap.append(s);
  },

  async load(silent) {
    let m; try { m = await api('GET', '/api/map', undefined, { silent }); } catch (_) { return; }
    if (!this.mapWrap) return;
    this.data = m;
    const nb = (m.blocked_hosts || []).length;
    this.blockedBtn.textContent = 'Blocked' + (nb ? ' (' + nb + ')' : '');
    this.geoNote.textContent = m.geo_enabled ? (m.home ? '' : 'locating this machine…') : 'geo lookups off (geo.enabled)';
    // drop a stale app filter if that app no longer has traffic
    if (this.appFilter && !(m.points || []).some(p => p.app === this.appFilter)) this.appFilter = null;
    this.renderLegend();
    this.renderOverlay();
    this.renderSide();
  },

  /* apps present, sorted by traffic, as a clickable colour legend / filter */
  appStats() {
    const m = this.data || {};
    const byApp = {};
    (m.points || []).forEach(p => {
      const a = p.app || '?';
      const s = byApp[a] || (byApp[a] = { app: a, bytes: 0, conns: 0, dests: 0 });
      s.bytes += (p.bytes_in || 0) + (p.bytes_out || 0); s.conns += p.conns || 0; s.dests++;
    });
    return Object.values(byApp).sort((x, y) => y.bytes - x.bytes);
  },

  renderLegend() {
    clear(this.legend);
    const apps = this.appStats();
    this.legend.append(h('span', { class: 'map-leg' }, h('span', { class: 'map-dot home' }), 'this machine'));
    if (!apps.length) { this.legend.append(h('span', { class: 'muted', style: { marginLeft: '8px' } }, 'no active connections')); return; }
    this.legend.append(h('span', { class: 'map-leg-sep muted' }, 'apps:'));
    const all = h('button', { class: 'map-app-leg' + (this.appFilter ? '' : ' active'), type: 'button', onclick: () => { this.appFilter = null; this.renderLegend(); this.renderOverlay(); this.renderSide(); } }, 'All (' + apps.length + ')');
    this.legend.append(all);
    apps.forEach(s => {
      const col = appColor(s.app);
      const b = h('button', { class: 'map-app-leg' + (this.appFilter === s.app ? ' active' : ''), type: 'button',
        title: s.app + ' · ' + s.dests + ' destinations · ' + fmt.bytes(s.bytes),
        onclick: () => { this.appFilter = (this.appFilter === s.app) ? null : s.app; this.renderLegend(); this.renderOverlay(); this.renderSide(); } },
        h('span', { class: 'map-sw', style: { background: col } }), s.app, h('span', { class: 'muted' }, ' ' + s.dests));
      this.legend.append(b);
    });
  },

  pointR(p) {
    const b = (p.bytes_in || 0) + (p.bytes_out || 0);
    return Math.max(4, Math.min(15, 4 + Math.log10(1 + b) * 1.5));
  },
  visible() {
    const pts = (this.data && this.data.points || []).filter(p => p.located);
    return this.appFilter ? pts.filter(p => p.app === this.appFilter) : pts;
  },

  renderOverlay() {
    const m = this.data || {};
    const g = this.overlay; if (!g) return;
    clear(g);
    const home = m.home && m.home.located ? mapProject(m.home.lon, m.home.lat) : null;
    const pts = this.visible().map(p => {
      const [bx, by] = mapProject(p.lon, p.lat);
      const [jx, jy] = appJitter(p.app);
      return { p, x: bx + jx, y: by + jy };
    });

    // arcs (under points), coloured by app
    if (home) pts.forEach(o => {
      const col = o.p.blocked ? 'var(--red)' : appColor(o.p.app);
      g.appendChild(svg('path', { d: this.arc(home[0], home[1], o.x, o.y), class: 'map-arc' + (o.p.blocked ? ' blocked' : '') + (this.sel === o.p.id ? ' sel' : ''), style: 'stroke:' + col }));
    });

    // destination points, coloured by app
    pts.forEach(o => {
      const p = o.p, r = this.pointR(p), col = p.blocked ? 'var(--red)' : appColor(p.app);
      const node = svg('g', { class: 'map-pt' + (p.blocked ? ' blocked' : '') + (this.sel === p.id ? ' sel' : '') + (p.approx ? ' approx' : ''), style: 'cursor:pointer' });
      node.appendChild(svg('circle', { cx: o.x, cy: o.y, r, style: 'fill:' + col }));
      node.appendChild(svg('circle', { cx: o.x, cy: o.y, r: r + 3, class: 'map-pt-ring', style: 'stroke:' + col }));
      node.appendChild(svg('title', null, p.app + ' → ' + (p.host || p.ip || '') + '\n' + (p.flag ? p.flag + ' ' : '') + (p.country || '?') + (p.city ? ', ' + p.city : '') + (p.isp ? ' · ' + p.isp : '') + '\n↑' + fmt.bytes(p.bytes_out) + ' ↓' + fmt.bytes(p.bytes_in) + (p.blocked ? '\n(blocked)' : '')));
      node.addEventListener('click', () => { this.sel = (this.sel === p.id) ? null : p.id; this.renderOverlay(); this.renderSide(); });
      g.appendChild(node);
    });

    // host-name labels with simple vertical de-cluttering
    if (this.showLabels && pts.length) {
      const labels = pts.map(o => ({ o, x: o.x, y: o.y, text: o.p.host || o.p.ip || '' })).filter(l => l.text);
      labels.sort((a, b) => a.y - b.y);
      let lastY = -1e9;
      labels.forEach(l => {
        let ly = l.y; if (ly - lastY < 12) ly = lastY + 12; lastY = ly;
        const p = l.o.p, col = p.blocked ? 'var(--red)' : appColor(p.app);
        const txt = this.clip(l.text, 26);
        const left = l.x + 9;
        const gL = svg('g', { class: 'map-lbl' + (this.sel === p.id ? ' sel' : ''), style: 'cursor:pointer' });
        gL.appendChild(svg('rect', { x: left - 2, y: ly - 8, width: txt.length * 5.0 + 6, height: 13, rx: 2, class: 'map-lbl-bg' }));
        gL.appendChild(svg('line', { x1: l.x, y1: l.y, x2: left - 2, y2: ly - 1, class: 'map-lbl-lead' }));
        const t = svg('text', { x: left, y: ly + 2, class: 'map-lbl-t', style: 'fill:' + col }, txt);
        gL.appendChild(t);
        gL.addEventListener('click', () => { this.sel = (this.sel === p.id) ? null : p.id; this.renderOverlay(); this.renderSide(); });
        g.appendChild(gL);
      });
    }

    // home marker on top
    if (home) {
      const hm = svg('g', { class: 'map-home' });
      hm.appendChild(svg('circle', { cx: home[0], cy: home[1], r: 10, class: 'map-home-pulse' }));
      hm.appendChild(svg('circle', { cx: home[0], cy: home[1], r: 5, class: 'map-home-dot' }));
      hm.appendChild(svg('title', null, 'this machine' + (m.home.country ? ' · ' + (m.home.flag ? m.home.flag + ' ' : '') + m.home.country : '') + (m.home.city ? ', ' + m.home.city : '') + (m.home.ip ? '\n' + m.home.ip : '') + (m.home.isp ? '\n' + m.home.isp : '')));
      g.appendChild(hm);
    }
  },

  clip(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; },
  arc(x1, y1, x2, y2) {
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, dx = x2 - x1, dy = y2 - y1, dist = Math.hypot(dx, dy);
    const nx = -dy / (dist || 1), ny = dx / (dist || 1), lift = Math.min(90, dist * 0.22);
    return 'M' + x1 + ',' + y1 + ' Q' + (mx + nx * lift) + ',' + (my + ny * lift) + ' ' + x2 + ',' + y2;
  },

  renderSide() {
    const m = this.data || {};
    clear(this.side);
    const pts = m.points || [];
    this.side.append(h('div', { class: 'map-side-head' },
      h('b', null, pts.length + ' connection' + (pts.length === 1 ? '' : 's')),
      m.home ? h('span', { class: 'muted small' }, ' from ', (m.home.flag || '') + ' ' + (m.home.country || 'here') + (m.home.city ? ', ' + m.home.city : '')) : null));
    if (!pts.length) { this.side.append(emptyState('No live destinations',
      'As your apps connect out, each one drops a pin on the map and a row here — colour-coded by app. Open a few apps or browse a bit to see it fill in.',
      { cls: 'small flat' })); return; }
    // group by app
    const groups = {};
    pts.forEach(p => { (groups[p.app || '?'] = groups[p.app || '?'] || []).push(p); });
    const apps = this.appStats().filter(s => !this.appFilter || s.app === this.appFilter);
    const list = h('div', { class: 'map-list' });
    this.side.append(list);
    apps.forEach(s => {
      const col = appColor(s.app);
      list.append(h('div', { class: 'map-grp-head', onclick: () => { this.appFilter = (this.appFilter === s.app) ? null : s.app; this.renderLegend(); this.renderOverlay(); this.renderSide(); }, style: 'cursor:pointer' },
        h('span', { class: 'map-sw', style: { background: col } }),
        h('b', null, s.app),
        h('span', { class: 'muted small' }, ' ' + s.dests + ' dest · ' + fmt.bytes(s.bytes)),
        this.appFilter === s.app ? h('span', { class: 'muted small', style: { marginLeft: '6px' } }, '(filtered — click to clear)') : null));
      (groups[s.app] || []).sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)).forEach(p => list.append(this.row(p, col)));
    });
  },

  row(p, col) {
    const sel = this.sel === p.id;
    const head = h('div', { class: 'map-row-head' },
      h('span', { class: 'map-cc', title: p.country || '' }, (p.flag || '🏳') + ' ' + (p.country || '?') + (p.city ? ', ' + p.city : '')),
      p.blocked ? badge('blocked', 'red') : null,
      p.approx ? h('span', { class: 'muted small', title: 'approximate location (country centroid)' }, '≈') : null,
      h('span', { class: 'spacer' }),
      h('span', { class: 'muted small mono' }, '↑' + fmt.bytes(p.bytes_out) + ' ↓' + fmt.bytes(p.bytes_in)));
    const hostLine = h('div', { class: 'map-row-host mono small' }, h('span', { class: 'map-sw', style: { background: col } }), (p.host || p.ip || ''));
    const target = p.host || p.ip;
    const act = h('div', { class: 'map-row-act' },
      p.blocked ? btn('Unblock', () => this.unblock(target), 'tiny') : btn('Block host', () => this.block(target), 'tiny danger', { title: 'block ' + target + ' for every app' }));
    const row = h('div', { class: 'map-row' + (sel ? ' sel' : '') + (p.blocked ? ' blocked' : ''), style: 'border-left:3px solid ' + col }, head, hostLine, act);
    head.addEventListener('click', () => { this.sel = sel ? null : p.id; this.renderOverlay(); this.renderSide(); });
    return row;
  },

  async block(host) { if (!host) return; try { await api('POST', '/api/firewall/block', { host }); toast('Blocked ' + host, 'ok'); } catch (e) { toast('Block failed: ' + e.message, 'error'); return; } this.load(true); },
  async unblock(host) { if (!host) return; try { await api('POST', '/api/firewall/unblock', { host }); toast('Unblocked ' + host, 'info'); } catch (e) { toast('Unblock failed: ' + e.message, 'error'); return; } this.load(true); },

  openBlocklist() {
    const m = this.data || {};
    const listWrap = h('div', { class: 'map-bl-list' });
    const input = h('input', { type: 'text', class: 'inp', placeholder: 'host, *.domain, 1.2.3.4 or 10.0.0.0/8' });
    const self = this;
    function render(hosts) {
      clear(listWrap);
      if (!hosts.length) { listWrap.append(emptyState('Nothing blocked',
        'Add a host, domain or IP below and it is denied for every app — even while program control is off. Loopback is never blocked.',
        { cls: 'small flat' })); return; }
      hosts.forEach(hn => listWrap.append(h('div', { class: 'map-bl-row' }, h('span', { class: 'mono' }, hn), h('span', { class: 'spacer' }),
        btn('Remove', async () => { try { const r = await api('POST', '/api/firewall/unblock', { host: hn }); render(r.blocked_hosts || []); self.load(true); } catch (e) { toast(e.message, 'error'); } }, 'tiny'))));
    }
    render(m.blocked_hosts || []);
    const add = async () => { const v = input.value.trim(); if (!v) return; try { const r = await api('POST', '/api/firewall/block', { host: v }); input.value = ''; render(r.blocked_hosts || []); self.load(true); } catch (e) { toast(e.message, 'error'); } };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); add(); } });
    openModal({
      title: 'Blocked hosts', width: '560px',
      body: h('div', { class: 'tab-panel' },
        h('div', { class: 'muted small', style: { marginBottom: '8px' } }, 'These destinations are denied for every application, even when program control is off. Loopback is never blocked.'),
        listWrap, h('div', { class: 'map-bl-add' }, input, btn('Block', add, 'primary'))),
      buttons: [{ label: 'Close' }],
    });
  },
};



/* ================================================================
 * 4g-bis. Processes — a Task-Manager-style process viewer + killer,
 *          with a "hide system/service processes" toggle.
 * ================================================================ */
Pages.processes = {
  title: 'Processes',
  hideSystem: true,
  filter: '',
  sortKey: 'cpu_pct',
  sortDir: -1,
  auto: true,
  data: null,
  async mount(root) {
    this.root = root;
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'Processes'),
      this.summary = h('span', { class: 'muted small' })));
    root.append(h('div', { class: 'proc-toolbar' },
      this.filterIn = h('input', { type: 'search', class: 'inp proc-filter', placeholder: 'filter name / user / pid / command  (/)',
        oninput: () => { this.filter = this.filterIn.value.trim().toLowerCase(); this.renderBody(); } }),
      h('label', { class: 'check proc-toggle', title: 'hide kernel threads and system/service accounts (uid < 1000)' },
        this.hideChk = h('input', { type: 'checkbox', checked: this.hideSystem, onchange: () => { this.hideSystem = this.hideChk.checked; this.render(); } }),
        h('span', null, 'Hide system processes')),
      h('span', { class: 'spacer' }),
      this.autoBtn = btn('Auto: on', () => { this.auto = !this.auto; this.autoBtn.textContent = 'Auto: ' + (this.auto ? 'on' : 'off'); this.schedule(); }, 'tiny'),
      btn('Refresh', () => this.load(), 'tiny')));
    this.sys = { cpuHist: [], memHist: [] };
    this.sysbar = h('div', { class: 'sysbar' });
    root.append(this.sysbar);
    this.buildSysbar();
    this.wrap = h('div', { class: 'table-wrap proc-wrap' });
    root.append(this.wrap);
    await Promise.all([this.load(), this.loadSys()]);
    if (!root.isConnected) return;
    this.schedule();
  },
  unmount() { clearInterval(this.timer); this.root = this.wrap = this.sysbar = null; },
  schedule() { clearInterval(this.timer); if (this.auto) this.timer = setInterval(() => { this.load(true); this.loadSys(); }, 2000); },
  focusFilter() { if (this.filterIn) { this.filterIn.focus(); this.filterIn.select(); } },

  async load(silent) {
    let d; try { d = await api('GET', '/api/procmon', undefined, { silent }); } catch (_) { return; }
    if (!this.wrap) return;
    this.data = d;
    this.render();
  },

  SORTS: [
    { k: 'pid', label: 'PID', cls: 'num' },
    { k: 'name', label: 'Name' },
    { k: 'cpu_pct', label: 'CPU %', cls: 'num' },
    { k: 'rss_kb', label: 'Memory', cls: 'num' },
    { k: 'threads', label: 'Thr', cls: 'num' },
    { k: 'conns', label: 'Net', cls: 'num' },
    { k: 'user', label: 'User' },
    { k: 'state', label: 'State' },
    { k: 'cmd', label: 'Command' },
  ],

  render() {
    const d = this.data || {};
    const s = d.summary || {};
    this.summary.textContent = s.total ? (s.total + ' processes · ' + s.user + ' user · ' + s.system + ' system · CPU ' + (s.cpu_pct || 0) + '% · ' + fmt.bytes((s.rss_kb || 0) * 1024)) : '';
    clear(this.wrap);
    const table = h('table', { class: 'grid proc-tbl' });
    const thead = h('thead'); const trh = h('tr');
    this.SORTS.forEach(c => {
      const active = this.sortKey === c.k;
      trh.append(h('th', { class: (c.cls || '') + (active ? ' sorted' : ''), onclick: () => { if (this.sortKey === c.k) this.sortDir *= -1; else { this.sortKey = c.k; this.sortDir = (c.k === 'name' || c.k === 'user' || c.k === 'cmd' || c.k === 'state') ? 1 : -1; } this.renderBody(); } },
        c.label, active ? h('span', { class: 'sort-ar' }, this.sortDir < 0 ? ' ▾' : ' ▴') : null));
    });
    trh.append(h('th', { class: 'proc-act-h' }, ''));
    thead.append(trh); table.append(thead);
    this.tbody = h('tbody');
    table.append(this.tbody);
    this.wrap.append(table);
    this.renderBody();
  },

  renderBody() {
    if (!this.tbody) return;
    const d = this.data || {};
    const own = (d.summary && d.summary.own_pid) || 0;
    let rows = (d.processes || []).slice();
    if (this.hideSystem) rows = rows.filter(p => !p.system);
    const f = this.filter;
    if (f) rows = rows.filter(p => String(p.pid) === f || (p.name || '').toLowerCase().includes(f) || (p.user || '').toLowerCase().includes(f) || (p.cmd || '').toLowerCase().includes(f));
    const k = this.sortKey, dir = this.sortDir;
    rows.sort((a, b) => {
      let av = a[k], bv = b[k];
      if (typeof av === 'string' || typeof bv === 'string') { av = String(av || ''); bv = String(bv || ''); return av.localeCompare(bv) * dir; }
      return ((av || 0) - (bv || 0)) * dir;
    });
    clear(this.tbody);
    if (!rows.length) { this.tbody.append(h('tr', null, h('td', { colspan: this.SORTS.length + 1 },
      emptyState('No matching processes',
        this.filter ? 'Nothing matches your filter. Clear it to see every process.' : 'Everything is hidden. Try turning off “Hide system processes”.',
        { cls: 'small flat' })))); return; }
    const frag = document.createDocumentFragment();
    rows.slice(0, 600).forEach(p => {
      const cpuHot = p.cpu_pct >= 40 ? ' hot' : (p.cpu_pct >= 10 ? ' warm' : '');
      const tr = h('tr', { class: (p.system ? 'proc-sys' : '') + (p.pid === own ? ' proc-self' : '') },
        h('td', { class: 'num mono' }, String(p.pid)),
        h('td', { class: 'proc-name' }, h('span', { class: 'mono', title: p.cmd || p.name }, p.name), p.pid === own ? badge('cyberboba', 'blue') : null, p.state && p.state.startsWith('Z') ? badge('zombie', 'red') : null),
        h('td', { class: 'num mono cpu' + cpuHot }, (p.cpu_pct || 0).toFixed(1)),
        h('td', { class: 'num mono' }, fmt.bytes((p.rss_kb || 0) * 1024)),
        h('td', { class: 'num mono' }, String(p.threads || '')),
        h('td', { class: 'num mono' }, p.conns ? String(p.conns) : ''),
        h('td', { class: 'mono proc-user' }, p.user || p.uid),
        h('td', { class: 'small proc-state' }, p.state || ''),
        h('td', { class: 'mono small proc-cmd', title: p.cmd || '' }, p.cmd || ''),
        h('td', { class: 'proc-act' }, p.pid === own ? h('span', { class: 'muted small' }, '—') : btn('Kill', () => this.confirmKill(p), 'tiny danger')));
      frag.append(tr);
    });
    this.tbody.append(frag);
  },

  confirmKill(p) {
    const self = this;
    const doKill = async (sig) => {
      try { await api('POST', '/api/processes/' + p.pid + '/kill?signal=' + sig, {}); toast('Sent SIG' + sig + ' to ' + p.name + ' (' + p.pid + ')', 'ok'); }
      catch (e) { toast('Kill failed: ' + e.message, 'error'); return; }
      m.close(); setTimeout(() => self.load(true), 400);
    };
    const m = openModal({
      title: 'Kill process',
      width: '460px',
      body: h('div', { class: 'tab-panel' },
        h('p', null, 'Send a signal to ', h('b', null, p.name), ' ', h('span', { class: 'mono' }, '(pid ' + p.pid + ', ' + (p.user || p.uid) + ')'), '?'),
        p.cmd ? h('div', { class: 'mono small muted', style: { wordBreak: 'break-all', margin: '4px 0 8px' } }, p.cmd) : null,
        p.system ? h('div', { class: 'warn-box small' }, 'This is a system / service process — killing it can destabilise the session.') : null,
        h('div', { class: 'muted small' }, h('b', null, 'End (TERM)'), ' asks it to exit cleanly; ', h('b', null, 'Force (KILL)'), ' cannot be ignored.')),
      buttons: [
        { label: 'End (TERM)', cls: 'primary', keep: true, onClick: () => doKill('TERM') },
        { label: 'Force kill (KILL)', cls: 'danger', keep: true, onClick: () => doKill('KILL') },
        { label: 'Cancel' },
      ],
    });
  },


  buildSysbar() {
    const spark = (cls) => h('canvas', { class: 'sys-spark ' + cls, 'aria-hidden': 'true' });
    this.cpuBig = h('span', { class: 'sys-big' }, '—');
    this.cpuSub = h('span', { class: 'sys-sub muted small' });
    this.cpuCores = h('div', { class: 'sys-cores' });
    this.cpuCanvas = spark('cpu');
    this.memBig = h('span', { class: 'sys-big' }, '—');
    this.memSub = h('span', { class: 'sys-sub muted small' });
    this.memCanvas = spark('mem');
    this.tempWrap = h('div', { class: 'sys-temps' });
    clear(this.sysbar);
    this.sysbar.append(
      h('div', { class: 'sys-card' },
        h('div', { class: 'sys-card-head' }, h('span', { class: 'sys-title' }, 'CPU'), this.cpuBig, this.cpuSub),
        this.cpuCores,
        h('div', { class: 'sys-graph' }, this.cpuCanvas)),
      h('div', { class: 'sys-card' },
        h('div', { class: 'sys-card-head' }, h('span', { class: 'sys-title' }, 'Memory'), this.memBig, this.memSub,
          h('span', { class: 'spacer' }),
          btn('Free RAM', () => this.reclaim({ caches: true }), 'small ghost', { title: 'drop the page/inode cache the kernel is holding (POST /api/system/reclaim)' }),
          this.swapBtn = btn('Trim swap', () => this.reclaim({ caches: true, swap: true }), 'small ghost', { title: 'move swapped pages back into RAM: swapoff -a && swapon -a', hidden: true })),
        h('div', { class: 'sys-graph' }, this.memCanvas)),
      h('div', { class: 'sys-card sys-card-temps' },
        h('div', { class: 'sys-card-head' }, h('span', { class: 'sys-title' }, 'Temperatures'), this.tempMax = h('span', { class: 'sys-big' }, '—')),
        this.tempWrap));
  },

  async loadSys(silent) {
    let d; try { d = await api('GET', '/api/sysstat', undefined, { silent: true }); } catch (_) { return; }
    if (!this.sysbar) return;
    this.sysData = d;
    const H = 60;
    this.sys.cpuHist.push(d.cpu ? (d.cpu.pct || 0) : 0); if (this.sys.cpuHist.length > H) this.sys.cpuHist.shift();
    this.sys.memHist.push(d.mem ? (d.mem.pct || 0) : 0); if (this.sys.memHist.length > H) this.sys.memHist.shift();
    this.renderSysbar();
  },

  async reclaim(opts) {
    const swap = !!opts.swap;
    if (swap && !confirm('Trim swap?\n\nThis runs swapoff -a then swapon -a, pulling everything in the swap file back into RAM, then re-enabling swap. It briefly uses more memory and can take a few seconds. Cancelled automatically if it would not fit in free RAM.')) return;
    let r; try { r = await api('POST', '/api/system/reclaim', { caches: opts.caches !== false, swap: swap, compact: !!opts.compact }); } catch (_) { return; }
    const freed = (r.freed_kb || 0) * 1024, sw = (r.swap_freed_kb || 0) * 1024;
    const warns = r.warnings || [];
    if (warns.length) {
      toast(warns.join(' · '), 'warn', 6000);
    } else {
      let msg = 'Freed ' + fmt.bytes(Math.max(0, freed)) + ' RAM';
      if (sw > 0) msg += ' · ' + fmt.bytes(sw) + ' swap';
      toast(msg, 'ok', 3500);
    }
    this.loadSys(true);
  },

  renderSysbar() {
    const d = this.sysData || {}; const cpu = d.cpu || {}, mem = d.mem || {};
    this.cpuBig.textContent = (cpu.pct != null ? cpu.pct.toFixed(0) : '—') + '%';
    this.cpuBig.className = 'sys-big ' + hotClass(cpu.pct, 60, 85);
    this.cpuSub.textContent = 'load ' + (cpu.load1 != null ? cpu.load1.toFixed(2) : '?') + ' · ' + (cpu.ncpu || '?') + ' cores';
    clear(this.cpuCores);
    (cpu.per_core || []).forEach((c, i) => {
      const bar = h('div', { class: 'sys-core', title: 'core ' + i + ': ' + c.toFixed(0) + '%' },
        h('div', { class: 'sys-core-fill ' + hotClass(c, 60, 85), style: { height: Math.max(2, c) + '%' } }));
      this.cpuCores.append(bar);
    });
    this.memBig.textContent = (mem.pct != null ? mem.pct.toFixed(0) : '—') + '%';
    this.memBig.className = 'sys-big ' + hotClass(mem.pct, 70, 90);
    this.memSub.textContent = fmt.bytes((mem.used_kb || 0) * 1024) + ' / ' + fmt.bytes((mem.total_kb || 0) * 1024) + (mem.swap_total_kb ? ' · swap ' + (mem.swap_pct || 0).toFixed(0) + '%' : '');
    if (this.swapBtn) this.swapBtn.hidden = !(mem.swap_used_kb > 0);
    // temperatures
    clear(this.tempWrap);
    const temps = (d.temps || []);
    let max = 0;
    temps.forEach(t => { if (t.celsius > max) max = t.celsius; });
    this.tempMax.textContent = temps.length ? max.toFixed(0) + '°' : 'n/a';
    this.tempMax.className = 'sys-big ' + hotClass(max, 70, 85);
    if (!temps.length) { this.tempWrap.append(h('span', { class: 'muted small' }, 'no sensors exposed')); }
    temps.forEach(t => {
      const name = t.label ? t.label : t.chip;
      this.tempWrap.append(h('span', { class: 'sys-temp ' + hotClass(t.celsius, 70, 85), title: t.chip + (t.label ? ' · ' + t.label : '') },
        h('span', { class: 'sys-temp-n' }, name), h('span', { class: 'sys-temp-v mono' }, t.celsius.toFixed(0) + '°')));
    });
    (d.fans || []).forEach(fan => this.tempWrap.append(h('span', { class: 'sys-temp fan', title: fan.chip }, h('span', { class: 'sys-temp-n' }, fan.label || fan.chip), h('span', { class: 'sys-temp-v mono' }, fan.rpm + '₊'))));
    this.drawSpark(this.cpuCanvas, this.sys.cpuHist, '--chart-in');
    this.drawSpark(this.memCanvas, this.sys.memHist, '--purple');
  },

  drawSpark(canvas, hist, colorVar) {
    if (!canvas || !canvas.isConnected) return;
    const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth || 300, H = canvas.clientHeight || 46;
    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); }
    const ctx = canvas.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    const grid = cssVar('--border') || '#333', col = cssVar(colorVar) || '#4c8dff';
    ctx.strokeStyle = grid; ctx.lineWidth = 1;
    for (let i = 0; i <= 2; i++) { const y = Math.round((H - 2) * i / 2) + 0.5; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
    const n = 60, pad = 2, gw = W - pad * 2, gh = H - pad * 2;
    const xOf = i => pad + gw * (i / (n - 1));
    const yOf = v => pad + gh - gh * Math.min(100, Math.max(0, v)) / 100;
    if (hist.length < 2) return;
    const off = n - hist.length;
    ctx.beginPath();
    hist.forEach((v, i) => { const x = xOf(off + i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.lineTo(xOf(off + hist.length - 1), pad + gh); ctx.lineTo(xOf(off), pad + gh); ctx.closePath();
    const sg = ctx.createLinearGradient(0, pad, 0, pad + gh);
    sg.addColorStop(0, hexA(col, 0.30)); sg.addColorStop(1, hexA(col, 0.02));
    ctx.fillStyle = sg; ctx.fill();
    ctx.beginPath();
    hist.forEach((v, i) => { const x = xOf(off + i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.strokeStyle = col; ctx.lineWidth = 1.75; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
    ctx.shadowColor = hexA(col, 0.4); ctx.shadowBlur = 4; ctx.stroke(); ctx.shadowBlur = 0; ctx.shadowColor = 'transparent';
  },

  onEvent() { /* polled on its own timer */ },
};

/* ================================================================
 * 4g-ter. Bandwidth — GlassWire-style per-app network speed + usage.
 * ================================================================ */
Pages.bandwidth = {
  title: 'Bandwidth',
  auto: true,
  data: null,
  async mount(root) {
    this.root = root;
    this.hin = []; this.hout = []; // total rate history for the graph
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'Bandwidth'),
      h('span', { class: 'page-sub muted' }, 'live network speed and data usage, per application'),
      h('span', { class: 'spacer' }),
      this.autoBtn = btn('Auto: on', () => { this.auto = !this.auto; this.autoBtn.textContent = 'Auto: ' + (this.auto ? 'on' : 'off'); this.schedule(); }, 'tiny'),
      btn('Refresh', () => this.load(), 'tiny'),
      btn('Usage history', () => this.dailyDialog(), 'tiny'),
      btn('Reset', () => this.reset(), 'tiny danger', { title: 'clear all bandwidth history (session + saved daily totals)' })));

    this.alertsWrap = h('div', { class: 'bw-alerts' });
    root.append(this.alertsWrap);
    // clear the nav badge: the user is now looking at the alerts
    state.bwAlerts = state.bwAlerts || [];
    updateBwBadge();
    this.seedAlerts();

    // totals: two big graphs
    this.dBig = h('span', { class: 'bw-big dl' }, '—'); this.dSub = h('span', { class: 'muted small' });
    this.uBig = h('span', { class: 'bw-big ul' }, '—'); this.uSub = h('span', { class: 'muted small' });
    this.dCanvas = h('canvas', { class: 'bw-graph', 'aria-hidden': 'true' });
    this.uCanvas = h('canvas', { class: 'bw-graph', 'aria-hidden': 'true' });
    root.append(h('div', { class: 'bw-cards' },
      h('div', { class: 'bw-card' },
        h('div', { class: 'bw-card-head' }, h('span', { class: 'bw-dot dl' }), h('span', { class: 'sys-title' }, 'Download'), this.dBig, this.dSub),
        h('div', { class: 'sys-graph' }, this.dCanvas)),
      h('div', { class: 'bw-card' },
        h('div', { class: 'bw-card-head' }, h('span', { class: 'bw-dot ul' }), h('span', { class: 'sys-title' }, 'Upload'), this.uBig, this.uSub),
        h('div', { class: 'sys-graph' }, this.uCanvas))));

    this.listWrap = h('div', { class: 'bw-apps' });
    root.append(this.listWrap);
    await this.load();
    if (!root.isConnected) return;
    this.schedule();
  },
  unmount() { clearInterval(this.timer); this.root = this.listWrap = null; },
  schedule() { clearInterval(this.timer); if (this.auto) this.timer = setInterval(() => this.load(true), 1500); },

  async load(silent) {
    let d; try { d = await api('GET', '/api/bandwidth', undefined, { silent: silent !== false }); } catch (_) { return; }
    if (!this.listWrap) return;
    this.data = d;
    const H = 90;
    this.hin.push(d.total_rate_in || 0); if (this.hin.length > H) this.hin.shift();
    this.hout.push(d.total_rate_out || 0); if (this.hout.length > H) this.hout.shift();
    this.render();
  },

  render() {
    const d = this.data || {}; const apps = d.apps || [];
    this.dBig.textContent = fmt.rate(d.total_rate_in || 0);
    this.uBig.textContent = fmt.rate(d.total_rate_out || 0);
    this.dSub.textContent = 'today ' + fmt.bytes(d.total_today_in || 0) + ' · 30d ' + fmt.bytes(d.total_month_in || 0);
    this.uSub.textContent = 'today ' + fmt.bytes(d.total_today_out || 0) + ' · 30d ' + fmt.bytes(d.total_month_out || 0);
    this.drawGraph(this.dCanvas, this.hin, '--chart-in');
    this.drawGraph(this.uCanvas, this.hout, '--chart-out');

    clear(this.listWrap);
    if (!apps.length) {
      this.listWrap.append(emptyState('No traffic tracked yet',
        'As soon as your apps send or receive data, they show up here with live speed and totals. Make sure proxify is on so cyberboba sees the connections.', { cls: 'flat' }));
      return;
    }
    const maxRate = Math.max(1, ...apps.map(a => (a.rate_in || 0) + (a.rate_out || 0)));
    const maxTot = Math.max(1, ...apps.map(a => (a.total_in || 0) + (a.total_out || 0)));
    const head = h('div', { class: 'bw-row bw-head' },
      h('span', { class: 'bw-app' }, 'Application'),
      h('span', { class: 'bw-rate' }, '↓ down'),
      h('span', { class: 'bw-rate' }, '↑ up'),
      h('span', { class: 'bw-bar-cell' }, 'now'),
      h('span', { class: 'bw-tot' }, 'today'),
      h('span', { class: 'bw-tot' }, 'session'),
      h('span', { class: 'bw-conns' }, 'conns'));
    this.listWrap.append(head);
    for (const a of apps) {
      const col = appColor(a.app);
      const sumR = (a.rate_in || 0) + (a.rate_out || 0);
      const active = sumR > 0;
      const barW = Math.round(100 * sumR / maxRate);
      this.listWrap.append(h('div', { class: 'bw-row' + (active ? ' active' : '') },
        h('span', { class: 'bw-app', title: a.app },
          h('span', { class: 'bw-swatch', style: { background: col } }), a.app),
        h('span', { class: 'bw-rate dl mono' }, active && a.rate_in ? fmt.rate(a.rate_in) : '·'),
        h('span', { class: 'bw-rate ul mono' }, active && a.rate_out ? fmt.rate(a.rate_out) : '·'),
        h('span', { class: 'bw-bar-cell' }, h('span', { class: 'bw-bar', style: { width: barW + '%', background: col } })),
        h('span', { class: 'bw-tot mono', title: '↓ ' + fmt.bytes(a.today_in) + '  ↑ ' + fmt.bytes(a.today_out) }, fmt.bytes((a.today_in || 0) + (a.today_out || 0))),
        h('span', { class: 'bw-tot mono', title: '↓ ' + fmt.bytes(a.total_in) + '  ↑ ' + fmt.bytes(a.total_out) }, fmt.bytes((a.total_in || 0) + (a.total_out || 0))),
        h('span', { class: 'bw-conns mono' }, a.conns ? String(a.conns) : '·')));
    }
  },

  drawGraph(canvas, hist, colorVar) {
    if (!canvas || !canvas.isConnected) return;
    const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth || 300, H = canvas.clientHeight || 60;
    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); }
    const ctx = canvas.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    const grid = cssVar('--border') || '#333', col = cssVar(colorVar) || '#4c8dff';
    ctx.strokeStyle = grid; ctx.lineWidth = 1;
    for (let i = 0; i <= 2; i++) { const y = Math.round((H - 2) * i / 2) + 0.5; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
    const n = 90, pad = 2, gw = W - pad * 2, gh = H - pad * 2;
    const peak = Math.max(1024, ...hist); // auto-scale, min 1KB/s so idle looks flat
    const xOf = i => pad + gw * (i / (n - 1));
    const yOf = v => pad + gh - gh * Math.min(1, v / peak);
    if (hist.length < 2) return;
    const off = n - hist.length;
    ctx.beginPath();
    hist.forEach((v, i) => { const x = xOf(off + i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.lineTo(xOf(off + hist.length - 1), pad + gh); ctx.lineTo(xOf(off), pad + gh); ctx.closePath();
    const sg = ctx.createLinearGradient(0, pad, 0, pad + gh);
    sg.addColorStop(0, hexA(col, 0.30)); sg.addColorStop(1, hexA(col, 0.02));
    ctx.fillStyle = sg; ctx.fill();
    ctx.beginPath();
    hist.forEach((v, i) => { const x = xOf(off + i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.strokeStyle = col; ctx.lineWidth = 1.75; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
    ctx.shadowColor = hexA(col, 0.4); ctx.shadowBlur = 4; ctx.stroke(); ctx.shadowBlur = 0; ctx.shadowColor = 'transparent';
  },

  async reset() {
    if (!confirm('Reset all bandwidth history?\n\nThis clears live session counters and the saved per-day usage totals. Connections themselves are not affected.')) return;
    try { await api('POST', '/api/bandwidth/reset'); } catch (_) { return; }
    this.hin = []; this.hout = [];
    toast('Bandwidth history cleared', 'ok');
    this.load();
  },

  async dailyDialog() {
    const box = h('div', { class: 'bw-daily' }, h('div', { class: 'muted small' }, h('span', { class: 'spinner' }), ' loading…'));
    openModal({ title: 'Data usage — last 30 days', width: '520px', body: box, buttons: [{ label: 'Close' }] });
    let r; try { r = await api('GET', '/api/bandwidth/daily', undefined, { silent: true }); }
    catch (e) { replace(box, h('div', { class: 'error-box' }, e.message)); return; }
    const days = r.days || [];
    if (!days.length) { replace(box, emptyState('No usage recorded yet', 'Daily totals appear here once cyberboba has seen some traffic.', { cls: 'small flat' })); return; }
    const peak = Math.max(1, ...days.map(d => (d.in || 0) + (d.out || 0)));
    clear(box);
    for (const d of days) {
      const tot = (d.in || 0) + (d.out || 0);
      box.append(h('div', { class: 'bw-day' },
        h('span', { class: 'bw-day-date mono' }, d.date),
        h('span', { class: 'bw-day-bar-cell' }, h('span', { class: 'bw-day-bar', style: { width: Math.round(100 * tot / peak) + '%' } })),
        h('span', { class: 'bw-day-tot mono', title: '↓ ' + fmt.bytes(d.in) + '  ↑ ' + fmt.bytes(d.out) }, fmt.bytes(tot))));
    }
  },

  async seedAlerts() {
    try {
      const r = await api('GET', '/api/bandwidth/alerts', undefined, { silent: true });
      if (r && r.alerts && r.alerts.length && (!state.bwAlerts || !state.bwAlerts.length)) state.bwAlerts = r.alerts.slice(0, 50);
    } catch (_) { /* ignore */ }
    this.renderAlerts();
  },
  renderAlerts() {
    if (!this.alertsWrap) return;
    clear(this.alertsWrap);
    const al = (state.bwAlerts || []);
    if (!al.length) return;
    const head = h('div', { class: 'bw-alert-head' },
      h('span', null, '\u26a0 Abnormal data transfer'),
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn tiny', type: 'button', onClick: () => { state.bwAlerts = []; updateBwBadge(); this.renderAlerts(); } }, 'Dismiss'));
    this.alertsWrap.append(head);
    for (const a of al.slice(0, 8)) {
      const dir = a.kind === 'download' ? '\u2193 downloading' : '\u2191 uploading';
      const when = a.at ? new Date(a.at).toLocaleTimeString() : '';
      this.alertsWrap.append(h('div', { class: 'bw-alert-row' },
        h('span', { class: 'bw-alert-app' }, h('span', { class: 'bw-swatch', style: { background: appColor(a.app) } }), a.app),
        h('span', { class: 'bw-alert-msg' }, dir + ' ' + fmt.rate(a.rate || 0) +
          (a.factor && a.factor >= 1.5 ? ' \u2014 ' + Math.round(a.factor) + '\u00d7 its normal baseline' : '') +
          (a.conns ? ' \u00b7 ' + a.conns + ' conn' + (a.conns > 1 ? 's' : '') : '')),
        h('span', { class: 'bw-alert-when muted small mono' }, when)));
    }
  },
  onEvent(type) { if (type === 'bw_alert') { this.renderAlerts(); this.load(true); } },
};

/* ================================================================
 * 4g-quater. DNS — Pi-hole-style ad/tracker/malware blocking + query log.
 * ================================================================ */
const DNS_RECOMMENDED = [
  { name: 'StevenBlack (ads + malware)', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' },
  { name: 'AdGuard DNS filter', url: 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt' },
  { name: 'OISD (big)', url: 'https://big.oisd.nl/domainswild' },
];
Pages.dns = {
  title: 'DNS',
  auto: true,
  blockedOnly: false,
  filter: '',
  cfg: null,
  async mount(root) {
    this.root = root;
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'DNS'),
      h('span', { class: 'page-sub muted' }, 'block ads, trackers and malware — and watch every lookup live'),
      h('span', { class: 'spacer' }),
      this.toggleBtn = btn('Blocking', () => this.toggleEnabled(), 'toggle', { 'aria-pressed': 'false' }),
      btn('Refresh lists', () => this.refresh(), 'tiny', { title: 'POST /api/dns/refresh — re-download the blocklists' }),
      btn('Lists & rules…', () => this.listsDialog(), 'tiny', { title: 'manage blocklists and manual block / allow domains' }),
      this.autoBtn = btn('Auto: on', () => { this.auto = !this.auto; this.autoBtn.textContent = 'Auto: ' + (this.auto ? 'on' : 'off'); this.schedule(); }, 'tiny'),
      btn('Reset stats', () => this.resetStats(), 'tiny danger', { title: 'clear the query log and counters' })));

    this.tiles = h('div', { class: 'dns-tiles' });
    root.append(this.tiles);

    this.filterIn = h('input', { type: 'search', class: 'inp', placeholder: 'filter domain  (/)', oninput: () => { this.filter = this.filterIn.value.trim().toLowerCase(); this.renderLog(); } });
    const blkChk = checkbox('blocked only', false);
    blkChk.input.addEventListener('change', () => { this.blockedOnly = blkChk.input.checked; this.loadLog(); });
    this.logBody = h('tbody');
    const logTable = h('table', { class: 'grid dns-log' },
      h('thead', null, h('tr', null,
        h('th', { class: 'c-time' }, 'Time'), h('th', { class: 'c-type' }, 'Type'),
        h('th', null, 'Domain'), h('th', { class: 'c-act' }, ''))),
      this.logBody);
    this.topBox = h('div', { class: 'dns-top' });

    root.append(h('div', { class: 'dns-main' },
      h('div', { class: 'dns-logwrap' },
        h('div', { class: 'dns-logbar' }, this.filterIn, h('label', { class: 'check' }, blkChk.input, h('span', null, 'blocked only'))),
        h('div', { class: 'table-wrap' }, logTable)),
      h('div', { class: 'dns-side' }, h('div', { class: 'dns-side-title' }, 'Top blocked'), this.topBox)));

    await Promise.all([this.loadStatus(), this.loadLog()]);
    if (!root.isConnected) return;
    this.schedule();
  },
  unmount() { clearInterval(this.timer); this.root = this.tiles = this.logBody = null; },
  schedule() { clearInterval(this.timer); if (this.auto) this.timer = setInterval(() => { this.loadStatus(true); this.loadLog(true); }, 2000); },
  focusFilter() { if (this.filterIn) { this.filterIn.focus(); this.filterIn.select(); } },

  async loadStatus(silent) {
    let d; try { d = await api('GET', '/api/dns', undefined, { silent: silent !== false }); } catch (_) { return; }
    if (!this.tiles) return;
    this.cfg = d.config || {};
    this.stats = d.stats || {};
    this.renderStatus();
  },
  async loadLog(silent) {
    let d; try { d = await api('GET', '/api/dns/log?limit=300' + (this.blockedOnly ? '&blocked=1' : ''), undefined, { silent: silent !== false }); } catch (_) { return; }
    if (!this.logBody) return;
    this.queries = d.queries || [];
    this.renderLog();
  },

  renderStatus() {
    const s = this.stats || {};
    const on = !!s.enabled;
    this.toggleBtn.classList.toggle('on', on);
    this.toggleBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
    this.toggleBtn.textContent = on ? 'Blocking: on' : 'Blocking: off';
    const tile = (label, value, cls) => h('div', { class: 'dns-tile ' + (cls || '') }, h('div', { class: 'dns-tile-v' }, value), h('div', { class: 'dns-tile-l muted small' }, label));
    clear(this.tiles);
    this.tiles.append(
      tile('Queries seen', fmt.num(s.total_queries || 0)),
      tile('Blocked', fmt.num(s.blocked_queries || 0) + (s.total_queries ? '  (' + (s.blocked_pct || 0).toFixed(1) + '%)' : ''), 'block'),
      tile('Domains on lists', fmt.num(s.list_domains || 0) + (s.updating ? ' …' : '')),
      tile('Manual block / allow', fmt.num(s.manual_block || 0) + ' / ' + fmt.num(s.allow || 0)));
    // top blocked
    clear(this.topBox);
    const top = s.top_blocked || [];
    if (!top.length) { this.topBox.append(h('div', { class: 'muted small' }, on ? 'Nothing blocked yet.' : 'Blocking is off.')); }
    const max = Math.max(1, ...top.map(t => t.count));
    for (const t of top) {
      this.topBox.append(h('div', { class: 'dns-top-row', title: t.name },
        h('span', { class: 'dns-top-bar', style: { width: Math.round(100 * t.count / max) + '%' } }),
        h('span', { class: 'dns-top-name mono' }, t.name),
        h('span', { class: 'dns-top-n mono' }, fmt.num(t.count))));
    }
  },

  renderLog() {
    clear(this.logBody);
    let rows = this.queries || [];
    if (this.filter) rows = rows.filter(q => q.name.includes(this.filter));
    if (!rows.length) {
      this.logBody.append(h('tr', null, h('td', { colspan: 4 }, emptyState('No DNS queries', this.blockedOnly ? 'Nothing has been blocked yet.' : 'As your apps resolve hostnames, every lookup shows up here live.', { cls: 'small flat' }))));
      return;
    }
    for (const q of rows.slice(0, 300)) {
      const act = q.blocked
        ? btn('Allow', () => this.unblock(q.name), 'tiny', { title: 'stop blocking this domain' })
        : btn('Block', () => this.block(q.name), 'tiny danger', { title: 'block this domain for every app' });
      this.logBody.append(h('tr', { class: q.blocked ? 'blocked' : '' },
        h('td', { class: 'c-time mono muted' }, fmt.time(q.at)),
        h('td', { class: 'c-type mono' }, q.type || ''),
        h('td', { class: 'mono dns-name' }, q.blocked ? badge('blocked', 'red') : null, ' ', q.name),
        h('td', { class: 'c-act' }, act)));
    }
  },

  async toggleEnabled() {
    const cfg = Object.assign({}, this.cfg, { enabled: !(this.stats && this.stats.enabled) });
    try { await api('PUT', '/api/dns', cfg); } catch (_) { return; }
    toast('DNS blocking ' + (cfg.enabled ? 'on' : 'off'), 'ok', 1800);
    this.loadStatus();
  },
  async block(dom) {
    try { await api('POST', '/api/dns/block', { domain: dom }); } catch (_) { return; }
    toast('Blocked ' + dom, 'ok', 1800); this.loadStatus(); this.loadLog();
  },
  async unblock(dom) {
    try { await api('POST', '/api/dns/unblock', { domain: dom }); } catch (_) { return; }
    toast('Allowed ' + dom, 'ok', 1800); this.loadStatus(); this.loadLog();
  },
  async refresh() {
    try { await api('POST', '/api/dns/refresh'); } catch (_) { return; }
    toast('Refreshing blocklists…', 'ok', 2500); setTimeout(() => this.loadStatus(), 1500);
  },
  async resetStats() {
    if (!confirm('Clear the DNS query log and counters?\n\nThe blocklists themselves are kept.')) return;
    try { await api('POST', '/api/dns/reset'); } catch (_) { return; }
    toast('Query log cleared', 'ok'); this.loadStatus(); this.loadLog();
  },

  async listsDialog() {
    const cfg = Object.assign({ enabled: false, blocklists: [], block: [], allow: [], sinkhole: 'nxdomain' }, this.cfg);
    cfg.blocklists = (cfg.blocklists || []).slice();
    cfg.block = (cfg.block || []).slice();
    cfg.allow = (cfg.allow || []).slice();
    const save = async () => { try { await api('PUT', '/api/dns', cfg); } catch (_) { return; } this.loadStatus(); draw(); toast('Saved', 'ok', 1200); };

    const listsBox = h('div', { class: 'dns-edit-list' });
    const chipsBox = (arr, kind) => {
      const box = h('div', { class: 'dns-chips' });
      arr.forEach((d, i) => box.append(h('span', { class: 'dns-chip' }, d,
        h('button', { type: 'button', class: 'dns-chip-x', title: 'remove', onClick: () => { arr.splice(i, 1); save(); } }, '×'))));
      if (!arr.length) box.append(h('span', { class: 'muted small' }, 'none'));
      return box;
    };
    const blockBox = h('div'), allowBox = h('div');
    const draw = () => {
      clear(listsBox);
      (cfg.blocklists || []).forEach((u, i) => listsBox.append(h('div', { class: 'dns-edit-row' },
        h('span', { class: 'mono small dns-url', title: u }, u),
        btn('Remove', () => { cfg.blocklists.splice(i, 1); save(); }, 'tiny danger'))));
      if (!cfg.blocklists.length) listsBox.append(h('div', { class: 'muted small' }, 'No blocklists yet. Add a recommended one below to start blocking ads & trackers.'));
      clear(blockBox); blockBox.append(chipsBox(cfg.block, 'block'));
      clear(allowBox); allowBox.append(chipsBox(cfg.allow, 'allow'));
    };

    const urlIn = textInput('', { class: 'mono', placeholder: 'https://…/hosts  (hosts or domain list)', spellcheck: 'false' });
    const addUrl = () => { const u = urlIn.value.trim(); if (!u) return; if (!cfg.blocklists.includes(u)) cfg.blocklists.push(u); urlIn.value = ''; save(); };
    urlIn.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addUrl(); } });
    const recRow = h('div', { class: 'dns-rec' }, h('span', { class: 'muted small' }, 'Recommended: '),
      ...DNS_RECOMMENDED.map(r => btn(r.name, () => { if (!cfg.blocklists.includes(r.url)) { cfg.blocklists.push(r.url); save(); } }, 'tiny', { title: r.url })));

    const blkIn = textInput('', { class: 'mono', placeholder: 'domain to block, e.g. ads.example.com', spellcheck: 'false' });
    blkIn.addEventListener('keydown', e => { if (e.key === 'Enter' && blkIn.value.trim()) { e.preventDefault(); cfg.block.push(blkIn.value.trim().toLowerCase()); blkIn.value = ''; save(); } });
    const alwIn = textInput('', { class: 'mono', placeholder: 'domain to always allow', spellcheck: 'false' });
    alwIn.addEventListener('keydown', e => { if (e.key === 'Enter' && alwIn.value.trim()) { e.preventDefault(); cfg.allow.push(alwIn.value.trim().toLowerCase()); alwIn.value = ''; save(); } });

    const sinkSel = sel([{ value: 'nxdomain', label: 'NXDOMAIN (domain does not exist)' }, { value: 'zero', label: '0.0.0.0 / :: (sinkhole)' }], cfg.sinkhole || 'nxdomain');
    sinkSel.addEventListener('change', () => { cfg.sinkhole = sinkSel.value; save(); });

    const body = h('div', { class: 'tab-panel' },
      h('div', { class: 'dns-sec-title' }, 'Blocklists'),
      h('div', { class: 'muted small' }, 'Downloaded and merged. Each can be a hosts file or a plain domain list. StevenBlack is a great default.'),
      listsBox, recRow,
      h('div', { class: 'row', style: { gap: '8px', marginTop: '6px' } }, urlIn, btn('Add list', addUrl, 'primary')),
      h('div', { class: 'dns-sec-title' }, 'Block these (manual)'),
      blockBox, blkIn,
      h('div', { class: 'dns-sec-title' }, 'Always allow (whitelist — wins over lists)'),
      allowBox, alwIn,
      h('div', { class: 'dns-sec-title' }, 'When blocking, answer with'),
      sinkSel);
    openModal({ title: 'DNS blocklists & rules', width: '640px', body, buttons: [{ label: 'Done' }] });
    draw();
  },

  onEvent() { /* polled on its own timer */ },
};

/* ================================================================
 * 4h-bis. AI Agents — control centre for AI CLI/coding agents:
 * what is running, what endpoints they talk to, and whether they are
 * sending credentials off the box.
 * ================================================================ */
Pages.ai = {
  title: 'AI Agents',
  auto: true,
  data: null,
  async mount(root) {
    this.root = root;
    state.bwAlerts = state.bwAlerts || [];
    // visiting the page clears the AI nav badge
    const navAi = document.querySelector('#nav-ai'); if (navAi) { navAi.textContent = ''; navAi.hidden = true; }
    root.append(h('div', { class: 'page-head' },
      h('h2', null, 'AI Agents'),
      h('span', { class: 'page-sub muted' }, 'what your AI tools are doing on the network — and what they send'),
      h('span', { class: 'spacer' }),
      this.monBtn = btn('…', () => this.toggleMonitor(), 'tiny'),
      this.autoBtn = btn('Auto: on', () => { this.auto = !this.auto; this.autoBtn.textContent = 'Auto: ' + (this.auto ? 'on' : 'off'); this.schedule(); }, 'tiny'),
      btn('Refresh', () => this.load(), 'tiny'),
      btn('Request log', () => this.logDialog(), 'tiny')));

    this.tiles = h('div', { class: 'dns-tiles' });
    this.leakBox = h('div', { class: 'ai-leaks' });
    this.listWrap = h('div', { class: 'ai-agents' });
    root.append(this.tiles, this.leakBox, this.listWrap);
    await this.load();
    if (!root.isConnected) return;
    this.schedule();
  },
  unmount() { clearInterval(this.timer); this.root = this.listWrap = this.tiles = this.leakBox = null; },
  schedule() { clearInterval(this.timer); if (this.auto) this.timer = setInterval(() => this.load(true), 3000); },

  async load(silent) {
    let d; try { d = await api('GET', '/api/ai', undefined, { silent: silent !== false }); } catch (_) { return; }
    if (!this.listWrap) return;
    this.data = d;
    this.render();
  },

  async toggleMonitor() {
    const on = this.data && this.data.monitoring;
    if (!on && !confirm('Monitor all known AI agents?\n\nThis installs an intercept rule matching every known AI API endpoint (api.anthropic.com, api.openai.com, …) so their HTTPS is decrypted and passively scanned for leaked keys/passwords. The agents must trust the cyberboba CA. Turn off any time.')) return;
    try {
      const d = await api(on ? 'DELETE' : 'POST', '/api/ai/monitor');
      this.data = d; this.render();
      toast(on ? 'Stopped monitoring AI agents' : 'Monitoring all AI agents', 'ok');
    } catch (_) { /* shown */ }
  },

  render() {
    const d = this.data || {}; const s = d.summary || {}; const agents = d.agents || [];
    // monitor button state
    if (this.monBtn) {
      this.monBtn.textContent = d.monitoring ? 'Monitoring: on' : 'Monitor all agents';
      this.monBtn.className = 'btn tiny' + (d.monitoring ? ' danger' : ' primary');
      this.monBtn.disabled = !d.enabled;
      this.monBtn.title = d.enabled ? '' : 'intercept engine is disabled';
    }
    // tiles
    clear(this.tiles);
    const tile = (label, value, cls) => h('div', { class: 'dns-tile ' + (cls || '') }, h('div', { class: 'dns-tile-v' }, value), h('div', { class: 'dns-tile-l muted small' }, label));
    this.tiles.append(
      tile('agents active', String(s.agents_active || 0)),
      tile('running now', String(s.agents_running || 0), (s.agents_running ? 'ok' : '')),
      tile('flows seen', fmt.num(s.total_flows || 0)),
      tile('credential leaks', String(s.total_leaks || 0), (s.total_leaks ? 'bad' : 'ok')));

    // credential leaks panel (headline)
    clear(this.leakBox);
    const leaks = [];
    for (const a of agents) for (const l of (a.leaks || [])) leaks.push(Object.assign({ agent: a.name }, l));
    if (leaks.length) {
      this.leakBox.append(h('div', { class: 'ai-leak-head' }, badge('' + leaks.length, 'red'),
        ' credential' + (leaks.length > 1 ? 's' : '') + ' seen leaving your AI agents'));
      for (const l of leaks.slice(0, 20)) {
        this.leakBox.append(h('div', { class: 'ai-leak-row sev-' + l.severity },
          badge(l.severity, SEV_BADGE[l.severity] || 'gray'),
          h('span', { class: 'ai-leak-agent' }, l.agent),
          h('span', { class: 'ai-leak-msg' }, 'sent ' + l.title + ' → ' + (l.host || '?')),
          h('a', { class: 'ai-leak-flow', href: '#/intercept', title: 'flow #' + l.flow_id,
            onClick: () => { setTimeout(() => { if (Pages.intercept && Pages.intercept.filterByIds) Pages.intercept.filterByIds([l.flow_id]); }, 60); } }, '#' + l.flow_id)));
      }
    } else if (d.monitoring) {
      this.leakBox.append(h('div', { class: 'ai-leak-ok' }, '✓ No credentials seen leaving your monitored AI agents.'));
    }

    // per-agent cards
    clear(this.listWrap);
    if (!agents.length) {
      this.listWrap.append(emptyState('No AI agents detected',
        d.monitoring ? 'No known AI tool is running or has made a request yet. Launch Claude Code, Codex, Gemini, Cursor, aider, ollama… and they appear here.'
          : 'cyberboba knows ' + (s.known || 0) + ' AI CLI/coding tools. Press "Monitor all agents" to transparently record and scan their API traffic for leaked keys and passwords.',
        { cls: 'flat', actions: d.enabled && !d.monitoring ? [btn('Monitor all agents', () => this.toggleMonitor(), 'primary')] : [] }));
      return;
    }
    for (const a of agents) {
      const running = (a.running || []);
      const bw = a.bandwidth || {};
      const card = h('div', { class: 'ai-card' + (a.leak_count ? ' leaking' : '') });
      card.append(h('div', { class: 'ai-card-head' },
        h('span', { class: 'ai-dot ' + (running.length ? 'on' : (a.live_conns || a.flows ? 'seen' : 'off')) }),
        h('span', { class: 'ai-name' }, a.name),
        h('span', { class: 'ai-vendor muted small' }, a.vendor),
        h('span', { class: 'spacer' }),
        running.length ? badge(running.length + ' running', 'green') : (a.live_conns ? badge('active', 'blue') : badge('idle', 'gray')),
        a.leak_count ? badge(a.leak_count + ' leak' + (a.leak_count > 1 ? 's' : ''), 'red') : null));

      const meta = h('div', { class: 'ai-card-meta muted small' });
      const bits = [];
      if (running.length) bits.push('pid ' + running.map(r => r.pid).join(', '));
      if (a.live_conns) bits.push(a.live_conns + ' live conn' + (a.live_conns > 1 ? 's' : ''));
      if (bw.rate_out || bw.rate_in) bits.push('↓ ' + fmt.rate(bw.rate_in || 0) + ' · ↑ ' + fmt.rate(bw.rate_out || 0));
      if (a.flows) bits.push(fmt.num(a.flows) + ' flow' + (a.flows > 1 ? 's' : ''));
      meta.textContent = bits.join('  ·  ') || 'no activity yet';
      card.append(meta);

      const eps = (a.endpoints || []);
      if (eps.length) {
        const tbl = h('div', { class: 'ai-eps' });
        tbl.append(h('div', { class: 'ai-ep ai-ep-head' }, h('span', null, 'endpoint'), h('span', null, 'reqs'), h('span', null, 'data'), h('span', null, 'last')));
        for (const e of eps.slice(0, 8)) {
          tbl.append(h('div', { class: 'ai-ep' },
            h('span', { class: 'ai-ep-host', title: e.host }, e.host),
            h('span', { class: 'mono' }, String(e.requests)),
            h('span', { class: 'mono' }, fmt.bytes(e.bytes || 0)),
            h('span', { class: 'muted small mono' }, e.last ? new Date(e.last).toLocaleTimeString() : '')));
        }
        card.append(tbl);
      } else if (a.live_conns && !a.flows) {
        card.append(h('div', { class: 'ai-hint muted small' }, 'Talking to the network but not decrypted yet — turn on monitoring to see endpoints and scan for leaks.'));
      }
      this.listWrap.append(card);
    }
    // idle known agents footnote
    const idle = d.idle || [];
    if (idle.length) {
      this.listWrap.append(h('div', { class: 'ai-idle muted small' },
        'Also watched (not running): ' + idle.map(a => a.name).join(', ')));
    }
  },

  async logDialog() {
    const box = h('div', { class: 'ai-log' }, h('div', { class: 'muted small' }, h('span', { class: 'spinner' }), ' loading…'));
    openModal({ title: 'AI agent request log', width: '760px', body: box, buttons: [{ label: 'Close' }] });
    let r; try { r = await api('GET', '/api/ai/log', undefined, { silent: true }); }
    catch (e) { replace(box, h('div', { class: 'error-box' }, e.message)); return; }
    const log = (r && r.log) || [];
    if (!log.length) { replace(box, emptyState('No agent requests recorded', 'Turn on monitoring, then use an AI agent — its API calls appear here.', { cls: 'small flat' })); return; }
    clear(box);
    for (const e of log) {
      box.append(h('div', { class: 'ai-log-row' },
        h('span', { class: 'ai-log-agent' }, e.agent_name),
        h('span', { class: 'ai-log-method mono' }, e.method),
        h('span', { class: 'ai-log-host mono', title: e.host + e.path }, e.host),
        h('span', { class: 'ai-log-path mono muted', title: e.path }, e.path || '/'),
        h('span', { class: 'ai-log-status mono' }, e.status || ''),
        e.leaks ? badge(e.leaks + ' leak' + (e.leaks > 1 ? 's' : ''), 'red') : null,
        h('span', { class: 'ai-log-time muted small mono' }, e.time ? new Date(e.time).toLocaleTimeString() : '')));
    }
  },

  onEvent(type) { if (type === 'flow' || type === 'bw_alert') this.load(true); },
};

/* ================================================================
 * 4h. Firewall (ZoneAlarm-style application firewall)
 * ================================================================ */
const FW_PERMS = [{ value: 'ask', label: 'Ask' }, { value: 'allow', label: 'Allow' }, { value: 'block', label: 'Block' }];
Pages.firewall = {
  title: 'Firewall',
  async mount(root) {
    this.root = root;
    await this.reload(true);
    if (!root.isConnected) return;
    root.prepend(this.head());
    this.body = h('div');
    root.append(this.body);
    this.render();
    this.timer = setInterval(() => this.loadPending(), 4000);
  },
  unmount() { clearInterval(this.timer); this.root = null; this.body = null; },
  onEvent(type) { if (type === 'fw_ask' || type === 'fw_resolved') this.loadPending(); if (type === 'fw_block' || type === 'fw_resolved') this.loadActivity(); },
  async reload(silent) {
    const r = await api('GET', '/api/firewall', undefined, { silent }).catch(() => null);
    if (!r) return;
    this.status = r;
    this.cfg = Object.assign({ enabled: false, mode: 'ask', stealth: false, internet_lock: false, allow_lan_inbound: true, trusted_nets: ['lan'], ask_timeout_sec: 20, ask_timeout_action: 'block', programs: [] }, r.config || {});
    if (!Array.isArray(this.cfg.programs)) this.cfg.programs = [];
    if (!Array.isArray(this.cfg.trusted_nets)) this.cfg.trusted_nets = ['lan'];
    const p = await api('GET', '/api/firewall/pending', undefined, { silent: true }).catch(() => ({ pending: [] }));
    this.pending = p.pending || [];
    const ac = await api('GET', '/api/firewall/activity?limit=200', undefined, { silent: true }).catch(() => ({ activity: [] }));
    this.activity = ac.activity || [];
  },
  head() {
    const lockOn = this.cfg.internet_lock;
    return h('div', { class: 'page-head' }, h('h2', null, 'Firewall'),
      h('span', { class: 'muted small' }, 'ZoneAlarm-style application control'),
      h('span', { class: 'spacer' }),
      this.lockBtn = btn(lockOn ? '■ Unlock Internet' : '⊘ Internet Lock', () => this.toggleLock(), lockOn ? 'danger' : '', { title: 'panic switch: block everything except lock-pass programs' }),
      btn('Reload', () => this.refresh()));
  },
  async refresh() { await this.reload(true); if (this.body) { replace(this.root, this.head(), this.body); this.render(); } },
  render() {
    const b = clear(this.body);
    const toAct = this.cfg.ask_timeout_action || 'allow';
    b.append(h('div', { class: 'info-box small', style: { marginBottom: '10px' } },
      h('b', null, 'How Ask mode works: '),
      'new connections from unknown programs are held and a popup asks you to Allow/Deny (one prompt per program, ' + (this.cfg.ask_timeout_sec || 20) + 's). ',
      'Keep a cyberboba tab/app open to answer. ',
      h('b', null, 'On timeout: '),
      toAct === 'block'
        ? h('span', null, 'an unanswered prompt is ', h('b', { class: 'bad' }, 'blocked'), ' (ask_timeout_action = block). A blocked program (e.g. a background updater showing up as ', h('code', null, 'http'), ') will fail silently \u2014 check ', h('b', null, 'Recent activity'), ' below to see exactly what was blocked, and click Allow. Switch the timeout action to Allow (in Settings) for fail-open.')
        : h('span', null, 'an unanswered prompt is ', h('b', null, 'allowed'), ' (fail-open, never silently blocked). For strict blocking use ', h('b', null, 'Block'), ' mode with an allowlist.')));
    b.append(h('div', { class: 'two-col' },
      h('div', { class: 'tab-panel' }, this.statusCard(), this.pendingCard()),
      h('div', { class: 'tab-panel' }, this.settingsCard(), this.zonesCard())));
    b.append(this.activityCard());
    b.append(this.programsCard());
  },

  activityCard() {
    const card = h('div', { class: 'card', style: { marginTop: '12px' } });
    const blk = checkbox('blocked only', !!this.actBlockedOnly);
    blk.input.addEventListener('change', () => { this.actBlockedOnly = blk.input.checked; this.renderActivity(); });
    card.append(h('div', { class: 'card-title' }, 'Recent activity',
      h('span', { class: 'muted small' }, '\u2014 what the firewall blocked / prompted'),
      h('span', { class: 'spacer' }),
      h('label', { class: 'check small' }, blk.input, h('span', null, 'blocked only')),
      btn('Refresh', () => this.loadActivity(), 'tiny')));
    this.actBox = h('div', { class: 'fw-activity' });
    card.append(this.actBox);
    this.renderActivity();
    return card;
  },
  renderActivity() {
    if (!this.actBox) return;
    const rows = (this.activity || []).filter(a => !this.actBlockedOnly || !a.allow);
    clear(this.actBox);
    if (!rows.length) {
      this.actBox.append(emptyState('No firewall activity yet',
        'Blocks and prompts appear here as they happen. If a program can\u2019t reach the network, look here first \u2014 you\u2019ll see what was blocked and can Allow it.', { cls: 'small flat' }));
      return;
    }
    const tbl = h('table', { class: 'grid fw-act' });
    tbl.append(h('thead', null, h('tr', null,
      h('th', null, 'time'), h('th', null, 'action'), h('th', null, 'app'), h('th', null, 'destination'), h('th', null, 'zone'), h('th', null, 'reason'), h('th', null, ''))));
    const tb = h('tbody');
    for (const a of rows) {
      const dst = (a.host || a.ip || '?') + (a.port ? ':' + a.port : '');
      const canAllow = !a.allow && a.app && a.zone === 'internet' && !String(a.app).startsWith('cmd:') && a.reason !== 'internet lock';
      tb.append(h('tr', { class: a.allow ? '' : 'fw-blocked' },
        h('td', { class: 'mono small' }, new Date(a.time).toLocaleTimeString()),
        h('td', null, a.allow ? badge('allow', 'green') : badge('BLOCK', 'red')),
        h('td', { title: a.exe || '' }, a.app || (a.pid ? 'unknown (pid ' + a.pid + ')' : 'unknown')),
        h('td', { class: 'mono small', title: dst }, dst),
        h('td', { class: 'muted small' }, a.zone),
        h('td', { class: 'muted small', title: a.reason }, a.reason),
        h('td', null, canAllow ? btn('Allow', () => this.allowApp(a.app), 'tiny') : null)));
    }
    tbl.append(tb);
    this.actBox.append(tbl);
  },
  async loadActivity() {
    const r = await api('GET', '/api/firewall/activity?limit=200', undefined, { silent: true }).catch(() => null);
    if (r) this.activity = r.activity || [];
    this.renderActivity();
  },
  async allowApp(app) {
    if (!confirm('Allow "' + app + '" to access the internet from now on?')) return;
    const progs = (this.cfg.programs || []).slice();
    const ex = progs.find(p => p.app === app);
    if (ex) ex.internet = 'allow'; else progs.push({ app: app, internet: 'allow' });
    if (await this.save({ programs: progs })) { toast(app + ' allowed', 'ok'); this.loadActivity(); }
  },
  statusCard() {
    const st = this.status || {}, s = (st.stats) || {};
    const on = this.cfg.enabled;
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Status',
        on ? badge('on', 'green') : badge('off', 'gray'),
        this.cfg.stealth ? badge('stealth', 'blue') : null,
        this.cfg.internet_lock ? badge('INTERNET LOCK', 'red') : null),
      h('div', { class: 'kv' },
        kv('mode', this.cfg.mode), kv('programs', (this.cfg.programs || []).length),
        kv('pending prompts', (this.pending || []).length),
        kv('allowed', num(s.allowed)), kv('blocked', num(s.blocked)), kv('asked', num(s.asked))),
      h('div', { class: 'muted small', style: { marginTop: '6px' } },
        'Program control gates every new TCP connection by app and zone. UDP/QUIC is governed by ', h('a', { href: '#/rules' }, 'rules'), ' / ', h('a', { href: '#/tags' }, 'tags'), '.'));
  },
  settingsCard() {
    const enable = checkbox('Firewall enabled', this.cfg.enabled);
    enable.input.addEventListener('change', async () => { await this.save({ enabled: enable.input.checked }); });
    const mode = sel([{ value: 'off', label: 'Off — allow everything' },
      { value: 'ask', label: 'Ask — prompt for unknown programs' },
      { value: 'auto', label: 'Auto-learn — allow & remember new programs' },
      { value: 'block', label: 'Block — deny unknown programs' }], this.cfg.mode);
    mode.addEventListener('change', async () => { await this.save({ mode: mode.value, enabled: mode.value !== 'off' ? true : this.cfg.enabled }); });
    const stealth = checkbox('Stealth — silently drop unsolicited inbound (invisible to scans; needs root)', this.cfg.stealth);
    stealth.input.addEventListener('change', async () => { await this.save({ stealth: stealth.input.checked }); });
    const lanIn = checkbox('Allow inbound from Trusted Zone (LAN file/printer sharing)', this.cfg.allow_lan_inbound);
    lanIn.input.addEventListener('change', async () => { await this.save({ allow_lan_inbound: lanIn.input.checked }); });
    const tmo = h('input', { type: 'number', value: this.cfg.ask_timeout_sec, min: 1, max: 600, class: 'mono', style: { width: '80px' } });
    const tmoAct = sel([{ value: 'block', label: 'block' }, { value: 'allow', label: 'allow' }], this.cfg.ask_timeout_action);
    const saveTmo = () => this.save({ ask_timeout_sec: num(tmo.value) || 20, ask_timeout_action: tmoAct.value });
    tmo.addEventListener('change', saveTmo); tmoAct.addEventListener('change', saveTmo);
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Program control'),
      h('div', { style: { marginBottom: '6px' } }, enable),
      field('Mode', mode),
      h('div', { style: { marginTop: '8px' } }, stealth),
      h('div', { style: { marginTop: '4px' } }, lanIn),
      h('div', { class: 'form-row', style: { marginTop: '8px', alignItems: 'flex-end', gap: '10px' } },
        field('Prompt timeout (s)', tmo), field('On timeout', tmoAct, 'allow = fail-open (recommended)')));
  },
  zonesCard() {
    const nets = tagsInput({ values: this.cfg.trusted_nets, placeholder: 'lan, 192.168.0.0/16', onChange: vals => { this.cfg.trusted_nets = vals; } });
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Trusted Zone'),
      h('div', { class: 'muted small', style: { marginBottom: '6px' } }, 'Networks treated as trusted (your LAN). ', h('code', null, 'lan'), ' = all private ranges.'),
      field('Trusted networks', nets),
      h('div', { class: 'form-actions' }, btn('Save zones', () => this.save({ trusted_nets: nets.getValues() }), 'primary')));
  },
  pendingCard() {
    const list = h('div', { class: 'fw-pending' });
    this.pendingList = list;
    this.renderPending();
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Pending prompts',
        this.pending && this.pending.length ? badge(String(this.pending.length), 'yellow') : null,
        h('span', { class: 'spacer' }),
        btn('Allow all', () => this.answerAll(true), 'tiny'),
        btn('Deny all', () => this.answerAll(false), 'tiny danger')),
      list);
  },
  renderPending() {
    const list = this.pendingList; if (!list) return;
    clear(list);
    const ps = this.pending || [];
    if (!ps.length) { list.append(emptyState('Nothing waiting for you',
      'When an unknown program tries to connect in Ask mode, it pauses here (and pops up) until you Allow or Deny it.',
      { cls: 'small flat' })); return; }
    for (const a of ps) {
      const dst = (a.host || a.ip || '?') + (a.port ? ':' + a.port : '');
      list.append(h('div', { class: 'fw-prow' },
        h('div', null, h('b', null, a.app || '(unknown)'), a.guess ? h('span', { class: 'muted small' }, ' (probably ' + a.guess + ')') : null, ' → ', h('span', { class: 'mono' }, dst), ' ', badge(a.zone, a.zone === 'trusted' ? 'green' : 'blue')),
        h('div', { class: 'form-row', style: { gap: '6px', marginTop: '4px' } },
          btn('Allow', () => this.answer(a.id, true, false), 'tiny primary'),
          btn('Allow + remember', () => this.answer(a.id, true, true), 'tiny'),
          btn('Deny', () => this.answer(a.id, false, false), 'tiny danger'))));
    }
  },
  programsCard() {
    this.ptbody = h('tbody');
    this.renderPrograms();
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Programs',
        h('span', { class: 'muted small' }, 'per-application permissions by zone'),
        h('span', { class: 'spacer' }),
        btn('+ Add program', () => this.addProgram()),
        this.pSaveBtn = btn('Save programs', () => this.savePrograms(), 'primary')),
      h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
        h('colgroup', null, h('col'), h('col', { style: { width: '120px' } }), h('col', { style: { width: '120px' } }), h('col', { style: { width: '100px' } }), h('col', { style: { width: '90px' } }), h('col', { style: { width: '56px' } })),
        h('thead', null, h('tr', null, h('th', null, 'Program (matcher)'), h('th', null, 'Trusted'), h('th', null, 'Internet'), h('th', null, 'Server'), h('th', null, 'Lock pass'), h('th'))),
        this.ptbody)));
  },
  renderPrograms() {
    const tb = clear(this.ptbody);
    const progs = this.cfg.programs || [];
    if (!progs.length) { tb.append(h('tr', null, h('td', { colspan: 6 },
      emptyState('No per-program rules yet',
        ['Until you add one, unknown apps follow the global mode above. Add a program to set exactly what it may reach in your Trusted (LAN) and Internet zones — or just answer an Ask prompt with ', h('b', null, 'remember'), ' and it lands here.'],
        { cls: 'small', actions: [btn('+ Add program', () => this.addProgram(), 'primary')] })))); return; }
    progs.forEach((p, i) => {
      const app = textInput(p.app, { class: 'mono' }); app.addEventListener('input', () => { p.app = app.value.trim(); });
      const trusted = sel(FW_PERMS, p.trusted || 'ask'); trusted.addEventListener('change', () => { p.trusted = trusted.value; });
      const internet = sel(FW_PERMS, p.internet || 'ask'); internet.addEventListener('change', () => { p.internet = internet.value; });
      const server = sel([{ value: '', label: '—' }, { value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }], p.server || ''); server.addEventListener('change', () => { p.server = server.value; });
      const lock = checkbox('', !!p.lock_pass); lock.input.addEventListener('change', () => { p.lock_pass = lock.input.checked; });
      tb.append(h('tr', null,
        h('td', null, app),
        h('td', null, trusted), h('td', null, internet), h('td', null, server),
        h('td', { style: { textAlign: 'center' } }, lock),
        h('td', null, btn('✕', () => { this.cfg.programs.splice(i, 1); this.renderPrograms(); }, 'tiny danger'))));
    });
  },
  addProgram() {
    pickAppModal(val => {
      if ((this.cfg.programs || []).some(p => p.app === val)) { toast('Already listed', 'info'); return; }
      this.cfg.programs.push({ app: val, trusted: 'allow', internet: 'ask', server: '', lock_pass: false });
      this.renderPrograms();
      toast('Added ' + val + ' — set its permissions and Save', 'ok');
    });
  },
  async save(patch) {
    Object.assign(this.cfg, patch);
    try { const r = await api('PUT', '/api/firewall', this.cfg); this.status = r; this.cfg = Object.assign(this.cfg, r.config || {}); toast('Firewall updated', 'ok'); this.refresh(); return true; }
    catch (_) { return false; }
  },
  async savePrograms() {
    for (const p of this.cfg.programs) if (!p.app) { toast('Every program needs a matcher', 'error'); return; }
    await this.save({ programs: this.cfg.programs });
  },
  async toggleLock() {
    const turningOn = !this.cfg.internet_lock;
    if (turningOn && !confirm('Lock the internet now?\n\nThis instantly cuts off all network access except programs you have marked “lock pass”. Use it as a panic switch — press the button again to restore access.')) return;
    try { const r = await api('POST', '/api/firewall/lock', { on: turningOn }); this.status = r; this.cfg = Object.assign(this.cfg, r.config || {}); toast(this.cfg.internet_lock ? 'Internet locked — only lock-pass programs can connect' : 'Internet unlocked — traffic flows normally again', this.cfg.internet_lock ? 'warn' : 'ok'); this.refresh(); }
    catch (_) { /* shown */ }
  },
  async answer(id, allow, remember) {
    try { await api('POST', '/api/firewall/answer', { id, allow, remember }, { silent: true }); } catch (_) { /* may have timed out */ }
    this.pending = (this.pending || []).filter(a => a.id !== id);
    state.fwQueue = state.fwQueue.filter(a => a.id !== id); updateFwBadge();
    this.renderPending();
  },
  async answerAll(allow) {
    try { await api('POST', '/api/firewall/answer_all', { allow }, { silent: true }); } catch (_) { /* ignore */ }
    this.pending = []; state.fwQueue = []; updateFwBadge(); this.renderPending();
  },
  async loadPending() {
    const p = await api('GET', '/api/firewall/pending', undefined, { silent: true }).catch(() => null);
    if (!p || !this.pendingList) return;
    this.pending = p.pending || [];
    this.renderPending();
  },
};

/* ================================================================
 * 4g. Caido
 * ================================================================ */
Pages.caido = {
  title: 'Caido (external)',
  async mount(root) {
    this.root = root;
    let r; try { r = await api('GET', '/api/caido'); } catch (_) { return; }
    if (!root.isConnected) return;
    this.status = r;
    this.cfg = Object.assign({ enabled: false, managed: true, binary: '', listen: '127.0.0.1:8080', data_path: '', ca_cert: '', extra_args: [], proxy_name: 'caido' }, r.config || {});
    if (!Array.isArray(this.cfg.extra_args)) this.cfg.extra_args = [];
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Caido (external)'),
      h('span', { class: 'muted small' }, 'external proxy tool; for the built-in interceptor see ', h('a', { href: '#/intercept' }, 'Intercept')),
      h('span', { class: 'spacer' }), btn('Refresh', () => this.refresh())));
    this.statusBox = h('div', { class: 'card' });
    this.logBox = h('div', { class: 'card' });
    root.append(h('div', { class: 'two-col' },
      h('div', { class: 'tab-panel' }, this.statusBox, this.logBox),
      h('div', { class: 'tab-panel' }, this.settingsCard(), this.helpCard())));
    this.renderStatus();
    this.renderLog();
    this.loadLog();
  },
  unmount() { clearInterval(this.logTimer); this.root = null; },
  async refresh() {
    let r; try { r = await api('GET', '/api/caido', undefined, { silent: true }); } catch (_) { return; }
    this.status = r; this.renderStatus();
  },
  renderStatus() {
    const c = this.status || {};
    const can = c.enabled && c.managed;
    replace(this.statusBox,
      h('div', { class: 'card-title' }, 'Status', caidoStateBadge(c)),
      h('div', { class: 'kv' },
        kv('listen', c.listen), kv('reachable', c.enabled ? (c.reachable ? 'yes' : 'no') : ''), kv('pid', c.running && c.pid ? c.pid : ''),
        kv('version', c.version), kv('binary', c.binary), kv('CA certificate', c.ca_cert),
        kv('UI', c.ui_url ? h('a', { href: c.ui_url, target: '_blank', rel: 'noopener' }, c.ui_url) : ''),
        kv('managed', c.managed ? 'yes (cyberboba starts/stops caido-cli)' : 'no (external instance)')),
      c.error ? h('div', { class: 'error-box', style: { marginTop: '6px' } }, c.error) : null,
      h('div', { class: 'card-actions' },
        btn('Start', () => this.action('start'), 'ok', { disabled: !can || c.running }),
        btn('Stop', () => this.action('stop'), 'danger', { disabled: !can || !c.running }),
        btn('Restart', () => this.action('restart'), '', { disabled: !can }),
        c.ui_url ? h('a', { class: 'btn', href: c.ui_url, target: '_blank', rel: 'noopener' }, 'Open UI ↗') : null,
        h('span', { class: 'spacer' }),
        this.installBtn = btn('Install caido-cli', () => this.install(), '', { title: 'POST /api/caido/install — downloads the latest caido-cli' })),
      h('div', { class: 'card-actions', style: { alignItems: 'flex-end' } },
        field('CA certificate path', this.caPath = textInput(c.ca_cert || '', { class: 'mono', placeholder: 'leave empty to use the configured ca_cert', style: { width: '300px' } })),
        btn('Install CA certificate', () => this.installCA(), '', { title: 'POST /api/caido/ca/install' })),
      this.caOut = h('div', { style: { marginTop: '6px' } }));
  },
  async action(act) {
    try { await api('POST', '/api/caido/' + act); toast('Caido ' + act + ' requested', 'ok'); } catch (_) { return; }
    setTimeout(() => this.refresh(), 800);
  },
  async install() {
    const b = this.installBtn;
    b.disabled = true; replace(b, h('span', { class: 'spinner' }), ' Installing… (may take a minute)');
    try {
      const r = await api('POST', '/api/caido/install');
      toast('caido-cli installed: ' + (r.binary || '') + ' ' + (r.version || ''), 'ok', 8000);
    } catch (_) { /* shown */ }
    await this.refresh();
  },
  async installCA() {
    const path = this.caPath.value.trim();
    replace(this.caOut, h('span', { class: 'muted' }, h('span', { class: 'spinner' }), ' installing CA…'));
    let r;
    try { r = await api('POST', '/api/caido/ca/install', path ? { path } : {}, { silent: true }); }
    catch (e) { replace(this.caOut, h('div', { class: 'error-box' }, e.message)); return; }
    replace(this.caOut,
      h('div', { class: r.ok ? 'ok-box' : 'warn-box' },
        h('div', null, r.ok ? 'CA installed into:' : 'CA installation finished with errors'),
        r.installed_into && r.installed_into.length ? h('ul', { class: 'mono', style: { margin: '4px 0', paddingLeft: '18px' } }, ...r.installed_into.map(p => h('li', null, p))) : null,
        r.errors && r.errors.length ? h('ul', { class: 'mono bad', style: { margin: '4px 0', paddingLeft: '18px' } }, ...r.errors.map(e => h('li', null, e))) : null,
        h('div', { class: 'muted small' }, 'Restart browsers for the new CA to take effect.')));
  },
  settingsCard() {
    const c = this.cfg;
    const enabled = checkbox('Enabled (adds the Caido proxy entry to the rule engine)', c.enabled); bind(enabled.input, c, 'enabled');
    const managed = checkbox('Managed (cyberboba starts and stops caido-cli)', c.managed); bind(managed.input, c, 'managed');
    const listen = bind(textInput(c.listen, { class: 'mono', placeholder: '127.0.0.1:8080' }), c, 'listen', null, s => s.trim());
    const binary = bind(textInput(c.binary, { class: 'mono', placeholder: 'auto (/usr/local/lib/cyberboba/caido-cli)' }), c, 'binary', null, s => s.trim());
    const data = bind(textInput(c.data_path, { class: 'mono', placeholder: 'default data directory' }), c, 'data_path', null, s => s.trim());
    const ca = bind(textInput(c.ca_cert, { class: 'mono', placeholder: '/etc/cyberboba/caido-ca.crt' }), c, 'ca_cert', null, s => s.trim());
    const pname = bind(textInput(c.proxy_name, { class: 'mono', placeholder: 'caido' }), c, 'proxy_name', null, s => s.trim());
    const extra = tagsInput({ values: c.extra_args, placeholder: 'extra caido-cli arguments', onChange: v => { c.extra_args = v; } });
    const save = btn('Save settings', async () => {
      save.disabled = true;
      try {
        const r = await api('PUT', '/api/caido', c);
        toast('Caido settings saved', 'ok');
        if (r && r.config) { this.status = r; this.renderStatus(); } else this.refresh();
      } catch (_) { /* shown */ }
      finally { save.disabled = false; }
    }, 'primary');
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, 'Settings'),
      h('div', { class: 'tab-panel' },
        enabled, managed,
        h('div', { class: 'form-grid' },
          field('Listen address', listen, 'proxy listener; also the UI address'),
          field('Proxy name', pname, 'name of the auto-generated proxy entry used in rules'),
          field('Binary', binary), field('Data path', data),
          field('CA certificate', ca, 'ca.crt exported from the Caido UI'), field('Extra args', extra)),
        h('div', { class: 'form-actions' }, save)));
  },
  helpCard() {
    const pn = this.cfg.proxy_name || 'caido';
    return h('div', { class: 'card help' },
      h('div', { class: 'card-title' }, 'How it works'),
      h('p', null, 'Caido listens on the configured address (', h('code', null, this.cfg.listen || '127.0.0.1:8080'), ') as an HTTP proxy and serves its web UI on the same port.'),
      h('ol', null,
        h('li', null, 'Enable Caido here and start it (or point cyberboba at an external instance with "managed" off).'),
        h('li', null, 'Create a rule with action ', badge('proxy', 'blue'), ' and proxy ', h('code', null, pn), ' for the apps whose HTTP(S) traffic you want to inspect. ', h('a', { href: '#/rules' }, 'Open rules →')),
        h('li', null, 'Export the CA certificate from the Caido UI, set its path above and click "Install CA certificate" so browsers trust intercepted TLS.'),
        h('li', null, 'Keep "Block QUIC" enabled in Settings: browsers then fall back from HTTP/3 (UDP) to TCP, which makes HTTPS visible to Caido.')));
  },
  renderLog() {
    this.logPre = h('div', { class: 'log tall' });
    this.logAuto = checkbox('auto-refresh', false);
    this.logAuto.input.addEventListener('change', () => this.syncLogTimer());
    replace(this.logBox, h('div', { class: 'card-title' }, 'caido-cli log', h('span', { class: 'spacer' }), this.logAuto, btn('Refresh', () => this.loadLog(), 'tiny')), this.logPre);
  },
  syncLogTimer() {
    clearInterval(this.logTimer);
    if (this.logAuto.input.checked) this.logTimer = setInterval(() => this.loadLog(), 2000);
  },
  async loadLog() {
    let r; try { r = await api('GET', '/api/caido/log', undefined, { silent: true }); }
    catch (e) { replace(this.logPre, h('span', { class: 'bad' }, e.message)); return; }
    if (!this.logPre) return;
    const atBottom = this.logPre.scrollHeight - this.logPre.scrollTop - this.logPre.clientHeight < 20;
    this.logPre.textContent = (r.lines || []).join('\n') || '(empty)';
    if (atBottom) this.logPre.scrollTop = this.logPre.scrollHeight;
  },
  onEvent(type, data) {
    if (type === 'caido' && data) { this.status = Object.assign({}, this.status, data); this.renderStatus(); }
  },
};

/* ================================================================
 * 4h. Settings (general / yaml / doctor + log panel)
 * ================================================================ */
const LOG_RANK = { debug: 0, info: 1, warn: 2, warning: 2, error: 3, fatal: 4 };

function makeLogPanel() {
  const body = h('div', { class: 'log' });
  const level = sel(['all', 'debug', 'info', 'warn', 'error'], localStorage.getItem('cyberboba.logLevel') || 'all');
  const auto = checkbox('follow', true);
  const filter = h('input', { type: 'search', class: 'mono', placeholder: 'filter…', style: { width: '180px' } });
  const show = l => {
    if (level.value !== 'all' && (LOG_RANK[(l.level || 'info').toLowerCase()] || 0) < LOG_RANK[level.value]) return false;
    const f = filter.value.trim().toLowerCase();
    return !f || String(l.msg || '').toLowerCase().includes(f);
  };
  const line = l => h('div', { class: 'log-line lvl-' + String(l.level || 'info').toLowerCase() },
    h('span', { class: 'log-time' }, fmt.time(l.time)), h('span', { class: 'log-level' }, String(l.level || '')), h('span', { class: 'log-msg' }, l.msg || ''));
  const render = () => {
    clear(body);
    for (const l of state.logs) if (show(l)) body.append(line(l));
    body.scrollTop = body.scrollHeight;
  };
  const push = l => {
    if (!show(l)) return;
    body.append(line(l));
    while (body.childElementCount > LOG_MAX) body.firstElementChild.remove();
    if (auto.input.checked) body.scrollTop = body.scrollHeight;
  };
  level.addEventListener('change', () => { localStorage.setItem('cyberboba.logLevel', level.value); render(); });
  filter.addEventListener('input', debounce(render, 120));
  const el = h('div', { class: 'card settings-log' },
    h('div', { class: 'card-title' }, 'Daemon log', h('span', { class: 'spacer' }), filter, level, auto,
      btn('Clear view', () => clear(body), 'tiny'), btn('Reload', async () => { await loadInitialLog(); render(); }, 'tiny')),
    body);
  return { el, push, render };
}

async function loadInitialLog() {
  try {
    const r = await api('GET', '/api/log?limit=500', undefined, { silent: true });
    state.logs = (r.lines || []).slice(-LOG_MAX);
  } catch (_) { /* ignore */ }
}

Pages.settings = {
  title: 'Settings',
  async mount(root) {
    this.root = root;
    root.append(h('div', { class: 'page-head' }, h('h2', null, 'Settings')));
    const tabs = [['general', 'General'], ['yaml', 'YAML'], ['doctor', 'Doctor']];
    this.panels = {};
    const bar = h('div', { class: 'tabs' });
    const host = h('div');
    for (const [id, label] of tabs) {
      const b = h('button', { type: 'button', dataset: { tab: id }, onClick: () => this.showTab(id) }, label);
      bar.append(b);
      this.panels[id] = h('div', { class: 'tab-panel', hidden: true });
      host.append(this.panels[id]);
    }
    this.bar = bar;
    root.append(bar, host);
    this.logPanel = makeLogPanel();
    root.append(this.logPanel.el);
    this.logPanel.render();
    this.loaded = {};
    this.showTab(sessionStorage.getItem('cyberboba.settingsTab') || 'general');
  },
  unmount() { this.root = null; this.logPanel = null; },
  showTab(id) {
    if (!this.panels[id]) id = 'general';
    sessionStorage.setItem('cyberboba.settingsTab', id);
    $$('button', this.bar).forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    for (const k of Object.keys(this.panels)) this.panels[k].hidden = k !== id;
    if (!this.loaded[id]) { this.loaded[id] = true; this['load_' + id](this.panels[id]); }
  },

  /* ---- general ---- */
  async load_general(panel) {
    let cfg; try { cfg = await api('GET', '/api/config'); } catch (e) { panel.append(h('div', { class: 'error-box' }, e.message)); return; }
    const p = Object.assign({}, cfg.proxifier || {});
    const a = Object.assign({}, cfg.api || {});
    const misc = { log_level: cfg.log_level || 'info' };
    const enabled = checkbox('Install netfilter rules at daemon start (proxifier.enabled)', p.enabled); bind(enabled.input, p, 'enabled');
    const listenTcp = bind(textInput(p.listen_tcp, { class: 'mono', placeholder: '127.0.0.1:7470' }), p, 'listen_tcp', null, s => s.trim());
    const listenDns = bind(textInput(p.listen_dns, { class: 'mono', placeholder: '127.0.0.1:7453' }), p, 'listen_dns', null, s => s.trim());
    const dnsUp = bind(textInput(p.dns_upstream, { class: 'mono', placeholder: '1.1.1.1:53' }), p, 'dns_upstream', null, s => s.trim());
    const dnsVia = checkbox('Route DNS queries through rules (dns_via_rules; matched as pseudo-app "dns")', p.dns_via_rules); bind(dnsVia.input, p, 'dns_via_rules');
    const quic = checkbox('Block QUIC (drop UDP/443 so browsers fall back to TCP)', p.block_quic); bind(quic.input, p, 'block_quic');
    const ipv6 = checkbox('Intercept IPv6 traffic', p.ipv6); bind(ipv6.input, p, 'ipv6');
    const sniff = checkbox('Sniff hostnames (TLS SNI / HTTP Host) for hostname rules', p.sniff_hostnames); bind(sniff.input, p, 'sniff_hostnames');
    const unixSock = bind(textInput(a.unix_socket, { class: 'mono', placeholder: '/run/cyberboba/cyberboba.sock' }), a, 'unix_socket', null, s => s.trim());
    const apiListen = bind(textInput(a.listen, { class: 'mono', placeholder: '127.0.0.1:7471 (empty = disabled)' }), a, 'listen', null, s => s.trim());
    const apiToken = bind(h('input', { type: 'password', class: 'mono', value: a.token || '', placeholder: 'optional bearer token', autocomplete: 'new-password' }), a, 'token', null, s => s.trim());
    const logLevel = bind(sel(['debug', 'info', 'warn', 'error'], misc.log_level), misc, 'log_level');
    const browserToken = h('input', { type: 'password', class: 'mono', value: authToken(), placeholder: 'token sent by this browser', autocomplete: 'new-password' });
    const save = btn('Save', async () => {
      save.disabled = true;
      try {
        const fresh = await api('GET', '/api/config');
        fresh.proxifier = Object.assign({}, fresh.proxifier, {
          enabled: p.enabled, listen_tcp: p.listen_tcp, listen_dns: p.listen_dns, dns_upstream: p.dns_upstream,
          dns_via_rules: p.dns_via_rules, block_quic: p.block_quic, ipv6: p.ipv6, sniff_hostnames: p.sniff_hostnames });
        fresh.api = Object.assign({}, fresh.api, { unix_socket: a.unix_socket, listen: a.listen, token: a.token });
        if (!fresh.api.token) delete fresh.api.token;
        fresh.log_level = misc.log_level;
        await api('PUT', '/api/config', fresh);
        toast('Configuration saved and applied', 'ok');
        if (Pages.dashboard.refresh) { try { state.status = await api('GET', '/api/status', undefined, { silent: true }); updateHeader(); } catch (_) { /* ignore */ } }
      } catch (_) { /* shown */ }
      finally { save.disabled = false; }
    }, 'primary');
    const saveTok = btn('Apply', () => {
      const v = browserToken.value.trim();
      if (v) localStorage.setItem('cyberboba.token', v); else localStorage.removeItem('cyberboba.token');
      toast('Browser token ' + (v ? 'saved' : 'cleared') + '; reconnecting event stream', 'ok');
      Events.connect();
    }, 'tiny');
    const autoCard = this.autostartCard();
    panel.append(
      autoCard,
      h('div', { class: 'cols' },
        h('div', { class: 'card' }, h('div', { class: 'card-title' }, 'Proxifier'),
          h('div', { class: 'tab-panel' },
            h('div', { class: 'form-grid' }, field('TCP listener', listenTcp, 'transparent TCP listener (loopback)'), field('DNS listener', listenDns, 'DNS forwarder'), field('DNS upstream', dnsUp, 'resolver used by the forwarder')),
            enabled, dnsVia, quic, ipv6, sniff)),
        h('div', { class: 'card' }, h('div', { class: 'card-title' }, 'API & logging'),
          h('div', { class: 'tab-panel' },
            h('div', { class: 'form-grid' }, field('Unix socket', unixSock), field('TCP listen', apiListen, 'web UI / TCP API address'), field('API token', apiToken, 'required from TCP clients when set'), field('Log level', logLevel)),
            h('hr', { style: { border: 0, borderTop: '1px solid var(--border)', margin: '4px 0' } }),
            h('div', { class: 'form-row' }, field('Token used by this browser', browserToken, 'stored in localStorage; sent as Authorization: Bearer'), saveTok)))),
      h('div', { class: 'form-actions' }, save, h('span', { class: 'muted small' }, 'Only the fields above are modified; the rest of the configuration is preserved.')),
      this.mcpCard());
  },

  /* ---- Autostart (daemon on boot + VPN auto-connect) ---- */
  autostartCard() {
    const card = h('div', { class: 'card', style: { marginBottom: '12px' } }, h('div', { class: 'card-title' }, 'Autostart'));
    const body = h('div', { class: 'tab-panel' }, h('div', { class: 'muted small' }, h('span', { class: 'spinner' }), ' loading\u2026'));
    card.append(body);
    this.loadAutostart(card, body);
    return card;
  },
  async loadAutostart(card, body) {
    let d; try { d = await api('GET', '/api/system/autostart', undefined, { silent: true }); }
    catch (e) { replace(body, h('div', { class: 'error-box' }, e.message)); return; }
    this.renderAutostart(card, body, d);
  },
  renderAutostart(card, body, d) {
    const toggle = checkbox('Start cyberboba on system boot', !!d.service_enabled);
    toggle.input.disabled = !d.can_manage;
    toggle.input.addEventListener('change', async () => {
      const want = toggle.input.checked;
      toggle.input.disabled = true;
      try {
        const r = await api('POST', '/api/system/autostart', { enabled: want });
        toast(r.service_enabled ? 'Autostart enabled \u2014 cyberboba will start on boot' : 'Autostart disabled', 'ok');
        this.renderAutostart(card, body, r);
      } catch (e) { toggle.input.checked = !want; toast('Failed: ' + e.message, 'error'); toggle.input.disabled = !d.can_manage; }
    });
    const vpns = d.vpn_autostart || [];
    clear(body);
    body.append(...[
      toggle,
      h('div', { class: 'muted small', style: { margin: '4px 0 8px' } },
        'When on, the daemon starts with the system and the VPNs below auto-connect at boot. Running now: ',
        h('b', { class: d.service_active ? 'ok' : 'bad' }, d.service_active ? 'yes' : 'no'), '.'),
      h('div', { class: 'form-row', style: { gap: '6px', flexWrap: 'wrap', alignItems: 'center' } },
        h('span', { class: 'muted small' }, 'Auto-connect VPNs:'),
        ...(vpns.length ? vpns.map(n => badge(n, 'green')) : [h('span', { class: 'muted small' }, 'none set')]),
        h('a', { href: '#/vpn', class: 'small', style: { marginLeft: '4px' } }, 'Manage VPNs \u2192')),
      vpns.length ? null : h('div', { class: 'muted small', style: { marginTop: '2px' } }, 'Tick \u201cAutostart with the daemon\u201d on a VPN to have it connect automatically.'),
      d.can_manage ? null : h('div', { class: 'warn-box', style: { marginTop: '6px' } },
        'Boot autostart can\u2019t be changed here (needs systemd and the daemon running as root).'),
    ].filter(Boolean));
  },

  /* ---- MCP (read-only info) ---- */
  mcpCard() {
    const origin = location.origin;
    const cmd = 'claude mcp add cyberboba -- cyberboba mcp';
    const httpUrl = origin + '/mcp';
    const line = (code, copyLabel, what) => h('div', { class: 'form-row mcp-row' },
      h('code', { class: 'mono mcp-code' }, code),
      btn(copyLabel, () => copyText(code, what), 'tiny'));
    return h('div', { class: 'card', style: { marginTop: '12px' } },
      h('div', { class: 'card-title' }, 'MCP (AI agents)'),
      h('div', { class: 'tab-panel' },
        h('div', { class: 'muted small' }, 'The daemon exposes an MCP server so AI agents (Claude Code, Claude Desktop, Cursor, …) can drive cyberboba. Two transports are available:'),
        h('div', { class: 'kv' },
          kv('stdio', h('code', { class: 'mono' }, 'cyberboba mcp')),
          kv('HTTP', h('span', { class: 'mono' }, 'POST ' + httpUrl + ' (Streamable HTTP; GET is 405)'))),
        h('div', { class: 'field-label' }, 'Register in Claude Code'),
        line(cmd, 'Copy command', 'Command copied'),
        h('div', { class: 'field-label', style: { marginTop: '6px' } }, 'HTTP endpoint'),
        line(httpUrl, 'Copy URL', 'URL copied'),
        h('div', { class: 'muted small' }, 'A bearer token (api.token) applies to the MCP HTTP endpoint when configured. See docs/AGENTS.md for the full tool list.')));
  },

  /* ---- yaml ---- */
  async load_yaml(panel) {
    const ta = h('textarea', { class: 'code', rows: 28, spellcheck: 'false', placeholder: 'loading…' });
    const err = h('div', { class: 'error-box', hidden: true });
    const status = h('span', { class: 'muted small' });
    const load = async () => {
      try { ta.value = await api('GET', '/api/config/yaml', undefined, { raw: true }); status.textContent = 'loaded ' + fmt.time(new Date().toISOString()); err.hidden = true; }
      catch (e) { replace(err, e.message); err.hidden = false; }
    };
    const save = btn('Save YAML', async () => {
      save.disabled = true; err.hidden = true;
      try {
        await api('PUT', '/api/config/yaml', ta.value, { raw: true, contentType: 'application/x-yaml', silent: true });
        toast('YAML configuration saved and applied', 'ok');
        status.textContent = 'saved ' + fmt.time(new Date().toISOString());
        this.loaded.general = false;
        clear(this.panels.general);
      } catch (e) { replace(err, e.message); err.hidden = false; }
      finally { save.disabled = false; }
    }, 'primary');
    ta.addEventListener('keydown', e => {
      if (e.key === 'Tab') { e.preventDefault(); const s = ta.selectionStart, en = ta.selectionEnd; ta.setRangeText('  ', s, en, 'end'); }
      if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); save.click(); }
    });
    const fileIn = h('input', { type: 'file', accept: '.yaml,.yml,.txt,text/yaml,text/plain', hidden: true });
    fileIn.addEventListener('change', () => {
      const f = fileIn.files && fileIn.files[0];
      fileIn.value = '';
      if (!f) return;
      const rd = new FileReader();
      rd.onload = async () => {
        const text = String(rd.result || '');
        if (!text.trim()) { toast('File is empty', 'error'); return; }
        if (!confirm('Replace the running configuration with "' + f.name + '" (' + fmt.bytes(f.size) + ')? It is validated, saved and applied live.')) return;
        err.hidden = true;
        try {
          await api('PUT', '/api/config/yaml', text, { raw: true, contentType: 'application/x-yaml', silent: true });
          toast('Configuration imported from ' + f.name, 'ok');
          this.loaded.general = false; clear(this.panels.general);
          await load();
        } catch (e) { ta.value = text; replace(err, 'Import rejected: ' + e.message); err.hidden = false; }
      };
      rd.onerror = () => toast('Could not read file', 'error');
      rd.readAsText(f);
    });
    panel.append(h('div', { class: 'muted small' }, 'Full configuration file. Saving validates, writes to disk and applies live. Ctrl+S saves.'), ta, err,
      h('div', { class: 'form-actions' }, save, btn('Reload', load), status, h('span', { class: 'spacer' }),
        dlLink('Export config', '/api/config/export', 'cyberboba-config.yaml', { title: 'GET /api/config/export — download the YAML' }),
        btn('Import config…', () => fileIn.click(), '', { title: 'load a YAML file and PUT /api/config/yaml' }), fileIn));
    await load();
  },

  /* ---- doctor ---- */
  async load_doctor(panel) {
    const grid = h('div', { class: 'doctor' });
    const summary = h('span', { class: 'muted small' });
    const run = async () => {
      replace(grid, h('span', { class: 'muted' }, h('span', { class: 'spinner' })), h('span', null, 'running checks…'), h('span'));
      let r; try { r = await api('GET', '/api/doctor'); } catch (e) { replace(grid, h('div', { class: 'error-box', style: { gridColumn: '1 / -1' } }, e.message)); return; }
      const checks = r.checks || [];
      clear(grid);
      for (const c of checks) {
        grid.append(h('span', { class: 'mark ' + (c.ok ? 'ok' : 'bad') }, c.ok ? '✓' : '✗'),
          h('span', { class: c.ok ? '' : 'bad' }, c.name), h('span', { class: 'detail' }, c.detail || ''));
      }
      const bad = checks.filter(c => !c.ok).length;
      summary.textContent = checks.length + ' checks, ' + (bad ? bad + ' failed' : 'all passed');
      summary.className = 'small ' + (bad ? 'bad' : 'ok');
    };
    panel.append(h('div', { class: 'card' }, h('div', { class: 'card-title' }, 'Doctor', h('span', { class: 'spacer' }), summary, btn('Run again', run, 'tiny')), grid));
    await run();
  },
  onEvent(type, data) {
    if (type === 'log' && this.logPanel) this.logPanel.push(data);
  },
};

/* ================================================================
 * 5. Boot
 * ================================================================ */
function setTheme(t, persist = true) {
  document.documentElement.setAttribute('data-theme', t);
  if (persist) { try { localStorage.setItem('cyberboba.theme', t); } catch (_) { /* ignore */ } }
  const b = $('#theme-toggle');
  if (b) b.textContent = t === 'dark' ? '☽' : '☀';
  document.dispatchEvent(new CustomEvent('cyberboba:theme', { detail: t }));
}
function currentTheme() { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'; }

function initKeyboard() {
  document.addEventListener('keydown', e => {
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '') || (e.target && e.target.isContentEditable);
    if (e.altKey && !e.ctrlKey && !e.metaKey) {
      const ALT_PAGES = ['dashboard', 'traffic', 'connections', 'rules', 'routebuilder', 'firewall', 'intercept', 'proxies', 'vpn', 'tags'];
      if (e.key >= '0' && e.key <= '9') {
        const page = ALT_PAGES[e.key === '0' ? 9 : Number(e.key) - 1];
        if (page) { e.preventDefault(); location.hash = '#/' + page; }
        return;
      }
      if (e.key === 'm' || e.key === 'M') { e.preventDefault(); location.hash = '#/map'; return; }
      if (e.key === 'p' || e.key === 'P') { e.preventDefault(); location.hash = '#/processes'; return; }
      if (e.key === 'b' || e.key === 'B') { e.preventDefault(); location.hash = '#/bandwidth'; return; }
      if (e.key === 'd' || e.key === 'D') { e.preventDefault(); location.hash = '#/dns'; return; }
      if (e.key === 'a' || e.key === 'A') { e.preventDefault(); location.hash = '#/ai'; return; }
    }
    if (inField || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/' && Router.name === 'connections' && Pages.connections.filterIn) { e.preventDefault(); Pages.connections.filterIn.focus(); Pages.connections.filterIn.select(); }
    else if (e.key === '/' && Router.name === 'intercept' && Pages.intercept.focusFilter) { e.preventDefault(); Pages.intercept.focusFilter(); }
    else if (e.key === '/' && Router.name === 'processes' && Pages.processes.focusFilter) { e.preventDefault(); Pages.processes.focusFilter(); }
    else if (e.key === 't') { setTheme(currentTheme() === 'dark' ? 'light' : 'dark'); }
  });
}

async function boot() {
  setTheme(currentTheme(), false);
  $('#theme-toggle').addEventListener('click', () => setTheme(currentTheme() === 'dark' ? 'light' : 'dark'));
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => { if (!localStorage.getItem('cyberboba.theme')) setTheme(mq.matches ? 'light' : 'dark', false); };
    if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
  }
  initKeyboard();
  window.addEventListener('hashchange', () => Router.go());
  updateHeader();
  Events.start();
  // Global firewall-prompt poll: fw_ask events can be dropped from a full SSE
  // buffer on a backgrounded tab, and resync only runs on reconnect. Poll the
  // pending queue everywhere (not just the Firewall page) so a held connection
  // always surfaces a popup even if its SSE event was lost.
  setInterval(resyncFirewall, 4000);
  loadInitialLog();
  try { state.status = await api('GET', '/api/status', undefined, { silent: true }); state.stats = state.status.stats; updateHeader(); }
  catch (e) { toast('Cannot reach cyberbobad: ' + e.message, 'error', 8000); }
  if (state.status && state.status.intercept && num(state.status.intercept.pending) > 0) syncPending();
  Router.go();
}

document.addEventListener('DOMContentLoaded', boot);
