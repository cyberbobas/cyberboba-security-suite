'use strict';
// System-wide alerts for the desktop shell.
//
// The daemon's web UI only shows firewall prompts / block toasts inside its own
// page, which is useless when the window is hidden in the tray or buried under
// a browser. This module keeps its own SSE subscription to the daemon from the
// Electron main process and turns events into OS-level UI:
//   fw_ask      -> an always-on-top popup window (Allow / Deny / Remember) plus
//                  a native notification that focuses the popup when clicked
//   fw_block    -> native notification (deduplicated per program+destination)
//   bw_alert    -> native notification (abnormal upload/download)
//   vpn         -> native notification on up / down / error transitions
//
// The subscription also counts as a "UI" for the daemon's fail-open logic, so
// asks are held (and prompted) whenever the desktop app runs, not only while
// the web page happens to be open.

const { app, BrowserWindow, Notification, ipcMain, screen } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

// ---------------------------------------------------------------- desktop notifications with buttons
// Electron's Notification has no action buttons on Linux, and on Wayland no
// window can force itself above the user's current app. The desktop's own
// notification banners can: they are shell chrome, always on top (even over
// fullscreen windows), and org.freedesktop.Notifications supports action
// buttons. notifier.py (python3 + GLib, present on every GNOME/KDE box) owns
// one D-Bus connection for Notify / CloseNotification and the ActionInvoked /
// NotificationClosed signals - GNOME delivers those only to the connection
// that created the notification, so it has to be a single long-lived helper.
const NOTIFIER = path.join(__dirname, 'notifier.py');

const PROMPT_W = 500;
const PROMPT_H = 330;
const PENDING_POLL_MS = 5000;
const BLOCK_DEDUP_MS = 8000;

class Notifier {
  constructor(log) {
    this.log = log;
    this.child = null;
    this.ready = false;
    this.failed = false;
    this.seq = 0;
    this.pending = new Map(); // ref -> resolve(id)
    this.onAction = () => {};
    this.onClosed = () => {};
  }
  start() {
    if (this.child || this.failed) return;
    let child;
    try {
      child = spawn('python3', [NOTIFIER], { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (err) {
      this.failed = true;
      this.log.warn(`[alerts] notifier: ${err.message}`);
      return;
    }
    this.child = child;
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let ev; try { ev = JSON.parse(line); } catch { continue; }
        if (ev.event === 'ready') this.ready = true;
        else if (ev.event === 'notified') { const r = this.pending.get(ev.ref); if (r) { this.pending.delete(ev.ref); r(ev.id); } }
        else if (ev.event === 'error') { const r = this.pending.get(ev.ref); if (r) { this.pending.delete(ev.ref); r(0); } this.log.warn(`[alerts] notifier: ${ev.error}`); }
        else if (ev.event === 'action') this.onAction(ev.id, ev.key);
        else if (ev.event === 'closed') this.onClosed(ev.id, ev.reason);
      }
    });
    let errText = '';
    child.stderr.on('data', (d) => { errText += d; if (errText.length > 4000) errText = errText.slice(-4000); });
    child.on('error', (err) => { this.failed = true; this.child = null; this.log.warn(`[alerts] notifier: ${err.message}`); this.flushPending(); });
    child.on('exit', (code) => {
      this.child = null; this.ready = false;
      this.flushPending();
      if (!this.stopped) {
        // Died at startup (no python3-gi?) -> give up and fall back to plain notifications.
        if (code !== 0 && !this.everReady) { this.failed = true; this.log.warn(`[alerts] notifier exited (${code}): ${errText.trim().split('\n').pop() || 'no output'} - using plain notifications`); }
        else { this.log.warn(`[alerts] notifier exited (${code}); restarting`); setTimeout(() => this.start(), 2000); }
      }
    });
    const markReady = setInterval(() => { if (this.ready) { this.everReady = true; clearInterval(markReady); } }, 100);
  }
  flushPending() { for (const r of this.pending.values()) r(0); this.pending.clear(); }
  send(obj) {
    if (!this.child) return false;
    try { this.child.stdin.write(JSON.stringify(obj) + '\n'); return true; } catch { return false; }
  }
  /** -> Promise<notification id | 0> */
  notify({ summary, body, actions = [], icon = '', urgency = 2, resident = true, expireMs = 0 }) {
    if (this.failed || !this.child) return Promise.resolve(0);
    const ref = String(++this.seq);
    return new Promise((resolve) => {
      this.pending.set(ref, resolve);
      if (!this.send({ op: 'notify', ref, summary, body, actions, icon, urgency, resident, expire: expireMs })) { this.pending.delete(ref); resolve(0); }
      setTimeout(() => { if (this.pending.has(ref)) { this.pending.delete(ref); resolve(0); } }, 6000);
    });
  }
  close(id) { if (id) this.send({ op: 'close', id }); }
  stop() { this.stopped = true; if (this.child) { this.send({ op: 'quit' }); const c = this.child; setTimeout(() => { try { c.kill(); } catch { /* gone */ } }, 500); } }
}

function createAlerts({ api, getConfig, showWindow, iconPath, log = console }) {
  let running = false;
  let abort = null;           // AbortController of the live SSE request
  let backoff = 1000;
  let pollTimer = null;
  let promptWin = null;
  let queue = [];             // pending asks, oldest first
  let current = null;         // ask shown in the popup
  let fwCfg = { timeoutSec: 40, timeoutAction: 'allow' };
  const seenBlocks = new Map();
  const vpnState = new Map(); // name -> last seen state
  const notifier = process.platform === 'linux' ? new Notifier(log) : null;
  const useDbus = Boolean(notifier);
  const notifByAsk = new Map(); // ask id -> notification id
  const askByNotif = new Map(); // notification id -> ask

  // ------------------------------------------------------------ helpers
  function notify(title, body, { urgency = 'normal', onClick } = {}) {
    if (!Notification.isSupported()) return null;
    try {
      const n = new Notification({ title, body, icon: iconPath, urgency, silent: urgency !== 'critical' });
      if (onClick) n.on('click', onClick);
      n.show();
      return n;
    } catch (err) {
      log.warn(`[alerts] notification: ${err.message}`);
      return null;
    }
  }

  function dst(a) { return (a.host || a.ip || '?') + (a.port ? ':' + a.port : ''); }

  async function refreshFwConfig() {
    try {
      const fw = await api('/api/firewall');
      const c = (fw && fw.config) || {};
      fwCfg = { timeoutSec: Number(c.ask_timeout_sec) || 0, timeoutAction: c.ask_timeout_action || 'allow' };
    } catch { /* keep previous */ }
  }

  // ------------------------------------------------------------ prompt window
  function ensurePromptWindow() {
    if (promptWin && !promptWin.isDestroyed()) return promptWin;
    const { workArea } = screen.getPrimaryDisplay();
    promptWin = new BrowserWindow({
      width: PROMPT_W,
      height: PROMPT_H,
      x: Math.max(workArea.x, workArea.x + workArea.width - PROMPT_W - 16),
      y: workArea.y + 16,
      show: false,
      frame: false,
      transparent: false,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      alwaysOnTop: true,
      skipTaskbar: false,
      title: 'cyberboba — firewall',
      backgroundColor: '#0f1115',
      icon: iconPath,
      webPreferences: {
        preload: path.join(__dirname, 'prompt-preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        spellcheck: false,
      },
    });
    promptWin.setAlwaysOnTop(true, 'screen-saver');
    promptWin.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
    promptWin.setMenuBarVisibility(false);
    promptWin.loadFile(path.join(__dirname, 'pages', 'prompt.html')).catch((err) => log.warn(`[alerts] prompt page: ${err.message}`));
    promptWin.on('closed', () => { promptWin = null; if (current) { current = null; } });
    return promptWin;
  }

  function showCurrent() {
    if (!current) {
      if (promptWin && !promptWin.isDestroyed()) promptWin.hide();
      return;
    }
    const w = ensurePromptWindow();
    const payload = { ask: current, queued: queue.length, timeoutSec: fwCfg.timeoutSec, timeoutAction: fwCfg.timeoutAction };
    const send = () => {
      if (!w || w.isDestroyed()) return;
      w.webContents.send('prompt:ask', payload);
      raise(w);
    };
    if (w.webContents.isLoading()) w.webContents.once('did-finish-load', send);
    else send();
  }

  // Put the prompt above everything and grab focus. Re-asserting alwaysOnTop
  // after show() matters: some WMs reset the state when a hidden window maps.
  function raise(w) {
    if (!w || w.isDestroyed()) return;
    if (!w.isVisible()) w.show();
    if (w.isMinimized()) w.restore();
    w.setAlwaysOnTop(true, 'screen-saver');
    w.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
    w.moveTop();
    w.focus();
    try { app.focus({ steal: true }); } catch { /* not supported */ }
    w.flashFrame(true);
    // A second nudge once the WM has processed the map request.
    setTimeout(() => { if (!w.isDestroyed() && w.isVisible()) { w.setAlwaysOnTop(true, 'screen-saver'); w.moveTop(); w.focus(); } }, 250);
  }

  function advance() {
    current = queue.shift() || null;
    showCurrent();
  }

  function forgetAsk(id) {
    queue = queue.filter((a) => a.id !== id);
    const nid = notifByAsk.get(id);
    if (nid) { notifByAsk.delete(id); askByNotif.delete(nid); notifier.close(nid); }
    if (current && current.id === id) advance();
  }

  // Answer an ask on behalf of the user (popup button or notification action).
  async function answerAsk(id, allow, remember) {
    try {
      await api('/api/firewall/answer', { method: 'POST', body: { id: Number(id), allow: Boolean(allow), remember: Boolean(remember) }, timeout: 5000 });
    } catch (err) {
      // 404 = already resolved (timeout) - nothing to show the user.
      if (!/no such pending/i.test(err.message)) return { ok: false, error: err.message };
    }
    forgetAsk(id);
    return { ok: true };
  }

  // One shell banner per ask: Allow / Allow always / Deny buttons; clicking
  // the body opens the detailed popup.
  async function askBanner(ask) {
    const actions = ['default', 'Open', 'allow', 'Allow', 'always', 'Allow always', 'deny', 'Deny'];
    const unresolved = !ask.app || ask.app === 'unknown program' || !(ask.pid > 0);
    const who = unresolved ? ('unknown program' + (ask.guess ? ` (probably ${ask.guess})` : '')) : ask.app;
    const body = `→ ${dst(ask)} (${ask.zone || 'internet'} zone)` + (ask.exe ? `\n${ask.exe}` : '')
      + (ask.user ? `\nuser: ${ask.user}` : '')
      + (unresolved ? `\nthe owning process exited or could not be resolved${ask.guess ? `; earlier connections to this host came from ${ask.guess}` : ''}` : '');
    const id = await notifier.notify({ summary: `Firewall: ${who} wants network access`, body, actions, icon: iconPath, urgency: 2, resident: true });
    if (!id) {
      notify(`Firewall: ${ask.app || 'unknown program'} wants network access`, `→ ${dst(ask)}. Click to allow or deny.`, { urgency: 'critical', onClick: () => showCurrent() });
      return;
    }
    // The ask may have been resolved while Notify was in flight.
    if (!(current && current.id === ask.id) && !queue.some((a) => a.id === ask.id)) { notifier.close(id); return; }
    notifByAsk.set(ask.id, id);
    askByNotif.set(id, ask);
    log.log(`[alerts] banner #${id} for ask #${ask.id} (${ask.app || 'unknown'} -> ${dst(ask)})`);
  }

  function onNotifAction(nid, key) {
    const ask = askByNotif.get(nid);
    if (!ask) return;
    if (key === 'allow') answerAsk(ask.id, true, false);
    else if (key === 'always') answerAsk(ask.id, true, Boolean(ask.app));
    else if (key === 'deny') answerAsk(ask.id, false, false);
    else { // 'default' (body click): bring the detailed popup forward on this ask
      if (current && current.id !== ask.id) { queue = [current, ...queue.filter((a) => a.id !== ask.id)]; current = ask; }
      else if (!current) { queue = queue.filter((a) => a.id !== ask.id); current = ask; }
      showCurrent();
    }
  }
  function onNotifClosed(nid) {
    const ask = askByNotif.get(nid);
    if (!ask) return;
    askByNotif.delete(nid);
    notifByAsk.delete(ask.id);
    // Dismissed without a choice: the popup window / daemon timeout take over.
  }

  function enqueue(ask) {
    if (!ask || !ask.id) return;
    if ((current && current.id === ask.id) || queue.some((a) => a.id === ask.id)) return;
    queue.push(ask);
    // The banner is the primary, always-on-top UI (Wayland cannot raise our
    // own window); the popup is the detailed view.
    if (useDbus) askBanner(ask);
    if (!current) {
      advance();
      if (!useDbus) {
        notify(`Firewall: ${ask.app || 'unknown program'} wants network access`,
          `→ ${dst(ask)} (${ask.zone || 'internet'} zone). Click to allow or deny.`,
          { urgency: 'critical', onClick: () => showCurrent() });
      }
    } else if (promptWin && !promptWin.isDestroyed()) {
      promptWin.webContents.send('prompt:ask', { ask: current, queued: queue.length, timeoutSec: fwCfg.timeoutSec, timeoutAction: fwCfg.timeoutAction });
    }
  }

  function resolved(id) {
    queue = queue.filter((a) => a.id !== id);
    const nid = notifByAsk.get(id);
    if (nid) { notifByAsk.delete(id); askByNotif.delete(nid); notifier.close(nid); }
    if (current && current.id === id) {
      if (promptWin && !promptWin.isDestroyed()) promptWin.webContents.send('prompt:resolved', { id });
      // Give the user a beat to read "resolved", then move on.
      setTimeout(() => { if (current && current.id === id) advance(); }, 600);
    } else if (promptWin && !promptWin.isDestroyed() && current) {
      promptWin.webContents.send('prompt:ask', { ask: current, queued: queue.length, timeoutSec: fwCfg.timeoutSec, timeoutAction: fwCfg.timeoutAction });
    }
  }

  async function resyncPending() {
    try {
      const p = await api('/api/firewall/pending');
      const pending = (p && p.pending) || [];
      const ids = new Set(pending.map((a) => a.id));
      // Drop asks the daemon no longer holds (answered elsewhere / timed out).
      for (const [askId, nid] of [...notifByAsk]) if (!ids.has(askId)) { notifByAsk.delete(askId); askByNotif.delete(nid); notifier.close(nid); }
      queue = queue.filter((a) => ids.has(a.id));
      if (current && !ids.has(current.id)) advance();
      for (const a of pending) enqueue(a);
    } catch { /* daemon away; SSE loop handles reconnects */ }
  }

  ipcMain.handle('prompt:answer', (_e, { id, allow, remember }) => answerAsk(id, allow, remember));
  ipcMain.handle('prompt:skip', (_e, { id }) => { forgetAsk(id); return { ok: true }; });
  ipcMain.handle('prompt:openFirewall', () => { showWindow('#/firewall'); return { ok: true }; });

  // ------------------------------------------------------------ event handlers
  function onEvent(type, data) {
    if (!data || typeof data !== 'object') return;
    switch (type) {
      case 'fw_ask':
        enqueue(data);
        break;
      case 'fw_resolved':
        resolved(data.id);
        break;
      case 'fw_block': {
        const key = `${data.app || ''}|${data.host || data.ip || ''}`;
        const now = Date.now();
        if (seenBlocks.get(key) && now - seenBlocks.get(key) < BLOCK_DEDUP_MS) return;
        seenBlocks.set(key, now);
        if (seenBlocks.size > 500) seenBlocks.clear();
        const body = `→ ${dst(data)}${data.reason ? ` (${data.reason})` : ''}. Open Firewall › Recent activity to allow it.`;
        if (useDbus) {
          notifier.notify({ summary: `Firewall blocked ${data.app || 'unknown program'}`, body, actions: ['default', 'Open'], icon: iconPath, urgency: 2, resident: false, expireMs: 12000 });
        } else {
          notify(`Firewall blocked ${data.app || 'unknown program'}`, body, { onClick: () => showWindow('#/firewall') });
        }
        break;
      }
      case 'bw_alert': {
        const dir = data.kind === 'download' ? 'downloading' : 'uploading';
        const rate = fmtRate(data.rate);
        const base = data.factor >= 1.5 ? ` — ${Math.round(data.factor)}× its normal` : '';
        notify(`Abnormal traffic: ${data.app || 'unknown program'}`, `${dir} at ${rate}${base}`, { onClick: () => showWindow('#/bandwidth') });
        break;
      }
      case 'vpn': {
        if (!data.name) return;
        const prev = vpnState.get(data.name);
        vpnState.set(data.name, data.state);
        if (prev === undefined || prev === data.state) return;
        if (data.state === 'up') notify(`VPN ${data.name} connected`, `${data.interface || ''} ${data.external ? '(brought up outside cyberboba)' : ''}`.trim() || 'tunnel is up', { onClick: () => showWindow('#/vpn') });
        else if (data.state === 'error') notify(`VPN ${data.name} failed`, data.error || 'see the VPN log', { urgency: 'critical', onClick: () => showWindow('#/vpn') });
        else if (data.state === 'down' && prev === 'up') notify(`VPN ${data.name} disconnected`, data.kill_switch_active ? 'kill switch is blocking traffic' : 'tunnel is down', { onClick: () => showWindow('#/vpn') });
        break;
      }
      default:
        break;
    }
  }

  function fmtRate(bps) {
    const n = Number(bps) || 0;
    if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB/s';
    if (n >= 1024) return (n / 1024).toFixed(1) + ' KB/s';
    return Math.round(n) + ' B/s';
  }

  // ------------------------------------------------------------ SSE loop
  async function sseLoop() {
    while (running) {
      const cfg = getConfig();
      abort = new AbortController();
      try {
        const headers = { Accept: 'text/event-stream' };
        if (cfg.token) headers.Authorization = `Bearer ${cfg.token}`;
        const res = await fetch(cfg.url + '/api/events', { headers, signal: abort.signal });
        if (!res.ok || !res.body) throw new Error(`${res.status} ${res.statusText}`);
        backoff = 1000;
        log.log('[alerts] subscribed to daemon events');
        await refreshFwConfig();
        await resyncPending();
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const chunk = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let type = 'message';
            const dataLines = [];
            for (const line of chunk.split('\n')) {
              if (line.startsWith('event:')) type = line.slice(6).trim();
              else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
            }
            if (!dataLines.length) continue;
            let data = null;
            try { data = JSON.parse(dataLines.join('\n')); } catch { continue; }
            try { onEvent(type, data); } catch (err) { log.warn(`[alerts] ${type}: ${err.message}`); }
          }
        }
        throw new Error('stream ended');
      } catch (err) {
        if (!running) break;
        if (err.name !== 'AbortError') log.warn(`[alerts] events: ${err.message} (retry in ${backoff / 1000}s)`);
        await new Promise((r) => setTimeout(r, backoff));
        backoff = Math.min(backoff * 2, 15000);
      }
    }
  }

  return {
    start() {
      if (running) return;
      running = true;
      if (useDbus) { notifier.onAction = onNotifAction; notifier.onClosed = onNotifClosed; notifier.start(); }
      sseLoop();
      // fw_ask can be evicted from a full SSE buffer; poll as a safety net.
      pollTimer = setInterval(resyncPending, PENDING_POLL_MS);
    },
    stop() {
      running = false;
      if (abort) abort.abort();
      if (pollTimer) clearInterval(pollTimer);
      if (useDbus) { for (const nid of askByNotif.keys()) notifier.close(nid); notifier.stop(); }
      if (promptWin && !promptWin.isDestroyed()) promptWin.destroy();
    },
    /** Re-subscribe (after the daemon URL/token changed). */
    restart() { if (abort) abort.abort(); },
    pendingCount() { return queue.length + (current ? 1 : 0); },
  };
}

module.exports = { createAlerts };
