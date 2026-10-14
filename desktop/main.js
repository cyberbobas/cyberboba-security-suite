'use strict';
// cyberboba desktop: a thin Electron shell around the cyberbobad web UI.
// It shows the daemon's own UI in a window and adds OS integration (tray,
// autostart, "start the service" helper). No UI pages are reimplemented here.

const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, dialog, session } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

// ---------------------------------------------------------------- constants
const DEFAULT_URL = 'http://127.0.0.1:7471';
const CONFIG_DIR = path.join(os.homedir(), '.config', 'cyberboba-desktop');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const AUTOSTART_FILE = path.join(os.homedir(), '.config', 'autostart', 'cyberboba-desktop.desktop');
const OFFLINE_PAGE = path.join(__dirname, 'pages', 'offline.html');
const APP_ICON = path.join(__dirname, 'assets', 'icon.png');
const PROBE_TIMEOUT_MS = 2000;
const TRAY_REFRESH_MS = 5000;
const OFFLINE_RETRY_MS = 3000;
const START_POLL_MAX_S = 30;
const OFFLINE_AFTER_FAILED_POLLS = 3; // daemon gone while UI is shown -> offline page

const startHiddenFlag = process.argv.includes('--hidden');

// The UI is the daemon's own web app, served from localhost and rebuilt on
// every upgrade. Disable Electron's HTTP cache so a new build is never masked
// by a stale cached app.js/style.css (otherwise the window keeps the old UI).
app.commandLine.appendSwitch('disable-http-cache');

// ---------------------------------------------------------------- config
function readConfigFile() {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (err) {
    if (err.code !== 'ENOENT') console.warn(`[config] ignoring ${CONFIG_FILE}: ${err.message}`);
    return {};
  }
}

function writeConfigFile(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
}

function normalizeUrl(u) {
  const s = String(u || '').trim().replace(/\/+$/, '');
  return /^https?:\/\//i.test(s) ? s : DEFAULT_URL;
}

// Effective config: file values, with CYBERBOBA_URL overriding the URL.
function getConfig() {
  const file = readConfigFile();
  return {
    url: normalizeUrl(process.env.CYBERBOBA_URL || file.url || DEFAULT_URL),
    token: typeof file.token === 'string' ? file.token : '',
    startHidden: Boolean(file.startHidden),
  };
}

function setConfig(partial) {
  const file = readConfigFile();
  const next = { ...file };
  if (partial && typeof partial === 'object') {
    if ('url' in partial) next.url = normalizeUrl(partial.url);
    if ('token' in partial) next.token = partial.token ? String(partial.token) : '';
    if ('startHidden' in partial) next.startHidden = Boolean(partial.startHidden);
  }
  writeConfigFile(next);
  if ('startHidden' in (partial || {})) setAutostart(next.startHidden);
  return getConfig();
}

let config = getConfig();
const daemonOrigin = () => new URL(config.url).origin;

// ---------------------------------------------------------------- API client
async function api(apiPath, { method = 'GET', body, timeout = PROBE_TIMEOUT_MS } = {}) {
  const headers = { Accept: 'application/json' };
  if (config.token) headers.Authorization = `Bearer ${config.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(config.url + apiPath, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!res.ok) {
    const msg = (data && data.error) || `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

async function probe() {
  try {
    const status = await api('/api/status');
    return status && typeof status === 'object' ? status : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- state
let win = null;
let tray = null;
let quitting = false;
let lastStatus = null;        // last successful /api/status
let showingOffline = false;
let offlineTimer = null;
let trayTimer = null;
let failedPolls = 0;
let startingService = false;
let loadingUI = null;         // in-flight loadUI() promise

// ---------------------------------------------------------------- window
function createWindow() {
  win = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1000,
    minHeight: 640,
    show: false,
    title: 'cyberboba',
    backgroundColor: '#0f1115',
    autoHideMenuBar: true,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  // Close -> hide to tray unless we are really quitting.
  win.on('close', (e) => {
    if (!quitting) {
      e.preventDefault();
      win.hide();
    }
  });
  win.on('closed', () => { win = null; });
  win.webContents.on('did-finish-load', () => console.log(`[window] loaded ${win.webContents.getURL()}`));

  // Links: anything opened in a new window goes to the system browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    openExternal(url);
    return { action: 'deny' };
  });
  // In-window navigation is only allowed within the daemon origin (and our
  // local offline page); everything else opens in the system browser.
  win.webContents.on('will-navigate', (e, url) => {
    if (isAllowedInWindow(url)) return;
    e.preventDefault();
    openExternal(url);
  });

  // Daemon down / restarted while navigating: show the offline page and retry.
  win.webContents.on('did-fail-load', (e, code, desc, url, isMainFrame) => {
    if (!isMainFrame || code === -3 /* ERR_ABORTED */) return;
    console.warn(`[window] load failed (${code} ${desc}) for ${url}`);
    showOffline();
  });
  win.webContents.on('render-process-gone', (e, details) => {
    console.warn(`[window] renderer gone: ${details.reason}`);
    if (details.reason !== 'clean-exit') loadUI();
  });

  if (!startHiddenFlag && !config.startHidden) {
    win.once('ready-to-show', () => win && win.show());
  }
  return win;
}

function isAllowedInWindow(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'file:') return u.pathname === OFFLINE_PAGE || u.pathname.startsWith(path.join(__dirname, 'pages'));
    return u.origin === daemonOrigin();
  } catch {
    return false;
  }
}

function openExternal(url) {
  try {
    const u = new URL(url);
    if (!['http:', 'https:', 'mailto:'].includes(u.protocol)) return;
    shell.openExternal(url).catch((err) => console.warn(`[shell] openExternal: ${err.message}`));
  } catch { /* ignore malformed */ }
}

function showWindow() {
  if (!win) createWindow();
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

// Probe the daemon; load the web UI when reachable, the offline page otherwise.
function loadUI() {
  if (loadingUI) return loadingUI;
  loadingUI = doLoadUI().finally(() => { loadingUI = null; });
  return loadingUI;
}

async function doLoadUI() {
  if (!win) return false;
  const status = await probe();
  if (status) {
    lastStatus = status;
    failedPolls = 0;
    stopOfflineRetry();
    showingOffline = false;
    await win.loadURL(config.url + '/').catch((err) => {
      console.warn(`[window] loadURL: ${err.message}`);
      showOffline();
    });
    refreshTray(status);
    return true;
  }
  showOffline();
  return false;
}

function showOffline() {
  if (!win) return;
  if (!showingOffline) {
    showingOffline = true;
    win.loadFile(OFFLINE_PAGE).catch((err) => console.warn(`[window] offline page: ${err.message}`));
  }
  startOfflineRetry();
  refreshTray(null);
}

function startOfflineRetry() {
  if (offlineTimer) return;
  offlineTimer = setInterval(async () => {
    if (startingService) return; // startService polls on its own
    const status = await probe();
    if (status) loadUI();
  }, OFFLINE_RETRY_MS);
}

function stopOfflineRetry() {
  if (offlineTimer) clearInterval(offlineTimer);
  offlineTimer = null;
}

// ---------------------------------------------------------------- service start
function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    } catch (err) {
      return resolve({ code: -1, out: '', err: err.message });
    }
    let out = '', errOut = '';
    child.stdout && child.stdout.on('data', (d) => { out += d; });
    child.stderr && child.stderr.on('data', (d) => { errOut += d; });
    child.on('error', (err) => resolve({ code: -1, out, err: err.message }));
    child.on('close', (code) => resolve({ code, out, err: errOut }));
  });
}

async function waitForDaemon(maxSeconds) {
  for (let i = 0; i < maxSeconds; i++) {
    const status = await probe();
    if (status) return status;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
}

async function startService() {
  if (startingService) return { ok: false, error: 'already starting' };
  startingService = true;
  try {
    // 1) systemd unit
    const sys = await run('pkexec', ['systemctl', 'start', 'cyberboba']);
    let note = '';
    if (sys.code !== 0) {
      const msg = (sys.err || sys.out || '').trim();
      // 126/127: polkit auth cancelled or pkexec unavailable -> do not retry with a second prompt.
      if (sys.code === 126 || sys.code === 127) {
        return { ok: false, error: msg || 'authorization cancelled' };
      }
      note = `systemctl start cyberboba failed (${sys.code}): ${msg || 'unknown error'}; trying cyberbobad directly`;
      console.warn(`[start] ${note}`);
      // 2) fallback: run the daemon binary directly (detached)
      const bin = ['/usr/local/bin/cyberbobad', '/usr/bin/cyberbobad'].find((p) => fs.existsSync(p));
      if (!bin) {
        return { ok: false, error: `${note}. cyberbobad binary not found - install the daemon first (see hint).` };
      }
      try {
        const child = spawn('pkexec', [bin], { detached: true, stdio: 'ignore' });
        child.on('error', (err) => console.warn(`[start] pkexec ${bin}: ${err.message}`));
        child.unref();
      } catch (err) {
        return { ok: false, error: `${note}. ${err.message}` };
      }
    }
    const status = await waitForDaemon(START_POLL_MAX_S);
    if (!status) {
      return { ok: false, error: `${note ? note + '. ' : ''}Daemon did not answer on ${config.url} within ${START_POLL_MAX_S}s.` };
    }
    await loadUI();
    return { ok: true };
  } finally {
    startingService = false;
  }
}

// ---------------------------------------------------------------- autostart
function autostartExec() {
  const q = (s) => `"${String(s).replace(/(["\\$`])/g, '\\$1')}"`;
  if (process.env.APPIMAGE) return `${q(process.env.APPIMAGE)} --hidden`;
  if (process.defaultApp) return `${q(process.execPath)} ${q(app.getAppPath())} --hidden`;
  return `${q(process.execPath)} --hidden`;
}

function isAutostartEnabled() {
  return fs.existsSync(AUTOSTART_FILE);
}

function setAutostart(enabled) {
  try {
    if (enabled) {
      fs.mkdirSync(path.dirname(AUTOSTART_FILE), { recursive: true });
      const entry = [
        '[Desktop Entry]',
        'Type=Application',
        'Version=1.0',
        'Name=cyberboba',
        'Comment=cyberboba desktop (tray)',
        `Exec=${autostartExec()}`,
        `Icon=${app.isPackaged ? 'cyberboba' : APP_ICON}`,
        'Terminal=false',
        'Categories=Network;',
        'X-GNOME-Autostart-enabled=true',
        'X-GNOME-Autostart-Delay=3',
        '',
      ].join('\n');
      fs.writeFileSync(AUTOSTART_FILE, entry, { mode: 0o644 });
    } else if (fs.existsSync(AUTOSTART_FILE)) {
      fs.unlinkSync(AUTOSTART_FILE);
    }
  } catch (err) {
    console.warn(`[autostart] ${err.message}`);
    dialog.showErrorBox('cyberboba', `Could not update autostart entry:\n${err.message}`);
  }
}

// ---------------------------------------------------------------- tray
function trayImage(on) {
  const base = path.join(__dirname, 'assets', on ? 'tray-on' : 'tray-off');
  const img = nativeImage.createFromPath(base + '.png');
  const big = nativeImage.createFromPath(base + '-32.png');
  if (!big.isEmpty()) img.addRepresentation({ scaleFactor: 1.5, buffer: big.toPNG() });
  return img;
}

function fmtRate(bps) {
  const n = Number(bps) || 0;
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB/s';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB/s';
  return Math.round(n) + ' B/s';
}

function buildTrayMenu(status) {
  const online = Boolean(status);
  const proxifyOn = online && status.proxify && status.proxify.enabled;
  const recording = online && status.intercept && status.intercept.recording;
  const vpns = (online && Array.isArray(status.vpns)) ? status.vpns : [];

  const vpnItems = vpns.length
    ? vpns.map((v) => ({
      label: `${v.name} \u2014 ${v.state || 'unknown'}`,
      click: () => trayAction(`vpn ${v.name}`, async () => {
        const up = v.state === 'up' || v.state === 'connecting';
        await api(`/api/vpn/${encodeURIComponent(v.name)}/${up ? 'down' : 'up'}`, { method: 'POST', timeout: 15000 });
      }),
    }))
    : [{ label: online ? '(no VPN profiles)' : '(daemon offline)', enabled: false }];

  return Menu.buildFromTemplate([
    { label: 'Show cyberboba', click: showWindow },
    { type: 'separator' },
    {
      label: online ? `Proxify: ${proxifyOn ? 'ON' : 'OFF'}` : 'Proxify: daemon offline',
      enabled: online,
      click: () => trayAction('proxify', () => api(`/api/proxify/${proxifyOn ? 'disable' : 'enable'}`, { method: 'POST', timeout: 10000 })),
    },
    {
      label: online ? `Intercept recording: ${recording ? 'on' : 'off'}` : 'Intercept recording: daemon offline',
      enabled: online,
      click: () => trayAction('intercept', () => api('/api/intercept/toggle', { method: 'POST', body: { recording: !recording }, timeout: 10000 })),
    },
    { label: 'VPN', submenu: vpnItems },
    { label: 'Open web UI in browser', click: () => openExternal(config.url + '/') },
    { type: 'separator' },
    {
      label: 'Start hidden at login',
      type: 'checkbox',
      checked: isAutostartEnabled(),
      click: (item) => { setAutostart(item.checked); refreshTray(lastStatus); },
    },
    { label: 'Quit', click: quit },
  ]);
}

async function trayAction(name, fn) {
  try {
    await fn();
  } catch (err) {
    console.warn(`[tray] ${name}: ${err.message}`);
    dialog.showErrorBox('cyberboba', `${name}: ${err.message}`);
  }
  pollStatus();
}

function trayTooltip(status) {
  if (!status) return `cyberboba \u2014 daemon not reachable (${config.url})`;
  const s = status.stats || {};
  const parts = [
    `proxify ${status.proxify && status.proxify.enabled ? 'ON' : 'OFF'}`,
    `${s.active || 0} active`,
    `\u2193${fmtRate(s.rate_in)} \u2191${fmtRate(s.rate_out)}`,
  ];
  const up = (status.vpns || []).filter((v) => v.state === 'up').map((v) => v.name);
  if (up.length) parts.push(`vpn: ${up.join(', ')}`);
  if (status.intercept && status.intercept.recording) parts.push('recording');
  return `cyberboba \u2014 ${parts.join(' \u00b7 ')}`;
}

let trayIsOn = null;
function refreshTray(status) {
  if (!tray) return;
  const on = Boolean(status && status.proxify && status.proxify.enabled);
  if (trayIsOn !== on) {
    tray.setImage(trayImage(on));
    trayIsOn = on;
  }
  tray.setToolTip(trayTooltip(status));
  tray.setContextMenu(buildTrayMenu(status));
}

async function pollStatus() {
  const status = await probe();
  if (status) {
    lastStatus = status;
    failedPolls = 0;
    if (showingOffline && !startingService) await loadUI();
    else refreshTray(status);
    return;
  }
  failedPolls++;
  refreshTray(null);
  if (!showingOffline && failedPolls >= OFFLINE_AFTER_FAILED_POLLS) {
    console.warn('[poll] daemon unreachable, switching to offline page');
    showOffline();
  }
}

function createTray() {
  tray = new Tray(trayImage(false));
  tray.setToolTip('cyberboba');
  tray.setContextMenu(buildTrayMenu(null));
  tray.on('click', () => { pollStatus(); showWindow(); });
  tray.on('double-click', showWindow);
  trayTimer = setInterval(pollStatus, TRAY_REFRESH_MS);
}

// ---------------------------------------------------------------- app menu
function createAppMenu() {
  const template = [
    {
      label: 'cyberboba',
      submenu: [
        { label: 'Show window', click: showWindow },
        { label: 'Reload', accelerator: 'F5', click: () => { if (win && win.webContents) win.webContents.reloadIgnoringCache(); else loadUI(); } },
        { label: 'Force reload (clear cache)', accelerator: 'CommandOrControl+Shift+R', click: async () => { try { await session.defaultSession.clearCache(); } catch (e) {} if (win && win.webContents) win.webContents.reloadIgnoringCache(); else loadUI(); } },
        { label: 'Open web UI in browser', click: () => openExternal(config.url + '/') },
        { type: 'separator' },
        { label: 'Hide to tray', accelerator: 'CommandOrControl+W', click: () => win && win.hide() },
        { label: 'Quit', accelerator: 'CommandOrControl+Q', click: quit },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'resetZoom' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
        { role: 'toggleDevTools' },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function quit() {
  quitting = true;
  app.quit();
}

// ---------------------------------------------------------------- IPC bridge
ipcMain.handle('cyberboba:startService', () => startService());
ipcMain.handle('cyberboba:retry', async () => ({ ok: await loadUI() }));
ipcMain.handle('cyberboba:getConfig', () => ({ ...getConfig(), autostart: isAutostartEnabled(), startHiddenFlag }));
ipcMain.handle('cyberboba:setConfig', (e, partial) => { config = setConfig(partial); return config; });
ipcMain.handle('cyberboba:openExternal', (e, url) => { openExternal(String(url)); });

// ---------------------------------------------------------------- lifecycle
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => showWindow());

  app.whenReady().then(async () => {
    try { await session.defaultSession.clearCache(); } catch (err) { console.warn(`[cache] clear: ${err.message}`); }
    createAppMenu();
    createWindow();
    try {
      createTray();
    } catch (err) {
      console.warn(`[tray] unavailable: ${err.message}`);
    }
    await loadUI();
    if (startHiddenFlag || config.startHidden) {
      console.log('[app] started hidden (tray only)');
    } else if (win && !win.isVisible()) {
      win.show();
    }
  });

  app.on('activate', showWindow);
  app.on('window-all-closed', () => { /* keep running in the tray */ });
  app.on('before-quit', () => {
    quitting = true;
    if (trayTimer) clearInterval(trayTimer);
    stopOfflineRetry();
  });
}
