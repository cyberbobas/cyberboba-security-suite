'use strict';
// Minimal bridge for the local offline page. The daemon's web UI does not need
// anything from it; it only exposes a handful of IPC calls on window.cyberboba.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberboba', {
  /** True inside the desktop shell. The web UI then leaves firewall prompts to
   *  the shell's system-wide popup instead of its in-window modal. */
  desktop: true,
  /** Start the daemon (pkexec systemctl start cyberboba) and wait for it. -> {ok, error?} */
  startService: () => ipcRenderer.invoke('cyberboba:startService'),
  /** Probe the daemon again; loads the web UI when it is up. -> {ok} */
  retry: () => ipcRenderer.invoke('cyberboba:retry'),
  /** Effective configuration: {url, token, startHidden, autostart}. */
  getConfig: () => ipcRenderer.invoke('cyberboba:getConfig'),
  /** Persist a partial {url, token, startHidden} to ~/.config/cyberboba-desktop/config.json. */
  setConfig: (partial) => ipcRenderer.invoke('cyberboba:setConfig', partial),
  /** Open an http(s) URL in the system browser. */
  openExternal: (url) => ipcRenderer.invoke('cyberboba:openExternal', url),
});
