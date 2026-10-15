'use strict';
// Bridge for the firewall prompt popup (pages/prompt.html).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberbobaPrompt', {
  /** cb({ask, queued, timeoutSec, timeoutAction}) whenever the shell wants a new ask displayed. */
  onAsk: (cb) => { ipcRenderer.on('prompt:ask', (_e, payload) => cb(payload)); },
  /** cb({id}) when the daemon resolved an ask on its own (timeout / answered elsewhere). */
  onResolved: (cb) => { ipcRenderer.on('prompt:resolved', (_e, payload) => cb(payload)); },
  /** Answer the current ask. -> {ok, error?} */
  answer: (id, allow, remember) => ipcRenderer.invoke('prompt:answer', { id, allow, remember }),
  /** Leave this ask to the daemon's timeout and show the next one (or hide). */
  skip: (id) => ipcRenderer.invoke('prompt:skip', { id }),
  /** Open the main window on the Firewall page. */
  openFirewall: () => ipcRenderer.invoke('prompt:openFirewall'),
});
