# cyberboba desktop

A thin Electron shell for the [cyberboba](../README.md) daemon (`cyberbobad`): it
shows the daemon's web UI (served on `http://127.0.0.1:7471`) in a window and
adds the OS integration a browser tab cannot give you:

- a tray icon (blue = proxify ON, grey = OFF) with a live menu: toggle proxify,
  toggle intercept recording, bring VPN profiles up/down, open the web UI in a
  browser; the tooltip shows active connections and current rates;
- close-to-tray, `--hidden` start, "Start hidden at login" (XDG autostart);
- an offline page with a "Start service" button (`pkexec systemctl start cyberboba`)
  when the daemon is not running, with automatic reconnect when it comes back.

It does **not** reimplement any UI page; everything you see inside the window
is the daemon's own UI. **The daemon must be installed separately** (see the
top-level README: `make build && sudo make install && sudo systemctl enable --now cyberboba`).

## Development

Node 20+ and npm are required.

```sh
cd desktop
npm install              # downloads Electron (~100 MB) into node_modules
npm run icons            # regenerates assets/tray-*.png and build/icon.png (pure Node, no deps)
npm start                # = electron .
npm start -- --hidden    # start minimized to the tray
CYBERBOBA_URL=http://127.0.0.1:7471 npm start
```

Files:

```
main.js            main process: window, tray, config, service start, IPC
preload.js         contextBridge: window.cyberboba.{startService,retry,getConfig,setConfig,openExternal}
pages/offline.html local page shown while cyberbobad is unreachable
assets/            tray icons + app icon (generated)
build/icon.png     application icon (generated), electron-builder build resources
tools/make-icons.js PNG generator (zlib only)
```

Keyboard: `F5` reloads, `Ctrl+Q` quits, `Ctrl+W` hides to the tray, `Alt`
toggles the (otherwise hidden) menu bar. Closing the window hides it to the
tray; use the tray's "Quit" or `Ctrl+Q` to exit. A second launch focuses the
existing window.

## Configuration

Order of precedence: `CYBERBOBA_URL` environment variable, then
`~/.config/cyberboba-desktop/config.json`, then the default `http://127.0.0.1:7471`.

```json
{
  "url": "http://127.0.0.1:7471",
  "token": "",
  "startHidden": false
}
```

- `token` – if the daemon's `api.token` is set, the desktop app sends it as
  `Authorization: Bearer <token>` on the API calls it makes itself (tray
  actions, status polling). The web UI inside the window authenticates on its own.
- `startHidden` – same effect as the `--hidden` flag.

## Autostart

"Start hidden at login" in the tray menu writes
`~/.config/autostart/cyberboba-desktop.desktop` with
`Exec=<app> --hidden`, where `<app>` is the AppImage path (`$APPIMAGE`) when
running from an AppImage, otherwise the installed binary
(`/opt/cyberboba/cyberboba` for the .deb). Unchecking removes the file. Running
from the source tree writes an `electron <path> --hidden` entry, which only
works while `node_modules` exists.

## Building packages

```sh
npm run dist             # dist/cyberboba-<version>.AppImage and dist/cyberboba_<version>_amd64.deb
```

electron-builder configuration lives in the `build` section of `package.json`
(appId `io.cyberboba.desktop`, category Network). The packages contain only the
desktop shell; install the daemon separately (`sudo make install` from the
repository root, or your distribution's package).

## Troubleshooting

- **Blank/offline page although the daemon runs** – check the address
  (`CYBERBOBA_URL` / `config.json`) and that `api.listen` in
  `/etc/cyberboba/config.yaml` is `127.0.0.1:7471`.
- **"Start service" does nothing / fails with 126 or 127** – polkit prompt was
  cancelled or `pkexec` is missing; run `sudo systemctl start cyberboba` manually.
- **No tray icon** – GNOME needs an AppIndicator extension; KDE, XFCE, MATE,
  Cinnamon work out of the box. The window still works (`npm start` without
  `--hidden`).
- **Electron fails to start on a minimal system** – it needs the usual GTK3
  runtime libraries (`libgtk-3-0 libnss3 libasound2 libxss1 libgbm1`). The
  `.deb` declares these as dependencies; the AppImage expects them on the host.
- **Noise on stdout** such as `Installed VAAPI version is too old`,
  `Failed to register with org.freedesktop.host.portal.Registry` or the
  `Electron Security Warning (Insecure Content-Security-Policy)` (the latter
  comes from the daemon's UI having no CSP and only appears unpackaged) is
  harmless Chromium logging, not an app error.
