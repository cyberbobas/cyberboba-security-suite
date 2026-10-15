# Running CyberBoba on Windows (WSL2) and macOS

CyberBoba's transparent, per-app interception, the application firewall and the
system monitors are built on Linux kernel facilities (netfilter/iptables,
policy routing + fwmark, `/proc`, cgroups). The fastest way to get the **full**
experience on Windows is **WSL2**; on macOS/Windows you can also run the native
"lite" binary (explicit-proxy mode). This page covers both.

---

## Windows — WSL2 (recommended, full features)

WSL2 is a real Linux kernel, so CyberBoba runs with (almost) all features for
traffic generated **inside** WSL2.

1. **Install WSL2 + Ubuntu** (PowerShell, as admin):

   ```powershell
   wsl --install -d Ubuntu
   ```

2. **Enable systemd** in WSL2 — edit `/etc/wsl.conf`:

   ```ini
   [boot]
   systemd=true
   ```

   then from PowerShell: `wsl --shutdown` and reopen Ubuntu.

3. **Build & install** inside Ubuntu:

   ```sh
   sudo apt update && sudo apt install -y git make iptables iproute2
   # install Go 1.26+ (https://go.dev/dl), then:
   git clone https://github.com/cyberbobas/cyberboba-security-suite.git
   cd cyberboba-security-suite
   make build && sudo make install
   sudo systemctl enable --now cyberboba
   ```

4. **Open the UI from Windows** — WSL2 forwards `localhost`, so just browse to
   <http://127.0.0.1:7471> in any Windows browser, or run the Electron desktop
   app on Windows pointing at it:

   ```powershell
   set CYBERBOBA_URL=http://127.0.0.1:7471
   npm --prefix path\to\desktop start
   ```

5. **Scope.** CyberBoba governs processes running **inside WSL2** (CLI tools,
   servers, Linux browsers, your AI agents launched in WSL). It does **not**
   transparently intercept Windows-host apps (WSL2 is a lightweight VM). To
   route Windows apps through it, point them at the SOCKS5 (`127.0.0.1:7472`) or
   HTTP (`127.0.0.1:7473`) proxy that WSL2 forwards to Windows.

   > Tip: run your AI coding agents (Claude Code, aider, …) inside WSL2 and the
   > **AI Agents** monitor will flag any credentials they send off the box.

---

## macOS / native Windows — "lite" mode (explicit proxy)

Prebuilt `darwin-arm64`, `darwin-amd64` and `windows-amd64` binaries are
attached to every [release](https://github.com/cyberbobas/cyberboba-security-suite/releases/latest).
They run, but transparent interception, the per-app firewall and the system
monitors are **Linux-only** and are disabled. What still works:

- the **web UI / HTTP API / MCP server** (drive it from an agent),
- **SOCKS5 / HTTP upstream proxies and chains**,
- the **intercepting HTTPS proxy as an *explicit* proxy** — point an app or
  browser at `127.0.0.1:8080`, install the CA, and capture its traffic,
- **DNS filtering** when you set the daemon as your resolver,
- proxy / VPN **config management**.

You lose the "no app configuration" magic (you configure each app's proxy) and
the Linux-only monitors. For the full experience, use WSL2 (Windows) or a Linux
VM (macOS).

---

## Why not a full native port?

The transparent engine needs a privileged, OS-specific component: a
**NetworkExtension/system extension** on macOS (Apple Developer Program +
entitlements + notarization) or a **WFP/WinDivert driver** on Windows (driver
signing), plus native process→socket attribution and system-stats code per OS.
It is on the roadmap; contributions welcome — see
[CONTRIBUTING](../CONTRIBUTING.md).
