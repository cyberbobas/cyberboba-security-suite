# CyberBoba Security Suite

Per-application network control for Linux in one daemon: Proxifier-style
routing rules, a WireGuard/OpenVPN manager, an intercepting HTTPS proxy, DNS
blocklists, an application firewall and a bandwidth monitor. Everything is
driven the same three ways: HTTP API, CLI and an MCP server, with a web UI and
an optional desktop app on top.

[![CI](https://github.com/cyberbobas/cyberboba-security-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/cyberbobas/cyberboba-security-suite/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Linux-333)](#requirements)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

![demo](docs/demo.gif)

## What it does

- **Per-app routing (Proxifier for Linux).** Rules match a process (name,
  path, command line, user, tag) and a destination (host, IP/CIDR, port,
  protocol) and send the connection direct, through a SOCKS5/HTTP proxy or a
  proxy chain, through a VPN, into the interceptor, or block it. Transparent:
  applications are not reconfigured.
- **VPN manager.** WireGuard (`wg-quick`) and OpenVPN profiles. `full` mode is
  a classic VPN (default route for everything). `selective` mode keeps the
  tunnel off the main routing table and only rule-routed traffic uses it, so
  several tunnels can be up at once. Kill switch, auto-reconnect, rotation
  groups. A tunnel brought up outside the daemon (`wg-quick up` by hand) is
  detected and shown as `up (external)`.
- **Intercepting HTTPS proxy.** Own CA, request/response history, hold and
  edit, repeater, match-and-replace rewrites, sessions, HAR export, and a
  passive scanner that flags leaked secrets, cleartext credentials, insecure
  cookies, missing security headers and CORS problems.
- **Application firewall.** Ask/allow/block per program and zone (LAN vs
  internet), a host blocklist that applies to every program, inbound stealth
  mode and an internet-lock switch. Prompts are delivered system-wide by the
  desktop app (notification banners with Allow / Allow always / Deny).
- **DNS filtering.** Pi-hole-style blocklists (hosts and domain lists),
  manual block/allow entries, NXDOMAIN or sinkhole answers, live query log.
- **Monitoring.** Live connection table with the owning process, per-app
  bandwidth with data-usage history and anomaly alerts, a geographic live map,
  a traffic map that shows the real path of every rule and connection
  (including an active full tunnel), process viewer and system stats.
- **AI agents view.** Recognises common AI coding agents (Claude Code, Codex,
  Gemini CLI, Cursor, Copilot, aider, ...) and shows what they connect to and
  whether a recorded request carried an API key or token.

Screenshots: [dashboard](docs/screenshots/dashboard.png) ·
[firewall](docs/screenshots/firewall.png) · [live map](docs/screenshots/live-map.png) ·
[intercept](docs/screenshots/intercept.png) · [AI agents](docs/screenshots/ai-agents.png) ·
[bandwidth](docs/screenshots/bandwidth.png) · [DNS](docs/screenshots/dns.png) ·
[processes](docs/screenshots/processes.png)

## Requirements

- Linux with netfilter: `iptables` (legacy or nft backend), `ip` from
  iproute2. The daemon runs as root (transparent interception, routing tables,
  `/proc` access for process attribution).
- Optional: `wireguard-tools` and/or `openvpn` for VPN profiles,
  `libnss3-tools` (`certutil`) to import the intercept CA into Firefox and
  Chromium profiles.
- To build from source: Go 1.26 or newer.
- Desktop app (optional): Node.js 20+ and npm. Firewall prompts with buttons
  use the desktop's notification service through `python3-gi` (preinstalled on
  GNOME and most desktops).

Tested on Ubuntu 24.04-based systems (Zorin OS 18) and Ubuntu 20.04-based
systems (Linux Mint 20). Other distributions with systemd and iptables should
work the same way.

## Install

### From source (recommended)

```sh
git clone https://github.com/cyberbobas/cyberboba-security-suite.git
cd cyberboba-security-suite

make build                 # builds bin/cyberbobad (daemon) and bin/cyberboba (CLI)
sudo make install          # /usr/local/bin, /etc/cyberboba/config.yaml, systemd unit
sudo systemctl daemon-reload
sudo systemctl enable --now cyberboba

cyberboba status           # daemon status; web UI at http://127.0.0.1:7471
cyberboba doctor           # checks iptables, ip, wg, openvpn, certutil, /dev/net/tun
```

`make install` never overwrites an existing `/etc/cyberboba/config.yaml`.

To upgrade:

```sh
git pull
make build && sudo make install && sudo systemctl restart cyberboba
```

### From a release tarball

Each [release](https://github.com/cyberbobas/cyberboba-security-suite/releases/latest)
ships `cyberboba-<version>-linux-amd64.tar.gz` with the two binaries only. It
is meant for upgrading an existing install; for a first install use the source
steps above, which also put the config and the systemd unit in place.

```sh
tar xzf cyberboba-v*-linux-amd64.tar.gz
sudo install -m 0755 cyberbobad cyberboba /usr/local/bin/
sudo systemctl restart cyberboba
```

### Desktop app

The desktop app is an Electron shell around the daemon's web UI. It adds a
tray icon, "start hidden at login", and the system-wide alerts: firewall
prompts as notification banners with Allow / Allow always / Deny, an
always-on-top prompt window with the details, and notifications for blocked
connections, bandwidth anomalies and VPN state changes.

```sh
cd desktop
npm install
npm start
```

It is not packaged; `npm start` runs it from the source tree. The release
workflow also attaches a best-effort AppImage to each release.

### Arch Linux

`packaging/aur/PKGBUILD` builds the binaries, the unit and the default config
with `makepkg -si`. It is maintained in-tree and not published on the AUR.

### Trust the intercept CA

Needed only for the intercepting proxy, so browsers accept the rewritten TLS:

```sh
sudo cyberboba intercept ca install    # system trust store + Firefox/Chromium NSS databases
```

### Uninstall

```sh
sudo make uninstall                              # stops the service, removes binaries and unit
sudo rm -rf /etc/cyberboba /var/lib/cyberboba    # config, CA, state (optional)
```

### Without root

`make run-dev` starts the daemon from the source tree without netfilter. The
web UI, API, rule engine, upstream proxies and the SOCKS5 (`:7472`) / HTTP
(`:7473`) inbound proxies work; transparent interception, VPNs and the
firewall need the root install.

## First steps

```sh
cyberboba rules                                   # ordered rule list
cyberboba rules test firefox example.com:443      # which rule would match
cyberboba route-test https://ifconfig.me/ip       # dial through the matched route, show exit IP
cyberboba conns -follow                           # live connection log with owning process
cyberboba vpn import office ~/office.conf         # WireGuard/OpenVPN profile, full mode by default
cyberboba vpn up office
cyberboba firewall mode ask                       # prompt for every new program
cyberboba dns on                                  # DNS blocklists
cyberboba bandwidth                               # per-app speed and data usage
cyberboba intercept record firefox                # record one app's HTTPS in the interceptor
cyberboba run -tag pentest -- firefox             # rules can match "tag:pentest"
```

Example rules in `/etc/cyberboba/config.yaml`:

```yaml
rules:
  - {name: LAN, targets: [lan], action: direct}
  - {name: Capture browsers, apps: [firefox, chrome], ports: ["80", "443"], action: intercept}
  - {name: Pentest tools, apps: ["tag:pentest"], action: proxy, proxy: socks-home}
  - {name: Work via office VPN, apps: [slack, "*teams*"], action: vpn, vpn: office}
  - {name: Kill telemetry, targets: ["*.telemetry.microsoft.com"], action: block}
  - {name: Default, action: direct}
```

The web UI has a visual RouteBuilder for the same thing: this machine, then
VPN and proxy hops, then the internet, scoped to all traffic or to chosen
applications.

## Agents: API, CLI, MCP

Every feature is reachable through the HTTP API, the CLI (`--json` for
machine output, `cyberboba api METHOD /path` for raw calls) and the MCP server
(92 tools, stdio and HTTP transports):

```sh
claude mcp add cyberboba -- cyberboba mcp         # Claude Code
cyberboba --json conns                            # same data as the UI
cyberboba api GET /api/topology                   # any endpoint directly
```

The API listens on loopback; set `api.token` in the config before exposing it.
Reference: [docs/API.md](docs/API.md), [docs/CONFIG.md](docs/CONFIG.md),
[docs/AGENTS.md](docs/AGENTS.md), `GET /api/openapi.json`.

## How it works

- Outbound TCP from the machine is redirected by an iptables `REDIRECT` rule
  in a `CYBERBOBA_OUT` chain to the daemon's transparent listener. The daemon
  reads the original destination (`SO_ORIGINAL_DST`), resolves the owning
  process with a `sock_diag` netlink query plus `/proc/<pid>/fd`, sniffs the
  SNI or Host header, evaluates the rules and dials upstream: direct, through
  a proxy or chain, through a VPN (packets marked with `SO_MARK`, policy
  routing table per selective tunnel), or into the interceptor.
- DNS from the machine is redirected to the daemon's forwarder, which applies
  the blocklists and remembers IP-to-hostname mappings for the rules.
- A full-mode VPN owns the default route, so it becomes the first hop of every
  connection that is not pinned to another tunnel; the traffic map and
  RouteBuilder draw it that way. Because `wg-quick` installs an anti-spoofing
  rule that would drop the replies of redirected connections, the daemon
  relaxes that rule for loopback (both the iptables and the nftables flavour).
- The daemon's own traffic is excluded from redirection by mark and uid, so
  it cannot loop through itself.

## Project layout

```
cmd/cyberbobad       daemon          internal/proxy      transparent + SOCKS5/HTTP engine, SNI/Host sniff
cmd/cyberboba        CLI             internal/upstream   SOCKS5 / HTTP CONNECT / chains / SO_MARK dialer
internal/config      YAML config     internal/netfilter  iptables chains, policy routing, wg-quick fix-ups
internal/rules       rule engine     internal/dnsfwd     DNS forwarder, blocklists, ip-to-host cache
internal/procinfo    socket to pid   internal/vpn        WireGuard and OpenVPN backends
internal/stats       live table/SSE  internal/firewall   application firewall
internal/bandwidth   per-app meter   internal/aiagents   AI agent registry
internal/intercept   MITM proxy: CA, flows, hold/edit, repeater, passive scanner, HAR
internal/sysstat     CPU/mem/temps   internal/topology   traffic map and live geographic map
internal/api         HTTP API        internal/mcp        MCP server (stdio and HTTP)
web/                 embedded web UI (vanilla JS)
desktop/             Electron shell, tray, system-wide alerts (alerts.js, notifier.py)
```

## Security and responsible use

CyberBoba is a defensive and introspection tool for machines you own or are
authorised to administer. It intercepts TLS with a CA you install, routes
traffic through proxies and VPNs, and firewalls processes. Use it only on
systems and traffic you are permitted to inspect. The intercept CA private key
lives in `/etc/cyberboba/ca`; protect it like any private key.

## Limitations

- Only TCP and DNS are intercepted transparently. Other UDP goes direct; QUIC
  is blocked by default so HTTPS stays on TCP. Use a `full` VPN for all UDP.
- Interception covers locally generated traffic (`OUTPUT` chain); forwarded
  traffic from other hosts is not touched.
- Intercepted TLS is HTTP/1.1 only; certificate-pinned apps belong in
  `intercept.passthrough`.
- Process attribution needs the socket to still exist when the connection is
  accepted. A program that connects and exits immediately shows up as
  "unknown program" with a best-effort guess from earlier connections.
- Linux only. Nothing here runs on macOS or Windows.

## License

Apache-2.0, see [LICENSE](LICENSE).
