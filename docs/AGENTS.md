# cyberboba for AI agents

cyberboba is built to be driven by agents first and humans second. Everything the
web UI can do is available through three machine interfaces, all backed by the
same daemon (`cyberbobad`):

| interface | when to use | entry point |
|---|---|---|
| **MCP server** (stdio) | Claude Code, Claude Desktop, Cursor, any MCP client | `cyberboba mcp` |
| **CLI with `--json`** | shell-driven agents, scripts, CI | `cyberboba --json <cmd>` / `cyberboba api METHOD /path [json]` |
| **HTTP JSON API** | anything else, long-lived integrations, SSE event streams | `http://127.0.0.1:7471/api/...`, spec at `/api/openapi.json` |

## 1. Register the MCP server

```sh
# Claude Code
claude mcp add cyberboba -- cyberboba mcp
# or with a TCP endpoint / token
claude mcp add cyberboba -- cyberboba -api 127.0.0.1:7471 -token "$CYBERBOBA_TOKEN" mcp
```

Generic MCP client config (stdio):

```json
{"mcpServers": {"cyberboba": {"command": "cyberboba", "args": ["mcp"]}}}
```

The server speaks JSON-RPC 2.0 over stdin/stdout (newline-delimited), protocol
`2025-06-18` (also answers `2024-11-05` / `2025-03-26` clients), and exposes
**70 tools**. Tool results are JSON text; errors come back as `isError: true`
with a readable message.

### Tool map

| area | tools |
|---|---|
| status | `status`, `doctor`, `log`, `list_processes`, `list_installed_apps`, `list_connections`, `proxify` |
| firewall (ZoneAlarm-style) | `firewall_status`, `firewall_pending`, `firewall_answer`, `firewall_answer_all`, `firewall_set_mode`, `firewall_lock`, `firewall_stealth`, `firewall_block`, `firewall_unblock`, `set_firewall` |
| config | `get_config`, `set_config` (YAML) |
| rules | `list_rules`, `add_rule`, `delete_rule`, `set_rules`, `test_rule` |
| proxies | `list_proxies`, `add_proxy`, `delete_proxy`, `set_proxies`, `check_proxy`, `rotation_status` (live rotate-group member) |
| VPN | `list_vpns`, `vpn_up`, `vpn_down`, `vpn_log`, `vpn_import`, `set_vpns`, `vpn_rotations`, `set_vpn_rotations` |
| intercept | `intercept_status`, `intercept_toggle`, `intercept_configure`, `list_flows`, `list_flows_by_body`, `wait_for_flow`, `get_flow`, `flow_as_curl`, `delete_flows`, `export_har`, `pending_flows`, `forward_flow`, `drop_flow`, `forward_all`, `send_request`, `ca_cert`, `install_ca` |
| rewrites | `list_rewrites`, `add_rewrite`, `set_rewrites` (match & replace on intercepted flows) |
| sessions | `save_session`, `load_session`, `list_sessions` (persist captured flows) |
| tags | `list_tags` (cgroup groups from `cyberboba run -tag`, incl. UDP policy) |
| processes | `list_processes` (quick name/exe/user list), `process_monitor` (Task-Manager snapshot: CPU%, memory, state, threads, connections, `system` flag), `kill_process` (signal a pid; TERM/KILL), `system_stats` (overall/per-core CPU, load, memory/swap, temperatures and fans) |
| traffic map | `traffic_graph` (nodes/edges/paths + live connections with the hop chain and destination country), `traffic_map` (geographic live map: home + destinations with lat/lon, apps, ISP, bytes, blocked flag), `geo_lookup`, `test_route_live` (dial a host through the resolved route, report real exit IP/country), `probe_route` (live-test an unsaved VPN/proxy chain) |

MCP also exposes **resources** (`cyberboba://status`, `cyberboba://flows`, `cyberboba://flows/{id}`, `cyberboba://topology`, `cyberboba://config`,
`cyberboba://ca.crt`, `cyberboba://openapi`, ...) and **prompts** (`route_app`, `capture_traffic`, `analyze_flows`).
Transport: stdio (`cyberboba mcp`) or Streamable HTTP (`POST http://127.0.0.1:7471/mcp`). The stdio server pushes
`notifications/resources/updated` (flows, connections) and `notifications/message` (log lines).

## 2. Typical agent workflows

**Route one application through a proxy, verify, roll back**
1. `list_processes` → find the process name (e.g. `telegram-desktop`).
2. `add_proxy {name: "socks-home", type: "socks5", addr: "10.0.0.1:1080", remote_dns: true}`
3. `check_proxy {name: "socks-home"}` → latency + exit IP.
4. `add_rule {name: "tg via socks", apps: ["telegram-desktop"], action: "proxy", proxy: "socks-home"}`
   (inserted above the catch-all rule by default).
5. `test_rule {app: "telegram-desktop", host: "api.telegram.org", port: 443}` → confirms the match.
6. `list_connections {limit: 20}` → watch the live effect (rule, action, via, bytes).
7. `delete_rule {name: "tg via socks"}` to undo.

**Capture and analyse an app's HTTPS traffic**
1. `install_ca` once (or `ca_cert` and install it yourself; browsers need the NSS import the tool performs).
2. `add_rule {name: "capture firefox", apps: ["firefox"], ports: ["80","443"], action: "intercept"}`
   (no proxy settings needed in the app; QUIC is blocked so HTTPS stays on TCP).
3. `intercept_configure {scope_include: ["*.target.com"]}` to keep the history focused.
4. `list_flows {host: "target.com", limit: 50}` → `get_flow {id}` for bodies and raw text → `flow_as_curl {id}`.
5. `export_har {scope_only: true}` for offline analysis.

**Man-in-the-middle edit**
1. `intercept_toggle {hold_requests: true}`.
2. `pending_flows` → read `req_raw`.
3. `forward_flow {id, raw: "<edited request>"}` or `drop_flow {id}`; `forward_all` to flush.
4. `intercept_toggle {hold_requests: false}`.

**Craft / replay requests (repeater)**
`send_request {host: "api.example.com", tls: true, raw: "POST /v1/x HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"a\":1}"}`
returns the full flow (status, headers, body, timing). Line endings may be `\n`;
`Content-Length` is recomputed. The request leaves through the intercept
upstream route (`intercept_configure {upstream_action: "vpn", upstream_vpn: "office"}`
sends repeater and intercepted traffic through a tunnel).

**Inject / rewrite traffic and wait for a result**
1. `add_rewrite {target: "request", part: "header", header: "Authorization", replace: "Bearer TEST"}` to force a header.
2. `add_rewrite {target: "response", part: "body", match: "<regex>", replace: "..."}` to patch responses.
3. Trigger the app, then `wait_for_flow {host: "api.example.com", status: "401", timeout_sec: 20}` to block until the matching flow appears.
4. `save_session {}` to persist the capture; `load_session {path}` later to re-inspect.

**Bring up a tunnel for one workload only**
1. `vpn_import {name: "office", content: "<wg conf>", mode: "selective"}`
2. `vpn_up {name: "office"}` → `list_vpns` shows interface, handshake, bytes.
3. `add_rule {name: "work via office", apps: ["tag:work"], action: "vpn", vpn: "office"}`
4. Run the workload with `cyberboba run -tag work -- <command>`; only it uses the tunnel. Because the process joins a
   net_cls cgroup, a `tag:work`-only rule with action `vpn` or `block` also governs its **UDP** traffic (QUIC, games,
   VoIP), which the transparent TCP proxy cannot see. `list_tags` shows the live members and UDP policy.

**Visualise how traffic flows (chained VPNs/proxies) and where it exits**
1. Bring up the tunnels/proxies and add rules as above (e.g. `vpn_up office`, a proxy chain, a `tag:work` rule).
2. `traffic_graph` → returns `nodes` (this machine, each VPN/proxy with its country, destinations), `edges`,
   `paths` (the ordered hop chain per enabled rule) and `live` (each open connection with its `nodes` chain and
   destination `country`/`flag`). The same view is the "Traffic" tab in the web UI (live animated map).
3. `geo_lookup {ip: "1.2.3.4"}` for an ad-hoc country/city/ISP lookup. Geolocation is cached and can be turned
   off with `geo.enabled: false` in the config (it queries an external provider).

## 3. CLI for shell agents

Every read command accepts `--json`. `cyberboba api` is a raw escape hatch:

```sh
cyberboba --json status
cyberboba --json intercept flows -host example.com -limit 20
cyberboba intercept flow 42 -raw                   # raw request + response
printf 'GET / HTTP/1.1\nHost: example.com\n\n' | cyberboba intercept send -host example.com -tls
cyberboba api POST /api/rules/test '{"app":"curl","host":"example.com","port":443}'
cyberboba api PUT /api/rules "$(cat rules.json)"
cyberboba conns -follow                            # streams new connections (SSE)
```

Exit code is non-zero and the error is printed to stderr when the daemon
rejects a change (validation errors list every problem in one message).

## 4. HTTP API notes

* Base URL `http://127.0.0.1:7471`, unix socket `/run/cyberboba/cyberboba.sock`
  (`curl --unix-socket`). Optional bearer token (`api.token`), also accepted as
  `?token=` for `EventSource`.
* `GET /api/openapi.json` for the machine-readable surface; `docs/API.md` for field-level detail.
* `GET /api/events` streams `conn`, `stats`, `vpn`, `caido`, `flow`, `intercept`, `log` events.
* All mutations are idempotent "replace the list" operations (`PUT /api/rules`,
  `PUT /api/proxies`, `PUT /api/vpn`, `PUT /api/config/yaml`); read, modify, write.
* Configuration is validated as a whole; a rule referencing a missing proxy is
  rejected before anything is applied.

## 5. Safety rails worth knowing

* Rules are first-match; keep a final catch-all (`action: direct`) so nothing is
  silently blocked. `test_rule` is cheap: use it before and after changes.
* `proxify {enabled: false}` removes all iptables rules at runtime without
  touching the configuration; the daemon also removes them on shutdown.
* The daemon's own sockets carry an fwmark and are never re-intercepted; a
  proxy process's own traffic is never routed into itself (loop guard).
* `kill_switch: true` on a full-mode VPN profile blocks non-VPN traffic while the
  tunnel is down after it was up; `reconnect: true` retries with backoff.
* Intercepted TLS is re-signed by a local CA stored in `/etc/cyberboba/ca`; apps
  with certificate pinning must be listed in `intercept.passthrough`.
