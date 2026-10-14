# cyberboba control API

The daemon (`cyberbobad`) exposes a JSON HTTP API on a unix socket
(`/run/cyberboba/cyberboba.sock`) and optionally on `127.0.0.1:7471` (web UI).
All responses are JSON. Errors: `{"error": "message"}` with a 4xx/5xx status.
If `api.token` is set, TCP clients must send `Authorization: Bearer <token>`.
The web UI is served from `/` (static files). Timestamps are RFC3339.

## Status

`GET /api/status`
```json
{
  "version": "0.1.0",
  "uptime_sec": 1234,
  "proxify": {"enabled": true, "listen_tcp": "127.0.0.1:7470", "listen_dns": "127.0.0.1:7453",
              "listen_socks": "127.0.0.1:7472", "listen_http": "127.0.0.1:7473", "ipv6": true, "block_quic": true, "netfilter_installed": true},
  "stats": {"active": 12, "total": 3456, "blocked": 7, "bytes_in": 123456, "bytes_out": 2345,
            "rate_in": 1024.0, "rate_out": 512.0,
            "by_action": {"direct": 100, "proxy": 20, "vpn": 5, "block": 7}},
  "vpns": [ {"name": "office", "type": "wireguard", "mode": "selective", "state": "up",
             "interface": "office", "since": "...", "rx_bytes": 1, "tx_bytes": 2,
             "endpoint": "1.2.3.4:51820", "last_handshake": "...", "local_ip": "10.0.0.2", "error": ""} ],
  "caido": {"enabled": true, "managed": true, "running": true, "pid": 123, "listen": "127.0.0.1:8080",
            "reachable": true, "version": "0.47.3", "binary": "/usr/local/bin/caido-cli",
            "ui_url": "http://127.0.0.1:8080", "ca_cert": "/etc/cyberboba/caido-ca.crt", "error": ""},
  "warnings": ["not running as root: netfilter disabled"]
}
```

`POST /api/proxify/enable` / `POST /api/proxify/disable` — install/remove netfilter rules at runtime
(does not change the saved config). Returns `GET /api/status`.

## Configuration

`GET /api/config` — full configuration as JSON (same field names as YAML, see `docs/CONFIG.md`).
`PUT /api/config` — replace the full configuration. Validated, saved to disk, applied live.
`GET /api/config/yaml` — raw YAML (`text/plain`); `PUT /api/config/yaml` with YAML body.

## Rules

`GET /api/rules` → `{"rules": [Rule...]}`; `PUT /api/rules` with `{"rules": [...]}` replaces the ordered list.

Rule object:
```json
{"name": "Browsers via Caido", "enabled": true, "comment": "",
 "apps": ["firefox", "chrome", "/usr/bin/curl", "tag:work"],
 "users": ["user"], "targets": ["*.example.com", "10.0.0.0/8", "lan"],
 "ports": ["80", "443", "8000-8100"], "protocols": ["tcp"],
 "action": "direct|proxy|vpn|block", "proxy": "caido", "vpn": "office"}
```

`POST /api/rules/test` with `{"app": "firefox", "user": "user", "host": "example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp"}`
→ `{"matched": true, "rule": "Browsers via Caido", "index": 2, "action": "proxy", "proxy": "caido", "vpn": ""}`.

## Proxies

`GET /api/proxies` → `{"proxies": [Proxy...]}`; `PUT /api/proxies` replaces the list.

Proxy object: `{"name": "home", "type": "socks5|http|chain", "addr": "1.2.3.4:1080", "username": "", "password": "",
"hops": ["a", "b"], "via_vpn": "", "remote_dns": true, "comment": ""}`

`POST /api/proxies/{name}/check` with optional `{"url": "https://example.com"}` →
`{"ok": true, "latency_ms": 123, "status": 200, "error": "", "exit_ip": "1.2.3.4"}`.

## VPN

`GET /api/vpn` → `{"vpns": [VPNStatus...]}` (same objects as in status plus `"config": {...profile}`).
`PUT /api/vpn` with `{"vpns": [Profile...]}` replaces profiles.
`POST /api/vpn/{name}/up`, `POST /api/vpn/{name}/down` → VPNStatus.
`GET /api/vpn/{name}/log` → `{"lines": ["..."]}` (last 500 lines of the backend output).
`POST /api/vpn/import` with `{"name": "x", "type": "wireguard|openvpn", "content": "<file text>", "mode": "selective"}`
stores the file under `/etc/cyberboba/vpn/` and adds a profile.

Profile object: `{"name": "office", "type": "wireguard", "config": "/etc/cyberboba/vpn/office.conf", "mode": "full|selective",
"autostart": false, "auth_file": "", "extra_args": [], "interface": "", "comment": ""}`

## Caido

`GET /api/caido` → caido status object (see status) plus `"config": {...}`.
`PUT /api/caido` with the config object `{"enabled": true, "managed": true, "binary": "", "listen": "127.0.0.1:8080",
"data_path": "", "ca_cert": "", "extra_args": [], "proxy_name": "caido"}`.
`POST /api/caido/start`, `POST /api/caido/stop`, `POST /api/caido/restart`.
`POST /api/caido/install` — downloads the latest `caido-cli` into `/usr/local/lib/cyberboba/caido-cli`; returns
`{"ok": true, "binary": "...", "version": "..."}`. Long-running (up to a minute).
`GET /api/caido/log` → `{"lines": [...]}`.
`POST /api/caido/ca/install` with `{"path": "/path/to/ca.crt"}` (optional if `ca_cert` set) installs the CA into
the system trust store and into every NSS db found under home directories (Firefox/Chromium).
→ `{"ok": true, "installed_into": ["/usr/local/share/ca-certificates/...", "~/.pki/nssdb", ...], "errors": []}`.

## Connections (Proxifier-style live view)

`GET /api/connections?limit=500&closed=1` →
```json
{"connections": [
  {"id": 42, "started": "...", "ended": null, "state": "open|closed|blocked|error",
   "proto": "tcp", "pid": 1234, "app": "firefox", "exe": "/usr/lib/firefox/firefox", "user": "user", "tag": "",
   "dst_ip": "1.2.3.4", "dst_port": 443, "host": "example.com",
   "rule": "Browsers via Caido", "action": "proxy", "via": "caido", "vpn": "",
   "bytes_in": 123, "bytes_out": 456, "error": ""}
]}
```
`DELETE /api/connections` clears the history of closed connections.
`POST /api/connections/{id}/close` terminates a live connection.

## Events (SSE)

`GET /api/events` — `text/event-stream`. Event types (`event:` line) and `data:` JSON:
- `conn` — a connection object (open, update, close).
- `stats` — the stats object from status, every second.
- `vpn` — a VPNStatus object on state change.
- `caido` — the caido status object on change.
- `log` — `{"time": "...", "level": "info", "msg": "..."}`.

## Logs & misc

`GET /api/log?limit=500` → `{"lines": [{"time","level","msg"}]}`.
`GET /api/processes` → `{"processes": [{"pid": 1, "name": "firefox", "exe": "/usr/lib/firefox/firefox", "user": "user"}]}`
(distinct names, for autocomplete in the rules editor).
`GET /api/doctor` → `{"checks": [{"name": "root", "ok": true, "detail": "..."}]}`.

---

# v0.2 additions

## Rule action `intercept`

Rules may use `"action": "intercept"`: the connection is terminated by the built-in intercepting proxy
(TLS is MITMed with cyberboba's own CA), recorded as HTTP flows and forwarded upstream. No `proxy`/`vpn` field.

## Proxy types

`type` may also be `socks4` (addr, optional username as userid), `failover` (hops tried in order until one
connects; each hop is a full proxy, not a chain) and `balance` (random hop per connection). `chain` stays as before.

## VPN profile fields (added)

`"kill_switch": false` – while the tunnel is down/connecting after having been up (full mode), block all
outbound traffic except loopback, LAN and the VPN endpoint. `"reconnect": true` – restart OpenVPN when it exits
unexpectedly. `"username"`, `"password"` – OpenVPN credentials (stored in config, written to a 0600 auth file
at start; takes precedence over `auth_file`). VPNStatus gets `"kill_switch_active": bool`, `"reconnects": n`.

## Intercepting proxy

`GET /api/intercept` →
```json
{"enabled": true, "listen": "127.0.0.1:8080", "recording": true, "hold_requests": false, "hold_responses": false,
 "flows": 1234, "pending": 1, "ca_cert": "/etc/cyberboba/ca/ca.crt", "ca_fingerprint": "SHA256:...",
 "ca_installed": true, "upstream": {"action": "direct", "proxy": "", "vpn": ""},
 "scope": {"include": ["*.example.com"], "exclude": ["*.google.com"]}, "passthrough": ["*.bank.com"],
 "verify_upstream_tls": false, "max_flows": 10000, "max_body": 1048576,
 "config": {... same fields as config.intercept ...}}
```
`PUT /api/intercept` with the config object (`enabled, listen, hold_requests, hold_responses, record_only_scope,
scope{include,exclude}, passthrough[], upstream{action,proxy,vpn}, verify_upstream_tls, max_flows, max_body`) → status.
`POST /api/intercept/toggle` with `{"recording": bool, "hold_requests": bool, "hold_responses": bool}` (any subset) → status.
Runtime toggles are not persisted (they are reset to config on restart).

Flow object:
```json
{"id": 42, "time": "...", "duration_ms": 123, "source": "transparent|proxy|repeater", "app": "firefox", "pid": 123,
 "host": "example.com", "port": 443, "tls": true, "in_scope": true, "intercepted": true, "edited": false,
 "method": "GET", "url": "https://example.com/path?q=1", "path": "/path?q=1", "proto": "HTTP/1.1",
 "req_headers": [["Host","example.com"],["Accept","*/*"]], "req_size": 123, "req_body_truncated": false,
 "status": 200, "status_text": "200 OK", "resp_headers": [["Content-Type","text/html"]], "resp_size": 4567,
 "resp_body_truncated": false, "content_type": "text/html", "websocket": false,
 "state": "pending_request|pending_response|sent|done|error|dropped", "error": ""}
```
Headers are ordered `[name, value]` pairs. Bodies are NOT included in list responses.

`GET /api/intercept/flows?limit=500&offset=0&q=substr&host=&method=&status=200&scope=1&ids=1,2,3` → `{"flows": [...], "total": n}` (newest first).
`GET /api/intercept/flows/{id}` → the flow plus `"req_body": "<utf8 or base64>", "req_body_b64": bool, "resp_body": "...", "resp_body_b64": bool, "req_raw": "GET / HTTP/1.1\r\n...", "resp_raw": "HTTP/1.1 200 OK\r\n..."`.
`DELETE /api/intercept/flows` (all) / `DELETE /api/intercept/flows/{id}`.
`GET /api/intercept/flows/{id}/export?format=har|curl|raw` → file download.
`GET /api/intercept/export?format=har` → HAR of all (filtered like list) flows.

Intercept queue (held flows): `GET /api/intercept/pending` → `{"pending": [flow objects with req_raw/resp_raw]}`.
`POST /api/intercept/pending/{id}/forward` with optional `{"raw": "<edited raw request or response>"}` (empty = unchanged).
`POST /api/intercept/pending/{id}/drop`. `POST /api/intercept/pending/forward-all`.
SSE events: `flow` (flow object on create/update/finish), `intercept` (status object on toggle changes).

Repeater: `POST /api/intercept/send` with `{"host": "example.com", "port": 443, "tls": true, "raw": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "follow_redirects": false, "timeout_sec": 30}`
→ `{"flow": {... full flow with bodies and raws ...}}`. Repeater sessions are UI state; the server only executes requests.

CA: `GET /api/intercept/ca` → `ca.crt` PEM download (`application/x-x509-ca-cert`). `POST /api/intercept/ca/install` installs
it into the system store and browser NSS dbs → `{"ok": true, "installed_into": [...], "errors": []}`.
`POST /api/intercept/ca/regenerate` → new CA (old leaf certs invalidated) → status.

## Config export/import

`GET /api/config/yaml` and `PUT /api/config/yaml` already exist; `GET /api/config/export` returns the YAML as a
download (`Content-Disposition: attachment; filename=cyberboba-config.yaml`).

## Status additions

`GET /api/status` gains `"intercept": {enabled, listen, recording, hold_requests, hold_responses, flows, pending}`.

---

# v0.3 additions

## Intercept: match & replace ("rewrites")

`intercept.rewrites` is an ordered list applied to every intercepted flow (not to repeater requests):
```json
{"name": "add auth", "enabled": true, "target": "request|response", "part": "header|body|url",
 "header": "X-Debug",            // header name when part=header
 "match": "regex or empty",      // empty match + part=header => set header to `replace`; part=body/url requires match
 "replace": "text, $1 groups allowed", "remove": false,  // remove=true deletes the header / matched text
 "hosts": ["*.example.com"]}     // optional host scope
```
Flows that were changed get `"rewritten": true`. Edit via `PUT /api/intercept` (full config) or
`PUT /api/intercept/rewrites` with `{"rewrites": [...]}`; `GET /api/intercept/rewrites`.

## Intercept: body search, sessions

`GET /api/intercept/flows?body=substr` also matches request/response bodies (case-insensitive).
`GET /api/intercept/flows/{id}?max_body=16000` truncates returned bodies/raws to that many chars (`req_body_cut`, `resp_body_cut` booleans tell).
`POST /api/intercept/session/save` `{"path": "/var/lib/cyberboba/sessions/x.json"}` (path optional → timestamped file in `/var/lib/cyberboba/sessions`) → `{"path": ..., "flows": n}`.
`POST /api/intercept/session/load` `{"path": "...", "replace": false}` → `{"loaded": n, "flows": total}`.
`GET /api/intercept/sessions` → `{"sessions": [{"path","size","modified"}]}`.

## Tags and UDP (cgroup routing)

Processes started with `cyberboba run -tag NAME` are placed in a per-tag cgroup. Rules whose `apps` consist only of
`tag:NAME` entries and whose action is `vpn` or `block` also apply to that tag's UDP traffic (QUIC, games, VoIP):
UDP is marked for the VPN's routing table or rejected. DNS (UDP/53) keeps going through the forwarder.
`POST /api/tags/attach` `{"pid": 123, "tag": "work"}` → `{"ok": true, "cgroup": "..."}` (used by the CLI).
`GET /api/tags` → `{"tags": [{"tag": "work", "classid": "0x00740001", "pids": [..], "udp_action": "vpn:office"}]}`.

## MCP over HTTP

`POST /mcp` on the daemon speaks MCP Streamable HTTP (JSON-RPC 2.0 request or batch in the body, JSON response;
notifications get 202). `GET /mcp` is not supported (405). Bearer token applies if configured.
Stdio transport (`cyberboba mcp`) additionally pushes `notifications/resources/updated` for `cyberboba://flows` and
`cyberboba://connections` and `notifications/message` log events.

MCP resources: `cyberboba://status`, `cyberboba://config` (YAML), `cyberboba://rules`, `cyberboba://proxies`, `cyberboba://vpns`,
`cyberboba://connections`, `cyberboba://flows` (last 100), `cyberboba://flows/{id}`, `cyberboba://flows/{id}/request`,
`cyberboba://flows/{id}/response`, `cyberboba://ca.crt`, `cyberboba://openapi`. Prompts: `route_app`, `capture_traffic`, `analyze_flows`.

## Traffic topology and geolocation

`GET /api/topology` returns the live traffic graph used by the "Traffic" tab:

```json
{
  "nodes": [{"id":"this","kind":"client","label":"this machine"},
            {"id":"vpn:office","kind":"vpn","state":"up","country":"Netherlands","cc":"NL","flag":"🇳🇱"},
            {"id":"proxy:socks-home","kind":"proxy","type":"socks5","addr":"1.2.3.4:1080","country":"Germany","cc":"DE"},
            {"id":"dst:api.example.com","kind":"dest","country":"United States","cc":"US","conns":2}],
  "edges": [{"from":"this","to":"vpn:office","active_conns":2,"active":true}],
  "paths": [{"rule":"work via office","action":"proxy","match":"apps=curl",
             "nodes":["this","vpn:office","proxy:p1","proxy:p2","internet"],"enabled":true}],
  "live":  [{"id":42,"app":"curl","host":"api.example.com","action":"proxy","via":"dbl",
             "nodes":["this","vpn:office","proxy:p1","proxy:p2","dst:api.example.com"],
             "country":"United States","cc":"US","flag":"🇺🇸","bytes_in":1234,"bytes_out":567}],
  "geo_enabled": true
}
```

`GET /api/map` returns the geographic live map (the "Live Map" tab): `home` (this machine's own public-IP
geolocation with `lat`/`lon`) and `points[]`. The map is application-centric: each point is one
`(app → destination host)` pair, so the same host reached by two apps is two points. A point carries `app`,
`host`/`ip`, `lat`/`lon`, `country`/`cc`/`city`/`isp`/`flag`, `conns`, `bytes_in`/`bytes_out`, `action`,
`blocked` (already on the blocklist) and `approx` (coordinates came from a country centroid, not the provider).
`located` is false when no coordinates are known. The UI colours points/labels by app. MCP: `traffic_map`.

`nodes[].kind` is one of `client`, `intercept`, `vpn`, `proxy`, `dest`, `internet`, `blocked`. Each `paths` entry is
the ordered hop chain a rule's traffic takes; each `live` entry carries the same chain for one open connection plus
its destination country. Edges are aggregated from enabled rule paths and flagged `active` when a live connection
uses them.

`GET /api/geo/{ip}` resolves one IP or hostname → `{"ip","country","cc","city","isp","flag","private"}` (synchronous,
cached). Private/loopback addresses resolve locally without a network call.

`POST /api/route/test` `{"host":"api.example.com","app":"firefox","port":443,"url":"https://..."}` evaluates the rules
for that tuple, then actually dials the URL through the resolved route and returns `{matched, rule, action, proxy,
vpn, hops, blocked, ok, status, exit_ip, country, cc, city, isp, flag, latency_ms, error}`. It is the live
counterpart to `/api/rules/test` (which only reports the match). A down VPN or unreachable proxy surfaces as `ok:false`
with the dial error.

`POST /api/route/probe` `{"hops":[{"kind":"vpn","name":"nl"},{"kind":"proxy","name":"exit-de"}],"host":"api.ipify.org"}`
dials a URL through an **ad-hoc, unsaved** chain (registers a transient chain proxy, probes, removes it) and returns
`{ok, exit_ip, country, cc, city, flag, isp, latency_ms, hops, vpn, error}`. Used by RouteBuilder's "Live test". At
most one VPN per chain (two+ needs full nested tunnels — create the route, bring them up, then use /api/route/test).

`GET /api/apps/installed` lists installed desktop applications parsed from freedesktop `.desktop` entries →
`{apps:[{name,comment,exec,binary,keyword,categories,icon,path}]}`. `keyword` is a suggested `cmd:` match stem
(e.g. Chrome → `chrome`) that matches the process command line — more reliable than the kernel comm name. The web UI's
"Choose an app" picker (Rules and RouteBuilder) uses it; `cyberboba apps` lists it on the CLI.

## Application firewall (ZoneAlarm-style)

`GET /api/firewall` → status + `config` (the `config.Firewall` object). `PUT /api/firewall` replaces the whole
firewall config. The firewall gates every new TCP connection by program and zone (Trusted LAN vs Internet):

* mode `off|ask|auto|block` governs UNKNOWN programs (ask = hold the connection and prompt; auto = allow & remember).
* `GET /api/firewall/pending` → held connections awaiting a decision; `POST /api/firewall/answer {id,allow,remember}`
  resolves one (remember persists a `programs` entry for that app+zone). A late answer after the prompt timed out
  still remembers, so the next connection from that program is not asked again. `POST /api/firewall/answer_all {allow}`.
  SSE `fw_resolved` includes `timeout: true` when the hold expired without a click.
* `POST /api/firewall/lock {on}` — Internet Lock panic switch (blocks all except `lock_pass` programs).
* `POST /api/firewall/stealth {on}` — silently DROP unsolicited inbound (needs root). `POST /api/firewall/mode {mode}`.
* `POST /api/firewall/block {host}` / `POST /api/firewall/unblock {host}` — add/remove a destination on the host
  blocklist (`config.firewall.blocked_hosts`). `host` is a hostname, `*.domain`, glob, IP or CIDR; it is denied for
  EVERY program and enforced even when program control is `off` (loopback is never blocked). `GET /api/firewall/blocked`
  lists them. This is the one-click "Block host" on the Live Map.
* SSE `/api/events` streams `fw_ask` (new prompt) and `fw_resolved`. CLI: `cyberboba firewall [mode|lock|stealth|pending|allow|deny|block|unblock|blocked]`.

## Processes (Task-Manager view)

`GET /api/procmon` → `{processes[], summary}`. Each process has `pid`, `ppid`, `name`, `cmd`, `user`/`uid`,
`state`, `cpu_pct` (over the interval since the previous call — poll ~2s for a live reading), `rss_kb`,
`threads`, `conns` (active tracked connections), `started` (unix), `kernel` and `system` (kernel thread, or a
service account with uid<1000 — the UI's "hide system processes" toggle filters these). `summary` has
`total`/`user`/`system`/`cpu_pct`/`rss_kb`/`own_pid`.

`POST /api/processes/{pid}/kill` sends a signal (`?signal=TERM|KILL|HUP|INT`, or JSON `{"signal":"KILL"}`;
default TERM). It refuses pid 1 and the cyberboba daemon itself. CLI: `cyberboba ps [--all]`, `cyberboba kill <pid> [KILL]`.
MCP: `process_monitor`, `kill_process`.

`GET /api/sysstat` → host resource usage for the Processes header: `cpu` (`pct`, `per_core[]`, `load1/5/15`,
`ncpu`), `mem` (`total_kb`/`used_kb`/`avail_kb`/`pct`, plus swap), `temps[]` (`chip`, `label`, `celsius` — every
hwmon sensor and uncovered thermal zone: CPU package/cores, chipset, etc.) and `fans[]`. CPU% is a delta between
calls, so poll ~2s. CLI: `cyberboba sysstat`. MCP: `system_stats`.
