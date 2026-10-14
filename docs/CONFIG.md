# Configuration reference (`/etc/cyberboba/config.yaml`)

The file is YAML. Every change made through the web UI, the CLI or the API is
validated, written back to this file and applied live.

## `proxifier`

| key | default | meaning |
|---|---|---|
| `enabled` | `true` | install iptables rules when the daemon starts |
| `listen_tcp` | `127.0.0.1:7470` | transparent TCP listener that REDIRECT targets |
| `listen_dns` | `127.0.0.1:7453` | DNS forwarder (UDP+TCP), outbound port 53 is redirected here |
| `listen_socks` | `127.0.0.1:7472` | inbound SOCKS5 listener for apps with proxy settings; `""` disables |
| `listen_http` | `127.0.0.1:7473` | inbound HTTP proxy listener (CONNECT and plain HTTP); `""` disables |
| `dns_upstream` | `1.1.1.1:53` | resolver used by the forwarder |
| `dns_via_rules` | `true` | route DNS queries with the rule engine (pseudo-app `dns`, target = query name) |
| `block_quic` | `true` | reject outbound UDP/443 and UDP/80 so browsers use TCP (needed for Caido) |
| `ipv6` | `true` | also intercept IPv6 |
| `sniff_hostnames` | `true` | peek TLS SNI / HTTP `Host` to match hostname rules |
| `mark_base` | `0x7400` | fwmark used for daemon sockets; VPN marks are `mark_base+1..` |
| `table_base` | `7400` | first routing table number for selective VPNs |

## `api`

| key | default | meaning |
|---|---|---|
| `unix_socket` | `/run/cyberboba/cyberboba.sock` | control socket used by the `cyberboba` CLI |
| `listen` | `127.0.0.1:7471` | web UI / HTTP API; `""` disables |
| `token` | `""` | if set, the TCP API requires `Authorization: Bearer <token>` |

## `intercept` (built-in intercepting proxy)

| key | default | meaning |
|---|---|---|
| `enabled` | `true` | start the engine |
| `listen` | `127.0.0.1:8080` | explicit HTTP proxy listener (CONNECT + absolute-URI); apps can also be routed in with rule `action: intercept` |
| `ca_dir` | `/etc/cyberboba/ca` | `ca.crt` / `ca.key`; generated on first start |
| `hold_requests` / `hold_responses` | `false` | default state of the hold switches |
| `record_only_scope` | `false` | record only flows whose host is in scope |
| `scope.include` / `scope.exclude` | `[]` | host patterns (`*.example.com`); empty include = everything |
| `passthrough` | `[]` | hosts tunneled without TLS termination (certificate pinning) |
| `upstream` | `{action: direct}` | how forwarded traffic leaves: `direct`, `proxy` + `proxy: name`, `vpn` + `vpn: name` |
| `verify_upstream_tls` | `false` | verify server certificates when forwarding |
| `max_flows` | `10000` | flows kept in memory |
| `max_body` | `1048576` | bytes kept per request/response body (rest is marked truncated) |
| `session_dir` | `/var/lib/cyberboba/sessions` | where saved capture sessions are written |
| `rewrites` | `[]` | ordered match & replace rules (see below) |

### `intercept.rewrites[]`

```yaml
rewrites:
  - name: inject auth
    target: request      # request | response
    part: header         # header | body | url
    header: Authorization
    match: ""            # empty match + part=header => set the header to `replace`
    replace: "Bearer X"
    remove: false        # true deletes the header or matched text
    hosts: ["*.api.example.com"]   # optional scope
  - name: strip CSP
    target: response
    part: header
    header: Content-Security-Policy
    remove: true
  - name: patch body
    target: response
    part: body
    match: "flag=false"
    replace: "flag=true"
```
Rewrites apply to transparently-intercepted and explicit-proxy flows (not to repeater `send_request`). A changed flow
is marked `rewritten`.

## `proxies[]`

```yaml
- name: home            # referenced by rules and chains
  type: socks5          # socks5 | socks4 | http | chain | failover | balance
  addr: 1.2.3.4:1080
  username: ""          # optional (SOCKS5 user/pass or HTTP basic)
  password: ""
  remote_dns: true      # send hostnames to the proxy instead of resolving locally
  via_vpn: office       # reach the proxy through this VPN (selective profiles)
- name: both
  type: chain
  hops: [home, caido]   # traversed in order; the last hop reaches the target
- name: redundant
  type: failover        # try members in order until one connects
  hops: [home, backup]
- name: spread
  type: balance         # random member per connection
  hops: [a, b, c]
```

When `caido.enabled` is true a proxy named `caido.proxy_name` (default
`caido`) is synthesized automatically and can be used in rules and chains.

## `vpns[]`

```yaml
- name: office
  type: wireguard       # wireguard | openvpn
  config: /etc/cyberboba/vpn/office.conf   # WireGuard configs must end in .conf
  mode: selective       # selective | full
  autostart: false
  interface: ""         # optional interface name override (WireGuard: file basename)
  auth_file: ""         # OpenVPN --auth-user-pass file
  username: ""          # OpenVPN credentials (written to a private auth file)
  password: ""
  kill_switch: false    # block non-VPN traffic while the tunnel is down after being up
  reconnect: false      # restart the backend with backoff when it dies
  extra_args: []        # extra openvpn arguments
```

* `full` – the tunnel behaves like a normal VPN client and takes the default route.
* `selective` – the tunnel never touches the main routing table. WireGuard is
  started with `Table = off`; OpenVPN with `--route-noexec`. cyberboba creates
  routing table `table_base+1+index` with a default route through the tunnel and a
  policy rule `fwmark mark_base+1+index`. Only connections whose rule says
  `action: vpn` (and DNS/proxies with `via_vpn`) are marked and therefore use it.

## `caido`

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | enable the integration (synthesizes the `caido` proxy) |
| `managed` | `true` | cyberboba starts and supervises `caido-cli` |
| `binary` | auto | path to `caido-cli`; `cyberboba caido install` downloads the latest release to `/usr/local/lib/cyberboba/caido-cli` |
| `listen` | `127.0.0.1:8080` | Caido listener (UI and proxy share the port) |
| `data_path` | `/etc/cyberboba/caido` | Caido data directory |
| `ca_cert` | `""` | Caido's exported `ca.crt`; `cyberboba caido ca-install` trusts it system-wide and in browser NSS databases |
| `extra_args` | `[]` | extra `caido-cli` flags |
| `proxy_name` | `caido` | name of the synthesized proxy |

## `rules[]`

Rules are evaluated top to bottom; the first match wins. A rule with no
`apps`/`users`/`targets`/`ports`/`protocols` matches everything (use it as the
last "Default" rule). Omitted fields are wildcards.

```yaml
- name: Browsers through Caido
  enabled: true
  apps: [firefox, chrome, "*chromium*", /usr/bin/curl, "tag:pentest", "cmd:--remote-debugging"]
  users: [user, "1000"]
  targets: ["*.example.com", 10.0.0.0/8, 203.0.113.7, lan]
  ports: ["80", "443", "8000-8999"]
  protocols: [tcp]
  action: proxy          # direct | proxy | vpn | intercept | block
  proxy: caido           # for action: proxy
  vpn: office            # for action: vpn
```

`apps` entries: process name (`comm`/executable basename), absolute path,
glob, `tag:NAME` (set with `cyberboba run -tag NAME -- cmd`), `cmd:SUBSTRING`
(match on the command line). `targets` entries: hostname, `*.domain`
(domain and all subdomains), glob, IP, CIDR, or `lan` (loopback, RFC1918,
link-local, CGNAT, ULA).

Hostnames are learned from the DNS forwarder (IP → name cache), from TLS SNI
and HTTP `Host` sniffing, and from SOCKS5 domain requests. If a connection
has no known hostname, hostname targets simply do not match it.

## Misc

| key | default | meaning |
|---|---|---|
| `log_level` | `info` | debug / info / warn / error |
| `max_conn_log` | `2000` | finished connections kept in memory for the UI |

## Geolocation (`geo`)

Powers the country labels in the Traffic map. Lookups hit an external HTTP
provider and are cached in memory; disable it to keep destination IPs local.

```yaml
geo:
  enabled: true
  provider: "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,query"
  cache_ttl_hours: 24
```

| key | default | meaning |
|---|---|---|
| `enabled` | `true` | perform geolocation lookups (off → Traffic map shows no countries) |
| `provider` | ip-api.com | URL template; `{ip}` is substituted. Accepts ip-api.com / ipwho.is style JSON |
| `cache_ttl_hours` | `24` | how long a successful lookup is reused |

Private, loopback and link-local addresses are labelled locally and never sent
to the provider.

## Firewall blocklist (`firewall.blocked_hosts`)

```yaml
firewall:
  blocked_hosts:
    - "*.doubleclick.net"
    - ads.example.com
    - 10.20.30.40
    - 203.0.113.0/24
```

Destination patterns (hostname, `*.domain`, glob, IP or CIDR) that are denied for **every** program. Unlike
`firewall.programs` (which depend on `firewall.mode`), the blocklist is enforced whenever the daemon is running,
even with the firewall otherwise disabled — loopback is never blocked, so the control UI/API stays reachable.
Populated by the one-click **Block host** button on the **Live Map** tab (`POST /api/firewall/block`).

## Rotation (proxy & VPN)

A **proxy rotation** is a proxy of `type: rotate` — a set of member proxies where one is
active at a time, switching every `rotate_every_sec` seconds (`rotate_mode: random | sequential`).
Point a rule at the rotate group like any proxy.

```yaml
proxies:
  - { name: us, type: socks5, addr: 1.1.1.1:1080 }
  - { name: de, type: socks5, addr: 2.2.2.2:1080 }
  - name: rotator
    type: rotate
    hops: [us, de]
    rotate_every_sec: 300
    rotate_mode: random
```

A **VPN rotation** cycles the active tunnel among a set of VPN profiles:

```yaml
vpn_rotations:
  - { name: geo-hop, enabled: true, vpns: [us, de, nl], every_sec: 300, mode: random }
```

Point a rule `action: vpn, vpn: geo-hop` at it; the active member switches every interval
(each switch re-handshakes, so keep the interval reasonable). Live state: `GET /api/proxies/rotation`,
`GET /api/vpn/rotations`.
