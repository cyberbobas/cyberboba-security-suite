# Contributing to CyberBoba Security Suite

Thanks for your interest! This is an **agent-first** Linux network-security
daemon: every feature must be reachable the same three ways —
**HTTP API → CLI → MCP tool** — and only then surfaced in the web UI. Keep that
contract in mind for any new capability.

## Prerequisites

- Linux (iptables legacy/nft, `ip`). For full functionality: `wireguard-tools`,
  `openvpn`, `libnss3-tools`.
- **Go 1.26 or newer** to build (`go.mod` pins the language version).
- Node/npm only if you touch the Electron desktop shell (`desktop/`).

## Build & run

```sh
make build                 # → bin/cyberbobad, bin/cyberboba
make run-dev               # run the daemon without root/netfilter (UI + API + proxies)
sudo make install && sudo systemctl enable --now cyberboba
```

The web UI lives at http://127.0.0.1:7471. The daemon needs root for transparent
interception, netfilter and VPNs; without root `make run-dev` still serves the
UI, API, rule engine and the SOCKS5/HTTP inbound proxies.

## Checks before you open a PR

CI runs these on every push/PR — run them locally first:

```sh
gofmt -l internal/ cmd/    # must print nothing
go vet ./...               # must be clean
go build ./...
go test ./...
```

For UI changes: the web assets are embedded via `go:embed`, so you must
**rebuild and reinstall** the binary (and reload the browser / desktop app with
Ctrl+Shift+R) to see them live. Keep `web/app.js` vanilla — no build step, no
external dependencies.

## Adding a feature (the agent-first checklist)

1. **Core logic** in an `internal/<pkg>`, with unit tests.
2. **HTTP API** handler in `internal/api/` (`/api/...`).
3. **CLI** subcommand in `cmd/cyberboba/`.
4. **MCP tool** in `internal/mcp/mcp.go` (with a clear, useful description —
   agents read it).
5. **Web UI** page/control in `web/`.
6. Update `docs/API.md` / `docs/CONFIG.md` / `docs/AGENTS.md` and the README.

## Code style

- Match the surrounding code; keep comments at the existing density.
- Go: standard `gofmt`; no lint config beyond `go vet`.
- Don't introduce new third-party dependencies without a good reason.

## Security

This tool intercepts TLS, routes traffic and firewalls processes. Only ever
test against machines and traffic you own or are authorised to inspect. Never
commit secrets, private keys, tokens or real VPN/proxy credentials. The
intercept CA private key lives under `/etc/cyberboba/ca` and must never be
committed.

## Reporting bugs / ideas

Open an issue with: what you expected, what happened, your OS, and (for the
daemon) relevant lines from `journalctl -u cyberboba`.

## License

By contributing you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
