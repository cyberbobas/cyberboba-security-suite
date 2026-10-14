# Find go even under sudo (secure_path drops ~/.local/go/bin).
GO      ?= $(shell command -v go 2>/dev/null || ls /home/$${SUDO_USER:-$$USER}/.local/go/bin/go 2>/dev/null || echo go)
VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.1.0)
LDFLAGS  = -s -w -X cyberboba/internal/app.Version=$(VERSION) -X cyberboba/internal/mcp.Version=$(VERSION)
PREFIX  ?= /usr/local

.PHONY: all build test vet clean install uninstall run-dev desktop desktop-dist

all: build

build:
	mkdir -p bin
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/cyberbobad ./cmd/cyberbobad
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/cyberboba ./cmd/cyberboba

bin/cyberbobad bin/cyberboba:
	$(MAKE) build

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf bin dist

# Install binaries, default config and the systemd unit. Run `make build` as
# your user first, then `sudo make install` (does not rebuild as root).
install: bin/cyberbobad bin/cyberboba
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)/etc/cyberboba/vpn $(DESTDIR)$(PREFIX)/lib/cyberboba
	install -m 0755 bin/cyberbobad $(DESTDIR)$(PREFIX)/bin/cyberbobad
	install -m 0755 bin/cyberboba  $(DESTDIR)$(PREFIX)/bin/cyberboba
	test -f $(DESTDIR)/etc/cyberboba/config.yaml || install -m 0600 packaging/config.example.yaml $(DESTDIR)/etc/cyberboba/config.yaml
	install -m 0644 packaging/cyberboba.service $(DESTDIR)/etc/systemd/system/cyberboba.service
	@echo "now: systemctl daemon-reload && systemctl enable --now cyberboba"

uninstall:
	-systemctl disable --now cyberboba
	rm -f $(PREFIX)/bin/cyberbobad $(PREFIX)/bin/cyberboba /etc/systemd/system/cyberboba.service

# Run the daemon from the source tree without netfilter (no root needed) for UI/API development.
run-dev: build
	./bin/cyberbobad --config ./packaging/dev-config.yaml --run-dir /tmp/cyberboba-dev --no-netfilter

# Desktop shell (Electron). Needs node/npm.
desktop:
	cd desktop && npm install && npm start

desktop-dist:
	cd desktop && npm install && npm run dist
