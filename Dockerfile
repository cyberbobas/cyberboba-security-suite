# Build CyberBoba Security Suite as a container image.
#   docker build -t cyberboba .
# Run (networking features need host network + NET_ADMIN; it manipulates the
# host's iptables, so this is invasive — best for the UI/API/SOCKS-proxy use):
#   docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
#     -v cyberboba-etc:/etc/cyberboba -v cyberboba-lib:/var/lib/cyberboba \
#     --name cyberboba cyberboba
# UI/API: http://127.0.0.1:7471
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN VER="$(cat VERSION 2>/dev/null || echo dev)" && CGO_ENABLED=0 go build \
      -ldflags "-s -w -X cyberboba/internal/app.Version=$VER -X cyberboba/internal/mcp.Version=$VER" \
      -o /out/cyberbobad ./cmd/cyberbobad \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/cyberboba ./cmd/cyberboba

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables iproute2 ca-certificates wireguard-tools openvpn libnss3-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cyberbobad /usr/local/bin/cyberbobad
COPY --from=build /out/cyberboba  /usr/local/bin/cyberboba
RUN mkdir -p /etc/cyberboba /var/lib/cyberboba
COPY packaging/config.example.yaml /etc/cyberboba/config.yaml
EXPOSE 7471 7470 7472 7473 8080 7453/udp
VOLUME ["/etc/cyberboba", "/var/lib/cyberboba"]
ENTRYPOINT ["/usr/local/bin/cyberbobad", "--config", "/etc/cyberboba/config.yaml"]
