# P2P Lab

Two-peer IPv4/IPv6 connectivity experiments, Chinese terminal UI, strict P2P chat,
image/file transfers, ping, directional throughput and compressed durable logs.
The IPv4 exchange server never relays application data.

## v0.1.1: Shared Server Port

The default server now uses only **8443/TCP + 8443/UDP**. TCP mapping probes use
the same HTTP/HTTPS listener as signaling and logs, but retain their actual
experiment socket. Separate legacy ports remain opt-in. Upgrade both programs.
Source and frozen-program regression tests cover same-port TCP mapping and
UDP STUN alongside chat, file transfers, ping, throughput and central logging.

## Downloads

- `P2PLab-Client-windows-x64.exe`: single-file Windows client; run in a terminal.
- `P2PLab-Server-windows-x64.exe`: single-file Windows server.
- `P2PLab-Client-linux-x64`: single-file Linux client.
- `P2PLab-Server-linux-x64`: single-file Linux server.
- `SHA256SUMS.txt`: checksums for all release assets.
- `THIRD-PARTY-LICENSES-*.zip`: original component licenses and version inventory.
- `build-record-*.json`: build provenance and frozen smoke-test results.

No separate Python installation is needed. Linux requires x86_64 and glibc 2.35+
(Ubuntu 22.04+ or an equivalent distribution), not Alpine/musl. On Linux, run
`chmod +x P2PLab-*linux-x64` once. One-file programs extract their embedded native
libraries into a temporary directory at startup; the host must permit this.
The binaries are not code-signed; Windows SmartScreen may show a warning.

Start the client, enter the server address and room number. Start a server with
`P2PLab-Server-linux-x64 --host 0.0.0.0 --allow-inbound-check`. Defaults: the same
port number on TCP and UDP, **8443/TCP + 8443/UDP**. `--port 9000` moves signaling,
logs, HTTP TCP mapping observation and UDP STUN together. No TLS/Nginx or room
password is required by default. Connect directly to the Python server: TCP
mapping observation cannot use a reverse proxy. TLS mode shares HTTPS/WSS and
still verifies certificates. UDP must also be allowed for UDP mapping tests.
The server needs its own IPv6 route for IPv6 HTTP callback experiments.

Upgrade both programs for shared-port operation. With a v0.1.0 client, use the
explicit legacy server flags `--stun-port 3478 --tcp-port 3479` and allow those
ports. New clients also support legacy servers. Complete RFC 5780 classification
is optional and still requires two server IPv4 addresses and two UDP ports;
default shared-port operation does not claim that classification.

Before real-network tests, turn off VPN/proxy/TUN on both peers. HTTP egress,
signaling observations and same-socket STUN mappings are different evidence.
Bundled LibreSpeed startup measurements can consume substantial WAN traffic;
disable `[wan].enabled` on metered networks. Optional native methods and raw
packet experiments remain platform/privilege dependent; unsupported methods are
logged honestly. CI passing does not establish cross-ISP or home-router success.

Source is MIT licensed; bundled components retain their original licenses.
Read `README.md`, `EXPERIMENT-COVERAGE.md` and `THIRD-PARTY-NOTICES.md` in the tag's
source archive for deployment, coverage, limitations and reproducible builds.
