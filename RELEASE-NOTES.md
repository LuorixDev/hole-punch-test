# P2P Lab

Two-peer IPv4/IPv6 connectivity experiments, Chinese terminal UI, strict P2P chat,
image/file transfers, ping, directional throughput and compressed durable logs.
The IPv4 exchange server never relays application data.

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
`P2PLab-Server-linux-x64 --host 0.0.0.0 --allow-inbound-check`. Defaults: TCP 8443,
UDP 3478 and TCP 3479. No TLS/Nginx or room password is required by default.
The server needs its own IPv6 route for IPv6 HTTP callback experiments.

Before real-network tests, turn off VPN/proxy/TUN on both peers. HTTP egress,
signaling observations and same-socket STUN mappings are different evidence.
Bundled LibreSpeed startup measurements can consume substantial WAN traffic;
disable `[wan].enabled` on metered networks. Optional native methods and raw
packet experiments remain platform/privilege dependent; unsupported methods are
logged honestly. CI passing does not establish cross-ISP or home-router success.

Source is MIT licensed; bundled components retain their original licenses.
Read `README.md`, `EXPERIMENT-COVERAGE.md` and `THIRD-PARTY-NOTICES.md` in the tag's
source archive for deployment, coverage, limitations and reproducible builds.
