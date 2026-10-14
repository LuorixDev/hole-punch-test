# P2P Lab

Two-peer IPv4/IPv6 connectivity experiments, Chinese terminal UI, strict P2P chat,
image/file transfers, ping, directional throughput and compressed durable logs.
The IPv4 exchange server never relays application data.

## v0.1.7: Parallel Connectivity Matrix

Upgrade both the client and server. Independent hole-punch experiments now run
in parallel while attempts that could interfere with the same address-family /
transport lane remain serialized.

- Run up to four independent IPv4/IPv6 and UDP/TCP experiment lanes concurrently
  to reduce matrix wall-clock time without cancelling remaining methods after a
  successful path is found.
- Keep gateway changes, port-pool scans, NAT64 and raw-packet research exclusive
  so those tests do not overlap other socket-sensitive experiments.
- Continue scheduling independent lanes while one method waits for its peer
  result, and log launches, concurrency and missing peer results.
- Associate reopened-path checks with their own attempt result instead of the
  mutable last-result position; return the actual hairpin probe result.
- Document that concurrent experiments share CPU and WAN capacity, so precision
  throughput comparisons should run after the matrix completes.

The full Linux regression suite passed (538 passed, 4 skipped) before release;
native Linux and Windows frozen-binary verification is run by GitHub Actions.
CI does not establish success across real-world ISP/NAT combinations.

## v0.1.6: Network Evidence and Transfer Reliability

Upgrade both the client and server. This release improves IPv4 NAT evidence,
P2P path recovery, throughput diagnostics and file-transfer measurements.

- Add conservative IPv4 NAT1-NAT4 classification from same-socket mapping
  observations and an independent RFC 5780 filtering socket. Unsupported test
  servers and ambiguous/loss-affected evidence are reported as inconclusive or
  explicitly marked as an estimate; IPv6 is not assigned an IPv4 NAT grade.
- Serialize cold-path recovery so concurrent chat actions reuse a verified path
  instead of starting overlapping punch/reconnect attempts.
- Bound and cancel benchmark work on timeout or disconnect, validate reverse
  speed-test replies, and report receiver-measured elapsed time with throughput.
- Show live and average file-transfer rates, elapsed time and receive time; improve
  queue cleanup and completion accounting on cancellation and errors.
- Harden public WAN speed-test discovery, response validation, retries, source
  revalidation, and coordination with active P2P transfers/benchmarks.
- Extend isolated performance tooling with direction-order controls, uTP tests,
  bounded native receive queues and read-only QUIC flow-control evidence.
- Correct `--forwarded` egress diagnostics for public-IP socat/reverse-proxy
  deployments while retaining the forwarding address as source evidence.

Performance limitation: the 2026-10-14 isolated 50 ms RTT tests still show a
large QUIC cold-sender throughput gap. The data does not establish that Python is
the cause, and this release does not change production congestion control or
claim gigabit performance. See `PERFORMANCE-REVALIDATION-2026-10-14.md` for
measurements and reproduction boundaries. Real cross-ISP success and Windows
real-network behavior remain outside CI guarantees.

## v0.1.5: Forwarded Deployment Fixes

Upgrade both the client and server. This release fixes misleading egress warnings
and reconnect loops observed in real socat-forwarded deployments.

The v0.1.4 candidate was withheld by the release gates: a Windows regression
fixture wrote an unescaped TOML path, and the frozen loopback test omitted its
explicit server permission for local TCP mapping observations. Both verification
issues are corrected and covered without relaxing production source validation
or skipping the shared-port TCP/STUN checks.

- Non-global signaling sources remain visible and logged, but no longer count as
  conflicting public egress addresses. Real public-address disagreements remain visible.
- Departed pairs and queued stale signals no longer disconnect waiting clients.
  Incomplete pair setup is cancelled without closing established P2P paths.
- Closing WebSockets no longer generate a second exception while sending errors.
- WAN discovery reads complete, size-bounded responses instead of parsing a
  partial network read. Source addresses are refreshed and revalidated before tests.
- Linux server-route diagnostics resolve IPv4 hostnames before invoking `ip route get`.
- `--forwarded` supports socat/reverse-proxy signaling and logs, while disabling
  invalid local TCP/STUN mapping observations and IPv4 callbacks to the forwarder.
  Public STUN, gateway experiments and IPv6 P2P/callbacks remain available.
- `--public-port` advertises a different shared external port for source-preserving
  DNAT. It does not restore source addresses lost by socat, and cannot describe
  the alternate topology required by complete RFC 5780 tests.

Example for a socat-forwarded backend:

```bash
./P2PLab-Server-linux-x64 --port 8443 --forwarded --allow-inbound-check
```

Clients enter the public forwarding endpoint, including its external port.
IPv6 callback checks require an IPv6 route on the Python server itself. HTTP IP
query results are never substituted for actual TCP/UDP mappings or IPv4 callback
targets. This mode does not claim that every mapping experiment remains measurable.

Linux regression coverage includes real socat forwarding on a different external
port, P2P chat, ping, bidirectional throughput and complete log export. Windows
CI also exercises reconnect, WAN diagnostics and inbound-check regressions.
Both platform builds must pass native source tests and frozen-program smoke tests
before their binaries are published. Real-network success is not inferred from CI.

## Previous Release: v0.1.3

The default server now uses only **8443/TCP + 8443/UDP**. TCP mapping probes use
the same HTTP/HTTPS listener as signaling and logs, but retain their actual
experiment socket. Separate legacy ports remain opt-in. Upgrade both programs.
Source and frozen-program regression tests cover same-port TCP mapping and
UDP STUN alongside chat, file transfers, ping, throughput and central logging.
The v0.1.1 candidate was not released: an older integration assertion incorrectly
required a failed loopback method, and the expanded frozen test exceeded the
verifier's first log page. Tests now verify all actual outcomes, including an
entirely successful matrix, and paginate every log entry without discarding logs.
The v0.1.2 candidate was also withheld. Windows ICE shutdown now aborts pending
UDP writes to avoid the CPython gh-156920 Proactor close hang. Frozen verification
exports compressed logs through the running server's authenticated HTTP API
before stopping it, instead of reopening its WAL after forced process teardown.

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
