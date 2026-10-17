# P2P Lab

Two-peer IPv4/IPv6 connectivity experiments, Chinese terminal UI, strict P2P chat,
image/file transfers, ping, directional throughput and compressed durable logs.
The IPv4 exchange server never relays application data.

## v0.1.12: Slow-Link Benchmarks and Windows Interface Recovery

The v0.1.11 candidate was withheld by the release gates. A Windows runtime-health
test could collect a report before its injected loop stall; it now arms the
sampler before blocking. A parallel Linux frozen run also exposed opposite
dual-stack/single-family scheduling order between peers. Overlapping attempts
now retain shared-plan order while independent transport lanes remain parallel;
paired regressions reproduce the old deadlock with normal and eager tasks.

Upgrade both clients and the server. Slow links now sample each benchmark
direction for approximately ten seconds or until the selected byte cap, then
drain acknowledged traffic and report actual transferred bytes and elapsed time.
The selected MiB value is a traffic ceiling, not a mandatory transfer size.

- Adapt the application send window to delivery rate. Send timely progress
  acknowledgements, including on small windows, to avoid slow-link deadlocks.
- Negotiate a dedicated QUIC stream per benchmark. Reset canceled streams and
  prioritize control traffic so queued benchmark bytes do not continue blocking
  chat, cancellation or the next direction. Legacy peers retain their supported
  protocol; upgrade both peers to obtain the complete fix.
- Retain a bounded history of canceled benchmark IDs for the connection lifetime
  so late data arriving after the old 130-second cutoff cannot close a healthy
  chat channel. Log timeout phases and confirmed byte counts explicitly.
- Use OS interface indices for Windows IPv6 PCP, SSDP and LAN multicast instead
  of resolving localized adapter aliases. Close gateway sockets on failures and
  drain canceled TCP connection tasks before restoring socket options.
- Defer automatic matrix retries during local/remote benchmarks, WAN tests and
  file transfers. Refresh RTT once after a completed bidirectional speed test;
  standby paths do not regain periodic network probes.
- Renew inbound HTTP callback quotas every 60 seconds within a signaling session.
  Distinguish server policy rejection from an actual inbound firewall test.
- Keep NAT grade in its own log field. Record application version and platform
  at startup, and local CPU, event-loop, UI and active-transport health every
  30 seconds without adding network probes.

Linux isolated two-process tests reproduced the old timeout and residual queue
at 1 Mbps / approximately 50 ms RTT. The fixed direction tests completed in
approximately 10.4 seconds at 0.851 Mbps, with post-test RTT near 52 ms and chat
ACK near 108 ms. The latest source regression run passed 606 tests with four
skips. A separate real server/two-client headless TUI run delivered all 231
messages and uploaded all current-session logs. See
`BENCH-RECOVERY-2026-10-17.md` and `LOG-AUDIT-2026-10-17-CENTRAL.md`.

These are controlled measurements, not cross-ISP guarantees. QUIC cold-start
throughput asymmetry remains, and the pre-benchmark second-scale latency seen
in older field logs has not been uniquely explained. The new runtime records
help distinguish scheduling/UI load from transport queues. A server reporting
`OBSERVER_SOURCE_UNAVAILABLE` still needs working IPv6 addressing/routing in its
actual runtime environment; this release cannot repair that deployment remotely.
Public WAN samples against overseas test nodes are not ISP bandwidth limits.

Both platforms must pass Actions source regressions, single-file chat/ping/speed/
file/log checks and packaged native-backend tests before their client/server
executables are published together.

## v0.1.10: Network Selection and Sustained Chat Reliability

Upgrade both the client and server. This release addresses the real-network log
findings and a reproduced TUI slowdown after the activity sidebar fills up.

The v0.1.8 candidate was withheld by the Windows release checks: deferred
per-entry automatic scrolling could override the user's reading position.
This release scrolls once per rendered batch immediately and adds a regression
that deliberately delays old scroll callbacks, without rerendering retained logs.
The v0.1.9 candidate fixed scrolling but was also withheld: its hidden-history
test asserted before Windows completed the asynchronous redraw. The test now
waits for the rendered serial and width with a fixed deadline, and both platforms
run this check before compiling native libraries.

- Prefer interfaces carrying the default route, including Windows interface
  metrics, while retaining alternative candidates within the configured budget.
  Refresh route evidence and invalidate STUN health checks after network changes.
- Try multiple DNS addresses and source-bound STUN health checks before choosing
  an ICE observer. Defaults include MiWiFi, Cloudflare and Google; service health
  is never substituted for a mapping measured on the actual punch socket.
- Log actual local/peer endpoints, mapping failures and socket errors, and make
  the distinction between interface bind addresses and mapped endpoints explicit
  in the Chinese TUI.
- Acknowledge file progress by elapsed time as well as byte count, so slow links
  do not hit the old 256 KiB confirmation gap. Fix sparse-arrival speed displays
  and include named timeout stages and transport evidence in failure logs.
- Adapt MTU probe waits to authenticated RTT and back off after timeouts. Require
  three consecutive primary-path liveness failures before rebuilding; received
  authenticated traffic also proves the path is alive.
- Report unavailable server source addresses/routes distinctly from a client
  inbound firewall result, and mark data-path success only after verification.
- Render sidebar log rollover incrementally instead of repeatedly redrawing all
  1,000 retained entries. Keep complete durable logs and preserve wrapped text,
  cached rendering, scroll position and history across hidden tabs and resizing.
- Bundle native libnice/libutp backends in Windows single-file builds, compile
  them from pinned sources in Actions and verify the packaged native transports.

Local Linux reproduction with two real clients and approximately 50 ms RTT
reduced chat-ACK P95 under synthetic log pressure from 313-323 ms to 127-149 ms.
A separate QUIC research run confirmed all 457 bidirectional messages without
retries and uploaded every generated client log record. These are isolated
Linux/headless-TUI results, not Windows or cross-ISP performance guarantees.
See `CHAT-LATENCY-REPRO-2026-10-17.md` and `LOG-AUDIT-2026-10-16-33.md`.

Both platforms must pass source tests and frozen-binary checks before Actions
publishes their client/server executables together. The local Linux
suite and isolated-network supplements run with required native backends. Windows CI
also covers the route/STUN selection and slow-transfer ACK regressions.
Real-router compatibility,
WAN throughput and real-world connectivity rates remain experimental.

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
