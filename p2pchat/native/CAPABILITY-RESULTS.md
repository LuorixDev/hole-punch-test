# Native capability results — 2026-10-11

This is implementation/controlled-test evidence, **not real residential NAT or remote-platform certification**. There is no relay, unknown-address scan, host firewall change, or real-router mapping in these tests.

## Actual matrix

| Method | Linux Python implementation / observed evidence | Windows desktop | Android |
|---|---|---|---|
| IPv4 UDP exact-tuple probe | Real same-bound-socket HMAC hello/ack, retries/backoff, authenticated ping/pong; two loopback endpoints pass | Portable socket source, not executed on Windows | Python sidecar is NOT Android implementation; unavailable |
| IPv6 stateful probe | IPv6-only sockets and bidirectional proof; `::1` test passes; no claim that loopback tests an ISP firewall | Source only, unverified | unavailable |
| IPv4 STUN Binding | RFC5389 transaction + XOR-MAPPED parsing, explicit server, same supplied socket; controlled responder passes | Source only, unverified | unavailable |
| Same-socket QUIC | aioquic low-level connection driven by the UDP socket that performed proof/probe; two endpoint IPv4/IPv6 random 64KiB integrity passes | Source / packaging integration separately owned; runtime unverified here | unavailable |
| TCP direct | Bound sockets + actual connect/accept + mutual TLS1.3 + attempt HMAC, IPv4/IPv6 integrity passes | Source only, unverified | unavailable |
| TCP simultaneous open | **Both sides bind/connect; neither listens.** Two separate processes in two child netns over veth, 80ms netem propagation, mutual TLS/HMAC, 65536 random bytes each direction pass. No RST suppression, no listen fallback. Zero-delay IPv4/IPv6 loopback can return `TCP_SIMOPEN_UNAVAILABLE` due to SYN/RST timing; this negative is retained. | OS/NAT-specific unverified; reports real connect failure | unavailable |
| UPnP IGD IPv4 | Real bounded SOAP Add/Delete/GetExternalIPAddress; explicit local gateway URL only; mock lifecycle/renew/failure tests | Real gateway validation unavailable (fail closed), no device test | unavailable |
| UPnP IPv6 pinhole | Real GetFirewallStatus/Add/Update/DeletePinhole SOAP; controlled `::1` service lifecycle passes | Local gateway validation unavailable; no device test | unavailable |
| PCP MAP / NAT-PMP UDP | Real encoding/UDP transactions, nonce or tuple matching, result errors, finite lease, renew/delete; controlled responder lifecycle passes | Local gateway validation unavailable; no device test | unavailable |

**All real devices/home NATs remain unverified**, including IPv6 firewall pinhole services, asymmetric/symmetric NAT and simultaneous-open behavior. NAT-PMP has no protocol nonce/authentication; explicit routed-gateway checking and external peer validation are required but do not create router cryptographic authentication. UPnP HTTP is local trusted gateway control, not Internet TLS. IPv6 link-local gateway scope negotiation is currently `LOCAL_GATEWAY_VALIDATION_UNAVAILABLE`; no unsafe scope guessing.

## Interface and trust

`python -m p2pchat.native.bridge --bind 127.0.0.1` implements v1 JSON-lines `capabilities/start/signal/send/stats/close`. `main()` is the packaging entry point. Default bind is loopback; the trusted platform main must choose an explicit local LAN address for non-loopback use. No renderer-selected file paths, executables, gateway URL or arbitrary bind parameter are consumed by start.

Python `NativeAdapter(bind_host=..., stun_server=(explicit_numeric_ip, port))` supports optional IPv4 STUN gathering. Desktop trusted main now offers a menu to import a ≤1024-byte JSON `{address,port}` file and explicitly confirm the endpoint; default off, session-only, forwarded via fixed `--stun-address`/`--stun-port` argv, never renderer RPC. Configure this only with an authorized server. IPv6 peer stateful probing is separate; STUN observes a mapped address, **not exact NAT type**. QUIC reuses the exact socket/port, not a newly opened aioquic client socket.

Every start binds connectionId, attemptId, local/remote peer ID, role (`offerer`/`answerer`), and auth. Both sides negotiate the SAME attemptId via authenticated room signaling. `profile` defaults to `direct`; UI uses direct/default/ipv4/ipv6. HMAC implements PROTOCOL hello and hello-ack exactly. Repeated identical UDP hello is idempotent for lost-ACK recovery, never establishes a new session; changed nonce in an existing attempt is rejected. Keepalive uses fresh challenges plus HMAC; replaying an old hello cannot maintain probe liveness.

Events:

- `candidate {connectionId,attemptId,nativeCandidate}` or `candidate {...,description:{type:offer|answer,sdp:PEM_CERTIFICATE}}`.
- `state {connectionId,attemptId,state,mechanism,profile,family,protocol,...}`.
- `data {connectionId,attemptId,lane,dataB64}` only after authenticated direct transport.
- `diagnostic {connectionId,attemptId,code}` never includes auth, payload or certificates.

Candidate certificate SHA256 is compared with the paired PEM from signaling. TCP requires mutual TLS and pins peer DER. QUIC client uses `CERT_REQUIRED` with the signaling certificate as a trust anchor. QUIC server explicitly requests client certificate proof-of-possession and checks peer DER SHA256 and validity before direct; room-key HMAC is repeated inside encrypted QUIC. No `CERT_NONE` workaround exists. This assumes authenticated signaling and the contract's shared-room-secret trust model, not independent identity against malicious room members. aioquic's private client-cert-request and send-buffer accounting APIs are used; regression tests must run when upgrading aioquic (tested 1.4.0).

UDP/QUIC now accepts up to 64 signaling-bound host/srflx/mapped candidates for the same remote socketId/certificate, with independent HMAC state **and an independently random 32-byte local challenge nonce** per exact source tuple, and round-robin probing capped at 20 packets/sec. Round 3 removes nonce reuse: a complete captured hello+ACK from candidate A cannot answer candidate B's challenge (tested in both frame orders). The MAC binds nonces rather than both sides' address strings, so NAT-translated peers need not agree on their locally observed tuples. One-direction-drop UDP/QUIC tests in both directions remain timeout, never direct. An unreachable first host does not block later srflx; selection occurs only after that exact tuple completes bilateral proof, then QUIC remains pinned with no automatic migration. TCP still requires a new attempt for a different tuple. Controlled UDP translation tests first keep host sinks unreachable for 250ms, then deliver mapped candidates; same fd/port and bidirectional 64KiB QUIC integrity pass. This is not real home NAT evidence. Gateway methods are candidate sources exposed through Python `gateway.py`, not message-bearing adapter paths. Bridge capabilities returns `unsupported/OPT_IN_GATEWAY_API_ONLY` for mapping controls rather than pretending renderer automatic mapping is available. Use a mapped candidate with the UDP/QUIC owner socket after independent validation.

UDP is `canMessage:false` (no plaintext UDP chat). TCP benchmark returns `BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION`; QUIC uses chat stream 0 and benchmark stream 4. This layer does not auto-run throughput tests or interpret file payloads: upper layers enforce the application's 32MiB/10s benchmark and file protocol. `goodput:null` avoids inventing throughput from bytes merely queued. tx/rx count validated application payload bytes; rtt comes from monotonic challenge timing (initial establishment latency includes handshake/setup).

## Budgets, lifecycle, integration limits

- Max 16 resident attempts, 64 received candidates per attempt, 4096 attempt IDs per sidecar session; duplicate attempt IDs rejected.
- Bounded 64KiB app frames / 128KiB RPC lines, send high-water 512KiB; QUIC queued retransmit bytes included. 40 probe packets/second/attempt, exponential probe intervals 0.1..1 sec, 30-sec maximum attempt timeout, 5-sec keepalive/20-sec dead threshold.
- No first-success cancellation. `Discovery.start_all` launches independent methods, catches per-method failures, and bounds concurrency. Explicit retry uses 1/2/4sec, new IDs and a caller signaling callback; no infinite retry.
- `network_changed` invalidates/cleans sockets. `Discovery.network_changed(new_bind, announce)` rebuilds with new IDs/candidates. **Platform must deliver network-change notification**; no automatic OS watcher is claimed.
- Explicit close/EOF/cancel releases tasks, sockets, TLS temp files and auth keys. TLS key files live in private transient directories with mode 0600, removed at close. No diagnostic persistence or central upload is implemented by transport (owned by logging integration); data events are local bridge only.
- Gateway operations default disabled. Non-mock Linux validates gateway against read-only OS routing table and binds a local address. Windows route validation and IPv6 scoped link-local control are unavailable, not silently accepted. No SSDP discovery/scan.
- Leases are capped at 7200 sec, eight mappings/client; renewal is explicit, requiring revalidation; close deletes tracked mappings. Caller must invoke renewal before expiration and close on shutdown. Crash can leave only finite lease state on router. External validator is required, times out, and false/error deletes the mapping. A mapping response alone is never a verified direct path.

## Reproduction and observed failures

```sh
.venv/bin/python -m compileall -q p2pchat/native
.venv/bin/python -m pytest p2pchat/tests/native -q
unshare -Urn .venv/bin/python p2pchat/tests/native/netns_simopen.py
```

The namespace test refuses an unmapped host user context. Its veth/tc changes occur only in namespaces owned by `unshare -Urn`, use no sudo and disappear on exit. Test skips explicitly if tools or user namespaces are unavailable; a skip is not positive evidence.

Observed isolated success: connection `309d2ebc-d959-4e8e-bc99-53bb98cb735f`, attempt `ea3eeb1b-7103-4c95-8d5e-fe5b33fe1330`, endpoints `10.231.0.1:33431` ↔ `10.231.0.2:45771`, both direct, each direction 65536-byte SHA256 verified. Exact tuples naturally change per run. 80ms propagation is a controlled network model, not home broadband.

Earlier failures retained as evidence: zero-delay simultaneous-open returned failed/TCP_SIMOPEN_UNAVAILABLE on both IPv4 and IPv6 loopback (2 failed, 10 passed before explicit negative test classification). First namespace harness attempted `/proc/1/ns/net` and was denied; replaced by user namespace uid-map + kernel capability ownership safety. Next harness had Python stdout StreamReader default 64KiB line limit after successful direct; fixed harness buffer to 128KiB before successful 64KiB payload checks. Neither harness failure was reported as transport success.
