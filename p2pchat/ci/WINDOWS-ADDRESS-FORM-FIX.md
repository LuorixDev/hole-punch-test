# Windows IOCP address-form repair (t3)

Scope: `p2pchat/native/*` and `p2pchat/tests/native/` only. No TURN/relay, no
server change, no IPv6 skip, no weakened IPv4/IPv6 positive assertion, no
host/firewall change. This note records the in-flight repair the t3 worker took
over, what the t3 worker added, and the exact evidence boundary.

## Root cause (CPython 3.12.10 source)

Windows uses `ProactorEventLoop`, so `loop.sock_sendto` / `loop.sock_connect`
reach `_overlapped`, which parses the destination by **tuple length**:

`Modules/overlapped.c` (v3.12.10), `parse_address()`:

```c
static int parse_address(PyObject *obj, SOCKADDR *Address, int Length)
{
    ...
    switch (PyTuple_GET_SIZE(obj)) {
    case 2: {
        if (!PyArg_ParseTuple(obj, "UH", &Host_obj, &Port)) { return -1; }
        ...
        Address->sa_family = AF_INET;
        if (WSAStringToAddressW(Host, AF_INET, NULL, Address, &Length) < 0) {
            SetFromWindowsErr(WSAGetLastError());   /* WSAEINVAL 10022 for "::1" */
            Length = -1;
        } else {
            ((SOCKADDR_IN*)Address)->sin_port = htons(Port);
        }
        ...
    case 4: {
        if (!PyArg_ParseTuple(obj, "UHkk;ConnectEx(): illegal address_as_bytes argument",
                              &Host_obj, &Port, &FlowInfo, &ScopeId)) { return -1; }
        ...
        Address->sa_family = AF_INET6;
        ...
    default:
        PyErr_SetString(PyExc_ValueError, "illegal address_as_bytes argument");
        return -1;
    }
}
```

The same file calls `parse_address()` from `Overlapped.WSASendTo`,
`Overlapped.ConnectEx` and `WSAConnect`. So a self-constructed **two**-element
IPv6 destination `('::1', port)` is parsed as `AF_INET`, `WSAStringToAddressW`
fails, and the error is `WSAEINVAL` = `WinError 10022`. Conversely the receive
side, `unparse_address()`, emits `Py_BuildValue("OiII", host, port, flowinfo,
scope_id)` for `AF_INET6`, i.e. a **four**-tuple; and `socket.getsockname()`
returns a four-tuple for an `AF_INET6` socket. Four elements therefore select
`AF_INET6` and work.

On POSIX, `loop.sock_sendto` goes through `socket.sendto` →
`getsockaddrarg()`, which accepts a two- or four-tuple for `AF_INET6`, so the
two-tuple form never failed there. This is a Windows-specific defect.

## Windows runner evidence (pre-fix, observed)

`/tmp/p2p-win-8a3de6d-failed.log` — windows-2022, CPython 3.12.10
(`pythonLocation: C:\hostedtoolcache\windows\Python\3.12.10\x64`):

- line 281 — the real-socket loopback diagnostic reports the exact OS error:
  `{"diag": "native-ipv6-loopback-error", "platform": "win32", "errorClass":
  "OSError", "errno": 22, "winerror": 10022}` (errno 22 = `EINVAL`, the mapped
  `WSAEINVAL` 10022). Line 694: `test_ipv6_stun_and_gateway_source_comparison`
  fails with the same `OSError: [WinError 10022]`.
- lines 265–267 and 278–280: every native IPv6 transport reaches
  `PROBE_TIMEOUT` (`udp-probe`, `quic`) or `TCP_TLS_OR_CONNECT_FAILED` (`tcp`);
  no IPv6 datagram/TCP connect ever leaves the host.
- **same run**, line 213: `test_real_udp_stun_and_abuse_rate[::1-23] PASSED`.
  That test builds its destination as
  `remote = transport.get_extra_info('sockname')` — the OS-returned four-tuple
  for `AF_INET6` — and then `await loop.sock_sendto(sock, request, remote)`
  plus a matching `sock_recvfrom` complete successfully. The four-tuple form is
  the working one; the two-tuple form is the fatal one.
- `/tmp/p2p-win-78a2050-failed.log` lines 299–319 show the same `::1` STUN case
  getting all the way past the successful send/receive and failing only later
  on the unrelated backend abuse-rate bound (`assert 25 <= 19`), which confirms
  the datagram exchange itself worked with the OS four-tuple.

Evidence boundary: these logs do not print the pre-fix call-site sockaddr, so
they establish (a) a two-element IPv6 destination is fatal on Windows with
`WinError 10022`, and (b) the four-element form works on the same runner/OS.
They do **not** by themselves prove that every filed IPv6 failure had this as
its sole cause; and no post-fix Windows run exists yet. **Windows status stays
pending the captain's runner; Linux results below are not Windows evidence.**

## Repair taken over (in-flight, reviewed, unchanged in this turn)

- `native/stun.py` — `socket_address(endpoint, family)`: validates and
  canonicalizes through the existing identity rule, then returns
  `(host, port, 0, 0)` for `AF_INET6` and `(host, port)` for `AF_INET`. This is
  the OS-call form only; the public identity stays the two-field tuple.
- `native/adapter.py` — `raw_udp()` (all `sock_sendto`, including QUIC flush and
  keepalive) and the simultaneous-open `sock_connect` go through
  `socket_address`; reception still normalizes with `canonical_endpoint`.
- `native/gateway.py` — `exchange()` sends through `socket_address`.
- `native/stun.py::binding()` — sends through `socket_address`.
- `stats()['remoteTuple']` remains `list(self.remote)` where `remote` is the
  canonical two-field identity; `localTuple` stays `[address, port]`.
- Receive-side comparison is one rule everywhere: UDP candidate lookup, TCP
  `accept`, native STUN reply source and gateway reply source all compare
  `canonical_endpoint(...)` results, so kernel 2-/4-tuples collapse to the same
  identity. Exact port and family, nonzero-scope rejection, IPv4 vs
  IPv4-mapped separation, unsigned-source rejection, per-candidate independent
  nonces and certificate pinning are untouched.

No production file needed a second edit; the in-flight repair already covers
every OS destination call site (verified by grep for `sock_sendto|sock_connect|
sock_accept|sock_recvfrom` under `p2pchat/native/`).

## Gap filled by t3

`udp_unreachable()` only recognized the Windows form. POSIX (Linux/macOS)
reports the same UDP ICMP port-unreachable as `ECONNREFUSED`, so an
unreachable candidate/STUN/gateway could still surface as a hard `OSError`
instead of the required bounded no-response. It now accepts
`ConnectionResetError`, `ConnectionRefusedError`, `winerror == 10054` and
`errno == 10054`; `EINVAL`/`EACCES` still propagate (asserted). The predicate is
used only on UDP paths — `connect_tcp` never calls it, so TCP refusal semantics
are unchanged. `receive_udp_retry()` keeps the caller's deadline, paces repeated
immediate ICMP failures at 10 ms (no busy loop), creates no lease, fabricates no
reply and never extends `PROBE_TIMEOUT`/`GATEWAY_TIMEOUT`.

Tests extended in `p2pchat/tests/native/test_endpoint_forms.py`: the POSIX
refusal form is now exercised across the gateway send/receive, probe
deadline/`PROBE_TIMEOUT` and STUN-timeout cases, and asserted as no-response
alongside the Windows form.

## Verification (Linux local, this worktree)

```text
.venv/bin/python -m pytest p2pchat/tests/native -q
74 passed in 15.33s   exit 0

.venv/bin/python -m pytest p2pchat/tests -q
178 passed, 8 warnings in 84.68s   exit 0
```

An earlier run of the full-suite command showed 8 failures, all in the untracked
in-flight file `p2pchat/tests/backend/test_preflight.py` owned by another task
(t4, `p2pchat/tools/server_preflight.py`); those tests never import
`p2pchat.native`, were not caused by this repair, and their owner has since made
the full suite pass. Both t3 verify commands now exit 0.

sha256 of the touched paths:

```text
ac8628849a471dd7686c0b95e42caff2b63c245592bd350a1440d847a0f8ba8c  p2pchat/native/adapter.py
b80276e6fbfcea038d901683c84e0d3012c64fe0f29073fb82ccb705e4a74a65  p2pchat/native/stun.py
0d69978519c4400024808dd9aeafe514ee518236c90fbfa617508f438ca9b176  p2pchat/native/gateway.py
e9d00ec13476840cb8b90a5a31369c3399a8916c9e3c279e102c6b268d07cb13  p2pchat/tests/native/test_windows_endpoints.py
85dd1b00505eca62adef88a630c3ee25ad83f2a14d3f88b967da92389bd4b7e9  p2pchat/tests/native/test_endpoint_forms.py
```

Real Windows confirmation must come from the captain's runner (full
`python -m pytest p2pchat/tests/native -q` plus the backend preflight suite).
If Windows still fails, keep the raw `test_actual_loopback_sockaddr_diagnostic`
JSON and the numeric `{errno, winerror}` from `stats()['socketError']` to
separate form errors from genuine transport/TLS errors.
