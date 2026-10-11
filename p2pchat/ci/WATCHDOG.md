# CI test watchdog contract

This diagnostic runner does not import or modify product code, filter tests, access user data directories, or generate/read credentials. Tests retain their existing temporary fixtures and random room secrets. Logs inherit stdout/stderr and are written only by the workflow to its existing artifact output directory; watchdog logs contain PID, timing and exit status, never command arguments/environment or Python locals.

Workflow runs all `p2pchat/tests` from repository root using `python -u`, pytest `-vv -s`, `faulthandler_timeout=120`, and `--durations=20`. Last nodeid and uncaptured failure/stack output survive in python-tests.log. Built-in faulthandler prints thread stacks; it is not guaranteed to reconstruct every pending asyncio Task. The enclosing watchdog bounds the entire suite to600 seconds, deliberately exceeding the mandatory60-second outage test. Timeout returns124, startup/cleanup failure125, and normal test failure preserves its nonzero code. No skip/continue-on-error is added. A12-minute Actions step limit is a secondary emergency bound, not the normal termination path.

On Windows, ctypes creates a private Job object with KILL_ON_JOB_CLOSE. A Python bootstrap waits for a one-byte stdin gate **before spawning the test command**. Parent assigns the bootstrap to the Job before releasing that gate, avoiding the attach-after-spawn race; normal descendants inherit the Job and breakaway is not enabled. Assignment failure fails closed; no uncontained tests execute. Timeout uses TerminateJobObject; closing the last Job handle also cleans orphan descendants after normal completion or parent failure. This is not broad process-name/taskkill termination. Local Linux verification cannot prove Windows kernel behavior; the same watchdog unit tests run natively on the next Windows Actions job, before the full suite.

On POSIX, the bootstrap owns a fresh process session/group. Finalization SIGKILLs only that group, including residual descendants, then waits at most5 seconds for the direct child. Product code is trusted not to deliberately daemonize into a new session; this is CI cleanup, not a malicious-process sandbox.

Fast unit tests check success0, failure7, timeout124 plus preserved faulthandler dump, timeout descendant cleanup, normal-exit orphan cleanup, and closed bootstrap gate125. Their temporary delayed marker detects descendant leakage without reading any user process data. `unittest discover` itself must fail if Windows Job integration does not work; it is not skipped on Windows.

Run locally from repository root:

```sh
.venv/bin/python -m unittest discover -s p2pchat/ci -p 'test_*.py'
```

This change is diagnostic only. It does not establish the cause of run38121429541's Windows hang or imply Windows product tests now pass. Owner repairs require observed nodeid/stack evidence and a new source freeze.
