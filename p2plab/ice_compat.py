"""Narrow compatibility guard for aioice 0.10.2's queued retry race."""

from aioice import stun


class GuardedTransaction(stun.Transaction):
    def _Transaction__retry(self):
        # Cancellation/response may finish the future after the timer is queued,
        # before run() gets its finally turn to cancel that timer.
        if not self._Transaction__future.done():
            super()._Transaction__retry()


def install_retry_guard():
    if not issubclass(stun.Transaction, GuardedTransaction):
        stun.Transaction = GuardedTransaction
