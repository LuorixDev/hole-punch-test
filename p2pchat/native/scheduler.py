"""Bounded parallel discovery coordinator; success never cancels another method.

Signaling remains the caller's job. Retry/network changes always issue NEW IDs;
a remote paired peer must negotiate the same IDs before probing can succeed.
"""
import asyncio
import uuid


class Discovery:
    def __init__(self, adapter, max_parallel=8):
        if not 1 <= max_parallel <= 16:
            raise ValueError("RESOURCE_LIMIT")
        self.adapter = adapter
        self.limit = max_parallel
        self.starts = {}
        self.retry_counts = {}
        self.lock = asyncio.Lock()

    async def start_all(self, requests):
        if len(requests) > self.limit:
            raise ValueError("RESOURCE_LIMIT")
        async def start(request):
            try:
                result = await self.adapter.start(request)
                self.starts[result["attemptId"]] = dict(request)
                return result
            except Exception as error:
                return {"attemptId": request.get("attemptId"), "state": "failed", "failureCode": type(error).__name__}
        return await asyncio.gather(*(start(request) for request in requests))

    async def retry(self, old_id, announce):
        """announce(new_request, retry_envelope) exchanges signaling with paired peer."""
        async with self.lock:
            old = self.starts[old_id]
            state = (await self.adapter.stats({"attemptId": old_id}))["state"]
            if state not in {"failed", "timeout"}:
                raise ValueError("RETRY_REQUIRES_FAILURE")
            lineage = (old["connectionId"], old["mechanism"], old.get("profile", "direct"))
            count = self.retry_counts.get(lineage, 0)
            if count >= 3:
                raise ValueError("RETRY_LIMIT")
            self.retry_counts[lineage] = count + 1
            await asyncio.sleep(2 ** count)
            request = {**old, "attemptId": str(uuid.uuid4())}
            await self.adapter.close({"attemptId": old_id, "reason": "SUPERSEDED"})
            await announce(request, {"previousAttemptId": old_id, "reason": "BOUNDED_RETRY"})
            result = await self.adapter.start(request)
            self.starts.pop(old_id, None)
            self.starts[request["attemptId"]] = request
            return result

    async def network_changed(self, bind_host, announce):
        """Explicit OS/platform network-change callback, not an automatic OS watcher."""
        requests = list(self.starts.values())
        await self.adapter.network_changed()
        self.adapter.bind_host = bind_host
        self.starts.clear()
        for old in requests:
            request = {**old, "attemptId": str(uuid.uuid4())}
            await announce(request, {"previousAttemptId": old["attemptId"], "reason": "NETWORK_CHANGED"})
            await self.adapter.start(request)
            self.starts[request["attemptId"]] = request

    async def close(self):
        await self.adapter.shutdown()
        self.starts.clear()  # release per-attempt auth config on explicit disposal
        self.retry_counts.clear()
