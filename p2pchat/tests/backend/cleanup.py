"""Test-only resource cleanup: one deadline, preserve body and cleanup errors."""
import asyncio

async def cleanup_peers(peers,tasks,runner,original=None,timeout=10):
    deadline=asyncio.get_running_loop().time()+timeout
    errors=[]
    async def settle(operations,phase,required):
        if not operations:return
        done,pending=await asyncio.wait(set(operations),timeout=max(0,deadline-asyncio.get_running_loop().time()))
        for operation in done:
            if operation.cancelled():
                if operation in required:errors.append(RuntimeError('TEST_CLEANUP_CANCELLED:'+phase))
            elif operation.exception() is not None:errors.append(operation.exception())
        if pending:
            print('TEST_CLEANUP_TIMEOUT phase='+phase,flush=True)
            errors.append(TimeoutError('TEST_CLEANUP_TIMEOUT:'+phase))
            for operation in pending:
                operation.cancel()
                operation.add_done_callback(lambda t:None if t.cancelled() else t.exception())
    peer_closers={asyncio.create_task(p.close()) for p in peers}
    await settle(peer_closers,'peers',peer_closers)
    for task in tasks:task.cancel()
    runner_closer=asyncio.create_task(runner.cleanup())
    await settle(list(tasks)+[runner_closer],'runs_and_server',{runner_closer})
    if errors:
        if original is not None:errors.insert(0,original)
        raise BaseExceptionGroup('body/cleanup failures',errors)
