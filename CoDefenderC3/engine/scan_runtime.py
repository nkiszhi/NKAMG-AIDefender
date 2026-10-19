"""Bound inference concurrency and retain capacity until real work has stopped."""
import asyncio
import faulthandler
import logging
import os
import signal
import threading

log = logging.getLogger('codefender.runtime')


class ScanBusy(RuntimeError):
    pass


class ScanTimeout(RuntimeError):
    pass


def exit_stalled_process():
    log.critical('Inference exceeded hard timeout; terminating model process for supervisor recovery')
    faulthandler.dump_traceback(all_threads=True)
    # Supervisor starts a process group for this service. Kill feature-extractor
    # children as well, but never kill an unrelated parent process group.
    if os.name == 'posix' and os.getpgrp() == os.getpid():
        os.killpg(os.getpgrp(), signal.SIGKILL)
    os._exit(70)


class ScanRuntime:
    def __init__(self, concurrency=1, timeout=240, hard_timeout=300, hard_exit=None):
        self.concurrency = max(1, int(concurrency))
        self.timeout = max(0.01, float(timeout))
        self.hard_timeout = max(self.timeout + 0.05, float(hard_timeout))
        self.hard_exit = hard_exit or exit_stalled_process
        self.active = 0
        self._jobs = set()

    async def run(self, operation, *args, **kwargs):
        # All admission occurs on the HTTP event loop, without an await between
        # checking and reserving. No unbounded semaphore waiters are created.
        if self.active >= self.concurrency:
            raise ScanBusy('model service is busy; retry later')
        self.active += 1

        def work():
            timer = threading.Timer(self.hard_timeout, self.hard_exit)
            timer.daemon = True
            timer.start()
            try:
                return operation(*args, **kwargs)
            finally:
                timer.cancel()

        job = asyncio.create_task(asyncio.to_thread(work))
        self._jobs.add(job)

        def finished(done):
            self._jobs.discard(done)
            self.active -= 1
            if not done.cancelled():
                error = done.exception()  # Retrieve errors even after HTTP timeout/disconnect.
                if error:
                    log.error('Inference worker failed: %s', error)

        job.add_done_callback(finished)
        try:
            return await asyncio.wait_for(asyncio.shield(job), timeout=self.timeout)
        except asyncio.TimeoutError as error:
            raise ScanTimeout(f'scan timeout after {self.timeout:g}s') from error
