import atexit
import os
import signal
from contextlib import contextmanager

from ._perf_trampoline import _afterfork_child
from ._perf_trampoline import _finish_trampoline
from ._perf_trampoline import _init_trampoline
from ._perf_trampoline import _is_trampoline_active


@contextmanager
def trampoline_context():
    try:
        _init_trampoline(True)
        yield
    finally:
        _init_trampoline(False)


atexit.register(_finish_trampoline)


def sigprof_handler(signum, frame):
    if not _is_trampoline_active():
        _init_trampoline(activate=True)
    else:
        _finish_trampoline()


def _afterfork_handle(*args, **kwargs):
    if _is_trampoline_active():
        _afterfork_child()


def register_handles():
    signal.signal(signal.SIGPROF, sigprof_handler)
    os.register_at_fork(after_in_child=_afterfork_handle)
