import pytest
import os
import pathlib
import sys

from perf_trampoline import is_trampoline_active
from perf_trampoline import register_handles
from perf_trampoline import trampoline_context


@pytest.fixture(autouse=True)
def clean_perf_file():
    perf_file = pathlib.Path("/tmp/perf-{os.getpid()}.map")
    if perf_file.exists():
        perf_file.unlink()


def test_trampoline_context():
    # GIVEN
    assert not is_trampoline_active()

    # WHEN
    with trampoline_context():
        # THEN
        assert is_trampoline_active()
    assert not is_trampoline_active()


def test_trampoline_works_when_calling_functions():
    # GIVEN
    def func():
        return 1

    # WHEN
    with trampoline_context():
        # THEN
        func()


def test_trampoline_is_registered():
    # GIVEN
    def func():
        return 1

    # WHEN
    with trampoline_context():
        assert func()

    # THEN
    perf_file = pathlib.Path(f"/tmp/perf-{os.getpid()}.map")
    assert f"py::{func.__qualname__}:{__file__}" in perf_file.read_text()

def test_trapoline_is_registered_in_forked_child():
    # GIVEN
    def func():
        return 1

    # WHEN
    register_handles()
    with trampoline_context():
        pid = os.fork()
        if pid == 0:
            # THEN
            func()
            assert is_trampoline_active()
            os._exit(0)
        else:
            os.waitpid(pid, 0)
    
    # THEN
    perf_file = pathlib.Path(f"/tmp/perf-{pid}.map")
    assert f"py::{func.__qualname__}:{__file__}" in perf_file.read_text()