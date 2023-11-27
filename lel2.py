import perf_trampoline.api as s
import time

def foo():
    pass

with s.trampoline_context():
    foo()