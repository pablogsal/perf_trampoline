import perf_trampoline.api as s
import time

def foo(n):
    if n > 0:
        bar(n-1)
    time.sleep(100)

def bar(n):
    if n > 0:
        baz(n-1)
    time.sleep(100)

def baz(n):
    if n > 0:
        foo(n-1)
    time.sleep(100)

with s.trampoline_context():
    foo(20)