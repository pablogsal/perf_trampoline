from setuptools import Extension
from setuptools import setup

perf_extension = Extension(
    "perf_trampoline._perf_trampoline",
    sources=[
        "src/perf_trampoline/_perf_trampoline.c",
        "src/perf_trampoline/gdb_support.c",],
    define_macros=[("Py_BUILD_CORE", "1")],
    extra_objects=["src/perf_trampoline/asm_trampoline.S"],
    include_dirs=["src/perf_trampoline"],
    language="c",
)

# Setup configuration
setup(
    name="perf_trampoline",
    version="1.0",
    python_requires=">=3.8.0",
    author="Pablo Galindo Salgado",
    package_dir={"": "src"},
    packages=["perf_trampoline"],
    ext_modules=[perf_extension],
    include_package_data=True,
)
