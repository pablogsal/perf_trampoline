#pragma once

#include "Python.h"

extern int g_gdb_support;
extern int g_gdb_write_elf_objects;
extern int g_gdb_stubs_support;

int gdb_support_enabled(void);

int register_raw_debug_symbol(
    const char* function_name,
    const char* filename,
    int lineno,
    void* code_addr,
    size_t code_size,
    size_t stack_size);

