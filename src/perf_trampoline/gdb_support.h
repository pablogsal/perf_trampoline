#pragma once

#include "Python.h"

static const size_t INITIAL_SIZE = 104;

// Begin GDB hook */
typedef enum { JIT_NOACTION = 0, JIT_REGISTER_FN, JIT_UNREGISTER_FN } JITActions;

typedef struct _jit_code_entry
{
    struct _jit_code_entry* next_entry;
    struct _jit_code_entry* prev_entry;
    const char* symfile_addr;
    uint64_t symfile_size;
} JITCodeEntry;

typedef struct
{
    uint32_t version;
    // This should be JITActions, but need to be specific about the size.
    uint32_t action_flag;
    JITCodeEntry* relevant_entry;
    JITCodeEntry* first_entry;
} JITDescriptor;

// API for gdb support

extern int g_gdb_support;
extern int g_gdb_write_elf_objects;
extern int g_gdb_stubs_support;

int
gdb_support_enabled(void);

int
register_raw_debug_symbol(
        const char* function_name,
        const char* filename,
        int lineno,
        const void* code_addr,
        size_t code_size,
        size_t stack_size);
