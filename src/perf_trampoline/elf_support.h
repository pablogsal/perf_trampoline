#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* In-memory ELF object generation -- largely borrowed from LuaJIT's
 * implementation. There is much magic here... I've tried to rationalize it a
 * bit and bring it more in line with Facebook's coding standards, but there's
 * only so much that can be done. */

/* ELF definitions. */
typedef struct ELFHeader
{
    uint8_t emagic[4];
    uint8_t eclass;
    uint8_t eendian;
    uint8_t eversion;
    uint8_t eosabi;
    uint8_t eabiversion;
    uint8_t epad[7];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uintptr_t entry;
    uintptr_t phofs;
    uintptr_t shofs;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstridx;
} ELFHeader;

typedef struct ELFSectionHeader
{
    uint32_t name;
    uint32_t type;
    uintptr_t flags;
    uintptr_t addr;
    uintptr_t ofs;
    uintptr_t size;
    uint32_t link;
    uint32_t info;
    uintptr_t align;
    uintptr_t entsize;
} ELFSectionHeader;

#define ELFSECT_IDX_ABS 0xfff1

enum {
    ELFSECT_TYPE_PROGBITS = 1,
    ELFSECT_TYPE_SYMTAB = 2,
    ELFSECT_TYPE_STRTAB = 3,
    ELFSECT_TYPE_NOBITS = 8
};

#define ELFSECT_FLAGS_WRITE 1
#define ELFSECT_FLAGS_ALLOC 2
#define ELFSECT_FLAGS_EXEC 4

typedef struct ELFSymbol
{
    uint32_t name;
    uint8_t info;
    uint8_t other;
    uint16_t sectidx;
    uintptr_t value;
    uint64_t size;
} ELFSymbol;

enum {
    ELFSYM_TYPE_FUNC = 2,
    ELFSYM_TYPE_FILE = 4,
    ELFSYM_BIND_LOCAL = 0 << 4,
    ELFSYM_BIND_GLOBAL = 1 << 4,
};

/* DWARF definitions. */
#define DWRF_CIE_VERSION 1

enum {
    DWRF_CFA_nop = 0x0,
    DWRF_CFA_offset_extended = 0x5,
    DWRF_CFA_def_cfa = 0xc,
    DWRF_CFA_def_cfa_offset = 0xe,
    DWRF_CFA_offset_extended_sf = 0x11,
    DWRF_CFA_advance_loc = 0x40,
    DWRF_CFA_offset = 0x80
};

enum { DWRF_EH_PE_udata4 = 3, DWRF_EH_PE_textrel = 0x20 };

enum { DWRF_TAG_compile_unit = 0x11 };

enum { DWRF_children_no = 0, DWRF_children_yes = 1 };

enum { DWRF_AT_name = 0x03, DWRF_AT_stmt_list = 0x10, DWRF_AT_low_pc = 0x11, DWRF_AT_high_pc = 0x12 };

enum { DWRF_FORM_addr = 0x01, DWRF_FORM_data4 = 0x06, DWRF_FORM_string = 0x08 };

enum { DWRF_LNS_extended_op = 0, DWRF_LNS_copy = 1, DWRF_LNS_advance_pc = 2, DWRF_LNS_advance_line = 3 };

enum { DWRF_LNE_end_sequence = 1, DWRF_LNE_set_address = 2 };

enum {
#ifdef __x86_64__
    /* Yes, the order is strange, but correct. */
    DWRF_REG_AX,
    DWRF_REG_DX,
    DWRF_REG_CX,
    DWRF_REG_BX,
    DWRF_REG_SI,
    DWRF_REG_DI,
    DWRF_REG_BP,
    DWRF_REG_SP,
    DWRF_REG_8,
    DWRF_REG_9,
    DWRF_REG_10,
    DWRF_REG_11,
    DWRF_REG_12,
    DWRF_REG_13,
    DWRF_REG_14,
    DWRF_REG_15,
    DWRF_REG_RA,
#elif defined(__aarch64__) && defined(__AARCH64EL__) && !defined(__ILP32__)
    DWRF_REG_SP = 31,
    DWRF_REG_RA = 30,
#else
#    error "Unsupported target architecture"
#endif
};

/* Minimal list of sections for the in-memory ELF object. */
enum {
    ELF_SECT_NULL,
    ELF_SECT_text,
    ELF_SECT_eh_frame,
    ELF_SECT_shstrtab,
    ELF_SECT_strtab,
    ELF_SECT_symtab,
    ELF_SECT_debug_info,
    ELF_SECT_debug_abbrev,
    ELF_SECT_debug_line,
    ELF_SECT__MAX
};

enum { ELF_SYM_UNDEF, ELF_SYM_FILE, ELF_SYM_FUNC, ELF_SYM__MAX };

/* In-memory ELF object. */
typedef struct ELFObject
{
    ELFHeader hdr; /* ELF header. */
    ELFSectionHeader sect[ELF_SECT__MAX]; /* ELF sections. */
    ELFSymbol sym[ELF_SYM__MAX]; /* ELF symbol table. */
    uint8_t space[4096]; /* Space for various section data. */
} ELFObject;

/* Template for in-memory ELF header. */
static const ELFHeader elfhdr_template = {
        .emagic = {0x7f, 'E', 'L', 'F'},
        .eclass = 2,
        .eendian = 1,
        .eversion = 1,
        .eosabi = 0, /* Nope, it's not 3. */
        .eabiversion = 0,
        .epad = {0, 0, 0, 0, 0, 0, 0},
        .type = 1,
#ifdef __x86_64__
        .machine = 62,
#elif defined(__aarch64__) && defined(__AARCH64EL__) && !defined(__ILP32__)
        .machine = 183,
#else
#    error "Unsupported target architecture"
#endif
        .version = 1,
        .entry = 0,
        .phofs = 0,
        .shofs = offsetof(ELFObject, sect),
        .flags = 0,
        .ehsize = sizeof(ELFHeader),
        .phentsize = 0,
        .phnum = 0,
        .shentsize = sizeof(ELFSectionHeader),
        .shnum = ELF_SECT__MAX,
        .shstridx = ELF_SECT_shstrtab};


