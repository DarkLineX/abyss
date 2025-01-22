#pragma once
#include "svcer_cmn.h"
#include <linux/elf.h>

#if defined(__arm__)
	#define TARGET_ARM
#elif defined(__aarch64__)
	#define TARGET_AARCH64
#elif defined(__i386__)
	#define TARGET_I386
#elif defined(__x86_64__)
	#define TARGET_X86_64
#else
	#error "Unsupported architecture."
#endif

typedef unsigned char abi_ubyte;
typedef char abi_byte;
typedef unsigned short abi_ushort;
typedef short abi_short;
typedef unsigned int abi_uint;
typedef int abi_int;
typedef uintptr_t abi_ulong;
typedef intptr_t abi_long;
typedef uint64_t abi_ullong;
typedef int64_t abi_llong;

typedef abi_ubyte target_ubyte;
typedef abi_byte target_byte;
typedef abi_ushort target_ushort;
typedef abi_short target_short;
typedef abi_uint target_uint;
typedef abi_int target_int;
typedef abi_ulong target_ulong;
typedef abi_long target_long;
typedef abi_ullong target_ullong;
typedef abi_llong target_llong;

#define qemu_host_page_size (1<<12)
#define qemu_host_page_mask (~(qemu_host_page_size-1))
#define qemu_host_page_align(addr) (((addr)+qemu_host_page_size-1)&qemu_host_page_mask)

#define qemu_real_host_page_size qemu_host_page_size

#define TARGET_PAGE_SIZE (1<<12)
#define TARGET_PAGE_MASK (~(TARGET_PAGE_SIZE-1))
#define TARGET_PAGE_ALIGN(addr) (((addr)+TARGET_PAGE_SIZE-1)&TARGET_PAGE_MASK)

#define HOST_PAGE_SIZE (1<<12)
#define HOST_PAGE_MASK (~(HOST_PAGE_SIZE-1))
#define HOST_PAGE_ALIGN(addr) (((addr)+HOST_PAGE_SIZE-1)&HOST_PAGE_MASK)

#define REAL_HOST_PAGE_SIZE (1<<12)
#define REAL_HOST_PAGE_MASK (~(REAL_HOST_PAGE_SIZE-1))
#define REAL_HOST_PAGE_ALIGN(addr) (((addr)+REAL_HOST_PAGE_SIZE-1)&REAL_HOST_PAGE_MASK)

extern abi_ulong mmap_min_addr;
extern abi_ulong reserved_va;
extern bool have_guest_base;
extern abi_ulong guest_base;
extern abi_ulong guest_stack_size;

#define put_user_ual(val, addr) *((abi_ulong*)(addr)) = (val)
#define g2h(addr) addr

/* same as PROT_xxx */
#define PAGE_READ      0x0001
#define PAGE_WRITE     0x0002
#define PAGE_EXEC      0x0004
#define PAGE_BITS      (PAGE_READ | PAGE_WRITE | PAGE_EXEC)
#define PAGE_VALID     0x0008
/* original state of the write flag (used when tracking self-modifying
 code */
#define PAGE_WRITE_ORG 0x0010

#ifndef MAX
#define MAX(a,b) ((a)>=(b))?(a):(b)
#endif
#ifndef MIN
#define MIN(a,b) ((a)<=(b))?(a):(b)
#endif

#define get_user_ual(x, gaddr) x = *(abi_ulong*)(gaddr)

enum arm_cpu_mode {
  ARM_CPU_MODE_USR = 0x10,
  ARM_CPU_MODE_FIQ = 0x11,
  ARM_CPU_MODE_IRQ = 0x12,
  ARM_CPU_MODE_SVC = 0x13,
  ARM_CPU_MODE_MON = 0x16,
  ARM_CPU_MODE_ABT = 0x17,
  ARM_CPU_MODE_HYP = 0x1a,
  ARM_CPU_MODE_UND = 0x1b,
  ARM_CPU_MODE_SYS = 0x1f
};

#define CPSR_M (0x1fU)
#define CPSR_T (1U << 5)
#define CPSR_F (1U << 6)
#define CPSR_I (1U << 7)
#define CPSR_A (1U << 8)
#define CPSR_E (1U << 9)
#define CPSR_IT_2_7 (0xfc00U)
#define CPSR_GE (0xfU << 16)
#define CPSR_IL (1U << 20)
/* Note that the RESERVED bits include bit 21, which is PSTATE_SS in
 * an AArch64 SPSR but RES0 in AArch32 SPSR and CPSR. In QEMU we use
 * env->uncached_cpsr bit 21 to store PSTATE.SS when executing in AArch32,
 * where it is live state but not accessible to the AArch32 code.
 */
#define CPSR_RESERVED (0x7U << 21)
#define CPSR_J (1U << 24)
#define CPSR_IT_0_1 (3U << 25)
#define CPSR_Q (1U << 27)
#define CPSR_V (1U << 28)
#define CPSR_C (1U << 29)
#define CPSR_Z (1U << 30)
#define CPSR_N (1U << 31)
#define CPSR_NZCV (CPSR_N | CPSR_Z | CPSR_C | CPSR_V)
#define CPSR_AIF (CPSR_A | CPSR_I | CPSR_F)

#define CPSR_IT (CPSR_IT_0_1 | CPSR_IT_2_7)
#define CACHED_CPSR_BITS (CPSR_T | CPSR_AIF | CPSR_GE | CPSR_IT | CPSR_Q \
    | CPSR_NZCV)
/* Bits writable in user mode.  */
#define CPSR_USER (CPSR_NZCV | CPSR_Q | CPSR_GE)
/* Execution state bits.  MRS read as zero, MSR writes ignored.  */
#define CPSR_EXEC (CPSR_T | CPSR_IT | CPSR_J | CPSR_IL)
/* Mask of bits which may be set by exception return copying them from SPSR */
#define CPSR_ERET_MASK (~CPSR_RESERVED)
