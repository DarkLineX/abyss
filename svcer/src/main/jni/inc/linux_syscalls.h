// This header will be kept up to date so that we can compile system-call
// policies even when system headers are old.
// System call numbers are accessible through __NR_syscall_name.

#ifndef __LINUX_SYSCALLS_H__
#define __LINUX_SYSCALLS_H__

#if defined(__arm__)
#include "linux_syscalls_arm.h"
#endif

#if defined(__aarch64__)
#include "linux_syscalls_arm64.h"
#endif

#if defined(__x86_64__)
#include "linux_syscalls_x86_64.h"
#endif

#if defined(__i386__)
#include "linux_syscalls_x86_32.h"
#endif

#endif  // __LINUX_SYSCALLS_H__

