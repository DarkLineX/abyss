#include "svcer_cmn.h"
#include "svcer_hooker.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include "svcer_syscall.h"
#include "seccomp_macro.h"
#include "svcer_finder.h"
#include "svcer_dumper.h"

bool SvcerHooker::sInited = false;

static int g_default_secomp = 0;
static struct sigaction g_default_act = {0};
static SvcerHookerItem** g_callbacks = nullptr;
static void handleSyscall(siginfo_t* info, ucontext_t *uc);
// ------------------------------------------------------------------------------------------------------------------------------------------------------
static void doCallOriginSysCall(siginfo_t* info, ucontext_t *uc) {
#if 0

#if defined(__arm__)
    long ret = ::syscall(info->si_syscall,
                        uc->uc_mcontext.arm_r0,
                        uc->uc_mcontext.arm_r1,
                        uc->uc_mcontext.arm_r2,
                        uc->uc_mcontext.arm_r3,
                        uc->uc_mcontext.arm_r4,
                        uc->uc_mcontext.arm_r5,
                        uc->uc_mcontext.arm_r6
                        );
    uc->uc_mcontext.arm_r0 = ((ret == -1) ? errno : ret);
#elif defined(__aarch64__)
    long ret = ::syscall(info->si_syscall,
                        uc->uc_mcontext.regs[0],
                        uc->uc_mcontext.regs[1],
                        uc->uc_mcontext.regs[2],
                        uc->uc_mcontext.regs[3],
                        uc->uc_mcontext.regs[4],
                        uc->uc_mcontext.regs[5],
                        uc->uc_mcontext.regs[6]
                        );
    uc->uc_mcontext.regs[0] = ((ret == -1) ? errno : ret);
#endif

#else
    intptr_t rc = SvcerSyscall::Call(SECCOMP_SYSCALL(uc),
//    SECCOMP_RESULT(uc) = ::syscall(SECCOMP_SYSCALL(uc),
                                   SECCOMP_PARM1(uc),
                                   SECCOMP_PARM2(uc),
                                   SECCOMP_PARM3(uc),
                                   SECCOMP_PARM4(uc),
                                   SECCOMP_PARM5(uc),
                                   SECCOMP_PARM6(uc)
    );
    // Update the CPU register that stores the return code of the system call
    // that we just handled, and restore "errno" to the value that it had
    // before entering the signal handler.
    SvcerSyscall::PutValueInUcontext(rc, uc);
#endif
}

#if 0
bool GetIsInSigHandler(const ucontext_t* ctx) {
    // Note: on Android, sigismember does not take a pointer to const.
    return sigismember(const_cast<sigset_t*>(&ctx->uc_sigmask), SIGBUS);
}

void SetIsInSigHandler() {
    sigset_t mask;
    if (sigemptyset(&mask) || sigaddset(&mask, SIGBUS) ||
        sigprocmask(SIG_BLOCK, &mask, nullptr)
        ) {
        LOGSVCW("Failed to block SIGBUS: %d, %s", errno, strerror(errno))
    }
}
#endif

static void handleSignalAction(int signo, siginfo_t* info, void* context) {
    const int old_errno = errno;

    if (!info || !context || signo != SIGSYS || info->si_code != SYS_SECCOMP) {
        LOGSVCW("signal: signo=%d, code=%d, errno=%d, call_addr=%p, arch=0x%x, syscall=0x%x,%s",
              info->si_signo, info->si_code, info->si_errno, info->si_call_addr, info->si_arch,
              info->si_syscall, SvcerDumper::index2name(info->si_syscall)
              )
        return;
    }

    ucontext_t *uc = reinterpret_cast<ucontext_t *>(context);

//    LOGSVCD("signal: signo=%d, code=%d, errno=%d, call_addr=%p, arch=0x%x, syscall=%d,%s",
//          info->si_signo, info->si_code, info->si_errno, info->si_call_addr, info->si_arch,
//          info->si_syscall, SvcerDumper::index2name(info->si_syscall)
//          )

    handleSyscall(info, uc);
//    LOGSVCD("signal <<<: signo=%d, %d", info->si_signo, errno)
    errno = old_errno;
}

static bool checkKernelVersion() {
    struct utsname un;
    uname(&un);

    char* str;
    int kernel_major = strtol(un.release, &str, 10);
    int kernel_minor = strtol(str + 1, nullptr, 10);
    if (KERNEL_VERSION(kernel_major, kernel_minor, 0) < KERNEL_VERSION(5, 9, 0)) {
        LOGSVCE("kernel %s not supported", un.release)
        __ASSERT(0)
        return false;
    }

    sigaction(SIGSYS, NULL, &g_default_act);
    g_default_secomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return true;
}

static void doInitSyscallLibFilterByAddr(struct sock_filter* filter, unsigned short& i, const uintptr_t& start, const uintptr_t& end) {
    // Load syscall lib into accumulator
#if defined(__arm__)
    filter[i++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer));
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start, 0, 2);
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, end, 1, 0);
    filter[i++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#else // __aarch64__
    filter[i++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, instruction_pointer) + 4));
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(start >> 32), 0, 4);
    filter[i++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, instruction_pointer)));
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)start, 0, 2);
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)end, 1, 0);
    filter[i++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
}

static void doInitSyscallLibFilter(int mode, SvcerFinder* finder, struct sock_filter* filter, unsigned short& i) {
    doInitSyscallLibFilterByAddr(filter, i, finder->getSelfAddrStart(), finder->getSelfAddrEnd());

    if (0 != (mode & ESvcerHookerMode_IgnoreVdso) && finder->getVdsoAddrStart() < finder->getVdsoAddrEnd()) {
        doInitSyscallLibFilterByAddr(filter, i, finder->getVdsoAddrStart(), finder->getVdsoAddrEnd());
    }
    if (0 != (mode & ESvcerHookerMode_IgnoreLibc) && finder->getLibcAddrStart() < finder->getLibcAddrEnd()) {
        doInitSyscallLibFilterByAddr(filter, i, finder->getLibcAddrStart(), finder->getLibcAddrEnd());
    }
    if (0 != (mode & ESvcerHookerMode_IgnoreLinker) && finder->getLinkerAddrStart() < finder->getLinkerAddrEnd()) {
        doInitSyscallLibFilterByAddr(filter, i, finder->getLinkerAddrStart(), finder->getLinkerAddrEnd());
    }
    filter[i++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
}

static void doInitSyscallNumberFilter(struct sock_filter* filter, unsigned short& i) {
    // Load syscall number into accumulator
    filter[i++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));
    // config target syscall
#if defined(__arm__)
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 21, 1);
#endif
    // add more syscall here ...
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 20, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 19, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmodat, 18, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchownat, 17, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat, 16, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat2, 15, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstatat, 14, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statfs, 13, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 12, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mknodat, 11, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_truncate, 10, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_linkat, 9, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 8, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 7, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_symlinkat, 6, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_utimensat, 5, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getcwd, 4, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 3, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 2, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0);

//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 2, 0);
//    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0);
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 3, 0);
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 2, 0);
    filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 1, 0);

    filter[i++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

int SvcerHooker::getDefaultSecomp() { return g_default_secomp; }

void SvcerHooker::setSigaction(const struct sigaction* act) {
    memcpy(&g_default_act, act, sizeof(g_default_act));
}

void SvcerHooker::getSigaction(struct sigaction* act) {
    memcpy(act, &g_default_act, sizeof(g_default_act));
}

int SvcerHooker::init(int mode, const char* selfLibName) {
    __ASSERT(!sInited)
    if (sInited) return 0;
    if (!checkKernelVersion()) return -1;

    SvcerFinder* finder = new SvcerFinder(selfLibName);
    __ASSERT(finder)
    if (!finder) return -4;

    int ret = finder->search();
    if (0 != ret) {
        LOGSVCE("finder: %d, %d, %s", ret, errno, strerror(errno))
        delete finder;
        __ASSERT(0)
        return ret;
    }

    // config BPF rules
    struct sock_filter* filter = (struct sock_filter*) calloc(0xFF, sizeof(struct sock_filter));
    if (!filter) {
        LOGSVCE("filter null")
        delete finder;
        __ASSERT(0)
        return -10;
    }

    unsigned short filterCount = 0;
    doInitSyscallNumberFilter(filter, filterCount);
    doInitSyscallLibFilter(mode, finder, filter, filterCount);
    delete finder;
    LOGSVCD("filter count: %d", filterCount)

    struct sigaction act = { 0 };
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    act.sa_sigaction = handleSignalAction;
    struct sigaction old_sa = {};

    ret = sigaction(SIGSYS, &act, &old_sa);
    if (0 != ret) {
        LOGSVCE("sigaction: %d, %d, %s", ret, errno, strerror(errno))
        ::free(filter);
        __ASSERT(0)
        return -11;
    }

    // Unmask SIGSYS
    sigset_t mask;
    if (sigemptyset(&mask) || sigaddset(&mask, SIGSYS) ||
        sigprocmask(SIG_UNBLOCK, &mask, nullptr)
        ) {
        LOGSVCE("sigprocmask: %d, %d, %s", ret, errno, strerror(errno))
        ::free(filter);
        __ASSERT(0)
        return -12;
    }

    struct sock_fprog prog = {
        .len = filterCount,
        .filter = filter,
    };

    // set to self process
    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (0 != ret) {
        LOGSVCE("PR_SET_NO_NEW_PRIVS: %d, %d, %s", ret, errno, strerror(errno))
        ::free(filter);
        __ASSERT(0)
        return -13;
    }

    // set seccomp to kernel
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    if (0 != ret) {
        LOGSVCE("PR_SET_SECCOMP: %d, %d, %s", ret, errno, strerror(errno))
        ::free(filter);
        __ASSERT(0)
        return -14;
    }

    ::free(filter);
    sInited = true;
    return 0;
}

void SvcerHooker::registerCallback(TSVCER_SYSCALL_Type type, SvcerHookerCallback cb) {
    if (!g_callbacks) {
        g_callbacks = new SvcerHookerItem * [SVCER_SYSCALL_Max]();
    }
    if (!g_callbacks[type]) {
        g_callbacks[type] = new SvcerHookerItem(cb);
    } else {
        g_callbacks[type]->addNext(new SvcerHookerItem(cb));
    }
}

void SvcerHooker::unregisterCallback(TSVCER_SYSCALL_Type type, SvcerHookerCallback cb) {
    if (nullptr == g_callbacks) return;

    SvcerHookerItem* item = g_callbacks[type];
    if (nullptr == item) return;

    if (item->callback() == cb) {
        g_callbacks[type] = item->next();
        delete item;
    } else {
        SvcerHookerItem* nxt;
        while (nullptr != (nxt = item->next())) {
            if (nxt->callback() == cb) {
                item = nxt->next();
                delete nxt;
                break;
            }
            item = nxt;
        }
    }
}

SvcerHookerItem* SvcerHooker::getHeader(int type) {
    if (nullptr == g_callbacks) return nullptr;

    switch (type) {
#if defined(__arm__)
    case __NR_open:         return g_callbacks[SVCER_SYSCALL_open];
#endif
    case __NR_openat:       return g_callbacks[SVCER_SYSCALL_openat];
    case __NR_faccessat:    return g_callbacks[SVCER_SYSCALL_faccessat];
    case __NR_fchmodat:     return g_callbacks[SVCER_SYSCALL_fchmodat];
    case __NR_fchownat:     return g_callbacks[SVCER_SYSCALL_fchownat];
    case __NR_renameat:     return g_callbacks[SVCER_SYSCALL_renameat];
    case __NR_renameat2:    return g_callbacks[SVCER_SYSCALL_renameat2];
    case __NR_fstatat:      return g_callbacks[SVCER_SYSCALL_fstatat];
    case __NR_statfs:       return g_callbacks[SVCER_SYSCALL_statfs];
    case __NR_mkdirat:      return g_callbacks[SVCER_SYSCALL_mkdirat];
    case __NR_mknodat:      return g_callbacks[SVCER_SYSCALL_mknodat];
    case __NR_truncate:     return g_callbacks[SVCER_SYSCALL_truncate];
    case __NR_linkat:       return g_callbacks[SVCER_SYSCALL_linkat];
    case __NR_readlinkat:   return g_callbacks[SVCER_SYSCALL_readlinkat];
    case __NR_unlinkat:     return g_callbacks[SVCER_SYSCALL_unlinkat];
    case __NR_symlinkat:    return g_callbacks[SVCER_SYSCALL_symlinkat];
    case __NR_utimensat:    return g_callbacks[SVCER_SYSCALL_utimensat];
    case __NR_getcwd:       return g_callbacks[SVCER_SYSCALL_getcwd];
    case __NR_chdir:        return g_callbacks[SVCER_SYSCALL_chdir];
    case __NR_execve:       return g_callbacks[SVCER_SYSCALL_execve];
    case __NR_execveat:     return g_callbacks[SVCER_SYSCALL_execveat];
    case __NR_fcntl:        return g_callbacks[SVCER_SYSCALL_fcntl];
    case __NR_prctl:        return g_callbacks[SVCER_SYSCALL_prctl];
    case __NR_rt_sigaction: return g_callbacks[SVCER_SYSCALL_sigaction];
    default: return nullptr;
    }
}

void handleSyscall(siginfo_t* info, ucontext_t *uc) {
    SvcerHookerItem* item = SvcerHooker::getHeader(info->si_syscall);
    if (item) {
        SvcerHookerArgument arg(info, uc, item);
        item->callback()(info->si_syscall, &arg);
    } else {
        doCallOriginSysCall(info, uc);
    }
}

SvcerHookerArgument::SvcerHookerArgument(void* info, void* uc, SvcerHookerItem* item)
: mInfo(info), mContext(uc), mItem(item)
{}

void SvcerHookerArgument::setArgument1(const intptr_t& p1) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM1(uc) = p1;
}

void SvcerHookerArgument::setArgument2(const intptr_t& p2) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM2(uc) = p2;
}

void SvcerHookerArgument::setArgument3(const intptr_t& p3) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM3(uc) = p3;
}

void SvcerHookerArgument::setArgument4(const intptr_t& p4) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM4(uc) = p4;
}

void SvcerHookerArgument::setArgument5(const intptr_t& p5) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM5(uc) = p5;
}

void SvcerHookerArgument::setArgument6(const intptr_t& p6) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_PARM6(uc) = p6;
}

void SvcerHookerArgument::setReturn(const intptr_t& p) {
    ucontext_t* uc = (ucontext_t*)mContext;
    SECCOMP_RESULT(uc) = p;
}

intptr_t SvcerHookerArgument::getArgument1() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM1(uc);
}

intptr_t SvcerHookerArgument::getArgument2() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM2(uc);
}

intptr_t SvcerHookerArgument::getArgument3() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM3(uc);
}

intptr_t SvcerHookerArgument::getArgument4() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM4(uc);
}

intptr_t SvcerHookerArgument::getArgument5() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM5(uc);
}

intptr_t SvcerHookerArgument::getArgument6() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_PARM6(uc);
}

intptr_t SvcerHookerArgument::getReturn() {
    ucontext_t* uc = (ucontext_t*)mContext;
    return (intptr_t)SECCOMP_RESULT(uc);
}

void SvcerHookerArgument::doSyscall() {
    siginfo_t* info = (siginfo_t*)mInfo;
    if (moveToNext()) {
        mItem->callback()(info->si_syscall, this);
    } else {
        doCallOriginSysCall(info, (ucontext_t*)mContext);
    }
}
