#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/types.h>
#include "linux_syscalls.h"
#include "svcer_dumper.h"
#include "svcer_cmn.h"

// ------------------------------------------------------------------------------------------------------------------------
#ifdef __ENABLE_LOG_SVC__
const char* SvcerDumper::index2name(int sn) {
    switch (sn) {
#if defined(__arm__)
    case __NR_open: return "open";
#endif
    case __NR_openat: return "openat";
    case __NR_faccessat: return "faccessat";
    case __NR_fchmod: return "fchmod";
    case __NR_fchmodat: return "fchmodat";
    case __NR_fchownat: return "fchownat";
    case __NR_renameat: return "renameat";
    case __NR_renameat2: return "renameat2";
    case __NR_fstatat: return "fstatat";
    case __NR_statfs: return "statfs";
    case __NR_mkdirat: return "mkdirat";
    case __NR_mknodat: return "mknodat";
    case __NR_truncate: return "truncate";
    case __NR_linkat: return "linkat";
    case __NR_readlinkat: return "readlinkat";
    case __NR_unlinkat: return "unlinkat";
    case __NR_symlinkat: return "symlinkat";
    case __NR_utimensat: return "utimensat";
    case __NR_getcwd: return "getcwd";
    case __NR_chdir: return "chdir";
    case __NR_execve: return "execve";
    case __NR_execveat: return "execveat";
    case __NR_prctl: return "prctl";
    case __NR_rt_sigaction: return "sigaction";
//    case __NR_dup: return "dup";
//    case __NR_dup2: return "dup2";
//    case __NR_dup3: return "dup3";
    case __NR_fcntl: return "fcntl";
    default:
        return "unknown";
    }
}
#else
const char* SvcerDumper::index2name(int sn) {
    return "";
}
#endif

static int g_cache_secomp = -1;
static int g_cache_no_new_privs = 0;

static void handleSvcerHookerCallback(int sn, SvcerHookerArgument* arg/*Not NULL*/) {
    switch (sn) {
#if defined(__arm__)
    case __NR_open:// int openat(const char *pathname, int flags, ...);
#endif
    case __NR_fchmod:// int fchmodat(const char* pathname, mode_t mode, int flags);
    case __NR_statfs:// int statfs(const char* path, struct statfs* result);
    case __NR_truncate:// typedef int truncate(const char *filename, off_t len);
    case __NR_chdir:// int chdir(const char *path);
    {
        const char* pathname = (const char*)arg->getArgument1();
        LOGSVCI("dumper, %s: %s", SvcerDumper::index2name(sn), __PRINTSTR(pathname))
    }   break;

    case __NR_openat:// int openat(int dirFd, const char *pathname, int flags, ...);
    case __NR_faccessat:// int faccessat(int dirfd, const char *pathname, int mode, int flags);
    case __NR_fchmodat:// int fchmodat(int dirfd, const char* pathname, mode_t mode, int flags);
    case __NR_fchownat:// int fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag);
    case __NR_fstatat:// int fstatat(int dirfd, const char* filename, struct stat* buf, int flags);
    case __NR_mkdirat:// int mkdirat(int dirfd, const char *pathname, mode_t mode);
    case __NR_mknodat:// int mknodat(int fd, const char *path, mode_t mode, dev_t dev);
    case __NR_unlinkat:// int unlinkat(int dirfd, const char *pathname, int flags);
    case __NR_utimensat:// int utimensat(int fd, const char *path, const struct timesepc times[2], int flag);
    {
        const char* pathname = (const char*)arg->getArgument2();
        LOGSVCI("dumper, %s: %s", SvcerDumper::index2name(sn), __PRINTSTR(pathname))
    }   break;

    case __NR_renameat:// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
    case __NR_renameat2:// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int type);
    case __NR_linkat:// ssize_t linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
    {
        const char* oldpath = (const char*)arg->getArgument2();
        const char* newpath = (const char*)arg->getArgument4();
        LOGSVCI("dumper, %s: %s -> %s", SvcerDumper::index2name(sn), __PRINTSTR(oldpath), __PRINTSTR(newpath))
    }   break;

    case __NR_symlinkat:// int symlinkat(const char *oldpath, int fd, const char *newpath);
    {
        const char* oldpath = (const char*)arg->getArgument1();
        const char* newpath = (const char*)arg->getArgument3();
        LOGSVCI("dumper, %s: %s -> %s", SvcerDumper::index2name(sn), __PRINTSTR(oldpath), __PRINTSTR(newpath))
        break;
    }

    case __NR_readlinkat:// ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
    {
        const char* pathname = (const char*)arg->getArgument2();
        LOGSVCI("dumper, %s >>> %s", SvcerDumper::index2name(sn), __PRINTSTR(pathname))

        char* buf = (char*)arg->getArgument3();
        size_t bufsiz = (size_t)arg->getArgument4();
        arg->doSyscall();
        ssize_t ret = (ssize_t)arg->getReturn();
        if (0 < ret && ret < bufsiz) {
            buf[ret] = '\0';
            LOGSVCI("dumper, %s <<<< %s", SvcerDumper::index2name(sn), __PRINTSTR(buf))
        }
        return;
    }

    case __NR_getcwd:// char* getcwd(char *buf, size_t size);
    {
        arg->doSyscall();
        char* ret = (char*)arg->getReturn();
        LOGSVCI("dumper, %s, %s", SvcerDumper::index2name(sn), __PRINTSTR(ret))
        return;
    }

    case __NR_execve:// int execve(const char *path, char *const argv[], char *const envp[]);
    {
        const char* path = (const char*)arg->getArgument1();
        LOGSVCI("dumper, %s, path: %s", SvcerDumper::index2name(sn), __PRINTSTR(path))

        char* const* argv = (char* const*)arg->getArgument2();
        int cnt = 0;
        while (argv[cnt]) {
            LOGSVCI("dumper, %s, argv[%d]: %s", SvcerDumper::index2name(sn), cnt, argv[cnt])
            ++cnt;
        }

        char* const* envp = (char* const*)arg->getArgument3();
        cnt = 0;
        while (envp[cnt]) {
            LOGSVCI("dumper, %s, envp[%d]: %s", SvcerDumper::index2name(sn), cnt, envp[cnt])
            ++cnt;
        }
        break;
    }
    case __NR_execveat:// int execve(int dirfd, const char *path, char *const argv[], char *const envp[]);
    {
        const char* path = (const char*)arg->getArgument2();
        LOGSVCI("dumper, %s, path: %s", SvcerDumper::index2name(sn), __PRINTSTR(path))

        char* const* argv = (char* const*)arg->getArgument3();
        int cnt = 0;
        while (argv[cnt]) {
            LOGSVCI("dumper, %s, argv[%d]: %s", SvcerDumper::index2name(sn), cnt, argv[cnt])
            ++cnt;
        }

        char* const* envp = (char* const*)arg->getArgument4();
        cnt = 0;
        while (envp[cnt]) {
            LOGSVCI("dumper, %s, envp[%d]: %s", SvcerDumper::index2name(sn), cnt, envp[cnt])
            ++cnt;
        }
        break;
    }
    case __NR_prctl:// int prctl(int __option, ...)
    {
        int option = arg->getArgument1();
        int mode = arg->getArgument2();
        LOGSVCI("dumper, %s, 0x%x, %d", SvcerDumper::index2name(sn), option, mode)
        if (PR_GET_NO_NEW_PRIVS == option) {
            arg->setReturn(g_cache_no_new_privs);
            return;
        }
        if (PR_SET_NO_NEW_PRIVS == option) {
            g_cache_no_new_privs = 1;
            arg->setReturn(0);
            return;
        }

        if (PR_SET_SECCOMP == option) {
            g_cache_secomp = mode;
            arg->setReturn(0);
            return;
        }
        if (PR_GET_SECCOMP == option) {
            if (0 <= g_cache_secomp) {
                arg->setReturn(g_cache_secomp);
            } else {
                arg->setReturn(SvcerHooker::getDefaultSecomp());
            }
            return;
        }
        break;
    }
    case __NR_rt_sigaction:// int sigaction(int __signal, const struct sigaction* __new_action, struct sigaction* __old_action);
    {
        int sig = arg->getArgument1();
        const struct sigaction* newAction = (const struct sigaction*)arg->getArgument2();
        struct sigaction* oldAction = (struct sigaction*)arg->getArgument3();
        LOGSVCI("dumper, %s, %d, %p, %p", SvcerDumper::index2name(sn), sig, newAction, oldAction)
        if (SIGSYS != sig) break;

        if (oldAction) {
            SvcerHooker::getSigaction(oldAction);
        }
        if (newAction) {
            SvcerHooker::setSigaction(newAction);
        }
        arg->setReturn(0);
        return;
    }
//    case __NR_dup:
//    case __NR_dup2:
//    case __NR_dup3:
//    case __NR_fcntl:
//        LOGSVCI("dumper, %s: %s", SvcerDumper::index2name(sn), (const char*)arg->getArgument2())
//        break;
    default:
        LOGSVCI("dumper, %s", SvcerDumper::index2name(sn))
        break;
    }
    arg->doSyscall();
}

void SvcerDumper::addAll() {
    for (int i=SVCER_SYSCALL_None; i<SVCER_SYSCALL_Max; ++i) {
        SvcerHooker::registerCallback((TSVCER_SYSCALL_Type)i, handleSvcerHookerCallback);
    }
}

void SvcerDumper::addDump(TSVCER_SYSCALL_Type type) {
    SvcerHooker::registerCallback(type, handleSvcerHookerCallback);
}
