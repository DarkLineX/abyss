#include <sys/file.h>
#include "svcer_finder.h"
#include "svcer_cmn.h"
#include "svcer_syscall.h"
#include "svcer_def.h"
#include <string.h>

#define REAL_NAME_LENGTH    256
// ------------------------------------------------------------------------------------------------------------------------
SvcerFinder::SvcerFinder(const char* selfLibName)
: mSelfLibName(selfLibName), mSelfLibNameLen(strlen(selfLibName))
, mVdsoAddrStart(UINTPTR_MAX), mVdsoAddrEnd(0)
, mLibcAddrStart(UINTPTR_MAX), mLibcAddrEnd(0)
, mLinkerAddrStart(UINTPTR_MAX), mLinkerAddrEnd(0)
, mSelfAddrStart(UINTPTR_MAX), mSelfAddrEnd(0)
{}

int SvcerFinder::doInitSysLibPath(char* libc_real_name, char* linker_real_name) {
#if defined(__aarch64__)
    const char* libc_path = "/system/lib64/libc.so";
    const char* linker_path = "/system/bin/linker64";
#else
    const char* libc_path = "/system/lib/libc.so";
    const char* linker_path = "/system/bin/linker";
#endif

    // get real path
    int ret = readlink(libc_path, libc_real_name, REAL_NAME_LENGTH - 1);
    if (ret <= 0) {
        if (ret != EINVAL) {
            LOGSVCE("SHF:readlink %s fail ret=%d", libc_path, ret);
            return -10;
        }
        strcpy(libc_real_name, libc_path);
    } else {
        libc_real_name[ret] = 0;
    }
    LOGSVCD("SHF: libc: %s\n", libc_real_name);

    ret = readlink(linker_path, linker_real_name, REAL_NAME_LENGTH - 1);
    if (ret <= 0) {
        if (ret != EINVAL) {
            LOGSVCE("SHF:readlink %s fail ret=%d", linker_path, ret);
            return -11;
        }
        strcpy(linker_real_name, linker_path);
    } else {
        linker_real_name[ret] = 0;
    }
    LOGSVCD("SHF: linker: %s", linker_real_name);
    return 0;
}

int SvcerFinder::search() {
    char* line = NULL;
    char libc_real_name[REAL_NAME_LENGTH];
    char linker_real_name[REAL_NAME_LENGTH];
    size_t libcLen, linkerLen;
    int ret = doInitSysLibPath(libc_real_name, linker_real_name);
    if (0 != ret) return ret;

    int fd = SvcerSyscall::Call(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        LOGSVCE("shf search: %d, %d, %s", fd, errno, strerror(errno));
        return -20;
    }

    FILE* fp = fdopen(fd, "r");
    if (__UNLIKELY(!fp)) { ret = -21; goto end; }

    line = (char*)malloc(1024);
    if (__UNLIKELY(!line)) { ret = -22; goto end; }

    libcLen = strlen(libc_real_name);
    linkerLen = strlen(linker_real_name);
    while (fgets(line, 1024, fp)) {
        doSearchLine(line, libc_real_name, libcLen, linker_real_name, linkerLen);
    }

end:
    if (__LIKELY(fp)) fclose(fp);
    if (__LIKELY(line)) free(line);

#ifdef __ENABLE_LOG_SVC_D__
    print();
#endif
    return isValid() ? 0 : -29;
}

__always_inline bool strcmpex(const char* target, const char* src, int len) {
    return memcmp(target, src, len) == 0 && (target[len] == '\0' || target[len] == '\n');
}

/**
 * 754f0000-7553a000 r-xp 00000000 b3:1c 91345      /data/data/com.demo/lib/libdemo.so
 * 75555000-75556000 r--s 0000c000 b3:1c 91400      /data/data/com.demo/lib/libdemo.apk
 * */
void SvcerFinder::doSearchLine(const char* line, const char* libc, size_t libcLen, const char* linker, size_t linkerLen) {
//    LOGSVCD("maps: %s", line)
    uintptr_t start_addr, end_addr;
    if (2 != sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start_addr, &end_addr)) return;

    const char* pos = strrchr(line, ' ');
    if (!pos) return;
    pos += 1;

    if (strcmpex(pos, "[vdso]", 6)) {
//        LOGSVCD("vdso: %08" PRIxPTR "-%08" PRIxPTR "", start_addr, end_addr);
        if (start_addr < mVdsoAddrStart) {
            mVdsoAddrStart = start_addr;
        }
        if (end_addr > mVdsoAddrEnd) {
            mVdsoAddrEnd = end_addr;
        }
    } else if (strcmpex(pos, libc, libcLen)) {
//        LOGSVCD("libc: %08" PRIxPTR "-%08" PRIxPTR "", start_addr, end_addr);
        if (start_addr < mLibcAddrStart) {
            mLibcAddrStart = start_addr;
        }
        if (end_addr > mLibcAddrEnd) {
            mLibcAddrEnd = end_addr;
        }
    } else if (strcmpex(pos, linker, linkerLen)) {
//        LOGSVCD("linker: %08" PRIxPTR "-%08" PRIxPTR "", start_addr, end_addr);
        if (start_addr < mLinkerAddrStart) {
            mLinkerAddrStart = start_addr;
        }
        if (end_addr > mLinkerAddrEnd) {
            mLinkerAddrEnd = end_addr;
        }
    } else {
        const char* shortname = strrchr(pos, '/');
        if (shortname) {
            shortname += 1;
        } else {
            shortname = pos;
        }
        if (strcmpex(shortname, mSelfLibName, mSelfLibNameLen)) {
//            LOGSVCD("self: %08" PRIxPTR "-%08" PRIxPTR "", start_addr, end_addr);
            if (start_addr < mSelfAddrStart) {
                mSelfAddrStart = start_addr;
            }
            if (end_addr > mSelfAddrEnd) {
                mSelfAddrEnd = end_addr;
            }
        }
    }
}

bool SvcerFinder::isValid() const {
//    if (mVdsoAddrEnd <= mVdsoAddrStart) return false;
    if (mLibcAddrEnd <= mLibcAddrStart) return false;
    if (mLinkerAddrEnd <= mLinkerAddrStart) return false;
    if (mSelfAddrEnd <= mSelfAddrStart) return false;
    return true;
}

void SvcerFinder::print() const {
    LOGSVCD("SHF::print: vdso %08" PRIxPTR "-%08" PRIxPTR "", mVdsoAddrStart, mVdsoAddrEnd)
    LOGSVCD("SHF::print: libc %08" PRIxPTR "-%08" PRIxPTR "", mLibcAddrStart, mLibcAddrEnd)
    LOGSVCD("SHF::print: linker %08" PRIxPTR "-%08" PRIxPTR "", mLinkerAddrStart, mLinkerAddrEnd)
    LOGSVCD("SHF::print: self %08" PRIxPTR "-%08" PRIxPTR "", mSelfAddrStart, mSelfAddrEnd)
}
