#ifndef __SVCER_HOOKER_H__
#define __SVCER_HOOKER_H__

#include "svcer_def.h"

typedef enum {
    SVCER_SYSCALL_None = 0,
    SVCER_SYSCALL_open = SVCER_SYSCALL_None,
    SVCER_SYSCALL_openat,
    SVCER_SYSCALL_faccessat,
    SVCER_SYSCALL_fchmodat,
    SVCER_SYSCALL_fchownat,
    SVCER_SYSCALL_renameat,
    SVCER_SYSCALL_renameat2,
    SVCER_SYSCALL_fstatat,
    SVCER_SYSCALL_statfs,
    SVCER_SYSCALL_mkdirat,
    SVCER_SYSCALL_mknodat,
    SVCER_SYSCALL_truncate,
    SVCER_SYSCALL_linkat,
    SVCER_SYSCALL_unlinkat,
    SVCER_SYSCALL_readlinkat,
    SVCER_SYSCALL_symlinkat,
    SVCER_SYSCALL_utimensat,
    SVCER_SYSCALL_getcwd,
    SVCER_SYSCALL_chdir,
    SVCER_SYSCALL_execve,
    SVCER_SYSCALL_execveat,
    SVCER_SYSCALL_fcntl,
    SVCER_SYSCALL_prctl,
    SVCER_SYSCALL_sigaction,
    // add more syscall here ...


    SVCER_SYSCALL_Max,
} TSVCER_SYSCALL_Type;

class SvcerHookerArgument;
typedef void (*SvcerHookerCallback)(int sn, SvcerHookerArgument* arg/*Not NULL*/);

class SvcerHookerItem {
public:
    SvcerHookerItem(SvcerHookerCallback cb) : mNext(nullptr), mCallback(cb)
    {}

    void addNext(SvcerHookerItem* item) {
        if (mNext) {
            mNext->addNext(item);
        } else {
            mNext = item;
        }
    }

    __always_inline SvcerHookerItem* next() const { return mNext; }
    __always_inline SvcerHookerCallback callback() const { return mCallback; }

private:
    SvcerHookerItem* mNext;
    SvcerHookerCallback  mCallback;
};

class SvcerHookerArgument {
public:
    SvcerHookerArgument(void* info, void *uc, SvcerHookerItem* item);

    __always_inline void setArgument1(const intptr_t& p1);
    __always_inline void setArgument2(const intptr_t& p2);
    __always_inline void setArgument3(const intptr_t& p3);
    __always_inline void setArgument4(const intptr_t& p5);
    __always_inline void setArgument5(const intptr_t& p5);
    __always_inline void setArgument6(const intptr_t& p6);

    __always_inline void setReturn(const intptr_t& p);

    __always_inline intptr_t getArgument1();
    __always_inline intptr_t getArgument2();
    __always_inline intptr_t getArgument3();
    __always_inline intptr_t getArgument4();
    __always_inline intptr_t getArgument5();
    __always_inline intptr_t getArgument6();

    __always_inline intptr_t getReturn();

    void doSyscall();

protected:
    SvcerHookerItem* moveToNext() {
        mItem = mItem->next();
        return mItem;
    }

private:
    void* mInfo;
    void* mContext;
    SvcerHookerItem* mItem;
};

enum {
    ESvcerHookerMode_None = 0,
    ESvcerHookerMode_IgnoreVdso     = 0x1,
    ESvcerHookerMode_IgnoreLibc     = 0x2,
    ESvcerHookerMode_IgnoreLinker   = 0x4,

    ESvcerHookerMode_IgnoreAll      = ESvcerHookerMode_IgnoreVdso|ESvcerHookerMode_IgnoreLibc|ESvcerHookerMode_IgnoreLinker,
};

class SvcerHooker {
public:

    /**
     * @param selfLibName such as: "libifmamts.so"
     * @return 0: success, otherwise fail
     * */
    static int init(int mode, const char* selfLibName);

    static void registerCallback(TSVCER_SYSCALL_Type type, SvcerHookerCallback cb);
    static void unregisterCallback(TSVCER_SYSCALL_Type type, SvcerHookerCallback cb);

    static SvcerHookerItem* getHeader(int type);
    static int getDefaultSecomp();
    static void setSigaction(const struct sigaction* act);
    static void getSigaction(struct sigaction* act);

private:
    static bool sInited;
};

#endif// end of __SVCER_HOOKER_H__
