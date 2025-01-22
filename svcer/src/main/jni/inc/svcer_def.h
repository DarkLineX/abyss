#ifndef __SVCER_DEF_H__
#define __SVCER_DEF_H__

#include <android/log.h>
#include "linux_syscalls.h"

#define __ENABLE_LOG_SVC_D__    1
#define __ENABLE_LOG_SVC_I__    1
#define __ENABLE_LOG_SVC_W__    1
#define __ENABLE_LOG_SVC_E__    1

#define __TAG_SVCER__   "svcer"

#if defined(__ENABLE_LOG_SVC_D__) || defined(__ENABLE_LOG_SVC_I__)
#define __ENABLE_LOG_SVC__      1
#endif

#ifdef __ENABLE_LOG_SVC_D__
#define LOGSVCD(...) __android_log_print(ANDROID_LOG_DEBUG, __TAG_SVCER__, __VA_ARGS__);
#else
#define LOGSVCD(...)
#endif

#ifdef __ENABLE_LOG_SVC_I__
#define LOGSVCI(...) __android_log_print(ANDROID_LOG_INFO, __TAG_SVCER__, __VA_ARGS__);
#else
#define LOGSVCI(...)
#endif

#ifdef __ENABLE_LOG_SVC_W__
#define LOGSVCW(...) __android_log_print(ANDROID_LOG_WARN, __TAG_SVCER__, __VA_ARGS__);
#else
#define LOGSVCW(...)
#endif

#ifdef __ENABLE_LOG_SVC_E__
#define LOGSVCE(...) __android_log_print(ANDROID_LOG_ERROR, __TAG_SVCER__, __VA_ARGS__);
#else
#define LOGSVCE(...)
#endif

/* Used to retry syscalls that can return EINTR. */
#define HANDLE_EINTR(exp) ({ \
    __typeof__(exp) _rc; \
    while (1) { \
        _rc = (exp); \
        if (_rc == -1) \
        { \
            if (_rc == EINTR) \
                continue; \
        } \
        break; \
    } \
    _rc; })

#endif// end of __SVCER_DEF_H__
