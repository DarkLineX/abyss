#ifndef __MTS_SVCER_FINDER_H__
#define __MTS_SVCER_FINDER_H__

#include "svcer_def.h"

class SvcerFinder {
public:
    SvcerFinder(const char* selfLibName);

    // return: 0(success), otherwise fail
    int search();

    __always_inline const uintptr_t& getVdsoAddrStart() const { return mVdsoAddrStart; }
    __always_inline const uintptr_t& getVdsoAddrEnd() const { return mVdsoAddrEnd; }

    __always_inline const uintptr_t& getLibcAddrStart() const { return mLibcAddrStart; }
    __always_inline const uintptr_t& getLibcAddrEnd() const { return mLibcAddrEnd; }

    __always_inline const uintptr_t& getLinkerAddrStart() const { return mLinkerAddrStart; }
    __always_inline const uintptr_t& getLinkerAddrEnd() const { return mLinkerAddrEnd; }

    __always_inline const uintptr_t& getSelfAddrStart() const { return mSelfAddrStart; }
    __always_inline const uintptr_t& getSelfAddrEnd() const { return mSelfAddrEnd; }

    bool isValid() const;
    void print() const;

protected:
    int doInitSysLibPath(char* libc_real_name, char* linker_real_name);
    void doSearchLine(const char* line, const char* libc, size_t libcLen, const char* linker, size_t linkerLen);

private:
    const char* mSelfLibName;
    size_t mSelfLibNameLen;
    uintptr_t mVdsoAddrStart, mVdsoAddrEnd;
    uintptr_t mLibcAddrStart, mLibcAddrEnd;
    uintptr_t mLinkerAddrStart, mLinkerAddrEnd;
    uintptr_t mSelfAddrStart, mSelfAddrEnd;
};

#endif // __MTS_SVCER_FINDER_H__
