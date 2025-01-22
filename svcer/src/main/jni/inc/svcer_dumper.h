#ifndef __SVCER_DUMPER_H__
#define __SVCER_DUMPER_H__

#include "svcer_hooker.h"

class SvcerDumper {
public:
    static void addAll();
    static void addDump(TSVCER_SYSCALL_Type type);

    static const char* index2name(int sc);
};

#endif// end of __SVCER_DUMPER_H__
