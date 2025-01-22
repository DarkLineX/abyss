LOCAL_PATH := $(call my-dir)

MODULE_SRC_FILES := \
         src/svcer_hooker.cpp \
         src/svcer_finder.cpp \
         src/svcer_syscall.cpp \
         src/svcer_dumper.cpp \


########################### build for static library
include $(CLEAR_VARS)
LOCAL_MODULE        := libhookersvcer
LOCAL_C_INCLUDES    += $(LOCAL_PATH)/inc
LOCAL_SRC_FILES     += $(MODULE_SRC_FILES)
LOCAL_CFLAGS        += -fvisibility=hidden
LOCAL_CFLAGS        += -DHAVE_PTHREADS
include $(BUILD_STATIC_LIBRARY)
# LOCAL_CFLAGS        += -DHAVE_PTHREADS -D__ENABLE_MODULE_JNIER__
