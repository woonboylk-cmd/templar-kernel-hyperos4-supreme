LOCAL_PATH := $(call my-dir)

# 1. Pixel 11 Identity & HEO Zygote Tamer Zygisk Shared Library
include $(CLEAR_VARS)
LOCAL_MODULE := pixel11_zygisk
LOCAL_SRC_FILES := pixel11_zygisk.cpp
LOCAL_LDLIBS := -llog
LOCAL_CPPFLAGS := -std=c++17 -fvisibility=hidden -Wall -Wextra -O3
include $(BUILD_SHARED_LIBRARY)

# 2. HEO PTrace Tracer Native ARM64 Executable
include $(CLEAR_VARS)
LOCAL_MODULE := heo_ptrace_tracer
LOCAL_SRC_FILES := heo_ptrace_tracer.c
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -std=c11 -Wall -Wextra -O2 -pie -fPIE
include $(BUILD_EXECUTABLE)
