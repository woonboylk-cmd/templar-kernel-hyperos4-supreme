LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := pixel11_zygisk
LOCAL_SRC_FILES := pixel11_zygisk.cpp
LOCAL_LDLIBS := -llog
LOCAL_CPPFLAGS := -std=c++17 -fvisibility=hidden -Wall -Wextra -O3
include $(BUILD_SHARED_LIBRARY)