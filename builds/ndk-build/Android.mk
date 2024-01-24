# Hooking.Patterns - ndk-build
# form Android ndk-build
# https://github.com/android/ndk
# https://developer.android.google.cn/ndk/guides/ndk-build
# https://developer.android.google.cn/ndk/guides/android_mk
# https://developer.android.google.cn/ndk/guides/application_mk

LOCAL_PATH:= $(call my-dir)

MY_PROJECT_PATH := ../../

# Hooking.Patterns main module
include $(CLEAR_VARS)

LOCAL_MODULE := HookingPatterns

LOCAL_CPP_EXTENSION := .cpp

LOCAL_SRC_FILES := $(MY_PROJECT_PATH)/src/Hooking.Patterns.cpp

LOCAL_EXPORT_C_INCLUDES := $(MY_PROJECT_PATH)/include
LOCAL_C_INCLUDES := $(MY_PROJECT_PATH)/include

# xdl module
# https://github.com/hexhacking/xDL
ifeq ($(PATTERNS_USE_XDL), 1)
	MY_XDL_PATH := $(MY_PROJECT_PATH)/3rdLibrarys/xDL/xdl/src/main/cpp
	
	LOCAL_SRC_FILES += $(MY_XDL_PATH)/xdl.c $(MY_XDL_PATH)/xdl_iterate.c \
	$(MY_XDL_PATH)/xdl_linker.c $(MY_XDL_PATH)/xdl_lzma.c $(MY_XDL_PATH)/xdl_util.c

	LOCAL_EXPORT_C_INCLUDES += $(MY_XDL_PATH)/include
	LOCAL_C_INCLUDES += $(MY_XDL_PATH)/include
	
	LOCAL_CXXFLAGS += -DPATTERNS_USE_XDL
endif

LOCAL_CXXFLAGS += -Oz -DPATTERNS_ANDROID_LOGGING \
-w -mthumb -Weverything -Wall -fpic -flto -faddrsig -mfloat-abi=softfp \
-fomit-frame-pointer -fdata-sections -ffunction-sections

LOCAL_CPP_FEATURES := exceptions

LOCAL_CXXONLYFLAGS := -std=c++17

# LOCAL_ARM_MODE := arm

include $(BUILD_STATIC_LIBRARY)
