# Copyright (c) 2024 晓梦大师/XMDS
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Hooking.Patterns - ndk-build
# form Google Android NDK
# https://github.com/android/ndk
# https://developer.android.google.cn/ndk/guides/ndk-build
# https://developer.android.google.cn/ndk/guides/android_mk
# https://developer.android.google.cn/ndk/guides/application_mk

include Message.mk

$(call message, Android Hooking.Patterns 0.1.0 - ndk-build)

LOCAL_PATH := $(call my-dir)

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
$(call message, xdl module. Supports Android 4.4 - 5.x. it is recommended to always enable it)
ifeq ($(PATTERNS_USE_XDL), 1)
$(call message, Enable use XDL library)
	
	MY_XDL_PATH := $(MY_PROJECT_PATH)/3rdLibrarys/xdl

	LOCAL_SRC_FILES += $(MY_XDL_PATH)/xdl.c $(MY_XDL_PATH)/xdl_iterate.c \
	$(MY_XDL_PATH)/xdl_linker.c $(MY_XDL_PATH)/xdl_lzma.c $(MY_XDL_PATH)/xdl_util.c
	
	LOCAL_EXPORT_C_INCLUDES += $(MY_XDL_PATH)/include
	LOCAL_C_INCLUDES += $(MY_XDL_PATH)/include
	
	LOCAL_CXXFLAGS += -DPATTERNS_USE_XDL
endif

ifeq ($(PATTERNS_USE_HINTS), 1)
$(call message, Enable use hints)
	LOCAL_CXXFLAGS += -DPATTERNS_USE_HINTS
endif

ifeq ($(PATTERNS_CAN_SERIALIZE_HINTS), 1)
$(call message, "Enable serialize hints")
	LOCAL_CXXFLAGS += -DPATTERNS_CAN_SERIALIZE_HINTS
endif

ifeq ($(NDK_DEBUG), 1)
$(call message, Debug mode)
	LOCAL_CXXFLAGS += -O0 -g -DDEBUG -DPATTERNS_ANDROID_LOGGING
else
$(call message, Release mode)
	LOCAL_CXXFLAGS += -Oz -DPATTERNS_ANDROID_LOGGING \
	-w -mthumb -Weverything -Wall -fpic -flto -faddrsig -mfloat-abi=softfp \
	-fomit-frame-pointer -fdata-sections -ffunction-sections
endif

LOCAL_CPP_FEATURES := exceptions

LOCAL_CXXONLYFLAGS := -std=c++17

# LOCAL_ARM_MODE := arm

ifeq ($(NDK_BUILD_LIB), shared)
$(call message, Build shared library)
	LOCAL_LDLIBS := -landroid -llog -ldl
	LOCAL_CXXFLAGS += -fvisibility=hidden
	include $(BUILD_SHARED_LIBRARY)
else
$(call message, Build static library)
	include $(BUILD_STATIC_LIBRARY)
endif
