LOCAL_PATH:= $(call my-dir)
 
include $(CLEAR_VARS)
LOCAL_MODULE := HookingPatternsExample
LOCAL_CPP_EXTENSION := .cpp

PATTERN_CPP_PATH = ../../src
PATTERN_HPP_PATH = ../../include
PATTERN_XDL_PATH = ../../3rdLibrarys/xdl
$(warning $(PATTERN_CPP_PATH))
$(warning $(PATTERN_HPP_PATH))
$(warning $(PATTERN_XDL_PATH))

LOCAL_EXPORT_C_INCLUDES := $(PATTERN_HPP_PATH) $(PATTERN_XDL_PATH)/
LOCAL_SRC_FILES := main.cpp $(PATTERN_CPP_PATH)/Hooking.Patterns.cpp \
$(PATTERN_XDL_PATH)/xdl.c $(PATTERN_XDL_PATH)/xdl_iterate.c $(PATTERN_XDL_PATH)/xdl_linker.c $(PATTERN_XDL_PATH)/xdl_lzma.c $(PATTERN_XDL_PATH)/xdl_util.c
LOCAL_CFLAGS += -Oz -mthumb -Wall -std=c17 -fpic -mfloat-abi=softfp -fexceptions
LOCAL_CXXFLAGS += -Oz -mthumb -Wall -std=c++17 -fpic -mfloat-abi=softfp -fexceptions
LOCAL_CXXONLYFLAGS := -std=c++17
LOCAL_LDLIBS += -landroid -llog -ldl
# LOCAL_ARM_MODE := arm

include $(BUILD_EXECUTABLE)
