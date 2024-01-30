# Copyright (c) 2024 晓梦大师/XMDS

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Hooking.Patterns - CMakeLists.txt
# Form Android NDK CMake build
# https://github.com/Kitware/CMake.git
# https://developer.android.google.cn/ndk/guides/cmake?hl=zh-cn
# https://github.com/bowserf/android-cmake-sample.git

cmake_minimum_required(VERSION 3.5.0)
project(HookingPatterns VERSION 0.1.0 LANGUAGES C CXX)

Message("CMakeBuilds: ${CMAKE_SYSTEM_NAME}-${PROJECT_NAME}-${PROJECT_VERSION}\n")

option(BUILD_SHARED_LIBS "Build shared library" ON)

include(CTest)
enable_testing()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

Message("xdl module, It is recommended to always enable it")
option(PATTERNS_USE_XDL "Enable XDL library" ON)
option(PATTERNS_ANDROID_LOGGING "Enable Android logging" ON)
option(PATTERNS_USE_HINTS "Use hints" OFF)
option(PATTERNS_CAN_SERIALIZE_HINTS "Can serialize hints" OFF)

set(CMAKE_CXX_STANDARD 17)

set(MY_PROJECT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../)

include_directories(${MY_PROJECT_PATH}/include)

if(PATTERNS_USE_XDL)
    Message("Enable use XDL library")
    add_definitions(-DPATTERNS_USE_XDL)
    include_directories(${MY_PROJECT_PATH}/3rdLibrarys/xDL/xdl/src/main/cpp/include)
    file(GLOB XDL_SRC ${MY_PROJECT_PATH}/3rdLibrarys/xDL/xdl/src/main/cpp/*.c)
endif()

if(PATTERNS_ANDROID_LOGGING)
    Message("Enable Android logging module")
    add_definitions(-DPATTERNS_ANDROID_LOGGING)
endif()

if(PATTERNS_USE_HINTS)
    Message("Use hints")
    add_definitions(-DPATTERNS_USE_HINTS)
endif()

if(PATTERNS_CAN_SERIALIZE_HINTS)
    add_definitions(-DPATTERNS_CAN_SERIALIZE_HINTS)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
    Message("Debug mode\n")
    add_compile_options(-O0 -g -DDEBUG)
else()
    Message("Release mode\n")
    add_compile_options(-Oz -w -mthumb -Weverything -Wall -fpic -flto -faddrsig 
    -mfloat-abi=softfp -fomit-frame-pointer -fdata-sections -ffunction-sections)
endif()

if(BUILD_SHARED_LIBS)
    Message("Build shared library\n")
    add_compile_options(-fvisibility=hidden)
    add_library(HookingPatterns SHARED ${MY_PROJECT_PATH}/src/Hooking.Patterns.cpp ${XDL_SRC})
    target_link_libraries(HookingPatterns 
        android
        log
        dl
    )
else()
    Message("Build static library\n")
    add_library(HookingPatterns STATIC ${MY_PROJECT_PATH}/src/Hooking.Patterns.cpp ${XDL_SRC})
    
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
