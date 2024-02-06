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
# form Android ndk-build
# https://github.com/android/ndk
# https://developer.android.google.cn/ndk/guides/ndk-build
# https://developer.android.google.cn/ndk/guides/android_mk
# https://developer.android.google.cn/ndk/guides/application_mk

NDK_TOOLCHAIN_VERSION := clang

APP_STL := c++_static

APP_ABI := armeabi-v7a arm64-v8a x86 x86_64

ifeq ($(NDK_DEBUG), 1)
	APP_OPTIM := debug
else
	APP_OPTIM := release
endif

APP_PLATFORM := android-21
