# Hooking.Patterns - ndk-build
# form Android ndk-build
# https://github.com/android/ndk
# https://developer.android.google.cn/ndk/guides/ndk-build
# https://developer.android.google.cn/ndk/guides/android_mk
# https://developer.android.google.cn/ndk/guides/application_mk

NDK_TOOLCHAIN_VERSION := clang
APP_STL := c++_static
APP_ABI := armeabi-v7a arm64-v8a
APP_OPTIM := release debug
APP_PLATFORM := android-21
