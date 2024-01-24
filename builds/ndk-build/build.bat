@echo off
cd /d "%~dp0"

call ndk-build NDK_LOG=1 -e PATTERNS_USE_XDL=1 -B V=1 ^
        NDK_PROJECT_PATH=. ^
        NDK_APPLICATION_MK=./Application.mk ^
        APP_BUILD_SCRIPT=./Android.mk
pause
