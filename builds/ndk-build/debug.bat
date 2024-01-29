@echo off
cd /d "%~dp0"

call ndk-build NDK_DEBUG=1 NDK_LOG=1 -B V=1 ^
        GEN_COMPILE_COMMANDS_DB=true ^
        -e PATTERNS_USE_XDL=1 NDK_BUILD_LIB=static ^
        NDK_PROJECT_PATH=. ^
        NDK_APPLICATION_MK=./Application.mk ^
        APP_BUILD_SCRIPT=./Android.mk
pause
