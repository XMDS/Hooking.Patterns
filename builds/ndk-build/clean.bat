@echo off
cd /d "%~dp0"

call ndk-build clean ^
        NDK_PROJECT_PATH=. ^
        NDK_APPLICATION_MK=./Application.mk ^
        APP_BUILD_SCRIPT=./Android.mk
pause
