@echo off
cd /d "%~dp0"

call ndk-build NDK_LOG=1
pause
