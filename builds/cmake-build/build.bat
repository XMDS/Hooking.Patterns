@echo off
cd /d "%~dp0"

:: Set Android NDK path form environment variable
SET "NDK=%ANDROID_NDK_HOME%"
if "%NDK%" == "" (
    echo "ANDROID_NDK_HOME" environment variable not set.
    echo "Please set the ANDROID_NDK_HOME environment variable to the path of your NDK installation."
    exit /b 1
)

:: Set CMAKE variable with the value "cmake"
SET "CMake=cmake"
if "%CMake%" == "" (
    echo "cmake" not found.
    echo "Please set the CMake variable to the path of your CMake installation."
    exit /b 1
)

:: echo %NDK%
:: echo %CMAKE%

:: Set project name
SET "PROJECT_NAME=HookingPattern"

:: Set build path
SET BUILD_PATH=build

:: Set targets
SET "ANDROID_ABI=arm64-v8a armeabi-v7a x86 x86_64"

:: Build
for %%x in (%ANDROID_ABI%) do (
    ECHO %PROJECT_NAME% - %BUILD_TYPE%
    ECHO -------- Building %%x --------
    ECHO ------------------------------

    CMake -S. -B%BUILD_PATH%/%%x -G "MinGW Makefiles" ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DANDROID_ABI=%%x ^
    -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE ^
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=%BUILD_PATH%/%%x/bin ^
    -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=%BUILD_PATH%/%%x/lib ^
    -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=%BUILD_PATH%/%%x/lib ^
    -DANDROID_TOOLCHAIN=clang ^
    -DCMAKE_TOOLCHAIN_FILE=%NDK%/build/cmake/android.toolchain.cmake ^
    -DCMAKE_C_COMPILER=%NDK%/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe ^
    -DCMAKE_CXX_COMPILER=%NDK%/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe ^
    -DCMAKE_ANDROID_STL_TYPE=c++_static ^
    -DANDROID_NDK=%NDK% ^
    -DANDROID_PLATFORM=android-21 ^
    -DANDROID_NATIVE_API_LEVEL=21
    
    CMake --build %BUILD_PATH%/%%x --config %BUILD_TYPE% -j8
)
