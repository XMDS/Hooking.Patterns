workspace "HookingPatterns"

    GetProjectPath = function()
        return path.getabsolute("../..")
    end

    GetPremakeScriptPath = function()
        return path.getdirectory(_SCRIPT)
    end
    
    location (GetPremakeScriptPath())
    objdir (path.join(GetPremakeScriptPath(), "obj"))
    
    configurations { 
        "Debug", 
        "Release" 
    }

    platforms { 
        "ARM",
        "ARM64",
        "x86a",
        "x64"
    }

    filter "configurations:Debug"
        defines { "DEBUG"}
        symbols "On"
        optimize "Off"

    filter "configurations:Release"
        defines { "NDEBUG"}
        symbols "Off"
        optimize "Full"
        
project "HookingPatterns"
    system "android"
    language "C++"
    cdialect "C11"
    cppdialect "C++latest"
    exceptionhandling "On"
    characterset "MBCS"
    staticruntime "On"
    toolset "clang"
    kind "StaticLib"

    files {
        GetProjectPath() .. "/src/Hooking.Patterns.cpp",
        GetProjectPath() .. "/3rdLibrarys/xDL/xdl/src/main/cpp/*.c"
    }

    includedirs {
        GetProjectPath() .. "/include",
        GetProjectPath() .. "/3rdLibrarys/xDL/xdl/src/main/cpp/include"
    }

    filter "platforms:ARM"
        architecture "ARM"
        targetdir (path.join(GetPremakeScriptPath(), "/ARM"))

    filter "platforms:ARM64"
        architecture "ARM64"
        targetdir (path.join(GetPremakeScriptPath(), "/ARM64"))

    filter "platforms:x86a"
        architecture "x86"
        targetdir (path.join(GetPremakeScriptPath(), "/x86"))

    filter "platforms:x64"
        architecture "x86_64"
        targetdir (path.join(GetPremakeScriptPath(), "/x64"))
