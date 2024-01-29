workspace "HookingPatterns"

    GetProjectPath = function()
        return path.getabsolute("../..")
    end

    GetPremakeScriptPath = function()
        return path.getdirectory(_SCRIPT)
    end
    
    location (path.join(GetPremakeScriptPath(), "build/") .. _ACTION)
    
    configurations { 
        "Debug", 
        "Release" 
    }

    platforms { 
        "ARM",
        "ARM64"
        "x86",
        "x64"
    }

    filter "configurations:Debug"
        defines { "DEBUG"}
        symbols "On"
        optimize "Off"


