rule DLL_Injection_Techniques {
    meta:
        description = "Detects source code or binaries containing common DLL Injection Windows API calls"
        author = "Kimi_Agent"
        date = "2024-06-17"
        severity = "High"
        technique = "T1055.001"
        technique_name = "Process Injection: Dynamic-link Library Injection"

    strings:
        // Classic CreateRemoteThread injection
        $api_createremotethread = "CreateRemoteThread" ascii wide nocase
        $api_virtualallocex = "VirtualAllocEx" ascii wide nocase
        $api_writeprocessmemory = "WriteProcessMemory" ascii wide nocase
        $api_loadlibrary = "LoadLibraryA" ascii wide nocase
        $api_loadlibraryw = "LoadLibraryW" ascii wide nocase
        $api_getprocaddress = "GetProcAddress" ascii wide nocase

        // Reflective Loading
        $api_ntcreateuserprocess = "NtCreateUserProcess" ascii wide nocase
        $api_virtualprotect = "VirtualProtect" ascii wide nocase

    condition:
        // High confidence DLL injection sequence
        (
            $api_createremotethread and
            $api_virtualallocex and
            $api_writeprocessmemory and
            ($api_loadlibrary or $api_loadlibraryw)
        ) or (
            $api_ntcreateuserprocess and $api_virtualprotect
        ) or (
            $api_createremotethread and $api_getprocaddress and
            ($api_loadlibrary or $api_loadlibraryw)
        )
}

rule Reflective_DLL_Injection {
    meta:
        description = "Detects Reflective DLL injection techniques or source code"
        author = "Kimi_Agent"
        date = "2024-06-17"
        severity = "Critical"
        technique = "T1620"
        technique_name = "Reflective Code Loading"

    strings:
        // Stephen Fewer's ReflectiveDLLInjection naming conventions
        $ref_1 = "ReflectiveLoader" ascii wide nocase
        $ref_2 = "ReflectiveDllInjection" ascii wide nocase
        $ref_3 = "DllMain" ascii wide nocase
        
        // Memory APIs often used in reflective loaders
        $api_1 = "VirtualAlloc" ascii wide nocase
        $api_2 = "VirtualProtect" ascii wide nocase

    condition:
        ($ref_1 or $ref_2 or $ref_3) and $api_1 and $api_2
}
