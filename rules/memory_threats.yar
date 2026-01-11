/*
 * RafSec - Memory Threat YARA Rules
 * ==================================
 * Detect fileless/in-memory malware patterns.
 */

rule Mimikatz_Memory {
    meta:
        description = "Mimikatz credential harvester in memory"
        severity = "CRITICAL"
        author = "RafSec Team"
    
    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "kerberos::list" ascii wide nocase
        $s4 = "lsadump::sam" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "token::elevate" ascii wide nocase
    
    condition:
        2 of them
}

rule ReflectiveLoader {
    meta:
        description = "Reflective DLL injection pattern"
        severity = "CRITICAL"
        author = "RafSec Team"
    
    strings:
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "VirtualAlloc" ascii wide
        $s3 = "NtFlushInstructionCache" ascii wide
        $s4 = { 4D 5A 90 00 03 00 00 00 }  // MZ header
    
    condition:
        ($s1 and $s2) or ($s3 and $s4)
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon in memory"
        severity = "CRITICAL"
        author = "RafSec Team"
    
    strings:
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon.dll" ascii wide
        $s3 = "beacon.x64.dll" ascii wide
        $s4 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B FA }
    
    condition:
        any of them
}

rule PowerShell_Inject {
    meta:
        description = "PowerShell injection pattern"
        severity = "HIGH"
        author = "RafSec Team"
    
    strings:
        $s1 = "IEX" ascii wide nocase
        $s2 = "Invoke-Expression" ascii wide nocase
        $s3 = "DownloadString" ascii wide nocase
        $s4 = "FromBase64String" ascii wide nocase
        $s5 = "-enc" ascii nocase
        $s6 = "-EncodedCommand" ascii wide nocase
        $s7 = "powershell.exe -nop -w hidden" ascii wide nocase
    
    condition:
        3 of them
}

rule Shellcode_Patterns {
    meta:
        description = "Generic shellcode patterns"
        severity = "HIGH"
        author = "RafSec Team"
    
    strings:
        // NOP sled
        $nop = { 90 90 90 90 90 90 90 90 }
        // GetProcAddress pattern
        $gpa = { 8B 74 24 24 01 F0 89 44 24 1C }
        // Egg hunter
        $egg = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
        // Metasploit shikata
        $met = { D9 74 24 F4 5? }
    
    condition:
        any of them
}

rule Meterpreter_Memory {
    meta:
        description = "Meterpreter payload in memory"
        severity = "CRITICAL"
        author = "RafSec Team"
    
    strings:
        $s1 = "meterpreter" ascii wide nocase
        $s2 = "stdapi_" ascii
        $s3 = "core_channel_" ascii
        $s4 = "ext_server" ascii
    
    condition:
        2 of them
}

rule Empire_Agent {
    meta:
        description = "PowerShell Empire agent"
        severity = "HIGH"
        author = "RafSec Team"
    
    strings:
        $s1 = "empire" ascii wide nocase
        $s2 = "Invoke-Empire" ascii wide
        $s3 = "stager" ascii wide nocase
        $s4 = "SafeChecks" ascii
    
    condition:
        2 of them
}

rule Process_Hollowing {
    meta:
        description = "Process hollowing technique"
        severity = "CRITICAL"
        author = "RafSec Team"
    
    strings:
        $s1 = "NtUnmapViewOfSection" ascii wide
        $s2 = "ZwUnmapViewOfSection" ascii wide
        $s3 = "NtResumeThread" ascii wide
        $s4 = "SetThreadContext" ascii wide
    
    condition:
        2 of them
}
