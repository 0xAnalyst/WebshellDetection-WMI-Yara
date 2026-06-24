/*
   Rule:   reflective_pe_memory.yar
   Desc:   Detects reflectively loaded PE images in process memory.
           Run with: yara64.exe -p <PID> reflective_pe_memory.yar
           or via a memory dump. Looks for MZ/PE headers outside of
           mapped image regions, which indicates a manually mapped PE
           (reflective DLL injection, in-memory assembly load, etc).
           Catches ReflectivePEShell.aspx and InMemory_Assembly_XOR.aspx
           running inside the IIS worker process (w3wp.exe).
   Author: 0xAnalyst
   ATT&CK: T1620 (Reflective Code Loading), T1055 (Process Injection)
   Date:   2026-06-24

   Usage (live process):
     yara64.exe -p <w3wp_PID> reflective_pe_memory.yar

   Usage (memory dump):
     yara64.exe reflective_pe_memory.yar w3wp.dmp
*/

rule Memory_ReflectivePE_MZHeader
{
    meta:
        description     = "MZ/PE header found in process memory outside of mapped image regions — reflective PE load"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1620, T1055"
        score           = 80

    strings:
        // MZ magic + DOS stub leading to PE header
        $mz_magic       = { 4D 5A }
        // PE signature
        $pe_sig         = { 50 45 00 00 }
        // Reflective loader export name commonly embedded
        $refl_loader    = "ReflectiveLoader"         ascii nocase
        $refl_load2     = "ReflectiveDLLInjection"   ascii nocase

    condition:
        $mz_magic at 0
        and $pe_sig
        and 1 of ($refl_loader, $refl_load2)
}


rule Memory_ManuallyMapped_PE
{
    meta:
        description     = "Manually mapped PE in memory — imports resolved, sections present, no backing file on disk"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1620, T1055"
        score           = 75

    strings:
        $mz             = { 4D 5A }
        $pe             = { 50 45 00 00 4C 01 }           // PE32
        $pe64           = { 50 45 00 00 64 86 }           // PE32+
        // Import table markers
        $import_str     = ".idata"                         ascii
        $kernel32       = "KERNEL32.DLL"                   ascii wide
        // Common injected payload exports or strings
        $dll_main       = "DllMain"                        ascii
        $dll_entry      = "DllEntryPoint"                  ascii

    condition:
        $mz at 0
        and 1 of ($pe, $pe64)
        and $kernel32
        and 1 of ($dll_main, $dll_entry, $import_str)
}


/*
   Rule:   ntdll_unhook_memory.yar
   Desc:   Detects the presence of a fresh (clean) copy of ntdll.dll mapped
           alongside the standard hooked copy in a process. EDR products hook
           ntdll functions in the loaded copy. Attackers load a second clean
           copy from disk to bypass those hooks. Presence of two distinct ntdll
           base addresses in one process is a high-confidence indicator.
           Catches NtCreateProcess_Unhook.aspx.
   ATT&CK: T1562.001, T1055
*/

rule Memory_NtdllCleanCopy_Unhook
{
    meta:
        description     = "Second clean ntdll.dll mapped in process memory — EDR hook bypass via fresh copy"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1562.001, T1055"
        score           = 85

    strings:
        // ntdll module name strings present in the manually mapped copy
        $ntdll_name     = "ntdll.dll"                      ascii wide nocase
        $ntdll_path1    = "\\Windows\\System32\\ntdll.dll" ascii wide nocase
        $ntdll_path2    = "\\SysWOW64\\ntdll.dll"          ascii wide nocase

        // NT function exports present in the clean copy
        $nt_alloc       = "NtAllocateVirtualMemory"        ascii
        $nt_create      = "NtCreateProcess"                ascii
        $nt_write       = "NtWriteVirtualMemory"           ascii
        $nt_protect     = "NtProtectVirtualMemory"         ascii
        $nt_thread      = "NtCreateThreadEx"               ascii

        // MZ header indicating a full PE loaded into the region
        $mz             = { 4D 5A }
        $pe             = { 50 45 00 00 }

        // Unhooking technique artifacts
        $map_view       = "NtMapViewOfSection"             ascii
        $create_section = "NtCreateSection"                ascii
        $read_file      = "NtReadFile"                     ascii

    condition:
        $mz at 0
        and $pe
        and 1 of ($ntdll_name, $ntdll_path1, $ntdll_path2)
        and 3 of ($nt_alloc, $nt_create, $nt_write, $nt_protect, $nt_thread)
}
