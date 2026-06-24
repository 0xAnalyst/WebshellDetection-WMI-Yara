/*
   Rule:   aspx_etw_amsi_patch.yar
   Desc:   Detects ASPX files that contain byte-patch sequences targeting
           EtwEventWrite (ETW telemetry blinding) and/or AmsiScanBuffer
           (AMSI bypass). Both patches overwrite the function prologue with
           a RET instruction (0xC3) or xor eax,eax / ret sequence to
           neutralise in-process scanning and EDR telemetry before execution.
           Catches ETWPatchShell.aspx, AMSIPatchShell.aspx, and
           WMI_Com_ETW_AMSI_Patch.aspx.
   Author: 0xAnalyst
   ATT&CK: T1562.001 (Disable or Modify Tools), T1562.006 (Indicator Blocking)
   Date:   2026-06-24
*/

rule ASPX_ETW_Patch
{
    meta:
        description     = "ASPX patches EtwEventWrite to blind ETW-based EDR telemetry"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1562.006"
        score           = 90

    strings:
        $aspx_tag       = "<%@"                          ascii

        // Target function name references
        $etw_func       = "EtwEventWrite"                ascii wide nocase
        $ntdll          = "ntdll"                        ascii wide nocase
        $ntdll_dll      = "ntdll.dll"                    ascii wide nocase

        // Byte-patch sequences: RET (0xC3) written via Marshal or unsafe pointer
        $ret_byte       = { C3 }
        $patch_marshal  = "Marshal.WriteByte"            ascii wide nocase
        $patch_copy     = "RtlCopyMemory"                ascii wide nocase
        $patch_protect  = "VirtualProtect"               ascii wide nocase

        // Unsafe pointer write pattern
        $unsafe_ptr     = /\*\s*\(\s*byte\s*\*\s*\)/    ascii

        // GetProcAddress used to locate target function
        $get_proc       = "GetProcAddress"               ascii wide nocase
        $get_module     = "GetModuleHandle"              ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $ntdll
        and $etw_func
        and ($patch_marshal or $patch_protect or $unsafe_ptr)
        and ($get_proc or $get_module)
}


rule ASPX_AMSI_Patch
{
    meta:
        description     = "ASPX patches AmsiScanBuffer to disable AMSI scanning in-process"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1562.001"
        score           = 90

    strings:
        $aspx_tag       = "<%@"                          ascii

        // AMSI target references
        $amsi_func      = "AmsiScanBuffer"               ascii wide nocase
        $amsi_dll       = "amsi.dll"                     ascii wide nocase

        // Patch mechanism
        $patch_marshal  = "Marshal.WriteByte"            ascii wide nocase
        $patch_protect  = "VirtualProtect"               ascii wide nocase
        $get_proc       = "GetProcAddress"               ascii wide nocase
        $load_lib       = "LoadLibrary"                  ascii wide nocase

        // Common patch payloads: xor eax,eax; ret  or  mov eax,0x80070057; ret
        $xor_ret        = { 33 C0 C3 }
        $mov_ret        = { B8 57 00 07 80 C3 }

    condition:
        filesize < 500KB
        and $aspx_tag
        and ($amsi_func or $amsi_dll)
        and (
            ($patch_marshal and ($get_proc or $load_lib))
            or ($patch_protect and $amsi_func)
            or $xor_ret
            or $mov_ret
        )
}


rule ASPX_ETW_AMSI_Combined
{
    meta:
        description     = "ASPX patches both ETW and AMSI before executing payload — combined evasion indicator"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1562.001, T1562.006"
        score           = 95

    strings:
        $aspx_tag       = "<%@"                          ascii
        $etw_func       = "EtwEventWrite"                ascii wide nocase
        $amsi_func      = "AmsiScanBuffer"               ascii wide nocase
        $patch_marshal  = "Marshal.WriteByte"            ascii wide nocase
        $get_proc       = "GetProcAddress"               ascii wide nocase
        $wmi_exec       = "Win32_Process"                ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $etw_func
        and $amsi_func
        and $patch_marshal
        and $get_proc
}
