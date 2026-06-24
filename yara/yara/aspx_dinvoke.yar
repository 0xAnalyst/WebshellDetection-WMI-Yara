/*
   Rule:   aspx_dinvoke.yar
   Desc:   Detects dynamic P/Invoke patterns in ASPX files where API names are
           resolved at runtime via GetProcAddress / LoadLibrary rather than
           declared with a static [DllImport] attribute. Catches
           CreateProcess_Dynamic.aspx and similar shells that avoid
           static string signatures by XOR-obfuscating the API name.
   Author: 0xAnalyst
   ATT&CK: T1106 (Native API), T1027 (Obfuscated Files or Information)
   Date:   2026-06-24
*/

import "pe"

rule ASPX_DynamicPInvoke_GetProcAddress
{
    meta:
        description     = "ASPX file resolves Win32 API at runtime via GetProcAddress — no static DllImport"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1106, T1027"
        score           = 75

    strings:
        // Runtime library loading
        $get_proc       = "GetProcAddress"           ascii wide nocase
        $load_lib       = "LoadLibrary"              ascii wide nocase
        $get_module     = "GetModuleHandle"          ascii wide nocase

        // Marshal-based delegate invocation (common dynamic P/Invoke pattern)
        $marshal_fp     = "Marshal.GetDelegateForFunctionPointer" ascii wide nocase
        $marshal_alloc  = "Marshal.AllocHGlobal"    ascii wide nocase

        // XOR decode loop indicators alongside API resolution
        $xor_loop       = /for\s*\([^)]+\)\s*\{[^}]*\^[^}]*\}/  ascii

        // Suspicious target APIs that are commonly obfuscated
        $api_create     = "CreateProcess"            ascii wide nocase
        $api_virtual    = "VirtualAlloc"             ascii wide nocase
        $api_write      = "WriteProcessMemory"       ascii wide nocase
        $api_thread     = "CreateRemoteThread"       ascii wide nocase

        // ASPX markers
        $aspx_tag       = "<%@"                      ascii
        $code_behind    = "System.Web"               ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $code_behind
        and (
            ($get_proc and $load_lib and 1 of ($api_*))
            or ($marshal_fp and $marshal_alloc)
            or ($get_proc and $xor_loop)
        )
}


rule ASPX_DynamicPInvoke_XorObfuscated
{
    meta:
        description     = "ASPX with XOR-obfuscated strings used alongside runtime API resolution — high confidence evasion"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1027, T1106"
        score           = 85

    strings:
        $aspx_tag       = "<%@"                      ascii
        $xor_decode     = /byte\[\][^;]+\^\s*0x[0-9a-fA-F]+/  ascii
        $b64_decode     = "Convert.FromBase64String" ascii wide nocase
        $get_proc       = "GetProcAddress"           ascii wide nocase
        $intptr         = "IntPtr"                   ascii wide nocase
        $delegate       = "Delegate"                 ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $get_proc
        and $intptr
        and $delegate
        and ($xor_decode or $b64_decode)
}
