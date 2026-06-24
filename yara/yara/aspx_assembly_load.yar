/*
   Rule:   aspx_assembly_load.yar
   Desc:   Detects ASPX files that load a .NET assembly from a byte array at
           runtime using Assembly.Load() or Assembly.LoadFrom(). Commonly
           combined with XOR or base64 decoding to carry the payload without
           touching disk. Catches InMemory_Assembly_XOR.aspx and similar
           reflective load shells.
   Author: 0xAnalyst
   ATT&CK: T1027 (Obfuscated Files), T1620 (Reflective Code Loading)
   Date:   2026-06-24
*/

rule ASPX_AssemblyLoad_InMemory
{
    meta:
        description     = "ASPX loads a .NET assembly from a byte array at runtime — no disk write"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1620, T1027"
        score           = 80

    strings:
        $aspx_tag       = "<%@"                          ascii
        $code_behind    = "System.Web"                   ascii wide nocase

        // Assembly loading methods
        $asm_load       = "Assembly.Load("               ascii wide nocase
        $asm_load_raw   = "Assembly.Load(new byte"       ascii wide nocase
        $asm_loadfrom   = "Assembly.LoadFrom"            ascii wide nocase
        $asm_refl       = "Assembly.ReflectionOnlyLoad"  ascii wide nocase

        // Reflection-based invocation after load
        $get_type       = "GetType("                     ascii wide nocase
        $get_method     = "GetMethod("                   ascii wide nocase
        $invoke         = ".Invoke("                     ascii wide nocase
        $entry_point    = "GetEntryPoint"                ascii wide nocase
        $create_inst    = "CreateInstance"               ascii wide nocase

        // Decode patterns that feed into Assembly.Load
        $xor_byte       = /\(\s*byte\s*\)\s*\([^)]+\^\s*0x[0-9a-fA-F]+\)/  ascii
        $b64_decode     = "Convert.FromBase64String"     ascii wide nocase
        $decompress     = "DeflateStream"                ascii wide nocase

    condition:
        filesize < 1MB
        and $aspx_tag
        and $code_behind
        and 1 of ($asm_*)
        and (
            (2 of ($get_type, $get_method, $invoke, $entry_point, $create_inst))
            or ($xor_byte and 1 of ($asm_*))
            or ($b64_decode and 1 of ($asm_*))
            or ($decompress and 1 of ($asm_*))
        )
}


rule ASPX_AssemblyLoad_XorEncoded
{
    meta:
        description     = "ASPX with XOR-encoded embedded byte array fed into Assembly.Load — high confidence in-memory loader"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1027, T1620"
        score           = 90

    strings:
        $aspx_tag       = "<%@"                      ascii
        $asm_load       = "Assembly.Load"            ascii wide nocase
        $xor_loop       = /for\s*\(\s*int\s+\w+\s*=\s*0[^)]+\)\s*\{[^}]*\^[^}]*\}/  ascii
        $byte_arr       = /byte\[\]\s+\w+\s*=\s*new\s+byte\s*\[/  ascii
        $invoke         = ".Invoke("                 ascii wide nocase

    condition:
        filesize < 1MB
        and $aspx_tag
        and $asm_load
        and $xor_loop
        and $byte_arr
        and $invoke
}
