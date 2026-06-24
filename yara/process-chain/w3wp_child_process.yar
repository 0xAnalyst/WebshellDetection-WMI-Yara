/*
   Rule:   w3wp_child_process.yar
   Desc:   Detects anomalous child processes spawned from w3wp.exe (IIS worker
           process). Designed for use with Sysmon Event ID 1 logs converted
           to a scannable format, or with memory-resident process tracking.
           Covers cmd.exe, powershell.exe, wscript.exe, cscript.exe, and
           common interpreter binaries.
   Author: 0xAnalyst
   ATT&CK: T1059.001 (PowerShell), T1059.003 (Windows Command Shell),
           T1505.003 (Web Shell)
   Date:   2026-06-24

   Usage:
     yara -r w3wp_child_process.yar /path/to/sysmon_logs/
     or integrate with Sysmon EID 1 in your SIEM as a string match.
*/

rule W3WP_Spawns_Shell
{
    meta:
        description     = "IIS worker process w3wp.exe spawned a command interpreter — likely webshell execution"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1059.001, T1059.003, T1505.003"
        score           = 85

    strings:
        // Parent process indicator (as seen in Sysmon EID 1 XML logs)
        $parent_w3wp    = "ParentImage"                  ascii wide nocase
        $w3wp           = "w3wp.exe"                     ascii wide nocase

        // Child process names — command interpreters
        $cmd            = "\\cmd.exe"                    ascii wide nocase
        $powershell     = "\\powershell.exe"             ascii wide nocase
        $pwsh           = "\\pwsh.exe"                   ascii wide nocase
        $wscript        = "\\wscript.exe"                ascii wide nocase
        $cscript        = "\\cscript.exe"                ascii wide nocase
        $mshta          = "\\mshta.exe"                  ascii wide nocase
        $sh             = "\\sh.exe"                     ascii wide nocase

    condition:
        $w3wp
        and $parent_w3wp
        and 1 of ($cmd, $powershell, $pwsh, $wscript, $cscript, $mshta, $sh)
}


rule W3WP_Spawns_Recon_Tool
{
    meta:
        description     = "IIS worker process spawned a reconnaissance or discovery tool — post-exploitation from webshell"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1057, T1018, T1505.003"
        score           = 80

    strings:
        $w3wp           = "w3wp.exe"                     ascii wide nocase
        $parent_w3wp    = "ParentImage"                  ascii wide nocase

        // Recon binaries
        $net            = "\\net.exe"                    ascii wide nocase
        $netstat        = "\\netstat.exe"                ascii wide nocase
        $whoami         = "\\whoami.exe"                 ascii wide nocase
        $ipconfig       = "\\ipconfig.exe"               ascii wide nocase
        $systeminfo     = "\\systeminfo.exe"             ascii wide nocase
        $tasklist       = "\\tasklist.exe"               ascii wide nocase
        $nltest         = "\\nltest.exe"                 ascii wide nocase
        $dsquery        = "\\dsquery.exe"                ascii wide nocase

    condition:
        $w3wp
        and $parent_w3wp
        and 1 of ($net, $netstat, $whoami, $ipconfig, $systeminfo, $tasklist, $nltest, $dsquery)
}
