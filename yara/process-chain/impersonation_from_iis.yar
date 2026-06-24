/*
   Rule:   impersonation_from_iis.yar
   Desc:   Detects ASPX shells that impersonate a logged-on user token
           and spawn processes under that identity using
           CreateProcessAsUser or ShellExecuteEx with the runas verb.
           These techniques break the parent-child process chain because
           the spawned process appears to originate from a different
           security context, defeating parent-lineage EDR rules.
           Catches CreateProcessAsUser_Impersonate.aspx and
           ShellExecuteEx_Runas.aspx.
   Author: 0xAnalyst
   ATT&CK: T1134.001 (Token Impersonation/Theft), T1548.002 (Bypass UAC)
   Date:   2026-06-24
*/

rule ASPX_CreateProcessAsUser_Impersonate
{
    meta:
        description     = "ASPX uses advapi32!CreateProcessAsUser with impersonated token to break parent-chain detection"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1134.001"
        score           = 85

    strings:
        $aspx_tag           = "<%@"                              ascii

        // Target API
        $create_as_user     = "CreateProcessAsUser"              ascii wide nocase
        $advapi             = "advapi32"                         ascii wide nocase

        // Token manipulation APIs
        $open_process_token = "OpenProcessToken"                 ascii wide nocase
        $duplicate_token    = "DuplicateTokenEx"                 ascii wide nocase
        $impersonate        = "ImpersonateLoggedOnUser"          ascii wide nocase
        $logon_user         = "LogonUser"                        ascii wide nocase

        // CREATE_SUSPENDED flag (0x00000004) — used to hollow/inject before resume
        $create_suspended   = "CREATE_SUSPENDED"                 ascii wide nocase
        $suspended_hex      = "0x00000004"                       ascii
        $suspended_int      = "4"                                ascii

        // Token access rights
        $token_dup          = "TOKEN_DUPLICATE"                  ascii wide nocase
        $token_query        = "TOKEN_QUERY"                      ascii wide nocase
        $token_all          = "TOKEN_ALL_ACCESS"                 ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $create_as_user
        and $advapi
        and (
            ($duplicate_token and 1 of ($open_process_token, $impersonate, $logon_user))
            or ($create_suspended and 1 of ($token_dup, $token_query, $token_all))
        )
}


rule ASPX_ShellExecuteEx_Runas
{
    meta:
        description     = "ASPX uses ShellExecuteEx with 'runas' verb and SW_HIDE — avoids CreateProcess logging, runs elevated"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1548.002"
        score           = 80

    strings:
        $aspx_tag           = "<%@"                              ascii

        $shell_ex           = "ShellExecuteEx"                   ascii wide nocase
        $shell32            = "shell32"                          ascii wide nocase

        // runas verb — triggers UAC elevation or alternate user execution
        $runas_verb         = "runas"                            ascii wide nocase

        // SW_HIDE (0) — hides the spawned window from user view
        $sw_hide            = "SW_HIDE"                         ascii wide nocase
        $sw_hide_zero       = "nShow = 0"                       ascii wide nocase
        $sw_hide_zero2      = "ShowWindow = 0"                  ascii wide nocase

        // SHELLEXECUTEINFO struct fields
        $sei_struct         = "SHELLEXECUTEINFO"                 ascii wide nocase
        $lpverb             = "lpVerb"                           ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $shell_ex
        and $shell32
        and $runas_verb
        and 1 of ($sw_hide, $sw_hide_zero, $sw_hide_zero2)
}
