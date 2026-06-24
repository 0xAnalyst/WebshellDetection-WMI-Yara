/*
   Rule:   lolbin_from_iis.yar
   Desc:   Detects Living-off-the-Land Binary (LOLBin) abuse where trusted
           Windows binaries are launched from an IIS worker process context.
           Covers MSBuild, regsvr32, mshta, certutil, bitsadmin, rundll32,
           regasm, regsvcs, and installutil — all commonly abused to proxy
           execution and evade application whitelisting.
   Author: 0xAnalyst
   ATT&CK: T1127.001 (MSBuild), T1218 (Signed Binary Proxy Execution)
   Date:   2026-06-24
*/

rule LOLBin_From_IIS_Worker
{
    meta:
        description     = "A trusted LOLBin was executed from w3wp.exe — signed binary proxy execution via webshell"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1127.001, T1218"
        score           = 85

    strings:
        $w3wp           = "w3wp.exe"                     ascii wide nocase
        $parent_field   = "ParentImage"                  ascii wide nocase

        // LOLBins commonly abused for proxy execution
        $msbuild        = "\\MSBuild.exe"                ascii wide nocase
        $regsvr32       = "\\regsvr32.exe"               ascii wide nocase
        $mshta          = "\\mshta.exe"                  ascii wide nocase
        $certutil       = "\\certutil.exe"               ascii wide nocase
        $bitsadmin      = "\\bitsadmin.exe"              ascii wide nocase
        $rundll32       = "\\rundll32.exe"               ascii wide nocase
        $regasm         = "\\regasm.exe"                 ascii wide nocase
        $regsvcs        = "\\regsvcs.exe"                ascii wide nocase
        $installutil    = "\\installutil.exe"            ascii wide nocase
        $cmstp          = "\\cmstp.exe"                  ascii wide nocase
        $wmic           = "\\wmic.exe"                   ascii wide nocase
        $forfiles       = "\\forfiles.exe"               ascii wide nocase
        $pcalua         = "\\pcalua.exe"                 ascii wide nocase

    condition:
        $w3wp
        and $parent_field
        and 1 of (
            $msbuild, $regsvr32, $mshta, $certutil, $bitsadmin,
            $rundll32, $regasm, $regsvcs, $installutil, $cmstp,
            $wmic, $forfiles, $pcalua
        )
}


rule MSBuild_Inline_Task_From_IIS
{
    meta:
        description     = "MSBuild launched with an inline task .proj file from IIS context — LOLBin C# compile-and-run"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1127.001"
        score           = 90

    strings:
        $w3wp           = "w3wp.exe"                     ascii wide nocase
        $msbuild        = "MSBuild.exe"                  ascii wide nocase
        // .proj or .csproj arguments in command line
        $proj_ext       = ".proj"                        ascii wide nocase
        $csproj_ext     = ".csproj"                      ascii wide nocase
        $temp_path      = "\\Temp\\"                     ascii wide nocase
        $appdata_path   = "\\AppData\\"                  ascii wide nocase

    condition:
        $w3wp
        and $msbuild
        and 1 of ($proj_ext, $csproj_ext)
        and 1 of ($temp_path, $appdata_path)
}
