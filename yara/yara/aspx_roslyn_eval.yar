/*
   Rule:   aspx_roslyn_eval.yar
   Desc:   Detects ASPX files that use the Roslyn scripting API
           (Microsoft.CodeAnalysis / CSharpScript) to compile and execute
           arbitrary C# code submitted at runtime. No disk write occurs —
           static signatures on the payload are impossible. Catches
           RoslynShell.aspx.
   Author: 0xAnalyst
   ATT&CK: T1027.010 (Command Obfuscation), T1059.001
   Date:   2026-06-24
*/

rule ASPX_Roslyn_RuntimeCompile
{
    meta:
        description     = "ASPX uses Roslyn CSharpScript to compile and execute C# at runtime — no disk artifact"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1027.010"
        score           = 85

    strings:
        $aspx_tag           = "<%@"                                      ascii

        // Roslyn scripting API imports
        $roslyn_ns          = "Microsoft.CodeAnalysis"                   ascii wide nocase
        $roslyn_csharp      = "Microsoft.CodeAnalysis.CSharp"            ascii wide nocase
        $roslyn_scripting   = "Microsoft.CodeAnalysis.CSharp.Scripting"  ascii wide nocase

        // Scripting entry points
        $csharp_script      = "CSharpScript"                             ascii wide nocase
        $script_eval        = "CSharpScript.EvaluateAsync"               ascii wide nocase
        $script_create      = "CSharpScript.Create"                      ascii wide nocase
        $script_run         = "Script.RunAsync"                          ascii wide nocase

        // Compilation API (lower-level Roslyn)
        $syntax_tree        = "SyntaxTree"                               ascii wide nocase
        $compilation        = "CSharpCompilation"                        ascii wide nocase
        $emit_stream        = ".Emit("                                   ascii wide nocase
        $memory_stream      = "MemoryStream"                             ascii wide nocase

        // Request parameter feeding the script (user-controlled input)
        $request_param      = "Request["                                 ascii wide nocase
        $request_form       = "Request.Form"                             ascii wide nocase
        $request_query      = "Request.QueryString"                      ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and (
            // Scripting API path
            ($csharp_script and 1 of ($script_*))
            or
            // Direct compilation API path
            ($syntax_tree and $compilation and $emit_stream and $memory_stream)
            or
            // Namespace import with eval
            ($roslyn_scripting and $script_eval)
        )
        and 1 of ($request_*)
}


rule ASPX_Roslyn_CompileAndLoad
{
    meta:
        description     = "ASPX uses Roslyn to compile C# to a MemoryStream then loads the resulting assembly — combined compile+reflect pattern"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1027.010, T1620"
        score           = 90

    strings:
        $aspx_tag       = "<%@"                          ascii
        $compilation    = "CSharpCompilation"            ascii wide nocase
        $emit           = ".Emit("                       ascii wide nocase
        $mem_stream     = "MemoryStream"                 ascii wide nocase
        $asm_load       = "Assembly.Load"                ascii wide nocase
        $to_array       = ".ToArray()"                   ascii wide nocase
        $invoke         = ".Invoke("                     ascii wide nocase

    condition:
        filesize < 500KB
        and $aspx_tag
        and $compilation
        and $emit
        and $mem_stream
        and $asm_load
        and $to_array
        and $invoke
}
