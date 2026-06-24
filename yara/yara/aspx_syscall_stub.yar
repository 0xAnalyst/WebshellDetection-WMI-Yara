/*
   Rule:   aspx_syscall_stub.yar
   Desc:   Detects ASPX files containing direct syscall stubs or Heaven's Gate
           (WOW64 far-call) patterns. These bypass EDR user-land hooks on ntdll
           by calling the kernel directly without going through the hooked
           ntdll function. Catches WinExec_Syscall.aspx and SyscallShell.aspx.
   Author: 0xAnalyst
   ATT&CK: T1055 (Process Injection), T1562.006 (Indicator Blocking)
   Date:   2026-06-24
*/

rule ASPX_DirectSyscall_Stub
{
    meta:
        description     = "ASPX embeds direct syscall stubs to bypass ntdll user-land hooks"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1055, T1562.006"
        score           = 90

    strings:
        $aspx_tag       = "<%@"                          ascii

        // x64 syscall instruction sequences embedded as byte arrays
        // mov r10, rcx; mov eax, <SSN>; syscall; ret
        $syscall_seq1   = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        // syscall; ret minimal stub
        $syscall_seq2   = { 0F 05 C3 }
        // int 2e (alternative syscall on older Windows)
        $int2e_seq      = { CD 2E C3 }

        // Heaven's Gate: far call to 0x33 segment (32->64 bit transition)
        $heavens_gate   = { 6A 33 E8 00 00 00 00 83 04 24 05 CB }
        $far_call_33    = { FF ?? 33 00 00 00 }

        // Byte array declarations feeding into syscall stubs
        $byte_stub      = /byte\[\]\s+\w+\s*=\s*new\s+byte\s*\[\s*\d+\s*\]\s*\{(\s*0x[0-9a-fA-F]{1,2}\s*,?\s*){5,}/  ascii

        // VirtualAlloc + executable memory for stub injection
        $valloc         = "VirtualAlloc"                 ascii wide nocase
        $mem_exec       = "PAGE_EXECUTE_READWRITE"       ascii wide nocase
        $mem_exec_hex   = "0x40"                         ascii

        // Syscall-related NT function names (used to look up SSN)
        $nt_alloc       = "NtAllocateVirtualMemory"      ascii wide nocase
        $nt_create      = "NtCreateProcess"              ascii wide nocase
        $nt_write       = "NtWriteVirtualMemory"         ascii wide nocase
        $nt_protect     = "NtProtectVirtualMemory"       ascii wide nocase
        $nt_thread      = "NtCreateThreadEx"             ascii wide nocase

        // Marshal function pointer for stub invocation
        $marshal_fp     = "Marshal.GetDelegateForFunctionPointer" ascii wide nocase
        $aspx_marker    = "System.Web"                   ascii wide nocase

    condition:
        filesize < 1MB
        and $aspx_tag
        and $aspx_marker
        and (
            // Direct byte-sequence match inside file
            (1 of ($syscall_seq*, $int2e_seq, $heavens_gate, $far_call_33))
            or
            // Indirect: byte stub + executable memory + NT function reference
            ($byte_stub and $valloc and 1 of ($nt_*))
            or
            // Marshal delegate + syscall NT function + executable alloc
            ($marshal_fp and $valloc and 1 of ($nt_*))
        )
}


rule ASPX_HeavensGate_WOW64
{
    meta:
        description     = "ASPX uses Heaven's Gate WOW64 far-call to transition to 64-bit and invoke syscall directly"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1055, T1562.006"
        score           = 95

    strings:
        $aspx_tag       = "<%@"                          ascii
        // Far jmp/call to CS selector 0x33
        $hg1            = { EA ?? ?? ?? ?? 33 00 }
        $hg2            = { FF 2D ?? ?? ?? ?? }
        $hg3            = "Heaven" nocase ascii
        $hg4            = "WOW64"  nocase ascii
        $syscall        = { 0F 05 }
        $valloc         = "VirtualAlloc"  ascii wide nocase

    condition:
        filesize < 1MB
        and $aspx_tag
        and $valloc
        and (
            1 of ($hg1, $hg2)
            or ($hg3 and $syscall)
            or ($hg4 and $syscall)
        )
}
