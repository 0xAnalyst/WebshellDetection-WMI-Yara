/*
   Rule:   network_detection.yar
   Desc:   Network-layer YARA rules for detecting webshell C2 traffic.
           Designed to run against PCAP files or network capture streams.
           Covers DNS-over-HTTPS (DoH) C2 channels and persistent WebSocket
           connections from IIS worker processes to external hosts.
           Run with: yara64.exe network_detection.yar capture.pcap
   Author: 0xAnalyst
   ATT&CK: T1071.001 (Web Protocols), T1071.004 (DNS)
   Date:   2026-06-24
*/

rule Network_DnsOverHTTPS_C2
{
    meta:
        description     = "DNS-over-HTTPS query with high-entropy or anomalous name field — potential DoH C2 channel"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1071.004"
        score           = 70

    strings:
        // DoH endpoints — Cloudflare, Google, Quad9
        $doh_cf         = "cloudflare-dns.com"           ascii
        $doh_google     = "dns.google"                   ascii
        $doh_quad9      = "dns.quad9.net"                ascii
        $doh_path       = "/dns-query"                   ascii

        // JSON DoH wire format
        $doh_json_name  = "\"name\":"                    ascii
        $doh_json_type  = "\"type\":"                    ascii
        $doh_ct         = "application/dns-json"         ascii

        // Suspicious: base64-like strings in DNS name field (encoded commands)
        $b64_in_name    = /\"name\"\s*:\s*\"[A-Za-z0-9+\/]{32,}={0,2}\"/  ascii

        // DNS wire format on port 443 — DoH framing
        $tls_header     = { 16 03 }
        $http2_magic    = { 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 }

        // Encoded payload patterns in the query name
        $xor_encoded    = /[a-z0-9\-]{50,}\.(com|net|io|co)/  ascii

    condition:
        (
            // JSON DoH with encoded name
            ($doh_path or 1 of ($doh_cf, $doh_google, $doh_quad9))
            and ($b64_in_name or ($doh_json_name and $xor_encoded))
        )
        or
        (
            // Wire-format DoH indicators
            $doh_ct
            and $doh_json_name
            and $b64_in_name
        )
}


rule Network_WebSocket_LongLived_IIS
{
    meta:
        description     = "WebSocket upgrade handshake followed by persistent connection — potential webshell C2 channel from IIS"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1071.001"
        score           = 65

    strings:
        // WebSocket upgrade request
        $ws_upgrade     = "Upgrade: websocket"           ascii nocase
        $ws_key         = "Sec-WebSocket-Key:"           ascii nocase
        $ws_version     = "Sec-WebSocket-Version:"       ascii nocase
        $ws_accept      = "Sec-WebSocket-Accept:"        ascii nocase

        // Server-side upgrade response
        $ws_101         = "HTTP/1.1 101"                 ascii
        $ws_proto       = "Sec-WebSocket-Protocol:"      ascii nocase

        // IIS server header — identifies origin as an IIS server (unusual to initiate WS outbound)
        $iis_server     = "Server: Microsoft-IIS"        ascii nocase
        $aspnet_header  = "X-Powered-By: ASP.NET"        ascii nocase

        // Suspicious: WebSocket from IIS to external with no Referer / Origin mismatch
        $no_origin      = "Origin: null"                 ascii nocase

        // WebSocket frame opcodes (binary/text) in data portion
        $ws_frame_bin   = { 82 }  // binary frame
        $ws_frame_txt   = { 81 }  // text frame

    condition:
        $ws_upgrade
        and $ws_key
        and ($ws_101 or $ws_accept)
        and (
            $iis_server
            or $aspnet_header
            or $no_origin
        )
}


rule Network_HeaderBased_C2
{
    meta:
        description     = "HTTP request with command payload embedded in User-Agent or custom headers — header-steganography C2"
        author          = "0xAnalyst"
        date            = "2026-06-24"
        reference       = "https://github.com/0xAnalyst/WebshellDetection-WMI-Yara"
        mitre_attack    = "T1071.001"
        score           = 70

    strings:
        // Anomalously long or base64-padded User-Agent
        $ua_b64         = /User-Agent: [A-Za-z0-9+\/]{60,}={0,2}\r\n/  ascii

        // Custom header used for command delivery
        $custom_hdr1    = "X-Command:"                   ascii nocase
        $custom_hdr2    = "X-Payload:"                   ascii nocase
        $custom_hdr3    = "X-Data:"                      ascii nocase
        $custom_hdr4    = "X-Token:"                     ascii nocase

        // Accept-Language with non-standard long values (encoded commands)
        $lang_encoded   = /Accept-Language: [A-Za-z0-9+\/\-_]{40,}/  ascii

        // Normal HTTP to ASPX endpoint
        $aspx_path      = ".aspx"                        ascii nocase
        $post_method    = "POST"                         ascii
        $get_method     = "GET"                          ascii

    condition:
        ($aspx_path and 1 of ($post_method, $get_method))
        and (
            $ua_b64
            or 1 of ($custom_hdr1, $custom_hdr2, $custom_hdr3, $custom_hdr4)
            or $lang_encoded
        )
}
