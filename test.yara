rule Strela_Infostealer
{
    meta:
        author = "SocAlexElmi"
        description = "Detects Strela Infostealer malware"
        date = "2025-02-28"
        version = "1.1"
        reference = "https://github.com/SocAlexElmi/Yara-Rule-Strela"
    
    strings:
        $md5_1 = "9b2a4d4c5e1e8c33f9a7a1f537a8f1a9"
        $sha256_1 = "12e24ac0a515aedf3f6e3560ddcb8e35d4cceffeb96a3caffb4a1f9a6b7e2a51"
        $ip_1 = "193.143.1.231"
        $domain_1 = "strela-malware.com"

    condition:
        any of them
}
