rule Strela_Infostealer
{
    meta:
        author = "SocAlexElmi"
        description = "Detects Strela Infostealer malware"
        date = "2025-02-28"
        version = "1.0"
        reference = "https://github.com/SocAlexElmi/Yara-Rule-Strela"
    
    strings:
        $s1 = "StrelaStealer" ascii wide nocase
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        $s3 = "Content-Type: application/json" ascii
        $s4 = "POST /api/logs HTTP/1.1" ascii
        $s5 = "User-Agent" ascii

        // Hash delle stringhe offuscate tipiche di Strela
        $hex1 = { 68 74 74 70 73 3A 2F 2F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2E 63 6F 6D } // URL offuscato

    condition:
        uint16(0) == 0x5A4D and // Il file è un eseguibile PE
        all of ($s*) or $hex1
}
