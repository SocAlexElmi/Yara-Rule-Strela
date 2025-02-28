rule StrelaInfostealer 
{
    meta:
        author = "AF"
        date = "2025-02-28"
        source = "https://github.com/SocAlexElmi/Yara-Rule-Strela"
    strings:
        $str0 = ""
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 2MB and
        all of them
}
