rule Strela_Infostealer {
    meta:
        description = "YARA rule to detect Strela Infostealer based on SHA256 hashes, domains, and IPs"
        author = "Automated Script"
        date = "2025-02-28"
        threat = "Strela Infostealer"
    
    strings:
        // SHA256 hashes
        $sha256_1 = "dcd7dd2aaef3e87b467ce4e4682a63d2d01da20e31fada494435ae8a921c09a"
        $sha256_2 = "75d996a0a5262bff134d7a752efd1fb6325bc2ce347b084967e06725008180f9"
        $sha256_3 = "c5279ff9c215afbd5c54793c6fc36c80d2cefb0342a1471581b15e43bd4a9b08"
        $sha256_4 = "be76ab2054ef174331abfef53825254ac26bfc9657dca9c3767a5e5daf7bec1e"
        $sha256_5 = "4e38abd0fef9a4b3f4cbc674601bc10766d4db588cb83d3e5fb50ec573c372cd"
        $sha256_6 = "08007bc4c3711990eddd7cb342d176f470298027d923589206e4c9212cc95ba3"
        $sha256_7 = "12cd832efcd3e3a6938ca5d445f572731b64866afc0129219d8110030aa22242"
        $sha256_8 = "150f490ae97098342e192a6722872e86d468cbd2fd8b3d6c46f4601acdea85d1"
        $sha256_9 = "154daf225df559d44d066027a5179aa68ebd9ce046787faa84bd3c230ad3fd08"
        $sha256_10 = "b9ae263904d3a5fb8471a0f8ab95fcbb224f632e6185e3a110e8d5aed9785420"
        $sha256_11 = "e6ff1872f3da3485fa55c36405abf69d8160b93b2d92cebcc06ec0ce064d054d"

        // Domains
        $domain_1 = "vaultdocker.com"
        $domain_2 = "cloudslimit.com"
        $domain_3 = "dailywebstats.com"
        $domain_4 = "endpointexperiment.com"
        $domain_5 = "apitestlabs.com"

        // IPs
        $ip_1 = "94.159.113.48"
        $ip_2 = "193.143.1.231"

    condition:
        any of them
}
