rule Strela {
    meta:
        description = "Regola detection Strela Infostealer"
        author = "Alex Flores"
        date = "2025-03-02"
    strings:
        //Strela Infostealer IOC List
        $ioc_SHA256 = "SHA256"
        $ioc_1 = "dcd7dd2aaef3e87b467ce4e4682a63d2d01da20e31fada494435ae8a921c09a"
        $ioc_2 = "75d996a0a5262bff134d7a752efd1fb6325bc2ce347b084967e06725008180f9"
        $ioc_3 = "c5279ff9c215afbd5c54793c6fc36c80d2cefb0342a1471581b15e43bd4a9b08"
        $ioc_4 = "be76ab2054ef174331abfef53825254ac26bfc9657dca9c3767a5e5daf7bec1e"
        $ioc_5 = "4e38abd0fef9a4b3f4cbc674601bc10766d4db588cb83d3e5fb50ec573c372cd"
        $ioc_6 = "08007bc4c3711990eddd7cb342d176f470298027d923589206e4c9212cc95ba3"
        $ioc_7 = "12cd832efcd3e3a6938ca5d445f572731b64866afc0129219d8110030aa22242"
        $ioc_8 = "150f490ae97098342e192a6722872e86d468cbd2fd8b3d6c46f4601acdea85d1"
        $ioc_9 = "154daf225df559d44d066027a5179aa68ebd9ce046787faa84bd3c230ad3fd08"
        $ioc_10 = "16ae254deaa02b0acf5beda73cb178eb5c50e50b8d1752841ae8148b28354585"
        $ioc_11 = "1a60dd873e71c926ede3bc395e45e10062f063a374f05e7ff6721b6e35706ec5"
        $ioc_12 = "1f3b7fb2ec7e3f292a9d5fab2e263c777c4273af872673d324d580387a5f3236"
        $ioc_13 = "22d34569742fc22c109f65a2edc8ef264c44f61e20014ac27160931acfba296c"
        $ioc_14 = "294c66460c3b0da83a3ed894bd1fb8a7fc5fed2b8fb3f6adb555d4b558371f00"
        $ioc_15 = "2c447b38bc71b6b68234e3f7ea389807a9d61597aab5a11cc60133ee01fb7b79"
        $ioc_16 = "3078f89fa189af1fc8d9b76ab03e2ae34de080072057d5630f8d829c18e0b29b"
        $ioc_17 = "32b8f94f5f7f359a3ef758a8de8ed554c7e5dec2b75f9a65461167eaa874cd00"
        $ioc_18 = "34e9df65677f7e89fd3514103d9a75f7fb526485f1c8fa3bf82fe8896991683a"
        $ioc_19 = "34fdf466af7288f0b458daaca9eb76be88e182ae1b2eadb3281371c2d6726bc3"
        $ioc_20 = "36a0751216fc7f90559abb10dcec2c1153e70c9d4da4d06a0a206ec2e726b92f"
        $ioc_21 = "37984a476fdeda094cdb82957a5aa0d2835527c4f403775d5e0182c64cb1a7fb"
        $ioc_22 = "3c09514e197004d822fd26798372cd7dc30ddcc7fe5585a8a13475319f57e7de"
        $ioc_23 = "3fe89e89556c0210bfb5094a524b1f81c87cde6b6bb2320abbe61d68ac6c4a4b"
        $ioc_24 = "404341b290e56b21c74d5768a98580813f5e81a5ef2e97e1af7aec6cb2a719b0"
        $ioc_25 = "4781f4c8a8a43b559d1c1452e0e967cd23f7fd3d41a1065e5a3ec3366e3bf496"
        $ioc_26 = "4a2317a78749539a8bf0d1e134bd68f64a5e956dee9a12157028969949bb29c4"
        $ioc_27 = "4eaf2d0023d9531ee9e0d3958014260d95b817af5e74b9c6819f371a1a5af753"
        $ioc_28 = "50c9bd0f5deca0b2edbc4128aa7895ec0268a246e536110efe81e3a3da696b0c"
        $ioc_29 = "540492ee7e2e3a0036bc34ff47519a17ad6a8300319b1ff9a1d1a210333cb46d"
        $ioc_30 = "58b0ae24a7f325b8c3acd001b4bdff35fc7e440a0bb910750e019a2657de0822"
        $ioc_31 = "59894ed00aaa9f8ab743ea09a1c7add38b7bf378b073aea978fb1703ea9aacdd"
        $ioc_32 = "59c8dcd99af398b149bfd80b921e1b06f97e8cc6908d806b174341efb899d647"
        $ioc_33 = "5a3633e0aad62b5ca063e3ffb15a2bbcdf7138f82113299b53f8194525cb32a3"
        $ioc_34 = "5b296616d0cd44147e84e638dffed68d07b305bcee60601147bf41cb01e8c038"
        $ioc_35 = "5c3a86bd9fb12cad7a98041d1ff35ac739b41a9e43abc525c4e96d61be6f9565"
        $ioc_36 = "6044ea92d233b14cc6422e1cea8ee7ea8e241812f3e780f57f096101e5917f8a"
        $ioc_37 = "662a2a870928dc42d9cd04dbbb7a948300c98496bf4f68aa7ce1320d93da3180"
        $ioc_38 = "666060f975e34e610bea2a3e2a6c8bad58506bee6acfbaefd2c02e563736351f"
        $ioc_39 = "67e95381a8d220063ea1a44e75bc9c9c2e0d973fb991c0ce92a798a1bfe23c1d"
        $ioc_40 = "680ea9c726dbfb5b8486ef5b5babb63704f32b4e3e949053b13a344440fe5149"
        $ioc_41 = "68ffebea33905d680c382b4df481c564817044cf41345f41166cfaca106abfee"
        $ioc_42 = "6cb21cba9555eec2a173719188ffa609f3f99b6f615ada694db3e2de7fa4d9fe"
        $ioc_43 = "70f500e1941ce7f0ae0d4c12c44f3e265c701c1169193a55e5f842c093f303cc"
        $ioc_44 = "72c9297608f3ccb059aec33126178e40bd343c3c24b14a8a31a7742757a08a00"
        $ioc_45 = "760c12ae673ae8902dfa096c17bbce7fc3e20eec069b7cc00d6bf1dd4a28757b"
        $ioc_46 = "76972fe36498d115bbcb742d842698fea1ebc062d0f79426dfbcaf4ad8bec0bd"
        $ioc_47 = "78c315657a6dd2d6ca01388aa3575344b689cbd18c172d83fe94399156b8010b"
        $ioc_48 = "7fcf23ad9d241ccd8f46a9a65bdd99741bade2bf323599f5639ebf160d35aa1e"
        $ioc_8502cf3b180e3ee6e526b5b33e17647d7234773c278d9009a6ae58a01fd96b97 = "8502cf3b180e3ee6e526b5b33e17647d7234773c278d9009a6ae58a01fd96b97"
        $ioc_8661d72b99ae335b6c0c74e2d2f156f8611666fe7f118ae251e224c8602f72f2 = "8661d72b99ae335b6c0c74e2d2f156f8611666fe7f118ae251e224c8602f72f2"
        $ioc_8ba18307df322c7c930dc19ff5f3a36b6a9040cc0dd05e65c1a434887a407b70 = "8ba18307df322c7c930dc19ff5f3a36b6a9040cc0dd05e65c1a434887a407b70"
        $ioc_9082620184a4fe05ed92a0e88caea02cfec14d4c6494dc55269d8afade95d352 = "9082620184a4fe05ed92a0e88caea02cfec14d4c6494dc55269d8afade95d352"
        $ioc_9255e44bcf40afa3c3fbd19f13a1d277c3bd7bd457866e904b220779fadce886 = "9255e44bcf40afa3c3fbd19f13a1d277c3bd7bd457866e904b220779fadce886"
        $ioc_93fc8a04b28af9feb86c348c9b3a7d8422729697832e6895f8738b663da32905 = "93fc8a04b28af9feb86c348c9b3a7d8422729697832e6895f8738b663da32905"
        $ioc_9a9303997fefb2de0a66db9652d53bce7d17b9a1e8e738ee91801a29f72621d6 = "9a9303997fefb2de0a66db9652d53bce7d17b9a1e8e738ee91801a29f72621d6"
        $ioc_9aefb3b5e3a0727c6d96b103c432acb57c42294373bbd8d984a8aeb94659cd43 = "9aefb3b5e3a0727c6d96b103c432acb57c42294373bbd8d984a8aeb94659cd43"
        $ioc_9eb4a88bc7ba156af849fcd956744c65677372db5e5cb09115df8ec900928cbb = "9eb4a88bc7ba156af849fcd956744c65677372db5e5cb09115df8ec900928cbb"
        $ioc_9fc8d64d8204045764d0990647d42cb386c98501199553d043c277133549193a = "9fc8d64d8204045764d0990647d42cb386c98501199553d043c277133549193a"
        $ioc_a09688c0ce051235e92bb938090eebedea57c706158e0b665edce17d8dbe7543 = "a09688c0ce051235e92bb938090eebedea57c706158e0b665edce17d8dbe7543"
        $ioc_a0def4009d3d6444b05f8d4071a65fbba6b6b36176104fc1fbb04affd0282969 = "a0def4009d3d6444b05f8d4071a65fbba6b6b36176104fc1fbb04affd0282969"
        $ioc_a21f6c960cb3a702a9cf1da645301688b98763a8d1a4269a6b010616477e742f = "a21f6c960cb3a702a9cf1da645301688b98763a8d1a4269a6b010616477e742f"
        $ioc_a76fc70044c88c9313da07e3afa039640373c639ac16ae85ddef201fa5995ce3 = "a76fc70044c88c9313da07e3afa039640373c639ac16ae85ddef201fa5995ce3"
        $ioc_a77cd7dcea434bea2ce6dbc1af32668007c0fc5168a325c0c9df8f976d47ae0c = "a77cd7dcea434bea2ce6dbc1af32668007c0fc5168a325c0c9df8f976d47ae0c"
        $ioc_b0f2cff2784b1779a9688a3cd43436d272683554b356d2a6f75903e40ce680ed = "b0f2cff2784b1779a9688a3cd43436d272683554b356d2a6f75903e40ce680ed"
        $ioc_b2efbb7368a89a746f5f1aea8e3df16cb017b4f79e0a6c3c1aaf51a7437cdd1b = "b2efbb7368a89a746f5f1aea8e3df16cb017b4f79e0a6c3c1aaf51a7437cdd1b"
        $ioc_b5f9dff76d3cdf16ad8c95e699a4dd347e2bf987d7b9a4601b4bb6b7505a560f = "b5f9dff76d3cdf16ad8c95e699a4dd347e2bf987d7b9a4601b4bb6b7505a560f"
        $ioc_c1503c63332d723bc67acdc8de2fbaffb92b11de8174030eaf863d7ed152f947 = "c1503c63332d723bc67acdc8de2fbaffb92b11de8174030eaf863d7ed152f947"
        $ioc_c55f10a2633aa6c7f5e246cee23ed04e73896f88a042c070a6c66698dc8b1f3e = "c55f10a2633aa6c7f5e246cee23ed04e73896f88a042c070a6c66698dc8b1f3e"
        $ioc_ca3a8107b0c1ecf1a9f258e5b155a652e81710a2fa910bfd5ed31305a10ed06f = "ca3a8107b0c1ecf1a9f258e5b155a652e81710a2fa910bfd5ed31305a10ed06f"
        $ioc_ca6446b428305c1845b87a4562c4ef24d99e5929a2a65101689ca473b0bbec43 = "ca6446b428305c1845b87a4562c4ef24d99e5929a2a65101689ca473b0bbec43"
        $ioc_d3b78c9fdf7df019c14a21c18f4ca27c4210f31191ba5f35de358373b4077d43 = "d3b78c9fdf7df019c14a21c18f4ca27c4210f31191ba5f35de358373b4077d43"
        $ioc_d40dbeaf32abed1610e11408953ddddad985cea279b86c31a27b841519112bfb = "d40dbeaf32abed1610e11408953ddddad985cea279b86c31a27b841519112bfb"
        $ioc_e2fa1484fa6cccfdae5838e59f4516017c3cd15e4872db0e459c43c8c8076882 = "e2fa1484fa6cccfdae5838e59f4516017c3cd15e4872db0e459c43c8c8076882"
        $ioc_ea090dccb35324c998ac5c2e3e499ed4c3812372cd6936777a9b4d10f8329c6 = "ea090dccb35324c998ac5c2e3e499ed4c3812372cd6936777a9b4d10f8329c6"
        $ioc_ee5cee0d57239e192cde8a52398172b515148969e4f6fc4bcf89de24aedafd4b = "ee5cee0d57239e192cde8a52398172b515148969e4f6fc4bcf89de24aedafd4b"
        $ioc_f2708c2b771610ecda87d43c409a943fc4df6cdb090737ea47017f5ea4fc6a85 = "f2708c2b771610ecda87d43c409a943fc4df6cdb090737ea47017f5ea4fc6a85"
        $ioc_f68522b21d226a9d7ab91105e4412ea3ad836801e090e1e6dce766def233c60 = "f68522b21d226a9d7ab91105e4412ea3ad836801e090e1e6dce766def233c60"
        $ioc_f85dbbb00236db3abcc3383f2708fa4f53f5a464a62c4338391f513f49ea8b76 = "f85dbbb00236db3abcc3383f2708fa4f53f5a464a62c4338391f513f49ea8b76"
        $ioc_fc9617a69ee597606fbc68a5280819e48c9679b1d44d09f86cb4b62b68835209 = "fc9617a69ee597606fbc68a5280819e48c9679b1d44d09f86cb4b62b68835209"
        $ioc_fd407ac4d456c2196b128587347d85856989faec188334a8fbc4469f4b4e6ef2 = "fd407ac4d456c2196b128587347d85856989faec188334a8fbc4469f4b4e6ef2"
        $ioc_fed183856e7f09bb9f73d8c9d57bd3573ec846da1a49dc1eeb295c845007f5a2 = "fed183856e7f09bb9f73d8c9d57bd3573ec846da1a49dc1eeb295c845007f5a2"
        $ioc_ffdf20ae5a3124a69711eb46b11b01bed6cffb66aef711732f96ddb4546cb635 = "ffdf20ae5a3124a69711eb46b11b01bed6cffb66aef711732f96ddb4546cb635"
        $ioc_ffe0ff011712afeb8ebc70e09bb455cc6fdd36c8d3b31004d25dc1cd8cc74b8f = "ffe0ff011712afeb8ebc70e09bb455cc6fdd36c8d3b31004d25dc1cd8cc74b8f"
        $ioc_04f2cd6ddf9faef579d303c5efd2fc65b9997e05c3f75ea9b0cfc474f5e9019a = "04f2cd6ddf9faef579d303c5efd2fc65b9997e05c3f75ea9b0cfc474f5e9019a"
        $ioc_13d96ed827887f6c31d907a5ee29441e2afd95be683e51e874cf5ad8207c1a98 = "13d96ed827887f6c31d907a5ee29441e2afd95be683e51e874cf5ad8207c1a98"
        $ioc_1970d38e7fa45a46e792372a19d890541c87d1007ddedd53858b6df6728d72ff = "1970d38e7fa45a46e792372a19d890541c87d1007ddedd53858b6df6728d72ff"
        $ioc_dbd301f710d45acdd639cda5cd47a5453b9abb8a361ed250bfc47de70318fec6 = "dbd301f710d45acdd639cda5cd47a5453b9abb8a361ed250bfc47de70318fec6"
        $ioc_13531bd403e5f8f607bf16144c38ffd94004eafa8e6a098628b915de07ba432b = "13531bd403e5f8f607bf16144c38ffd94004eafa8e6a098628b915de07ba432b"
        $ioc_080caffde331496a46e8cb35acd107ed113046b46310747a2dd15a62efab23b5 = "080caffde331496a46e8cb35acd107ed113046b46310747a2dd15a62efab23b5"
        $ioc_bd26724bdc8c5d9cb65d361231048725fbc31072d4c457c23531bc4333460011 = "bd26724bdc8c5d9cb65d361231048725fbc31072d4c457c23531bc4333460011"
        $ioc_77836c0b18bbfef70fd04ba674ea045bf109851efe76ae9bcc55c2dcd08cc3c5 = "77836c0b18bbfef70fd04ba674ea045bf109851efe76ae9bcc55c2dcd08cc3c5"
        $ioc_03853c56bcfdf87d71ba4e17c4f6b55f989edb29fc1db2c82de3d50be99d7311 = "03853c56bcfdf87d71ba4e17c4f6b55f989edb29fc1db2c82de3d50be99d7311"
        $ioc_cd39bec789b79d9ea6a642ab2ddc93121f5596de21e3b13c335ceaddb83f2083 = "cd39bec789b79d9ea6a642ab2ddc93121f5596de21e3b13c335ceaddb83f2083"
        $ioc_b9ae263904d3a5fb8471a0f8ab95fcbb224f632e6185e3a110e8d5aed9785420 = "b9ae263904d3a5fb8471a0f8ab95fcbb224f632e6185e3a110e8d5aed9785420"
        $ioc_e6ff1872f3da3485fa55c36405abf69d8160b93b2d92cebcc06ec0ce064d054d = "e6ff1872f3da3485fa55c36405abf69d8160b93b2d92cebcc06ec0ce064d054d"
        $ioc_Domains = "Domains"
        $ioc_vaultdocker[.]com = "vaultdocker[.]com"
        $ioc_cloudslimit[.]com = "cloudslimit[.]com"
        $ioc_dailywebstats[.]com = "dailywebstats[.]com"
        $ioc_endpointexperiment[.]com = "endpointexperiment[.]com"
        $ioc_apitestlabs[.]com = "apitestlabs[.]com"
        $ioc_IP = "IP"
        $ioc_94[.]159[.]113[.]48 = "94[.]159[.]113[.]48"
        $ioc_193[.]143[.]1[.]231 = "193[.]143[.]1[.]231"
    condition:
        any of them
}
