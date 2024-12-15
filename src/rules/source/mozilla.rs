use crate::*;
pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[
/*
serial=0D6A5F083F285C3E5195DF5D
issuer=C = US, ST = Illinois, L = Chicago, O = "Trustwave Holdings, Inc.", CN = Trustwave Global ECC P256 Certification Authority
sha1 Fingerprint=B4:90:82:DD:45:0C:BE:8B:5B:B1:66:D3:E2:A4:08:26:CD:ED:42:CF
sha256 Fingerprint=94:5B:BC:82:5E:A5:54:F4:89:D1:FD:51:A7:3D:DF:2E:A6:24:AC:70:19:A0:52:05:22:5C:22:A7:8C:CF:A8:B4
*/
Fingerprint::SHA256(hex!("945bbc825ea554f489d1fd51a73ddf2ea624ac7019a05205225c22a78ccfa8b4")),


/*
serial=08BD85976C9927A48068473B
issuer=C = US, ST = Illinois, L = Chicago, O = "Trustwave Holdings, Inc.", CN = Trustwave Global ECC P384 Certification Authority
sha1 Fingerprint=E7:F3:A3:C8:CF:6F:C3:04:2E:6D:0E:67:32:C5:9E:68:95:0D:5E:D2
sha256 Fingerprint=55:90:38:59:C8:C0:C3:EB:B8:75:9E:CE:4E:25:57:22:5F:F5:75:8B:BD:38:EB:D4:82:76:60:1E:1B:D5:80:97
*/
Fingerprint::SHA256(hex!("55903859c8c0c3ebb8759ece4e2557225ff5758bbd38ebd48276601e1bd58097")),


/*
serial=0194301EA20BDDF5C5332AB1434471F8D6504D0D
issuer=C = KR, O = NAVER BUSINESS PLATFORM Corp., CN = NAVER Global Root Certification Authority
sha1 Fingerprint=8F:6B:F2:A9:27:4A:DA:14:A0:C4:F4:8E:61:27:F9:C0:1E:78:5D:D1
sha256 Fingerprint=88:F4:38:DC:F8:FF:D1:FA:8F:42:91:15:FF:E5:F8:2A:E1:E0:6E:0C:70:C3:75:FA:AD:71:7B:34:A4:9E:72:65
*/
Fingerprint::SHA256(hex!("88f438dcf8ffd1fa8f429115ffe5f82ae1e06e0c70c375faad717b34a49e7265")),


/*
serial=62F6326CE5C4E3685C1B62DD9C2E9D95
issuer=C = ES, O = FNMT-RCM, OU = Ceres, organizationIdentifier = VATES-Q2826004J, CN = AC RAIZ FNMT-RCM SERVIDORES SEGUROS
sha1 Fingerprint=62:FF:D9:9E:C0:65:0D:03:CE:75:93:D2:ED:3F:2D:32:C9:E3:E5:4A
sha256 Fingerprint=55:41:53:B1:3D:2C:F9:DD:B7:53:BF:BE:1A:4E:0A:E0:8D:0A:A4:18:70:58:FE:60:A2:B8:62:B2:E4:B8:7B:CB
*/
Fingerprint::SHA256(hex!("554153b13d2cf9ddb753bfbe1a4e0ae08d0aa4187058fe60a2b862b2e4b87bcb")),


/*
serial=11D2BBB9D723189E405F0A9D2DD0DF2567D1
issuer=C = BE, O = GlobalSign nv-sa, CN = GlobalSign Root R46
sha1 Fingerprint=53:A2:B0:4B:CA:6B:D6:45:E6:39:8A:8E:C4:0D:D2:BF:77:C3:A2:90
sha256 Fingerprint=4F:A3:12:6D:8D:3A:11:D1:C4:85:5A:4F:80:7C:BA:D6:CF:91:9D:3A:5A:88:B0:3B:EA:2C:63:72:D9:3C:40:C9
*/
Fingerprint::SHA256(hex!("4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9")),


/*
serial=11D2BBBA336ED4BCE62468C50D841D98E843
issuer=C = BE, O = GlobalSign nv-sa, CN = GlobalSign Root E46
sha1 Fingerprint=39:B4:6C:D5:FE:80:06:EB:E2:2F:4A:BB:08:33:A0:AF:DB:B9:DD:84
sha256 Fingerprint=CB:B9:C4:4D:84:B8:04:3E:10:50:EA:31:A6:9F:51:49:55:D7:BF:D2:E2:C6:B4:93:01:01:9A:D6:1D:9F:50:58
*/
Fingerprint::SHA256(hex!("cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058")),


/*
serial=5A4BBD5AFB4F8A5BFA65E5
issuer=C = AT, O = e-commerce monitoring GmbH, CN = GLOBALTRUST 2020
sha1 Fingerprint=D0:67:C1:13:51:01:0C:AA:D0:C7:6A:65:37:31:16:26:4F:53:71:A2
sha256 Fingerprint=9A:29:6A:51:82:D1:D4:51:A2:E3:7F:43:9B:74:DA:AF:A2:67:52:33:29:F9:0F:9A:0D:20:07:C3:34:E2:3C:9A
*/
Fingerprint::SHA256(hex!("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")),


/*
serial=0DD3E3BC6CF96BB1
issuer=serialNumber = G63287510, C = ES, O = ANF Autoridad de Certificacion, OU = ANF CA Raiz, CN = ANF Secure Server Root CA
sha1 Fingerprint=5B:6E:68:D0:CC:15:B6:A0:5F:1E:C1:5F:AE:02:FC:6B:2F:5D:6F:74
sha256 Fingerprint=FB:8F:EC:75:91:69:B9:10:6B:1E:51:16:44:C6:18:C5:13:04:37:3F:6C:06:43:08:8D:8B:EF:FD:1B:99:75:99
*/
Fingerprint::SHA256(hex!("fb8fec759169b9106b1e511644c618c51304373f6c0643088d8beffd1b997599")),


/*
serial=788F275C81125220A504D02DDDBA73F4
issuer=C = PL, O = Asseco Data Systems S.A., OU = Certum Certification Authority, CN = Certum EC-384 CA
sha1 Fingerprint=F3:3E:78:3C:AC:DF:F4:A2:CC:AC:67:55:69:56:D7:E5:16:3C:E1:ED
sha256 Fingerprint=6B:32:80:85:62:53:18:AA:50:D1:73:C9:8D:8B:DA:09:D5:7E:27:41:3D:11:4C:F7:87:A0:F5:D0:6C:03:0C:F6
*/
Fingerprint::SHA256(hex!("6b328085625318aa50d173c98d8bda09d57e27413d114cf787a0f5d06c030cf6")),


/*
serial=1EBF5950B8C980374C06F7EB554FB5ED
issuer=C = PL, O = Asseco Data Systems S.A., OU = Certum Certification Authority, CN = Certum Trusted Root CA
sha1 Fingerprint=C8:83:44:C0:18:AE:9F:CC:F1:87:B7:8F:22:D1:C5:D7:45:84:BA:E5
sha256 Fingerprint=FE:76:96:57:38:55:77:3E:37:A9:5E:7A:D4:D9:CC:96:C3:01:57:C1:5D:31:76:5B:A9:B1:57:04:E1:AE:78:FD
*/
Fingerprint::SHA256(hex!("fe7696573855773e37a95e7ad4d9cc96c30157c15d31765ba9b15704e1ae78fd")),


/*
serial=00
issuer=C = US, O = "Starfield Technologies, Inc.", OU = Starfield Class 2 Certification Authority
sha1 Fingerprint=AD:7E:1C:28:B0:64:EF:8F:60:03:40:20:14:C3:D0:E3:37:0E:B5:8A
sha256 Fingerprint=14:65:FA:20:53:97:B8:76:FA:A6:F0:A9:95:8E:55:90:E4:0F:CC:7F:AA:4F:B7:C2:C8:67:75:21:FB:5F:B6:58
*/
Fingerprint::SHA256(hex!("1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658")),


/*
serial=1302D5E2404C92468616675DB4BBBBB26B3EFC13
issuer=C = TN, O = Agence Nationale de Certification Electronique, CN = TunTrust Root CA
sha1 Fingerprint=CF:E9:70:84:0F:E0:73:0F:9D:F6:0C:7F:2C:4B:EE:20:46:34:9C:BB
sha256 Fingerprint=2E:44:10:2A:B5:8C:B8:54:19:45:1C:8E:19:D9:AC:F3:66:2C:AF:BC:61:4B:6A:53:96:0A:30:F7:D0:E2:EB:41
*/
Fingerprint::SHA256(hex!("2e44102ab58cb85419451c8e19d9acf3662cafbc614b6a53960a30f7d0e2eb41")),


/*
serial=39CA931CEF43F3C68E93C7F46489387E
issuer=C = GR, O = Hellenic Academic and Research Institutions CA, CN = HARICA TLS RSA Root CA 2021
sha1 Fingerprint=02:2D:05:82:FA:88:CE:14:0C:06:79:DE:7F:14:10:E9:45:D7:A5:6D
sha256 Fingerprint=D9:5D:0E:8E:DA:79:52:5B:F9:BE:B1:1B:14:D2:10:0D:32:94:98:5F:0C:62:D9:FA:BD:9C:D9:99:EC:CB:7B:1D
*/
Fingerprint::SHA256(hex!("d95d0e8eda79525bf9beb11b14d2100d3294985f0c62d9fabd9cd999eccb7b1d")),


/*
serial=67749D8D77D83B6ADB22F4FF59E2BFCE
issuer=C = GR, O = Hellenic Academic and Research Institutions CA, CN = HARICA TLS ECC Root CA 2021
sha1 Fingerprint=BC:B0:C1:9D:E9:98:92:70:19:38:57:E9:8D:A7:B4:5D:6E:EE:01:48
sha256 Fingerprint=3F:99:CC:47:4A:CF:CE:4D:FE:D5:87:94:66:5E:47:8D:15:47:73:9F:2E:78:0F:1B:B4:CA:9B:13:30:97:D4:01
*/
Fingerprint::SHA256(hex!("3f99cc474acfce4dfed58794665e478d1547739f2e780f1bb4ca9b133097d401")),


/*
serial=1B70E9D2FFAE6C71
issuer=C = ES, CN = Autoridad de Certificacion Firmaprofesional CIF A62634068
sha1 Fingerprint=0B:BE:C2:27:22:49:CB:39:AA:DB:35:5C:53:E3:8C:AE:78:FF:B6:FE
sha256 Fingerprint=57:DE:05:83:EF:D2:B2:6E:03:61:DA:99:DA:9D:F4:64:8D:EF:7E:E8:44:1C:3B:72:8A:FA:9B:CD:E0:F9:B2:6A
*/
Fingerprint::SHA256(hex!("57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a")),


/*
serial=6E6ABC59AA53BE983967A2D26BA43BE66D1CD6DA
issuer=C = CN, O = "iTrusChina Co.,Ltd.", CN = vTrus ECC Root CA
sha1 Fingerprint=F6:9C:DB:B0:FC:F6:02:13:B6:52:32:A6:A3:91:3F:16:70:DA:C3:E1
sha256 Fingerprint=30:FB:BA:2C:32:23:8E:2A:98:54:7A:F9:79:31:E5:50:42:8B:9B:3F:1C:8E:EB:66:33:DC:FA:86:C5:B2:7D:D3
*/
Fingerprint::SHA256(hex!("30fbba2c32238e2a98547af97931e550428b9b3f1c8eeb6633dcfa86c5b27dd3")),


/*
serial=43E37113D8B359145DB7CE8CFD35FD6FBC058D45
issuer=C = CN, O = "iTrusChina Co.,Ltd.", CN = vTrus Root CA
sha1 Fingerprint=84:1A:69:FB:F5:CD:1A:25:34:13:3D:E3:F8:FC:B8:99:D0:C9:14:B7
sha256 Fingerprint=8A:71:DE:65:59:33:6F:42:6C:26:E5:38:80:D0:0D:88:A1:8D:A4:C6:A9:1F:0D:CB:61:94:E2:06:C5:C9:63:87
*/
Fingerprint::SHA256(hex!("8a71de6559336f426c26e53880d00d88a18da4c6a91f0dcb6194e206c5c96387")),


/*
serial=41D29DD172EAEEA780C12C6CE92F8752
issuer=C = US, O = Internet Security Research Group, CN = ISRG Root X2
sha1 Fingerprint=BD:B1:B9:3C:D5:97:8D:45:C6:26:14:55:F8:DB:95:C7:5A:D1:53:AF
sha256 Fingerprint=69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70
*/
Fingerprint::SHA256(hex!("69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470")),


/*
serial=2DDDACCE629794A143E8B0CD766A5E60
issuer=C = TW, O = "Chunghwa Telecom Co., Ltd.", CN = HiPKI Root CA - G1
sha1 Fingerprint=6A:92:E4:A8:EE:1B:EC:96:45:37:E3:29:57:49:CD:96:E3:E5:D2:60
sha256 Fingerprint=F0:15:CE:3C:C2:39:BF:EF:06:4B:E9:F1:D2:C4:17:E1:A0:26:4A:0A:94:BE:1F:0C:8D:12:18:64:EB:69:49:CC
*/
Fingerprint::SHA256(hex!("f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc")),


/*
serial=0203E57EF53F93FDA50921B2A6
issuer=OU = GlobalSign ECC Root CA - R4, O = GlobalSign, CN = GlobalSign
sha1 Fingerprint=6B:A0:B0:98:E1:71:EF:5A:AD:FE:48:15:80:77:10:F4:BD:6F:0B:28
sha256 Fingerprint=B0:85:D7:0B:96:4F:19:1A:73:E4:AF:0D:54:AE:7A:0E:07:AA:FD:AF:9B:71:DD:08:62:13:8A:B7:32:5A:24:A2
*/
Fingerprint::SHA256(hex!("b085d70b964f191a73e4af0d54ae7a0e07aafdaf9b71dd0862138ab7325a24a2")),


/*
serial=0203E5936F31B01349886BA217
issuer=C = US, O = Google Trust Services LLC, CN = GTS Root R1
sha1 Fingerprint=E5:8C:1C:C4:91:3B:38:63:4B:E9:10:6E:E3:AD:8E:6B:9D:D9:81:4A
sha256 Fingerprint=D9:47:43:2A:BD:E7:B7:FA:90:FC:2E:6B:59:10:1B:12:80:E0:E1:C7:E4:E4:0F:A3:C6:88:7F:FF:57:A7:F4:CF
*/
Fingerprint::SHA256(hex!("d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf")),


/*
serial=0CE7E0E517D846FE8FE560FC1BF03039
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Assured ID Root CA
sha1 Fingerprint=05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43
sha256 Fingerprint=3E:90:99:B5:01:5E:8F:48:6C:00:BC:EA:9D:11:1E:E7:21:FA:BA:35:5A:89:BC:F1:DF:69:56:1E:3D:C6:32:5C
*/
Fingerprint::SHA256(hex!("3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c")),


/*
serial=0203E5AEC58D04251AAB1125AA
issuer=C = US, O = Google Trust Services LLC, CN = GTS Root R2
sha1 Fingerprint=9A:44:49:76:32:DB:DE:FA:D0:BC:FB:5A:7B:17:BD:9E:56:09:24:94
sha256 Fingerprint=8D:25:CD:97:22:9D:BF:70:35:6B:DA:4E:B3:CC:73:40:31:E2:4C:F0:0F:AF:CF:D3:2D:C7:6E:B5:84:1C:7E:A8
*/
Fingerprint::SHA256(hex!("8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8")),


/*
serial=0203E5B882EB20F825276D3D66
issuer=C = US, O = Google Trust Services LLC, CN = GTS Root R3
sha1 Fingerprint=ED:E5:71:80:2B:C8:92:B9:5B:83:3C:D2:32:68:3F:09:CD:A0:1E:46
sha256 Fingerprint=34:D8:A7:3E:E2:08:D9:BC:DB:0D:95:65:20:93:4B:4E:40:E6:94:82:59:6E:8B:6F:73:C8:42:6B:01:0A:6F:48
*/
Fingerprint::SHA256(hex!("34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48")),


/*
serial=0203E5C068EF631A9C72905052
issuer=C = US, O = Google Trust Services LLC, CN = GTS Root R4
sha1 Fingerprint=77:D3:03:67:B5:E0:0C:15:F6:0C:38:61:DF:7C:E1:3B:92:46:4D:47
sha256 Fingerprint=34:9D:FA:40:58:C5:E2:63:12:3B:39:8A:E7:95:57:3C:4E:13:13:C8:3F:E6:8F:93:55:6C:D5:E8:03:1B:3C:7D
*/
Fingerprint::SHA256(hex!("349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d")),


/*
serial=01675F27D6FE7AE3E4ACBE095B059E
issuer=C = FI, O = Telia Finland Oyj, CN = Telia Root CA v2
sha1 Fingerprint=B9:99:CD:D1:73:50:8A:C4:47:05:08:9C:8C:88:FB:BE:A0:2B:40:CD
sha256 Fingerprint=24:2B:69:74:2F:CB:1E:5B:2A:BF:98:89:8B:94:57:21:87:54:4E:5B:4D:99:11:78:65:73:62:1F:6A:74:B8:2C
*/
Fingerprint::SHA256(hex!("242b69742fcb1e5b2abf98898b94572187544e5b4d9911786573621f6a74b82c")),


/*
serial=7CC98F2B84D7DFEA0FC9659AD34B4D96
issuer=C = DE, O = D-Trust GmbH, CN = D-TRUST BR Root CA 1 2020
sha1 Fingerprint=1F:5B:98:F0:E3:B5:F7:74:3C:ED:E6:B0:36:7D:32:CD:F4:09:41:67
sha256 Fingerprint=E5:9A:AA:81:60:09:C2:2B:FF:5B:25:BA:D3:7D:F3:06:F0:49:79:7C:1F:81:D8:5A:B0:89:E6:57:BD:8F:00:44
*/
Fingerprint::SHA256(hex!("e59aaa816009c22bff5b25bad37df306f049797c1f81d85ab089e657bd8f0044")),


/*
serial=5F0241D77A877C4C03A3AC968DFBFFD0
issuer=C = DE, O = D-Trust GmbH, CN = D-TRUST EV Root CA 1 2020
sha1 Fingerprint=61:DB:8C:21:59:69:03:90:D8:7C:9C:12:86:54:CF:9D:3D:F4:DD:07
sha256 Fingerprint=08:17:0D:1A:A3:64:53:90:1A:2F:95:92:45:E3:47:DB:0C:8D:37:AB:AA:BC:56:B8:1A:A1:00:DC:95:89:70:DB
*/
Fingerprint::SHA256(hex!("08170d1aa36453901a2f959245e347db0c8d37abaabc56b81aa100dc958970db")),


/*
serial=09E09365ACF7D9C8B93E1C0B042A2EF3
issuer=C = US, O = "DigiCert, Inc.", CN = DigiCert TLS ECC P384 Root G5
sha1 Fingerprint=17:F3:DE:5E:9F:0F:19:E9:8E:F6:1F:32:26:6E:20:C4:07:AE:30:EE
sha256 Fingerprint=01:8E:13:F0:77:25:32:CF:80:9B:D1:B1:72:81:86:72:83:FC:48:C6:E1:3B:E9:C6:98:12:85:4A:49:0C:1B:05
*/
Fingerprint::SHA256(hex!("018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05")),


/*
serial=08F9B478A8FA7EDA6A333789DE7CCF8A
issuer=C = US, O = "DigiCert, Inc.", CN = DigiCert TLS RSA4096 Root G5
sha1 Fingerprint=A7:88:49:DC:5D:7C:75:8C:8C:DE:39:98:56:B3:AA:D0:B2:A5:71:35
sha256 Fingerprint=37:1A:00:DC:05:33:B3:72:1A:7E:EB:40:E8:41:9E:70:79:9D:2B:0A:0F:2C:1D:80:69:31:65:F7:CE:C4:AD:75
*/
Fingerprint::SHA256(hex!("371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75")),


/*
serial=8E0FF94B907168653354F4D44439B7E0
issuer=C = US, O = Certainly, CN = Certainly Root R1
sha1 Fingerprint=A0:50:EE:0F:28:71:F4:27:B2:12:6D:6F:50:96:25:BA:CC:86:42:AF
sha256 Fingerprint=77:B8:2C:D8:64:4C:43:05:F7:AC:C5:CB:15:6B:45:67:50:04:03:3D:51:C6:0C:62:02:A8:E0:C3:34:67:D3:A0
*/
Fingerprint::SHA256(hex!("77b82cd8644c4305f7acc5cb156b45675004033d51c60c6202a8e0c33467d3a0")),


/*
serial=062533B1470333275CF98D9AB9BFCCF8
issuer=C = US, O = Certainly, CN = Certainly Root E1
sha1 Fingerprint=F9:E1:6D:DC:01:89:CF:D5:82:45:63:3E:C5:37:7D:C2:EB:93:6F:2B
sha256 Fingerprint=B4:58:5F:22:E4:AC:75:6A:4E:86:12:A1:36:1C:5D:9D:03:1A:93:FD:84:FE:BB:77:8F:A3:06:8B:0F:C4:2D:C2
*/
Fingerprint::SHA256(hex!("b4585f22e4ac756a4e8612a1361c5d9d031a93fd84febb778fa3068b0fc42dc2")),


/*
serial=083BE056904246B1A1756AC95991C74A
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
sha1 Fingerprint=A8:98:5D:3A:65:E5:E5:C4:B2:D7:D6:6D:40:C6:DD:2F:B1:9C:54:36
sha256 Fingerprint=43:48:A0:E9:44:4C:78:CB:26:5E:05:8D:5E:89:44:B4:D8:4F:96:62:BD:26:DB:25:7F:89:34:A4:43:C7:01:61
*/
Fingerprint::SHA256(hex!("4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161")),


/*
serial=E17C3740FD1BFE67
issuer=C = JP, O = "SECOM Trust Systems CO.,LTD.", CN = Security Communication RootCA3
sha1 Fingerprint=C3:03:C8:22:74:92:E5:61:A2:9C:5F:79:91:2B:1E:44:13:91:30:3A
sha256 Fingerprint=24:A5:5C:2A:B0:51:44:2D:06:17:76:65:41:23:9A:4A:D0:32:D7:C5:51:75:AA:34:FF:DE:2F:BC:4F:5C:52:94
*/
Fingerprint::SHA256(hex!("24a55c2ab051442d0617766541239a4ad032d7c55175aa34ffde2fbc4f5c5294")),


/*
serial=D65D9BB378812EEB
issuer=C = JP, O = "SECOM Trust Systems CO.,LTD.", CN = Security Communication ECC RootCA1
sha1 Fingerprint=B8:0E:26:A9:BF:D2:B2:3B:C0:EF:46:C9:BA:C7:BB:F6:1D:0D:41:41
sha256 Fingerprint=E7:4F:BD:A5:5B:D5:64:C4:73:A3:6B:44:1A:A7:99:C8:A6:8E:07:74:40:E8:28:8B:9F:A1:E5:0E:4B:BA:CA:11
*/
Fingerprint::SHA256(hex!("e74fbda55bd564c473a36b441aa799c8a68e077440e8288b9fa1e50e4bbaca11")),


/*
serial=556F65E3B4D9906A1B09D16C3EC06C20
issuer=C = CN, O = BEIJING CERTIFICATE AUTHORITY, CN = BJCA Global Root CA1
sha1 Fingerprint=D5:EC:8D:7B:4C:BA:79:F4:E7:E8:CB:9D:6B:AE:77:83:10:03:21:6A
sha256 Fingerprint=F3:89:6F:88:FE:7C:0A:88:27:66:A7:FA:6A:D2:74:9F:B5:7A:7F:3E:98:FB:76:9C:1F:A7:B0:9C:2C:44:D5:AE
*/
Fingerprint::SHA256(hex!("f3896f88fe7c0a882766a7fa6ad2749fb57a7f3e98fb769c1fa7b09c2c44d5ae")),


/*
serial=2C17087D642AC0FE85185906CFB44AEB
issuer=C = CN, O = BEIJING CERTIFICATE AUTHORITY, CN = BJCA Global Root CA2
sha1 Fingerprint=F4:27:86:EB:6E:B8:6D:88:31:67:02:FB:BA:66:A4:53:00:AA:7A:A6
sha256 Fingerprint=57:4D:F6:93:1E:27:80:39:66:7B:72:0A:FD:C1:60:0F:C2:7E:B6:6D:D3:09:29:79:FB:73:85:64:87:21:28:82
*/
Fingerprint::SHA256(hex!("574df6931e278039667b720afdc1600fc27eb66dd3092979fb73856487212882")),


/*
serial=42F2CCDA1B6937445F15FE752810B8F4
issuer=C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46
sha1 Fingerprint=EC:8A:39:6C:40:F0:2E:BC:42:75:D4:9F:AB:1C:1A:5B:67:BE:D2:9A
sha256 Fingerprint=C9:0F:26:F0:FB:1B:40:18:B2:22:27:51:9B:5C:A2:B5:3E:2C:A5:B3:BE:5C:F1:8E:FE:1B:EF:47:38:0C:53:83
*/
Fingerprint::SHA256(hex!("c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383")),


/*
serial=758DFD8BAE7C0700FAA925A7E1C7AD14
issuer=C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root R46
sha1 Fingerprint=AD:98:F9:F3:E4:7D:75:3B:65:D4:82:B3:A4:52:17:BB:6E:F5:E4:38
sha256 Fingerprint=7B:B6:47:A6:2A:EE:AC:88:BF:25:7A:A5:22:D0:1F:FE:A3:95:E0:AB:45:C7:3F:93:F6:56:54:EC:38:F2:5A:06
*/
Fingerprint::SHA256(hex!("7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06")),


/*
serial=6FBEDAAD73BD0840E28B4DBED4F75B91
issuer=C = US, O = SSL Corporation, CN = SSL.com TLS RSA Root CA 2022
sha1 Fingerprint=EC:2C:83:40:72:AF:26:95:10:FF:0E:F2:03:EE:31:70:F6:78:9D:CA
sha256 Fingerprint=8F:AF:7D:2E:2C:B4:70:9B:B8:E0:B3:36:66:BF:75:A5:DD:45:B5:DE:48:0F:8E:A8:D4:BF:E6:BE:BC:17:F2:ED
*/
Fingerprint::SHA256(hex!("8faf7d2e2cb4709bb8e0b33666bf75a5dd45b5de480f8ea8d4bfe6bebc17f2ed")),


/*
serial=1403F5ABFB378B17405BE243B2A5D1C4
issuer=C = US, O = SSL Corporation, CN = SSL.com TLS ECC Root CA 2022
sha1 Fingerprint=9F:5F:D9:1A:54:6D:F5:0C:71:F0:EE:7A:BD:17:49:98:84:73:E2:39
sha256 Fingerprint=C3:2F:FD:9F:46:F9:36:D1:6C:36:73:99:09:59:43:4B:9A:D6:0A:AF:BB:9E:7C:F3:36:54:F1:44:CC:1B:A1:43
*/
Fingerprint::SHA256(hex!("c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143")),


/*
serial=3D983BA6663D9063F77E26573804EF00
issuer=CN = Atos TrustedRoot Root CA ECC TLS 2021, O = Atos, C = DE
sha1 Fingerprint=9E:BC:75:10:42:B3:02:F3:81:F4:F7:30:62:D4:8F:C3:A7:51:B2:DD
sha256 Fingerprint=B2:FA:E5:3E:14:CC:D7:AB:92:12:06:47:01:AE:27:9C:1D:89:88:FA:CB:77:5F:A8:A0:08:91:4E:66:39:88:A8
*/
Fingerprint::SHA256(hex!("b2fae53e14ccd7ab9212064701ae279c1d8988facb775fa8a008914e663988a8")),


/*
serial=53D5CFE619930BFB2B0512D8C22AA2A4
issuer=CN = Atos TrustedRoot Root CA RSA TLS 2021, O = Atos, C = DE
sha1 Fingerprint=18:52:3B:0D:06:37:E4:D6:3A:DF:23:E4:98:FB:5B:16:FB:86:74:48
sha256 Fingerprint=81:A9:08:8E:A5:9F:B3:64:C5:48:A6:F8:55:59:09:9B:6F:04:05:EF:BF:18:E5:32:4E:C9:F4:57:BA:00:11:2F
*/
Fingerprint::SHA256(hex!("81a9088ea59fb364c548a6f85559099b6f0405efbf18e5324ec9f457ba00112f")),


/*
serial=02AC5C266A0B409B8F0B79F2AE462577
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert High Assurance EV Root CA
sha1 Fingerprint=5F:B7:EE:06:33:E2:59:DB:AD:0C:4C:9A:E6:D3:8F:1A:61:C7:DC:25
sha256 Fingerprint=74:31:E5:F4:C3:C1:CE:46:90:77:4F:0B:61:E0:54:40:88:3B:A9:A0:1E:D0:0B:A6:AB:D7:80:6E:D3:B1:18:CF
*/
Fingerprint::SHA256(hex!("7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf")),


/*
serial=64F60E6577616AAB3BB4EA8584BBB189B871930F
issuer=C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia Global Root CA G3
sha1 Fingerprint=63:CF:B6:C1:27:2B:56:E4:88:8E:1C:23:9A:B6:2E:81:47:24:C3:C7
sha256 Fingerprint=E0:D3:22:6A:EB:11:63:C2:E4:8F:F9:BE:3B:50:B4:C6:43:1B:E7:BB:1E:AC:C5:C3:6B:5D:5E:C5:09:03:9A:08
*/
Fingerprint::SHA256(hex!("e0d3226aeb1163c2e48ff9be3b50b4c6431be7bb1eacc5c36b5d5ec509039a08")),


/*
serial=4F2364B88E97639EC65381C1764ECB2A7415D6D7
issuer=C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia Global Root CA G4
sha1 Fingerprint=57:73:A5:61:5D:80:B2:E6:AC:38:82:FC:68:07:31:AC:9F:B5:92:5A
sha256 Fingerprint=BE:4B:56:CB:50:56:C0:13:6A:52:6D:F4:44:50:8D:AA:36:A0:B5:4F:42:E4:AC:38:F7:2A:F4:70:E4:79:65:4C
*/
Fingerprint::SHA256(hex!("be4b56cb5056c0136a526df444508daa36a0b54f42e4ac38f72af470e479654c")),


/*
serial=43708277CF4D5D34F1CAAE322F37F7F47F75A09E
issuer=C = US, O = CommScope, CN = CommScope Public Trust ECC Root-01
sha1 Fingerprint=07:86:C0:D8:DD:8E:C0:80:98:06:98:D0:58:7A:EF:DE:A6:CC:A2:5D
sha256 Fingerprint=11:43:7C:DA:7B:B4:5E:41:36:5F:45:B3:9A:38:98:6B:0D:E0:0D:EF:34:8E:0C:7B:B0:87:36:33:80:0B:C3:8B
*/
Fingerprint::SHA256(hex!("11437cda7bb45e41365f45b39a38986b0de00def348e0c7bb0873633800bc38b")),


/*
serial=28FD99604147A6013ACA147B1FEFF96808835D7D
issuer=C = US, O = CommScope, CN = CommScope Public Trust ECC Root-02
sha1 Fingerprint=3C:3F:EF:57:0F:FE:65:93:86:9E:A0:FE:B0:F6:ED:8E:D1:13:C7:E5
sha256 Fingerprint=2F:FB:7F:81:3B:BB:B3:C8:9A:B4:E8:16:2D:0F:16:D7:15:09:A8:30:CC:9D:73:C2:62:E5:14:08:75:D1:AD:4A
*/
Fingerprint::SHA256(hex!("2ffb7f813bbbb3c89ab4e8162d0f16d71509a830cc9d73c262e5140875d1ad4a")),


/*
serial=3E034981751674318E4CABD5C5902996C53910DD
issuer=C = US, O = CommScope, CN = CommScope Public Trust RSA Root-01
sha1 Fingerprint=6D:0A:5F:F7:B4:23:06:B4:85:B3:B7:97:64:FC:AC:75:F5:33:F2:93
sha256 Fingerprint=02:BD:F9:6E:2A:45:DD:9B:F1:8F:C7:E1:DB:DF:21:A0:37:9B:A3:C9:C2:61:03:44:CF:D8:D6:06:FE:C1:ED:81
*/
Fingerprint::SHA256(hex!("02bdf96e2a45dd9bf18fc7e1dbdf21a0379ba3c9c2610344cfd8d606fec1ed81")),


/*
serial=5416BF3B7E3995718DD1AA00A5860D2B8F7A054E
issuer=C = US, O = CommScope, CN = CommScope Public Trust RSA Root-02
sha1 Fingerprint=EA:B0:E2:52:1B:89:93:4C:11:68:F2:D8:9A:AC:22:4C:A3:8A:57:AE
sha256 Fingerprint=FF:E9:43:D7:93:42:4B:4F:7C:44:0C:1C:3D:64:8D:53:63:F3:4B:82:DC:87:AA:7A:9F:11:8F:C5:DE:E1:01:F1
*/
Fingerprint::SHA256(hex!("ffe943d793424b4f7c440c1c3d648d5363f34b82dc87aa7a9f118fc5dee101f1")),


/*
serial=363A968CC95CB258CDD0015DC5E55700
issuer=C = DE, O = Deutsche Telekom Security GmbH, CN = Telekom Security TLS ECC Root 2020
sha1 Fingerprint=C0:F8:96:C5:A9:3B:01:06:21:07:DA:18:42:48:BC:E9:9D:88:D5:EC
sha256 Fingerprint=57:8A:F4:DE:D0:85:3F:4E:59:98:DB:4A:EA:F9:CB:EA:8D:94:5F:60:B6:20:A3:8D:1A:3C:13:B2:BC:7B:A8:E1
*/
Fingerprint::SHA256(hex!("578af4ded0853f4e5998db4aeaf9cbea8d945f60b620a38d1a3c13b2bc7ba8e1")),


/*
serial=219C542DE8F6EC7177FA4EE8C3705797
issuer=C = DE, O = Deutsche Telekom Security GmbH, CN = Telekom Security TLS RSA Root 2023
sha1 Fingerprint=54:D3:AC:B3:BD:57:56:F6:85:9D:CE:E5:C3:21:E2:D4:AD:83:D0:93
sha256 Fingerprint=EF:C6:5C:AD:BB:59:AD:B6:EF:E8:4D:A2:23:11:B3:56:24:B7:1B:3B:1E:A0:DA:8B:66:55:17:4E:C8:97:86:46
*/
Fingerprint::SHA256(hex!("efc65cadbb59adb6efe84da22311b35624b71b3b1ea0da8b6655174ec8978646")),


/*
serial=319721EDAF89427F354187A167564C6D
issuer=C = ES, O = Firmaprofesional SA, organizationIdentifier = VATES-A62634068, CN = FIRMAPROFESIONAL CA ROOT-A WEB
sha1 Fingerprint=A8:31:11:74:A6:14:15:0D:CA:77:DD:0E:E4:0C:5D:58:FC:A0:72:A5
sha256 Fingerprint=BE:F2:56:DA:F2:6E:9C:69:BD:EC:16:02:35:97:98:F3:CA:F7:18:21:A0:3E:01:82:57:C5:3C:65:61:7F:3D:4A
*/
Fingerprint::SHA256(hex!("bef256daf26e9c69bdec1602359798f3caf71821a03e018257c53c65617f3d4a")),


/*
serial=4001348CC200000000000000013CF2C6
issuer=C = TW, O = TAIWAN-CA, OU = Root CA, CN = TWCA CYBER Root CA
sha1 Fingerprint=F6:B1:1C:1A:83:38:E9:7B:DB:B3:A8:C8:33:24:E0:2D:9C:7F:26:66
sha256 Fingerprint=3F:63:BB:28:14:BE:17:4E:C8:B6:43:9C:F0:8D:6D:56:F0:B7:C4:05:88:3A:56:48:A3:34:42:4D:6B:3E:C5:58
*/
Fingerprint::SHA256(hex!("3f63bb2814be174ec8b6439cf08d6d56f0b7c405883a5648a334424d6b3ec558")),


/*
serial=BB401C43F55E4FB0
issuer=C = CH, O = SwissSign AG, CN = SwissSign Gold CA - G2
sha1 Fingerprint=D8:C5:38:8A:B7:30:1B:1B:6E:D4:7A:E6:45:25:3A:6F:9F:1A:27:61
sha256 Fingerprint=62:DD:0B:E9:B9:F5:0A:16:3E:A0:F8:E7:5C:05:3B:1E:CA:57:EA:55:C8:68:8F:64:7C:68:81:F2:C8:35:7B:95
*/
Fingerprint::SHA256(hex!("62dd0be9b9f50a163ea0f8e75c053b1eca57ea55c8688f647c6881f2c8357b95")),


/*
serial=66F9C7C1AFECC251B4ED5397E6E682C32B1C9016
issuer=C = JP, O = "Cybertrust Japan Co., Ltd.", CN = SecureSign Root CA12
sha1 Fingerprint=7A:22:1E:3D:DE:1B:06:AC:9E:C8:47:70:16:8E:3C:E5:F7:6B:06:F4
sha256 Fingerprint=3F:03:4B:B5:70:4D:44:B2:D0:85:45:A0:20:57:DE:93:EB:F3:90:5F:CE:72:1A:CB:C7:30:C0:6D:DA:EE:90:4E
*/
Fingerprint::SHA256(hex!("3f034bb5704d44b2d08545a02057de93ebf3905fce721acbc730c06ddaee904e")),


/*
serial=64DB5A0C204EE8D72977C85027A25A27DD2DF2CB
issuer=C = JP, O = "Cybertrust Japan Co., Ltd.", CN = SecureSign Root CA14
sha1 Fingerprint=DD:50:C0:F7:79:B3:64:2E:74:A2:B8:9D:9F:D3:40:DD:BB:F0:F2:4F
sha256 Fingerprint=4B:00:9C:10:34:49:4F:9A:B5:6B:BA:3B:A1:D6:27:31:FC:4D:20:D8:95:5A:DC:EC:10:A9:25:60:72:61:E3:38
*/
Fingerprint::SHA256(hex!("4b009c1034494f9ab56bba3ba1d62731fc4d20d8955adcec10a925607261e338")),


/*
serial=1615C7C3D849A7BE690C8A88EDF070F9DDB73E87
issuer=C = JP, O = "Cybertrust Japan Co., Ltd.", CN = SecureSign Root CA15
sha1 Fingerprint=CB:BA:83:C8:C1:5A:5D:F1:F9:73:6F:CA:D7:EF:28:13:06:4A:07:7D
sha256 Fingerprint=E7:78:F0:F0:95:FE:84:37:29:CD:1A:00:82:17:9E:53:14:A9:C2:91:44:28:05:E1:FB:1D:8F:B6:B8:88:6C:3A
*/
Fingerprint::SHA256(hex!("e778f0f095fe843729cd1a0082179e5314a9c291442805e1fb1d8fb6b8886c3a")),


/*
serial=4F1BD42F54BB2F4B
issuer=C = CH, O = SwissSign AG, CN = SwissSign Silver CA - G2
sha1 Fingerprint=9B:AA:E5:9F:56:EE:21:CB:43:5A:BE:25:93:DF:A7:F0:40:D1:1D:CB
sha256 Fingerprint=BE:6C:4D:A2:BB:B9:BA:59:B6:F3:93:97:68:37:42:46:C3:C0:05:99:3F:A9:8F:02:0D:1D:ED:BE:D4:8A:81:D5
*/
Fingerprint::SHA256(hex!("be6c4da2bbb9ba59b6f3939768374246c3c005993fa98f020d1dedbed48a81d5")),


/*
serial=0CF08E5C0816A5AD427FF0EB271859D0
issuer=C = US, O = SecureTrust Corporation, CN = SecureTrust CA
sha1 Fingerprint=87:82:C6:C3:04:35:3B:CF:D2:96:92:D2:59:3E:7D:44:D9:34:FF:11
sha256 Fingerprint=F1:C1:B5:0A:E5:A2:0D:D8:03:0E:C9:F6:BC:24:82:3D:D3:67:B5:25:57:59:B4:E7:1B:61:FC:E9:F7:37:5D:73
*/
Fingerprint::SHA256(hex!("f1c1b50ae5a20dd8030ec9f6bc24823dd367b5255759b4e71b61fce9f7375d73")),


/*
serial=075622A4E8D48A894DF413C8F0F8EAA5
issuer=C = US, O = SecureTrust Corporation, CN = Secure Global CA
sha1 Fingerprint=3A:44:73:5A:E5:81:90:1F:24:86:61:46:1E:3B:9C:C4:5F:F5:3A:1B
sha256 Fingerprint=42:00:F5:04:3A:C8:59:0E:BB:52:7D:20:9E:D1:50:30:29:FB:CB:D4:1C:A1:B5:06:EC:27:F1:5A:DE:7D:AC:69
*/
Fingerprint::SHA256(hex!("4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69")),


/*
serial=4E812D8A8265E00B02EE3E350246E53D
issuer=C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO Certification Authority
sha1 Fingerprint=66:31:BF:9E:F7:4F:9E:B6:C9:D5:A6:0C:BA:6A:BE:D1:F7:BD:EF:7B
sha256 Fingerprint=0C:2C:D6:3D:F7:80:6F:A3:99:ED:E8:09:11:6B:57:5B:F8:79:89:F0:65:18:F9:80:8C:86:05:03:17:8B:AF:66
*/
Fingerprint::SHA256(hex!("0c2cd63df7806fa399ede809116b575bf87989f06518f9808c860503178baf66")),


/*
serial=1F47AFAA62007050544C019E9B63992A
issuer=C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO ECC Certification Authority
sha1 Fingerprint=9F:74:4E:9F:2B:4D:BA:EC:0F:31:2C:50:B6:56:3B:8E:2D:93:C3:11
sha256 Fingerprint=17:93:92:7A:06:14:54:97:89:AD:CE:2F:8F:34:F7:F0:B6:6D:0F:3A:E3:A3:B8:4D:21:EC:15:DB:BA:4F:AD:C7
*/
Fingerprint::SHA256(hex!("1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7")),


/*
serial=040000000001154B5AC394
issuer=C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
sha1 Fingerprint=B1:BC:96:8B:D4:F4:9D:62:2A:A8:9A:81:F2:15:01:52:A4:1D:82:9C
sha256 Fingerprint=EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99
*/
Fingerprint::SHA256(hex!("ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99")),


/*
serial=FEDCE3010FC948FF
issuer=C = FR, O = Dhimyotis, CN = Certigna
sha1 Fingerprint=B1:2E:13:63:45:86:A4:6F:1A:B2:60:68:37:58:2D:C4:AC:FD:94:97
sha256 Fingerprint=E3:B6:A2:DB:2E:D7:CE:48:84:2F:7A:C5:32:41:C7:B7:1D:54:14:4B:FB:40:C1:1F:3F:1D:0B:42:F5:EE:A1:2D
*/
Fingerprint::SHA256(hex!("e3b6a2db2ed7ce48842f7ac53241c7b71d54144bfb40c11f3f1d0b42f5eea12d")),


/*
serial=15C8BD65475CAFB897005EE406D2BC9D
issuer=C = TW, O = "Chunghwa Telecom Co., Ltd.", OU = ePKI Root Certification Authority
sha1 Fingerprint=67:65:0D:F1:7E:8E:7E:5B:82:40:A4:F4:56:4B:CF:E2:3D:69:C6:F0
sha256 Fingerprint=C0:A6:F4:DC:63:A2:4B:FD:CF:54:EF:2A:6A:08:2A:0A:72:DE:35:80:3E:2F:F5:FF:52:7A:E5:D8:72:06:DF:D5
*/
Fingerprint::SHA256(hex!("c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5")),


/*
serial=200605167002
issuer=C = RO, O = certSIGN, OU = certSIGN ROOT CA
sha1 Fingerprint=FA:B7:EE:36:97:26:62:FB:2D:B0:2A:F6:BF:03:FD:E8:7C:4B:2F:9B
sha256 Fingerprint=EA:A9:62:C4:FA:4A:6B:AF:EB:E4:15:19:6D:35:1C:CD:88:8D:4F:53:F3:FA:8A:E6:D7:C4:66:A9:4E:60:42:BB
*/
Fingerprint::SHA256(hex!("eaa962c4fa4a6bafebe415196d351ccd888d4f53f3fa8ae6d7c466a94e6042bb")),


/*
serial=49412CE40010
issuer=C = HU, L = Budapest, O = NetLock Kft., OU = Tan\C3\BAs\C3\ADtv\C3\A1nykiad\C3\B3k (Certification Services), CN = NetLock Arany (Class Gold) F\C5\91tan\C3\BAs\C3\ADtv\C3\A1ny
sha1 Fingerprint=06:08:3F:59:3F:15:A1:04:A0:69:A4:6B:A9:03:D0:06:B7:97:09:91
sha256 Fingerprint=6C:61:DA:C3:A2:DE:F0:31:50:6B:E0:36:D2:A6:FE:40:19:94:FB:D1:3D:F9:C8:D4:66:59:92:74:C4:46:EC:98
*/
Fingerprint::SHA256(hex!("6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98")),


/*
serial=01
issuer=C = JP, O = "Japan Certification Services, Inc.", CN = SecureSign RootCA11
sha1 Fingerprint=3B:C4:9F:48:F8:F3:73:A0:9C:1E:BD:F8:5B:B1:C3:65:C7:D8:11:B3
sha256 Fingerprint=BF:0F:EE:FB:9E:3A:58:1A:D5:F9:E9:DB:75:89:98:57:43:D2:61:08:5C:4D:31:4F:6F:5D:72:59:AA:42:16:12
*/
Fingerprint::SHA256(hex!("bf0feefb9e3a581ad5f9e9db7589985743d261085c4d314f6f5d7259aa421612")),


/*
serial=C27E43044E473F19
issuer=C = HU, L = Budapest, O = Microsec Ltd., CN = Microsec e-Szigno Root CA 2009, emailAddress = info@e-szigno.hu
sha1 Fingerprint=89:DF:74:FE:5C:F4:0F:4A:80:F9:E3:37:7D:54:DA:91:E1:01:31:8E
sha256 Fingerprint=3C:5F:81:FE:A5:FA:B8:2C:64:BF:A2:EA:EC:AF:CD:E8:E0:77:FC:86:20:A7:CA:E5:37:16:3D:F3:6E:DB:F3:78
*/
Fingerprint::SHA256(hex!("3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378")),


/*
serial=04000000000121585308A2
issuer=OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
sha1 Fingerprint=D6:9B:56:11:48:F0:1C:77:C5:45:78:C1:09:26:DF:5B:85:69:76:AD
sha256 Fingerprint=CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B
*/
Fingerprint::SHA256(hex!("cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b")),


/*
serial=B0B75A16485FBFE1CBF58BD719E67D
issuer=C = ES, O = IZENPE S.A., CN = Izenpe.com
sha1 Fingerprint=2F:78:3D:25:52:18:A7:4A:65:39:71:B5:2C:A2:9C:45:15:6F:E9:19
sha256 Fingerprint=25:30:CC:8E:98:32:15:02:BA:D9:6F:9B:1F:BA:1B:09:9E:2D:29:9E:0F:45:48:BB:91:4F:36:3B:C0:D4:53:1F
*/
Fingerprint::SHA256(hex!("2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f")),


/*
serial=00
issuer=C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
sha1 Fingerprint=47:BE:AB:C9:22:EA:E8:0E:78:78:34:62:A7:9F:45:C2:54:FD:E6:8B
sha256 Fingerprint=45:14:0B:32:47:EB:9C:C8:C5:B4:F0:D7:B5:30:91:F7:32:92:08:9E:6E:5A:63:E2:74:9D:D3:AC:A9:19:8E:DA
*/
Fingerprint::SHA256(hex!("45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda")),


/*
serial=00
issuer=C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Root Certificate Authority - G2
sha1 Fingerprint=B5:1C:06:7C:EE:2B:0C:3D:F8:55:AB:2D:92:F4:FE:39:D4:E7:0F:0E
sha256 Fingerprint=2C:E1:CB:0B:F9:D2:F9:E1:02:99:3F:BE:21:51:52:C3:B2:DD:0C:AB:DE:1C:68:E5:31:9B:83:91:54:DB:B7:F5
*/
Fingerprint::SHA256(hex!("2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5")),


/*
serial=3863DEF8
issuer=O = Entrust.net, OU = www.entrust.net/CPS_2048 incorp. by ref. (limits liab.), OU = (c) 1999 Entrust.net Limited, CN = Entrust.net Certification Authority (2048)
sha1 Fingerprint=50:30:06:09:1D:97:D4:F5:AE:39:F7:CB:E7:92:7D:7D:65:2D:34:31
sha256 Fingerprint=6D:C4:71:72:E0:1C:BC:B0:BF:62:58:0D:89:5F:E2:B8:AC:9A:D4:F8:73:80:1E:0C:10:B9:C8:37:D2:1E:B1:77
*/
Fingerprint::SHA256(hex!("6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177")),


/*
serial=00
issuer=C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
sha1 Fingerprint=92:5A:8F:8D:2C:6D:04:E0:66:5F:59:6A:FF:22:D8:63:E8:25:6F:3F
sha256 Fingerprint=56:8D:69:05:A2:C8:87:08:A4:B3:02:51:90:ED:CF:ED:B1:97:4A:60:6A:13:C6:E5:29:0F:CB:2A:E6:3E:DA:B5
*/
Fingerprint::SHA256(hex!("568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5")),


/*
serial=7777062726A9B17C
issuer=C = US, O = AffirmTrust, CN = AffirmTrust Commercial
sha1 Fingerprint=F9:B5:B6:32:45:5F:9C:BE:EC:57:5F:80:DC:E9:6E:2C:C7:B2:78:B7
sha256 Fingerprint=03:76:AB:1D:54:C5:F9:80:3C:E4:B2:E2:01:A0:EE:7E:EF:7B:57:B6:36:E8:A9:3C:9B:8D:48:60:C9:6F:5F:A7
*/
Fingerprint::SHA256(hex!("0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7")),


/*
serial=7C4F04391CD4992D
issuer=C = US, O = AffirmTrust, CN = AffirmTrust Networking
sha1 Fingerprint=29:36:21:02:8B:20:ED:02:F5:66:C5:32:D1:D6:ED:90:9F:45:00:2F
sha256 Fingerprint=0A:81:EC:5A:92:97:77:F1:45:90:4A:F3:8D:5D:50:9F:66:B5:E2:C5:8F:CD:B5:31:05:8B:0E:17:F3:F0:B4:1B
*/
Fingerprint::SHA256(hex!("0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b")),


/*
serial=6D8C1446B1A60AEE
issuer=C = US, O = AffirmTrust, CN = AffirmTrust Premium
sha1 Fingerprint=D8:A6:33:2C:E0:03:6F:B1:85:F6:63:4F:7D:6A:06:65:26:32:28:27
sha256 Fingerprint=70:A7:3F:7F:37:6B:60:07:42:48:90:45:34:B1:14:82:D5:BF:0E:69:8E:CC:49:8D:F5:25:77:EB:F2:E9:3B:9A
*/
Fingerprint::SHA256(hex!("70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a")),


/*
serial=7497258AC73F7A54
issuer=C = US, O = AffirmTrust, CN = AffirmTrust Premium ECC
sha1 Fingerprint=B8:23:6B:00:2F:1D:16:86:53:01:55:6C:11:A4:37:CA:EB:FF:C3:BB
sha256 Fingerprint=BD:71:FD:F6:DA:97:E4:CF:62:D1:64:7A:DD:25:81:B0:7D:79:AD:F8:39:7E:B4:EC:BA:9C:5E:84:88:82:14:23
*/
Fingerprint::SHA256(hex!("bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")),


/*
serial=0444C0
issuer=C = PL, O = Unizeto Technologies S.A., OU = Certum Certification Authority, CN = Certum Trusted Network CA
sha1 Fingerprint=07:E0:32:E0:20:B7:2C:3F:19:2F:06:28:A2:59:3A:19:A7:0F:06:9E
sha256 Fingerprint=5C:58:46:8D:55:F5:8E:49:7E:74:39:82:D2:B5:00:10:B6:D1:65:37:4A:CF:83:A7:D4:A3:2D:B7:68:C4:40:8E
*/
Fingerprint::SHA256(hex!("5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e")),


/*
serial=01
issuer=C = TW, O = TAIWAN-CA, OU = Root CA, CN = TWCA Root Certification Authority
sha1 Fingerprint=CF:9E:87:6D:D3:EB:FC:42:26:97:A3:B5:A3:7A:A0:76:A9:06:23:48
sha256 Fingerprint=BF:D8:8F:E1:10:1C:41:AE:3E:80:1B:F8:BE:56:35:0E:E9:BA:D1:A6:B9:BD:51:5E:DC:5C:6D:5B:87:11:AC:44
*/
Fingerprint::SHA256(hex!("bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44")),


/*
serial=00
issuer=C = JP, O = "SECOM Trust Systems CO.,LTD.", OU = Security Communication RootCA2
sha1 Fingerprint=5F:3B:8C:F2:F8:10:B3:7D:78:B4:CE:EC:19:19:C3:73:34:B9:C7:74
sha256 Fingerprint=51:3B:2C:EC:B8:10:D4:CD:E5:DD:85:39:1A:DF:C6:C2:DD:60:D8:7B:B7:36:D2:B5:21:48:4A:A4:7A:0E:BE:F6
*/
Fingerprint::SHA256(hex!("513b2cecb810d4cde5dd85391adfc6c2dd60d87bb736d2b521484aa47a0ebef6")),


/*
serial=570A119742C4E3CC
issuer=C = IT, L = Milan, O = Actalis S.p.A./03358520967, CN = Actalis Authentication Root CA
sha1 Fingerprint=F3:73:B3:87:06:5A:28:84:8A:F2:F3:4A:CE:19:2B:DD:C7:8E:9C:AC
sha256 Fingerprint=55:92:60:84:EC:96:3A:64:B9:6E:2A:BE:01:CE:0B:A8:6A:64:FB:FE:BC:C7:AA:B5:AF:C1:55:B3:7F:D7:60:66
*/
Fingerprint::SHA256(hex!("55926084ec963a64b96e2abe01ce0ba86a64fbfebcc7aab5afc155b37fd76066")),


/*
serial=02
issuer=C = NO, O = Buypass AS-983163327, CN = Buypass Class 2 Root CA
sha1 Fingerprint=49:0A:75:74:DE:87:0A:47:FE:58:EE:F6:C7:6B:EB:C6:0B:12:40:99
sha256 Fingerprint=9A:11:40:25:19:7C:5B:B9:5D:94:E6:3D:55:CD:43:79:08:47:B6:46:B2:3C:DF:11:AD:A4:A0:0E:FF:15:FB:48
*/
Fingerprint::SHA256(hex!("9a114025197c5bb95d94e63d55cd43790847b646b23cdf11ada4a00eff15fb48")),


/*
serial=020000B9
issuer=C = IE, O = Baltimore, OU = CyberTrust, CN = Baltimore CyberTrust Root
sha1 Fingerprint=D4:DE:20:D0:5E:66:FC:53:FE:1A:50:88:2C:78:DB:28:52:CA:E4:74
sha256 Fingerprint=16:AF:57:A9:F6:76:B0:AB:12:60:95:AA:5E:BA:DE:F2:2A:B3:11:19:D6:44:AC:95:CD:4B:93:DB:F3:F2:6A:EB
*/
Fingerprint::SHA256(hex!("16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb")),


/*
serial=02
issuer=C = NO, O = Buypass AS-983163327, CN = Buypass Class 3 Root CA
sha1 Fingerprint=DA:FA:F7:FA:66:84:EC:06:8F:14:50:BD:C7:C2:81:A5:BC:A9:64:57
sha256 Fingerprint=ED:F7:EB:BC:A2:7A:2A:38:4D:38:7B:7D:40:10:C6:66:E2:ED:B4:84:3E:4C:29:B4:AE:1D:5B:93:32:E6:B2:4D
*/
Fingerprint::SHA256(hex!("edf7ebbca27a2a384d387b7d4010c666e2edb4843e4c29b4ae1d5b9332e6b24d")),


/*
serial=01
issuer=C = DE, O = T-Systems Enterprise Services GmbH, OU = T-Systems Trust Center, CN = T-TeleSec GlobalRoot Class 3
sha1 Fingerprint=55:A6:72:3E:CB:F2:EC:CD:C3:23:74:70:19:9D:2A:BE:11:E3:81:D1
sha256 Fingerprint=FD:73:DA:D3:1C:64:4F:F1:B4:3B:EF:0C:CD:DA:96:71:0B:9C:D9:87:5E:CA:7E:31:70:7A:F3:E9:6D:52:2B:BD
*/
Fingerprint::SHA256(hex!("fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd")),


/*
serial=0983F3
issuer=C = DE, O = D-Trust GmbH, CN = D-TRUST Root Class 3 CA 2 2009
sha1 Fingerprint=58:E8:AB:B0:36:15:33:FB:80:F7:9B:1B:6D:29:D3:FF:8D:5F:00:F0
sha256 Fingerprint=49:E7:A4:42:AC:F0:EA:62:87:05:00:54:B5:25:64:B6:50:E4:F4:9E:42:E3:48:D6:AA:38:E0:39:E9:57:B1:C1
*/
Fingerprint::SHA256(hex!("49e7a442acf0ea6287050054b52564b650e4f49e42e348d6aa38e039e957b1c1")),


/*
serial=0983F4
issuer=C = DE, O = D-Trust GmbH, CN = D-TRUST Root Class 3 CA 2 EV 2009
sha1 Fingerprint=96:C9:1B:0B:95:B4:10:98:42:FA:D0:D8:22:79:FE:60:FA:B9:16:83
sha256 Fingerprint=EE:C5:49:6B:98:8C:E9:86:25:B9:34:09:2E:EC:29:08:BE:D0:B0:F3:16:C2:D4:73:0C:84:EA:F1:F3:D3:48:81
*/
Fingerprint::SHA256(hex!("eec5496b988ce98625b934092eec2908bed0b0f316c2d4730c84eaf1f3d34881")),


/*
serial=92B888DBB08AC163
issuer=C = SK, L = Bratislava, O = Disig a.s., CN = CA Disig Root R2
sha1 Fingerprint=B5:61:EB:EA:A4:DE:E4:25:4B:69:1A:98:A5:57:47:C2:34:C7:D9:71
sha256 Fingerprint=E2:3D:4A:03:6D:7B:70:E9:F5:95:B1:42:20:79:D2:B9:1E:DF:BB:1F:B6:51:A0:63:3E:AA:8A:9D:C5:F8:07:03
*/
Fingerprint::SHA256(hex!("e23d4a036d7b70e9f595b1422079d2b91edfbb1fb651a0633eaa8a9dc5f80703")),


/*
serial=5EC3B7A6437FA4E0
issuer=CN = ACCVRAIZ1, OU = PKIACCV, O = ACCV, C = ES
sha1 Fingerprint=93:05:7A:88:15:C6:4F:CE:88:2F:FA:91:16:52:28:78:BC:53:64:17
sha256 Fingerprint=9A:6E:C0:12:E1:A7:DA:9D:BE:34:19:4D:47:8A:D7:C0:DB:18:22:FB:07:1D:F1:29:81:49:6E:D1:04:38:41:13
*/
Fingerprint::SHA256(hex!("9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113")),


/*
serial=0CBE
issuer=C = TW, O = TAIWAN-CA, OU = Root CA, CN = TWCA Global Root CA
sha1 Fingerprint=9C:BB:48:53:F6:A4:F6:D3:52:A4:E8:32:52:55:60:13:F5:AD:AF:65
sha256 Fingerprint=59:76:90:07:F7:68:5D:0F:CD:50:87:2F:9F:95:D5:75:5A:5B:2B:45:7D:81:F3:69:2B:61:0A:98:67:2F:0E:1B
*/
Fingerprint::SHA256(hex!("59769007f7685d0fcd50872f9f95d5755a5b2b457d81f3692b610a98672f0e1b")),


/*
serial=95BE16A0F72E46F17B398272FA8BCD96
issuer=O = TeliaSonera, CN = TeliaSonera Root CA v1
sha1 Fingerprint=43:13:BB:96:F1:D5:86:9B:C1:4E:6A:92:F6:CF:F6:34:69:87:82:37
sha256 Fingerprint=DD:69:36:FE:21:F8:F0:77:C1:23:A1:A5:21:C1:22:24:F7:22:55:B7:3E:03:A7:26:06:93:E8:A2:4B:0F:A3:89
*/
Fingerprint::SHA256(hex!("dd6936fe21f8f077c123a1a521c12224f72255b73e03a7260693e8a24b0fa389")),


/*
serial=01
issuer=C = DE, O = T-Systems Enterprise Services GmbH, OU = T-Systems Trust Center, CN = T-TeleSec GlobalRoot Class 2
sha1 Fingerprint=59:0D:2D:7D:88:4F:40:2E:61:7E:A5:62:32:17:65:CF:17:D8:94:E9
sha256 Fingerprint=91:E2:F5:78:8D:58:10:EB:A7:BA:58:73:7D:E1:54:8A:8E:CA:CD:01:45:98:BC:0B:14:3E:04:1B:17:05:25:52
*/
Fingerprint::SHA256(hex!("91e2f5788d5810eba7ba58737de1548a8ecacd014598bc0b143e041b17052552")),


/*
serial=5C33CB622C5FB332
issuer=CN = Atos TrustedRoot 2011, O = Atos, C = DE
sha1 Fingerprint=2B:B1:F5:3E:55:0C:1D:C5:F1:D4:E6:B7:6A:46:4B:55:06:02:AC:21
sha256 Fingerprint=F3:56:BE:A2:44:B7:A9:1E:B3:5D:53:CA:9A:D7:86:4A:CE:01:8E:2D:35:D5:F8:F9:6D:DF:68:A6:F4:1A:A4:74
*/
Fingerprint::SHA256(hex!("f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474")),


/*
serial=456B5054
issuer=C = US, O = "Entrust, Inc.", OU = www.entrust.net/CPS is incorporated by reference, OU = "(c) 2006 Entrust, Inc.", CN = Entrust Root Certification Authority
sha1 Fingerprint=B3:1E:B1:B7:40:E3:6C:84:02:DA:DC:37:D4:4D:F5:D4:67:49:52:F9
sha256 Fingerprint=73:C1:76:43:4F:1B:C6:D5:AD:F4:5B:0E:76:E7:27:28:7C:8D:E5:76:16:C1:E6:E6:14:1A:2B:2C:BC:7D:8E:4C
*/
Fingerprint::SHA256(hex!("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c")),


/*
serial=78585F2EAD2C194BE3370735341328B596D46593
issuer=C = BM, O = QuoVadis Limited, CN = QuoVadis Root CA 1 G3
sha1 Fingerprint=1B:8E:EA:57:96:29:1A:C9:39:EA:B8:0A:81:1A:73:73:C0:93:79:67
sha256 Fingerprint=8A:86:6F:D1:B2:76:B5:7E:57:8E:92:1C:65:82:8A:2B:ED:58:E9:F2:F2:88:05:41:34:B7:F1:F4:BF:C9:CC:74
*/
Fingerprint::SHA256(hex!("8a866fd1b276b57e578e921c65828a2bed58e9f2f288054134b7f1f4bfc9cc74")),


/*
serial=445734245B81899B35F2CEB82B3B5BA726F07528
issuer=C = BM, O = QuoVadis Limited, CN = QuoVadis Root CA 2 G3
sha1 Fingerprint=09:3C:61:F3:8B:8B:DC:7D:55:DF:75:38:02:05:00:E1:25:F5:C8:36
sha256 Fingerprint=8F:E4:FB:0A:F9:3A:4D:0D:67:DB:0B:EB:B2:3E:37:C7:1B:F3:25:DC:BC:DD:24:0E:A0:4D:AF:58:B4:7E:18:40
*/
Fingerprint::SHA256(hex!("8fe4fb0af93a4d0d67db0bebb23e37c71bf325dcbcdd240ea04daf58b47e1840")),


/*
serial=2EF59B0228A7DB7AFFD5A3A9EEBD03A0CF126A1D
issuer=C = BM, O = QuoVadis Limited, CN = QuoVadis Root CA 3 G3
sha1 Fingerprint=48:12:BD:92:3C:A8:C4:39:06:E7:30:6D:27:96:E6:A4:CF:22:2E:7D
sha256 Fingerprint=88:EF:81:DE:20:2E:B0:18:45:2E:43:F8:64:72:5C:EA:5F:BD:1F:C2:D9:D2:05:73:07:09:C5:D8:B8:69:0F:46
*/
Fingerprint::SHA256(hex!("88ef81de202eb018452e43f864725cea5fbd1fc2d9d205730709c5d8b8690f46")),


/*
serial=0B931C3AD63967EA6723BFC3AF9AF44B
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Assured ID Root G2
sha1 Fingerprint=A1:4B:48:D9:43:EE:0A:0E:40:90:4F:3C:E0:A4:C0:91:93:51:5D:3F
sha256 Fingerprint=7D:05:EB:B6:82:33:9F:8C:94:51:EE:09:4E:EB:FE:FA:79:53:A1:14:ED:B2:F4:49:49:45:2F:AB:7D:2F:C1:85
*/
Fingerprint::SHA256(hex!("7d05ebb682339f8c9451ee094eebfefa7953a114edb2f44949452fab7d2fc185")),


/*
serial=0BA15AFA1DDFA0B54944AFCD24A06CEC
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Assured ID Root G3
sha1 Fingerprint=F5:17:A2:4F:9A:48:C6:C9:F8:A2:00:26:9F:DC:0F:48:2C:AB:30:89
sha256 Fingerprint=7E:37:CB:8B:4C:47:09:0C:AB:36:55:1B:A6:F4:5D:B8:40:68:0F:BA:16:6A:95:2D:B1:00:71:7F:43:05:3F:C2
*/
Fingerprint::SHA256(hex!("7e37cb8b4c47090cab36551ba6f45db840680fba166a952db100717f43053fc2")),


/*
serial=033AF1E6A711A9A0BB2864B11D09FAE5
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
sha1 Fingerprint=DF:3C:24:F9:BF:D6:66:76:1B:26:80:73:FE:06:D1:CC:8D:4F:82:A4
sha256 Fingerprint=CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F
*/
Fingerprint::SHA256(hex!("cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f")),


/*
serial=055556BCF25EA43535C3A40FD5AB4572
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G3
sha1 Fingerprint=7E:04:DE:89:6A:3E:66:6D:00:E6:87:D3:3F:FA:D9:3B:E8:3D:34:9E
sha256 Fingerprint=31:AD:66:48:F8:10:41:38:C7:38:F3:9E:A4:32:01:33:39:3E:3A:18:CC:02:29:6E:F9:7C:2A:C9:EF:67:31:D0
*/
Fingerprint::SHA256(hex!("31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0")),


/*
serial=059B1B579E8E2132E23907BDA777755C
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Trusted Root G4
sha1 Fingerprint=DD:FB:16:CD:49:31:C9:73:A2:03:7D:3F:C8:3A:4D:7D:77:5D:05:E4
sha256 Fingerprint=55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88
*/
Fingerprint::SHA256(hex!("552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988")),


/*
serial=4CAAF9CADB636FE01FF74ED85B03869D
issuer=C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO RSA Certification Authority
sha1 Fingerprint=AF:E5:D2:44:A8:D1:19:42:30:FF:47:9F:E2:F8:97:BB:CD:7A:8C:B4
sha256 Fingerprint=52:F0:E1:C4:E5:8E:C6:29:29:1B:60:31:7F:07:46:71:B8:5D:7E:A8:0D:5B:07:27:34:63:53:4B:32:B4:02:34
*/
Fingerprint::SHA256(hex!("52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234")),


/*
serial=01FD6D30FCA3CA51A81BBC640E35032D
issuer=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority
sha1 Fingerprint=2B:8F:1B:57:33:0D:BB:A2:D0:7A:6C:51:F7:0E:E9:0D:DA:B9:AD:8E
sha256 Fingerprint=E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2
*/
Fingerprint::SHA256(hex!("e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2")),


/*
serial=01
issuer=C = GB, ST = Greater Manchester, L = Salford, O = Comodo CA Limited, CN = AAA Certificate Services
sha1 Fingerprint=D1:EB:23:A4:6D:17:D6:8F:D9:25:64:C2:F1:F1:60:17:64:D8:E3:49
sha256 Fingerprint=D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4
*/
Fingerprint::SHA256(hex!("d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4")),


/*
serial=5C8B99C55A94C5D27156DECD8980CC26
issuer=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust ECC Certification Authority
sha1 Fingerprint=D1:CB:CA:5D:B2:D5:2A:7F:69:3B:67:4D:E5:F0:5A:1D:0C:95:7D:F0
sha256 Fingerprint=4F:F4:60:D5:4B:9C:86:DA:BF:BC:FC:57:12:E0:40:0D:2B:ED:3F:BC:4D:4F:BD:AA:86:E0:6A:DC:D2:A9:AD:7A
*/
Fingerprint::SHA256(hex!("4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a")),


/*
serial=605949E0262EBB55F90A778A71F94AD86C
issuer=OU = GlobalSign ECC Root CA - R5, O = GlobalSign, CN = GlobalSign
sha1 Fingerprint=1F:24:C6:30:CD:A4:18:EF:20:69:FF:AD:4F:DD:5F:46:3A:1B:69:AA
sha256 Fingerprint=17:9F:BC:14:8A:3D:D0:0F:D2:4E:A1:34:58:CC:43:BF:A7:F5:9C:81:82:D7:83:A5:13:F6:EB:EC:10:0C:89:24
*/
Fingerprint::SHA256(hex!("179fbc148a3dd00fd24ea13458cc43bfa7f59c8182d783a513f6ebec100c8924")),


/*
serial=0A0142800000014523C844B500000002
issuer=C = US, O = IdenTrust, CN = IdenTrust Commercial Root CA 1
sha1 Fingerprint=DF:71:7E:AA:4A:D9:4E:C9:55:84:99:60:2D:48:DE:5F:BC:F0:3A:25
sha256 Fingerprint=5D:56:49:9B:E4:D2:E0:8B:CF:CA:D0:8A:3E:38:72:3D:50:50:3B:DE:70:69:48:E4:2F:55:60:30:19:E5:28:AE
*/
Fingerprint::SHA256(hex!("5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae")),


/*
serial=0A0142800000014523CF467C00000002
issuer=C = US, O = IdenTrust, CN = IdenTrust Public Sector Root CA 1
sha1 Fingerprint=BA:29:41:60:77:98:3F:F4:F3:EF:F2:31:05:3B:2E:EA:6D:4D:45:FD
sha256 Fingerprint=30:D0:89:5A:9A:44:8A:26:20:91:63:55:22:D1:F5:20:10:B5:86:7A:CA:E1:2C:78:EF:95:8F:D4:F4:38:9F:2F
*/
Fingerprint::SHA256(hex!("30d0895a9a448a262091635522d1f52010b5867acae12c78ef958fd4f4389f2f")),


/*
serial=4A538C28
issuer=C = US, O = "Entrust, Inc.", OU = See www.entrust.net/legal-terms, OU = "(c) 2009 Entrust, Inc. - for authorized use only", CN = Entrust Root Certification Authority - G2
sha1 Fingerprint=8C:F4:27:FD:79:0C:3A:D1:66:06:8D:E8:1E:57:EF:BB:93:22:72:D4
sha256 Fingerprint=43:DF:57:74:B0:3E:7F:EF:5F:E4:0D:93:1A:7B:ED:F1:BB:2E:6B:42:73:8C:4E:6D:38:41:10:3D:3A:A7:F3:39
*/
Fingerprint::SHA256(hex!("43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339")),


/*
serial=A68B79290000000050D091F9
issuer=C = US, O = "Entrust, Inc.", OU = See www.entrust.net/legal-terms, OU = "(c) 2012 Entrust, Inc. - for authorized use only", CN = Entrust Root Certification Authority - EC1
sha1 Fingerprint=20:D8:06:40:DF:9B:25:F5:12:25:3A:11:EA:F7:59:8A:EB:14:B5:47
sha256 Fingerprint=02:ED:0E:B2:8C:14:DA:45:16:5C:56:67:91:70:0D:64:51:D7:FB:56:F0:B2:AB:1D:3B:8E:B0:70:E5:6E:DF:F5
*/
Fingerprint::SHA256(hex!("02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5")),


/*
serial=184ACCD6
issuer=C = CN, O = China Financial Certification Authority, CN = CFCA EV ROOT
sha1 Fingerprint=E2:B8:29:4B:55:84:AB:6B:58:C2:90:46:6C:AC:3F:B8:39:8F:84:83
sha256 Fingerprint=5C:C3:D7:8E:4E:1D:5E:45:54:7A:04:E6:87:3E:64:F9:0C:F9:53:6D:1C:CC:2E:F8:00:F3:55:C4:C5:FD:70:FD
*/
Fingerprint::SHA256(hex!("5cc3d78e4e1d5e45547a04e6873e64f90cf9536d1ccc2ef800f355c4c5fd70fd")),


/*
serial=76B1205274F0858746B3F8231AF6C2C0
issuer=C = CH, O = WISeKey, OU = OISTE Foundation Endorsed, CN = OISTE WISeKey Global Root GB CA
sha1 Fingerprint=0F:F9:40:76:18:D3:D7:6A:4B:98:F0:A8:35:9E:0C:FD:27:AC:CC:ED
sha256 Fingerprint=6B:9C:08:E8:6E:B0:F7:67:CF:AD:65:CD:98:B6:21:49:E5:49:4A:67:F5:84:5E:7B:D1:ED:01:9F:27:B8:6B:D6
*/
Fingerprint::SHA256(hex!("6b9c08e86eb0f767cfad65cd98b62149e5494a67f5845e7bd1ed019f27b86bd6")),


/*
serial=3E8A5D07EC55D232D5B7E3B65F01EB2DDCE4D6E4
issuer=C = PL, O = Krajowa Izba Rozliczeniowa S.A., CN = SZAFIR ROOT CA2
sha1 Fingerprint=E2:52:FA:95:3F:ED:DB:24:60:BD:6E:28:F3:9C:CC:CF:5E:B3:3F:DE
sha256 Fingerprint=A1:33:9D:33:28:1A:0B:56:E5:57:D3:D3:2B:1C:E7:F9:36:7E:B0:94:BD:5F:A7:2A:7E:50:04:C8:DE:D7:CA:FE
*/
Fingerprint::SHA256(hex!("a1339d33281a0b56e557d3d32b1ce7f9367eb094bd5fa72a7e5004c8ded7cafe")),


/*
serial=21D6D04A4F250FC93237FCAA5E128DE9
issuer=C = PL, O = Unizeto Technologies S.A., OU = Certum Certification Authority, CN = Certum Trusted Network CA 2
sha1 Fingerprint=D3:DD:48:3E:2B:BF:4C:05:E8:AF:10:F5:FA:76:26:CF:D3:DC:30:92
sha256 Fingerprint=B6:76:F2:ED:DA:E8:77:5C:D3:6C:B0:F6:3C:D1:D4:60:39:61:F4:9E:62:65:BA:01:3A:2F:03:07:B6:D0:B8:04
*/
Fingerprint::SHA256(hex!("b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804")),


/*
serial=0509
issuer=C = BM, O = QuoVadis Limited, CN = QuoVadis Root CA 2
sha1 Fingerprint=CA:3A:FB:CF:12:40:36:4B:44:B2:16:20:88:80:48:39:19:93:7C:F7
sha256 Fingerprint=85:A0:DD:7D:D7:20:AD:B7:FF:05:F8:3D:54:2B:20:9D:C7:FF:45:28:F7:D6:77:B1:83:89:FE:A5:E5:C4:9E:86
*/
Fingerprint::SHA256(hex!("85a0dd7dd720adb7ff05f83d542b209dc7ff4528f7d677b18389fea5e5c49e86")),


/*
serial=00
issuer=C = GR, L = Athens, O = Hellenic Academic and Research Institutions Cert. Authority, CN = Hellenic Academic and Research Institutions RootCA 2015
sha1 Fingerprint=01:0C:06:95:A6:98:19:14:FF:BF:5F:C6:B0:B6:95:EA:29:E9:12:A6
sha256 Fingerprint=A0:40:92:9A:02:CE:53:B4:AC:F4:F2:FF:C6:98:1C:E4:49:6F:75:5E:6D:45:FE:0B:2A:69:2B:CD:52:52:3F:36
*/
Fingerprint::SHA256(hex!("a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36")),


/*
serial=00
issuer=C = GR, L = Athens, O = Hellenic Academic and Research Institutions Cert. Authority, CN = Hellenic Academic and Research Institutions ECC RootCA 2015
sha1 Fingerprint=9F:F1:71:8D:92:D5:9A:F3:7D:74:97:B4:BC:6F:84:68:0B:BA:B6:66
sha256 Fingerprint=44:B5:45:AA:8A:25:E6:5A:73:CA:15:DC:27:FC:36:D2:4C:1C:B9:95:3A:06:65:39:B1:15:82:DC:48:7B:48:33
*/
Fingerprint::SHA256(hex!("44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833")),


/*
serial=8210CFB0D240E3594463E0BB63828B00
issuer=C = US, O = Internet Security Research Group, CN = ISRG Root X1
sha1 Fingerprint=CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8
sha256 Fingerprint=96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6
*/
Fingerprint::SHA256(hex!("96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6")),


/*
serial=5D938D306736C8061D1AC754846907
issuer=C = ES, O = FNMT-RCM, OU = AC RAIZ FNMT-RCM
sha1 Fingerprint=EC:50:35:07:B2:15:C4:95:62:19:E2:A8:9A:5B:42:99:2C:4C:2C:20
sha256 Fingerprint=EB:C5:57:0C:29:01:8C:4D:67:B1:AA:12:7B:AF:12:F7:03:B4:61:1E:BC:17:B7:DA:B5:57:38:94:17:9B:93:FA
*/
Fingerprint::SHA256(hex!("ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa")),


/*
serial=066C9FCF99BF8C0A39E2F0788A43E696365BCA
issuer=C = US, O = Amazon, CN = Amazon Root CA 1
sha1 Fingerprint=8D:A7:F9:65:EC:5E:FC:37:91:0F:1C:6E:59:FD:C1:CC:6A:6E:DE:16
sha256 Fingerprint=8E:CD:E6:88:4F:3D:87:B1:12:5B:A3:1A:C3:FC:B1:3D:70:16:DE:7F:57:CC:90:4F:E1:CB:97:C6:AE:98:19:6E
*/
Fingerprint::SHA256(hex!("8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e")),


/*
serial=066C9FD29635869F0A0FE58678F85B26BB8A37
issuer=C = US, O = Amazon, CN = Amazon Root CA 2
sha1 Fingerprint=5A:8C:EF:45:D7:A6:98:59:76:7A:8C:8B:44:96:B5:78:CF:47:4B:1A
sha256 Fingerprint=1B:A5:B2:AA:8C:65:40:1A:82:96:01:18:F8:0B:EC:4F:62:30:4D:83:CE:C4:71:3A:19:C3:9C:01:1E:A4:6D:B4
*/
Fingerprint::SHA256(hex!("1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4")),


/*
serial=066C9FD5749736663F3B0B9AD9E89E7603F24A
issuer=C = US, O = Amazon, CN = Amazon Root CA 3
sha1 Fingerprint=0D:44:DD:8C:3C:8C:1A:1A:58:75:64:81:E9:0F:2E:2A:FF:B3:D2:6E
sha256 Fingerprint=18:CE:6C:FE:7B:F1:4E:60:B2:E3:47:B8:DF:E8:68:CB:31:D0:2E:BB:3A:DA:27:15:69:F5:03:43:B4:6D:B3:A4
*/
Fingerprint::SHA256(hex!("18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4")),


/*
serial=066C9FD7C1BB104C2943E5717B7B2CC81AC10E
issuer=C = US, O = Amazon, CN = Amazon Root CA 4
sha1 Fingerprint=F6:10:84:07:D6:F8:BB:67:98:0C:C2:E2:44:C2:EB:AE:1C:EF:63:BE
sha256 Fingerprint=E3:5D:28:41:9E:D0:20:25:CF:A6:90:38:CD:62:39:62:45:8D:A5:C6:95:FB:DE:A3:C2:2B:0B:FB:25:89:70:92
*/
Fingerprint::SHA256(hex!("e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092")),


/*
serial=01
issuer=C = TR, L = Gebze - Kocaeli, O = Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK, OU = Kamu Sertifikasyon Merkezi - Kamu SM, CN = TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
sha1 Fingerprint=31:43:64:9B:EC:CE:27:EC:ED:3A:3F:0B:8F:0D:E4:E8:91:DD:EE:CA
sha256 Fingerprint=46:ED:C3:68:90:46:D5:3A:45:3F:B3:10:4A:B8:0D:CA:EC:65:8B:26:60:EA:16:29:DD:7E:86:79:90:64:87:16
*/
Fingerprint::SHA256(hex!("46edc3689046d53a453fb3104ab80dcaec658b2660ea1629dd7e867990648716")),


/*
serial=7D0997FEF047EA7A
issuer=C = CN, O = "GUANG DONG CERTIFICATE AUTHORITY CO.,LTD.", CN = GDCA TrustAUTH R5 ROOT
sha1 Fingerprint=0F:36:38:5B:81:1A:25:C3:9B:31:4E:83:CA:E9:34:66:70:CC:74:B4
sha256 Fingerprint=BF:FF:8F:D0:44:33:48:7D:6A:8A:A6:0C:1A:29:76:7A:9F:C2:BB:B0:5E:42:0F:71:3A:13:B9:92:89:1D:38:93
*/
Fingerprint::SHA256(hex!("bfff8fd04433487d6a8aa60c1a29767a9fc2bbb05e420f713a13b992891d3893")),


/*
serial=05C6
issuer=C = BM, O = QuoVadis Limited, CN = QuoVadis Root CA 3
sha1 Fingerprint=1F:49:14:F7:D8:74:95:1D:DD:AE:02:C0:BE:FD:3A:2D:82:75:51:85
sha256 Fingerprint=18:F1:FC:7F:20:5D:F8:AD:DD:EB:7F:E0:07:DD:57:E3:AF:37:5A:9C:4D:8D:73:54:6B:F4:F1:FE:D1:E1:8D:35
*/
Fingerprint::SHA256(hex!("18f1fc7f205df8adddeb7fe007dd57e3af375a9c4d8d73546bf4f1fed1e18d35")),


/*
serial=7B2C9BD316803299
issuer=C = US, ST = Texas, L = Houston, O = SSL Corporation, CN = SSL.com Root Certification Authority RSA
sha1 Fingerprint=B7:AB:33:08:D1:EA:44:77:BA:14:80:12:5A:6F:BD:A9:36:49:0C:BB
sha256 Fingerprint=85:66:6A:56:2E:E0:BE:5C:E9:25:C1:D8:89:0A:6F:76:A8:7E:C1:6D:4D:7D:5F:29:EA:74:19:CF:20:12:3B:69
*/
Fingerprint::SHA256(hex!("85666a562ee0be5ce925c1d8890a6f76a87ec16d4d7d5f29ea7419cf20123b69")),


/*
serial=75E6DFCBC1685BA8
issuer=C = US, ST = Texas, L = Houston, O = SSL Corporation, CN = SSL.com Root Certification Authority ECC
sha1 Fingerprint=C3:19:7C:39:24:E6:54:AF:1B:C4:AB:20:95:7A:E2:C3:0E:13:02:6A
sha256 Fingerprint=34:17:BB:06:CC:60:07:DA:1B:96:1C:92:0B:8A:B4:CE:3F:AD:82:0E:4A:A3:0B:9A:CB:C4:A7:4E:BD:CE:BC:65
*/
Fingerprint::SHA256(hex!("3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65")),


/*
serial=56B629CD34BC78F6
issuer=C = US, ST = Texas, L = Houston, O = SSL Corporation, CN = SSL.com EV Root Certification Authority RSA R2
sha1 Fingerprint=74:3A:F0:52:9B:D0:32:A0:F4:4A:83:CD:D4:BA:A9:7B:7C:2E:C4:9A
sha256 Fingerprint=2E:7B:F1:6C:C2:24:85:A7:BB:E2:AA:86:96:75:07:61:B0:AE:39:BE:3B:2F:E9:D0:CC:6D:4E:F7:34:91:42:5C
*/
Fingerprint::SHA256(hex!("2e7bf16cc22485a7bbe2aa8696750761b0ae39be3b2fe9d0cc6d4ef73491425c")),


/*
serial=2C299C5B16ED0595
issuer=C = US, ST = Texas, L = Houston, O = SSL Corporation, CN = SSL.com EV Root Certification Authority ECC
sha1 Fingerprint=4C:DD:51:A3:D1:F5:20:32:14:B0:C6:C5:32:23:03:91:C7:46:42:6D
sha256 Fingerprint=22:A2:C1:F7:BD:ED:70:4C:C1:E7:01:B5:F4:08:C3:10:88:0F:E9:56:B5:DE:2A:4A:44:F9:9C:87:3A:25:A7:C8
*/
Fingerprint::SHA256(hex!("22a2c1f7bded704cc1e701b5f408c310880fe956b5de2a4a44f99c873a25a7c8")),


/*
serial=45E6BB038333C3856548E6FF4551
issuer=OU = GlobalSign Root CA - R6, O = GlobalSign, CN = GlobalSign
sha1 Fingerprint=80:94:64:0E:B5:A7:A1:CA:11:9C:1F:DD:D5:9F:81:02:63:A7:FB:D1
sha256 Fingerprint=2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69
*/
Fingerprint::SHA256(hex!("2cabeafe37d06ca22aba7391c0033d25982952c453647349763a3ab5ad6ccf69")),


/*
serial=212A560CAEDA0CAB4045BF2BA22D3AEA
issuer=C = CH, O = WISeKey, OU = OISTE Foundation Endorsed, CN = OISTE WISeKey Global Root GC CA
sha1 Fingerprint=E0:11:84:5E:34:DE:BE:88:81:B9:9C:F6:16:26:D1:96:1F:C3:B9:31
sha256 Fingerprint=85:60:F9:1C:36:24:DA:BA:95:70:B5:FE:A0:DB:E3:6F:F1:1A:83:23:BE:94:86:85:4F:B3:F3:4A:55:71:19:8D
*/
Fingerprint::SHA256(hex!("8560f91c3624daba9570b5fea0dbe36ff11a8323be9486854fb3f34a5571198d")),


/*
serial=5DDFB1DA5AA3ED5DBE5A6520650390EF
issuer=C = CN, O = UniTrust, CN = UCA Global G2 Root
sha1 Fingerprint=28:F9:78:16:19:7A:FF:18:25:18:AA:44:FE:C1:A0:CE:5C:B6:4C:8A
sha256 Fingerprint=9B:EA:11:C9:76:FE:01:47:64:C1:BE:56:A6:F9:14:B5:A5:60:31:7A:BD:99:88:39:33:82:E5:16:1A:A0:49:3C
*/
Fingerprint::SHA256(hex!("9bea11c976fe014764c1be56a6f914b5a560317abd9988393382e5161aa0493c")),


/*
serial=4FD22B8FF564C8339E4F345866237060
issuer=C = CN, O = UniTrust, CN = UCA Extended Validation Root
sha1 Fingerprint=A3:A1:B0:6F:24:61:23:4A:E3:36:A5:C2:37:FC:A6:FF:DD:F0:D7:3A
sha256 Fingerprint=D4:3A:F9:B3:54:73:75:5C:96:84:FC:06:D7:D8:CB:70:EE:5C:28:E7:73:FB:29:4E:B4:1E:E7:17:22:92:4D:24
*/
Fingerprint::SHA256(hex!("d43af9b35473755c9684fc06d7d8cb70ee5c28e773fb294eb41ee71722924d24")),


/*
serial=CAE91B89F155030DA3E6416DC4E3A6E1
issuer=C = FR, O = Dhimyotis, OU = 0002 48146308100036, CN = Certigna Root CA
sha1 Fingerprint=2D:0D:52:14:FF:9E:AD:99:24:01:74:20:47:6E:6C:85:27:27:F5:43
sha256 Fingerprint=D4:8D:3D:23:EE:DB:50:A4:59:E5:51:97:60:1C:27:77:4B:9D:7B:18:C9:4D:5A:05:95:11:A1:02:50:B9:31:68
*/
Fingerprint::SHA256(hex!("d48d3d23eedb50a459e55197601c27774b9d7b18c94d5a059511a10250b93168")),


/*
serial=31F5E4620C6C58EDD6D8
issuer=C = IN, OU = emSign PKI, O = eMudhra Technologies Limited, CN = emSign Root CA - G1
sha1 Fingerprint=8A:C7:AD:8F:73:AC:4E:C1:B5:75:4D:A5:40:F4:FC:CF:7C:B5:8E:8C
sha256 Fingerprint=40:F6:AF:03:46:A9:9A:A1:CD:1D:55:5A:4E:9C:CE:62:C7:F9:63:46:03:EE:40:66:15:83:3D:C8:C8:D0:03:67
*/
Fingerprint::SHA256(hex!("40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367")),


/*
serial=50946CEC18EAD59C4DD597EF758FA0AD
issuer=C = US, OU = www.xrampsecurity.com, O = XRamp Security Services Inc, CN = XRamp Global Certification Authority
sha1 Fingerprint=B8:01:86:D1:EB:9C:86:A5:41:04:CF:30:54:F3:4C:52:B7:E5:58:C6
sha256 Fingerprint=CE:CD:DC:90:50:99:D8:DA:DF:C5:B1:D2:09:B7:37:CB:E2:C1:8C:FB:2C:10:C0:FF:0B:CF:0D:32:86:FC:1A:A2
*/
Fingerprint::SHA256(hex!("cecddc905099d8dadfc5b1d209b737cbe2c18cfb2c10c0ff0bcf0d3286fc1aa2")),


/*
serial=3CF607A968700EDA8B84
issuer=C = IN, OU = emSign PKI, O = eMudhra Technologies Limited, CN = emSign ECC Root CA - G3
sha1 Fingerprint=30:43:FA:4F:F2:57:DC:A0:C3:80:EE:2E:58:EA:78:B2:3F:E6:BB:C1
sha256 Fingerprint=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
*/
Fingerprint::SHA256(hex!("86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b")),


/*
serial=AECF00BAC4CF32F843B2
issuer=C = US, OU = emSign PKI, O = eMudhra Inc, CN = emSign Root CA - C1
sha1 Fingerprint=E7:2E:F1:DF:FC:B2:09:28:CF:5D:D4:D5:67:37:B1:51:CB:86:4F:01
sha256 Fingerprint=12:56:09:AA:30:1D:A0:A2:49:B9:7A:82:39:CB:6A:34:21:6F:44:DC:AC:9F:39:54:B1:42:92:F2:E8:C8:60:8F
*/
Fingerprint::SHA256(hex!("125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f")),


/*
serial=7B71B68256B8127C9CA8
issuer=C = US, OU = emSign PKI, O = eMudhra Inc, CN = emSign ECC Root CA - C3
sha1 Fingerprint=B6:AF:43:C2:9B:81:53:7D:F6:EF:6B:C3:1F:1F:60:15:0C:EE:48:66
sha256 Fingerprint=BC:4D:80:9B:15:18:9D:78:DB:3E:1D:8C:F4:F9:72:6A:79:5D:A1:64:3C:A5:F1:35:8E:1D:DB:0E:DC:0D:7E:B3
*/
Fingerprint::SHA256(hex!("bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3")),


/*
serial=08165F8A4CA5EC00C99340DFC4C6AE23B81C5AA4
issuer=C = HK, ST = Hong Kong, L = Hong Kong, O = Hongkong Post, CN = Hongkong Post Root CA 3
sha1 Fingerprint=58:A2:D0:EC:20:52:81:5B:C1:F3:F8:64:02:24:4E:C2:8E:02:4B:02
sha256 Fingerprint=5A:2F:C0:3F:0C:83:B0:90:BB:FA:40:60:4B:09:88:44:6C:76:36:18:3D:F9:84:6E:17:10:1A:44:7F:B8:EF:D6
*/
Fingerprint::SHA256(hex!("5a2fc03f0c83b090bbfa40604b0988446c7636183df9846e17101a447fb8efd6")),


/*
serial=D9B5437FAFA9390F000000005565AD58
issuer=C = US, O = "Entrust, Inc.", OU = See www.entrust.net/legal-terms, OU = "(c) 2015 Entrust, Inc. - for authorized use only", CN = Entrust Root Certification Authority - G4
sha1 Fingerprint=14:88:4E:86:26:37:B0:26:AF:59:62:5C:40:77:EC:35:29:BA:96:01
sha256 Fingerprint=DB:35:17:D1:F6:73:2A:2D:5A:B9:7C:53:3E:C7:07:79:EE:32:70:A6:2F:B4:AC:42:38:37:24:60:E6:F0:1E:88
*/
Fingerprint::SHA256(hex!("db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88")),


/*
serial=66F23DAF87DE8BB14AEA0C573101C2EC
issuer=C = US, O = Microsoft Corporation, CN = Microsoft ECC Root Certificate Authority 2017
sha1 Fingerprint=99:9A:64:C3:7F:F4:7D:9F:AB:95:F1:47:69:89:14:60:EE:C4:C3:C5
sha256 Fingerprint=35:8D:F3:9D:76:4A:F9:E1:B7:66:E9:C9:72:DF:35:2E:E1:5C:FA:C2:27:AF:6A:D1:D7:0E:8E:4A:6E:DC:BA:02
*/
Fingerprint::SHA256(hex!("358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02")),


/*
serial=1ED397095FD8B4B347701EAABE7F45B3
issuer=C = US, O = Microsoft Corporation, CN = Microsoft RSA Root Certificate Authority 2017
sha1 Fingerprint=73:A5:E6:4A:3B:FF:83:16:FF:0E:DC:CC:61:8A:90:6E:4E:AE:4D:74
sha256 Fingerprint=C7:41:F7:0F:4B:2A:8D:88:BF:2E:71:C1:41:22:EF:53:EF:10:EB:A0:CF:A5:E6:4C:FA:20:F4:18:85:30:73:E0
*/
Fingerprint::SHA256(hex!("c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0")),


/*
serial=015448EF21FD97590DF5040A
issuer=C = HU, L = Budapest, O = Microsec Ltd., organizationIdentifier = VATHU-23584497, CN = e-Szigno Root CA 2017
sha1 Fingerprint=89:D4:83:03:4F:9E:9A:48:80:5F:72:37:D4:A9:A6:EF:CB:7C:1F:D1
sha256 Fingerprint=BE:B0:0B:30:83:9B:9B:C3:2C:32:E4:44:79:05:95:06:41:F2:64:21:B1:5E:D0:89:19:8B:51:8A:E2:EA:1B:99
*/
Fingerprint::SHA256(hex!("beb00b30839b9bc32c32e4447905950641f26421b15ed089198b518ae2ea1b99")),


/*
serial=110034B64EC6362D36
issuer=C = RO, O = CERTSIGN SA, OU = certSIGN ROOT CA G2
sha1 Fingerprint=26:F9:93:B4:ED:3D:28:27:B0:B9:4B:A7:E9:15:1D:A3:8D:92:E5:32
sha256 Fingerprint=65:7C:FE:2F:A7:3F:AA:38:46:25:71:F3:32:A2:36:3A:46:FC:E7:02:09:51:71:07:02:CD:FB:B6:EE:DA:33:05
*/
Fingerprint::SHA256(hex!("657cfe2fa73faa38462571f332a2363a46fce7020951710702cdfbb6eeda3305")),


/*
serial=05F70E86DA49F346352EBAB2
issuer=C = US, ST = Illinois, L = Chicago, O = "Trustwave Holdings, Inc.", CN = Trustwave Global Certification Authority
sha1 Fingerprint=2F:8F:36:4F:E1:58:97:44:21:59:87:A5:2A:9A:D0:69:95:26:7F:B5
sha256 Fingerprint=97:55:20:15:F5:DD:FC:3C:87:88:C0:06:94:45:55:40:88:94:45:00:84:F1:00:86:70:86:BC:1A:2B:B5:8D:C8
*/
Fingerprint::SHA256(hex!("97552015f5ddfc3c8788c006944555408894450084f100867086bc1a2bb58dc8")),


/*
serial=00
issuer=C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
sha1 Fingerprint=27:96:BA:E6:3F:18:01:E2:77:26:1B:A0:D7:77:70:02:8F:20:EE:E4
sha256 Fingerprint=C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4
*/
Fingerprint::SHA256(hex!("c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4")),


];
