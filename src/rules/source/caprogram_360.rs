use crate::*;
pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[
    /* SM2 begin */
    Fingerprint::SHA1(hex!("f1ec3b4c09a8cc4e4db802fff4209b61d9964dc3")), // UCA Root SM2
    Fingerprint::SHA1(hex!("f0fe97b482030ada4975fa00b276f69bab4355b5")), // UniTrust Global Root CA R3
    Fingerprint::SHA1(hex!("5860ee6465e8fd28dd37245028aa27b99fcd9f64")), // BJCA Global Root CA4
    Fingerprint::SHA1(hex!("d3b62f674f59185486d03f47237fadfdfcbdd648")), // GDCA GM SM2 ROOT
    Fingerprint::SHA1(hex!("67cae891bb5dfe90bd12655f37379b01121a32ee")), // vTrus SM2 Root CA G1
    Fingerprint::SHA1(hex!("f69a41ce24a0fdce4054803d331842c7372c0cce")), // WoTrus-SM2
    Fingerprint::SHA1(hex!("e0d3b896865c7237a23735fa624633eae78a4f2b")), // SZCA SM2 ROOT CA
    Fingerprint::SHA1(hex!("d567e15af3d6b12b9128462f00384fa75d55f7bc")), // AHCA SM2 ROOT
    Fingerprint::SHA1(hex!("94566c85c56095630126f8ca5c207a60b4f88be7")), // CFCA CS SM2 CA
    Fingerprint::SHA1(hex!("331d93142bc3945930d1fa4d3704b8199e751c29")), // 陕西CA国密根证书
    Fingerprint::SHA1(hex!("e939b533b1383273e9b93a9104b485952e532e51")), // CMCA SM2 ROOT CA
    Fingerprint::SHA1(hex!("c8136a3da3c6d5a8e229c78fa5f5104b0967e14f")), // CCS NETCA SM2 Root WB1
    Fingerprint::SHA1(hex!("4dcac7f4c3e619be8510b753b8c4b4b7cf6c63b8")), // TrustAsia Global SM2 Root CA G2
    Fingerprint::SHA1(hex!("45df30187b9681288d6a94838a816d6ea3498b8a")), // TrustAsia SM2 Root CA
    Fingerprint::SHA1(hex!("1ca6e94b692b8c8c67036000e8aeb00db0d1e648")), // NJCA SM2 ROOT
    Fingerprint::SHA1(hex!("47620569633087FCDAD91DA5C19FA685D95C583A")), // SCCA Root CA1
    Fingerprint::SHA1(hex!("77331482b9cd1e15ccdb1981802e5311412bb36e")), // CHINA UNICOM GLOBAL ROOT CA SM2
    Fingerprint::SHA1(hex!("8e856b17deb55eb85d68fbc7fdaf75e885c703a5")), // SDCASM2ROOTCA
    Fingerprint::SHA1(hex!("b817d2df62ca1a05cf2874a686d9f90fcc7adb0e")), // Guizhou SM2 CA
    Fingerprint::SHA1(hex!("6630a4cc4b970bb6313e8907c66e02f4432e03b9")), // 江苏智慧数字认证有限公司
    Fingerprint::SHA1(hex!("149dcc7fe499d0f5f7511d45a749dc751f3e06bd")), // ZXCA SM2 ROOT R4

    /* RSA begin */
    Fingerprint::SHA1(hex!("eb466cd37565f93cde1062cd8d9826ed23730f12")), // GDCA TrustAUTH E5 ROOT
    Fingerprint::SHA1(hex!("0f36385b811a25c39b314e83cae9346670cc74b4")), // GDCA TrustAUTH R5 ROOT
    Fingerprint::SHA1(hex!("23eb1ba46471a1e7e9f2db5701fef8f2f80caae9")), // 数安时代 R5 根 CA
    Fingerprint::SHA1(hex!("f69cdbb0fcf60213b65232a6a3913f1670dac3e1")), // vTrus ECC Root CA
    Fingerprint::SHA1(hex!("841a69fbf5cd1a2534133de3f8fcb899d0c914b7")), // vTrus Root CA
    Fingerprint::SHA1(hex!("a3a1b06f2461234ae336a5c237fca6ffddf0d73a")), // UCA Extended Validation Root
    Fingerprint::SHA1(hex!("28f97816197aff182518aa44fec1a0ce5cb64c8a")), // UCA Global G2 Root
    Fingerprint::SHA1(hex!("e2b8294b5584ab6b58c290466cac3fb8398f8483")), // CFCA EV ROOT
    Fingerprint::SHA1(hex!("d5ec8d7b4cba79f4e7e8cb9d6bae77831003216a")), // BJCA Global Root CA1
    Fingerprint::SHA1(hex!("f42786eb6eb86d88316702fbba66a45300aa7aa6")), // BJCA Global Root CA2
    Fingerprint::SHA1(hex!("3143649becce27eced3a3f0b8f0de4e891ddeeca")), // TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
    Fingerprint::SHA1(hex!("63cfb6c1272b56e4888e1c239ab62e814724c3c7")), // TrustAsia Global Root CA G3
    Fingerprint::SHA1(hex!("5773a5615d80b2e6ac3882fc680731ac9fb5925a")), // TrustAsia Global Root CA G4
];
