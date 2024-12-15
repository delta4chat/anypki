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
    Fingerprint::SHA1(hex!("47620569633087fcdad91da5c19fa685d95c583a")), // SCCA Root CA1
    Fingerprint::SHA1(hex!("77331482b9cd1e15ccdb1981802e5311412bb36e")), // CHINA UNICOM GLOBAL ROOT CA SM2
    Fingerprint::SHA1(hex!("8e856b17deb55eb85d68fbc7fdaf75e885c703a5")), // SDCASM2ROOTCA
    Fingerprint::SHA1(hex!("b817d2df62ca1a05cf2874a686d9f90fcc7adb0e")), // Guizhou SM2 CA
    Fingerprint::SHA1(hex!("6630a4cc4b970bb6313e8907c66e02f4432e03b9")), // 江苏智慧数字认证有限公司
    Fingerprint::SHA1(hex!("149dcc7fe499d0f5f7511d45a749dc751f3e06bd")), // ZXCA SM2 ROOT R4

    /* RSA begin */
    Fingerprint::SHA256(hex!("ea152fd132de4f4e71930a9760517a81dacbbb5f1014d8bd7782ac0cc37e9431")), // GDCA TrustAUTH E5 ROOT
    Fingerprint::SHA256(hex!("bfff8fd04433487d6a8aa60c1a29767a9fc2bbb05e420f713a13b992891d3893")), // GDCA TrustAUTH R5 ROOT
    Fingerprint::SHA256(hex!("71a1a38ff485137002dd5cd780b3873dde146723ee28080ecf3738c7c4feb1ae")), // 数安时代 R5 根 CA
    Fingerprint::SHA256(hex!("30fbba2c32238e2a98547af97931e550428b9b3f1c8eeb663 3dcfa86c5b27dd3")), // vTrus ECC Root CA
    Fingerprint::SHA256(hex!("8a71de6559336f426c26e53880d00d88a18da4c6a91f0dcb6 194e206c5c96387")), // vTrus Root CA
    Fingerprint::SHA256(hex!("d43af9b35473755c9684fc06d7d8cb70ee5c28e773fb294eb41ee71722924d24")), // UCA Extended Validation Root
    Fingerprint::SHA256(hex!("9bea11c976fe014764c1be56a6f914b5a560317abd9988393382e5161aa0493c")), // UCA Global G2 Root
    Fingerprint::SHA256(hex!("5cc3d78e4e1d5e45547a04e6873e64f90cf9536d1ccc2ef800f355c4c5fd70fd")), // CFCA EV ROOT
    Fingerprint::SHA256(hex!("f3896f88fe7c0a882766a7fa6ad2749fb57a7f3e98fb769c1fa7b09c2c44d5ae")), // BJCA Global Root CA1
    Fingerprint::SHA256(hex!("574df6931e278039667b720afdc1600fc27eb66dd3092979fb73856487212882")), // BJCA Global Root CA2
    Fingerprint::SHA256(hex!("46edc3689046d53a453fb3104ab80dcaec658b2660ea1629dd7e867990648716")), // TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
    Fingerprint::SHA256(hex!("e0d3226aeb1163c2e48ff9be3b50b4c6431be7bb1eacc5c36b5d5ec509039a08")), // TrustAsia Global Root CA G3
    Fingerprint::SHA256(hex!("be4b56cb5056c0136a526df444508daa36a0b54f42e4ac38f72af470e479654c")), // TrustAsia Global Root CA G4
];
