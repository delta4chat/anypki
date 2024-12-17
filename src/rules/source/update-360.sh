#!/bin/bash

set -e
set -x

type jq
type mktemp
type curl
type cat
type realpath
type rm
type mv

outdir="$(realpath .)"
outfile="${outdir}/caprogram_360.rs"

tmp="$(mktemp -d -t anypkiRulesBlacklistCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

cat <<EOF > rs.tmp.out
use crate::*;
pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[
    /* SM2 begin */
EOF

curl https://caprogram.360.cn/trusted_root_cert_sm.json -v -L -o 360-sm.json
cat 360-sm.json | jq -r '.data[] | "    Fingerprint::SHA1(hex!(\"" + (.fingerprintSha1 | ascii_downcase) + "\")), // " + .rootCertificate' >> rs.tmp.out

cat <<EOF >> rs.tmp.out

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
EOF

mv rs.tmp.out $outfile
