#!/bin/bash

outdir="$(realpath .)"
outfile="${outdir}/caprogram_360.rs"

set -e
set -x

type jq
type mktemp
type curl
type rm
type mv

tmp="$(mktemp -d -t anypkiRulesBlacklistCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

cat <<EOF > rs.tmp.out
use crate::*;
pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[
    /* SM2 begin */
EOF

curl https://caprogram.360.cn/trusted_root_cert_sm.json -v -L -o 360-sm.json
cat 360-sm.json | jq -r '.data[] | "    Fingerprint::SHA1(hex!(\""+.fingerprintSha1 + "\")), // " + .rootCertificate' >> rs.tmp.out

cat <<EOF >> rs.tmp.out

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
EOF

mv rs.tmp.out $outfile
