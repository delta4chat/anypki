#!/bin/bash

outdir="$(realpath .)"
outfile="${outdir}/mozilla.rs"

set -e
set -x

type openssl
type mktemp
type curl
type sha256sum
type awk
type mkdir
type rm
type mv

tmp="$(mktemp -d -t anypkiRulesMozillaPkiCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://curl.se/ca/cacert.pem -v -L -o mozilla.pem

mkdir mozilla
cd mozilla

cat ../mozilla.pem | awk 'split_after==1{n++;split_after=0}
   /-----END CERTIFICATE-----/ {split_after=1}
   {if(length($0) > 0) print > "cert" (1+n) ".pem"}'

echo "use crate::*;" > rs.tmp.out
echo "pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[" >> rs.tmp.out

for cert in *.pem
do
    echo "/*"
    openssl x509 -in $cert -noout -serial -issuer -sha1 -fingerprint
    openssl x509 -in $cert -noout -sha256 -fingerprint
    echo "*/"
    echo "Fingerprint::SHA256(hex!(\"$(openssl x509 -in $cert -outform der | sha256sum | awk '{print $1}')\")),"
    echo -e "\n"
done >> rs.tmp.out

echo "];" >> rs.tmp.out

mv rs.tmp.out $outfile

