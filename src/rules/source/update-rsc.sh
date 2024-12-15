#!/bin/bash

outdir="$(realpath .)"
outfile="${outdir}/revoke_suspicious_certs.rs"

set -e
set -x

type jq
type openssl
type mktemp
type unzip
type curl
type sha1sum
type awk
type rm
type mv

tmp="$(mktemp -d -t anypkiRulesBlacklistCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/zh250/RevokeSuspiciousCerts/archive/master.zip -v -L -o rsc.zip
unzip rsc.zip

echo "use crate::*;" > rs.tmp.out
echo "pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[" >> rs.tmp.out
for cert in $(find -type f -name '*.crt')
do
	echo "/*"
	openssl x509 -in $cert -noout -serial -issuer -subject -sha1 -fingerprint
	openssl x509 -in $cert -noout -sha256 -fingerprint
	echo "*/"
	
	echo "Fingerprint::SHA256(hex!(\"$(echo $(openssl x509 -in $cert -outform der | sha256sum | awk '{print $1}'))\")),"
	echo -e "\n"
done >> rs.tmp.out
echo "];" >> rs.tmp.out

mv rs.tmp.out $outfile

