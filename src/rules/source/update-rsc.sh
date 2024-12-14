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
cd RevokeSuspiciousCerts-master/Shared/Certificates/

echo "use crate::*;" > rs.tmp.out
echo "pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[" >> rs.tmp.out
for cert in *.crt
do
	echo "/*" >> rs.tmp.out
	openssl x509 -in $cert -noout -serial -sha1 -fingerprint -issuer -subject >> rs.tmp.out
	echo "*/" >> rs.tmp.out
	
	echo "Fingerprint::SHA1(hex!(\"$(echo $(openssl x509 -in $cert -outform der | sha1sum | awk '{print $1}'))\")])," >> rs.tmp.out
	echo -e "\n" >> rs.tmp.out
done
echo "];" >> rs.tmp.out

mv rs.tmp.out $outfile

