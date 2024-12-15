#!/bin/bash

outdir="$(realpath .)"
outfile="${outdir}/trustedpki.rs"

set -e
set -x

type bash
type mktemp
type awk
type grep
type cargo
type jq
type sed
type rm
type mv

bash update-mozilla.sh

tmp="$(mktemp -d -t anypkiRulesTrustedPkiCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
#cd $tmp

tmpout="${tmp}/rs.tmp.out"

echo "use crate::*;" > $tmpout
echo "pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[" >> $tmpout

fpl="$(cargo test moz -- --nocapture 2>&1 | grep -F "trustedpki:" | awk '{print $2}' | jq -r '.[]')"
fpn="$(cat mozilla.rs | grep -n -E $(echo $fpl | tr ' ' '|') | tr ':' ' ' | awk '{print $1}')"

sed_command=()
for n in $fpn
do
    sed_command+=("$[n-6],$[n+2]p;")
done
sed_command="$(echo ${sed_command[*]})"

cat mozilla.rs | sed -n "$sed_command" >> $tmpout

echo "];" >> $tmpout

mv $tmpout $outfile

