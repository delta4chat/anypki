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

tmp="$(mktemp -d -t anypkiRulesTrustedPkiCertUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
#cd $tmp

tmpout="${tmp}/rs.tmp.out"

echo "use crate::*;" > $tmpout
echo "pub const FINGERPRINT_LIST: &'static [Fingerprint] = &[" >> $tmpout

fph="$(cargo test moz -- --nocapture 2>&1 | grep -F "trustedpki:" | awk '{print $2}')"
fpl="$(cat mozilla.rs | grep -n -E $fph | tr ':' ' ' | awk '{print $1}')"

sed_command=()
for l in $fpl
do
    sed_command+=("$[l-6],$[l+2]p;")
done
sed_command="$(echo ${sed_command[*]})"

cat mozilla.rs | sed -n "$sed_command" >> $tmpout

echo "];" >> $tmpout

mv $tmpout $outfile

