pub mod rules;

use core::ops::Deref;
use std::collections::HashSet;

use slice_find::SliceFind;

use country_code_enum::CountryCode;

use x509cert::{
    X509Certificate,
    KeyAlgorithm, SignatureAlgorithm, DigestAlgorithm,
};

#[derive(Debug, Clone)]
pub struct Certificate(X509Certificate);

impl From<X509Certificate> for Certificate {
    fn from(val: X509Certificate) -> Self {
        Self(val)
    }
}
impl From<Certificate> for X509Certificate {
    fn from(val: Certificate) -> Self {
        val.0
    }
}

impl TryFrom<rustls_pki_types::TrustAnchor<'_>> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: rustls_pki_types::TrustAnchor<'_>) -> anyhow::Result<Self> {
        val.subject.deref().try_into()
    }
}
impl TryFrom<rustls_pki_types::CertificateDer<'_>> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: rustls_pki_types::CertificateDer<'_>) -> anyhow::Result<Self> {
        val.deref().try_into()
    }
}
impl TryFrom<native_tls::Certificate> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: native_tls::Certificate) -> anyhow::Result<Self> {
        val.to_der()?.try_into()
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: &[u8]) -> anyhow::Result<Self> {
        if let Ok(cert) = X509Certificate::from_der(val) {
            return Ok(cert.into());
        }
        if let Ok(cert) = X509Certificate::from_ber(val) {
            return Ok(cert.into());
        }
        if let Ok(cert) = X509Certificate::from_pem(val) {
            return Ok(cert.into());
        }

        anyhow::bail!("provided byte array is not a valid format of DER, BER, or PEM.");
    }
}
impl TryFrom<Vec<u8>> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: Vec<u8>) -> anyhow::Result<Self> {
        let val: &[u8] = val.as_ref();
        val.try_into()
    }
}
impl<const N: usize> TryFrom<&[u8; N]> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: &[u8; N]) -> anyhow::Result<Self> {
        val.as_ref().try_into()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    SHA1([u8; 20]),
    SHA256([u8; 32]),
    SHA384([u8; 48]),
    SHA512([u8; 64]),
}
impl PartialEq<[u8]> for Fingerprint {
    fn eq(&self, other: &[u8]) -> bool {
        use Fingerprint::*;
        match self {
            SHA1(v)   => { &v[..] == other },
            SHA256(v) => { &v[..] == other },
            SHA384(v) => { &v[..] == other },
            SHA512(v) => { &v[..] == other },
        }
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(val: &[u8]) -> anyhow::Result<Self> {
        Ok(match val.len() {
            20 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(val);
                Self::SHA1(h)
            },
            32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(val);
                Self::SHA256(h)
            },
            48 => {
                let mut h = [0u8; 48];
                h.copy_from_slice(val);
                Self::SHA384(h)
            },
            64 => {
                let mut h = [0u8; 64];
                h.copy_from_slice(val);
                Self::SHA512(h)
            },
            _ => {
                anyhow::bail!("provided byte array length is not valid for SHA1, SHA256, SHA384, and SHA512.");
            }
        })
    }
}

impl From<&Fingerprint> for DigestAlgorithm {
    fn from(val: &Fingerprint) -> Self {
        use Fingerprint::*;
        use DigestAlgorithm::*;
        match val {
            SHA1(_) => Sha1,
            SHA256(_) => Sha256,
            SHA384(_) => Sha384,
            SHA512(_) => Sha512,
        }
    }
}

/// A filter exclude certificates by country code, fingerprint, or name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Filter {
    CountryCode(CountryCode),
    PublicKey(Vec<u8>),
    SerialNumber(bcder::int::Integer),
    Fingerprint(Fingerprint),
    Name(String),
    SignatureAlgorithm(SignatureAlgorithm),
    KeyAlgorithm(KeyAlgorithm),
}

macro_rules! filter_from_inner_impl {
    ($n:ident, $t:ty) => {
        impl From<$t> for Filter {
            #[inline(always)]
            fn from(val: $t) -> Self {
                Self::$n(val)
            }
        }
    };
}

filter_from_inner_impl!(CountryCode, CountryCode);
filter_from_inner_impl!(PublicKey, Vec<u8>);
filter_from_inner_impl!(SerialNumber, bcder::int::Integer);
filter_from_inner_impl!(Fingerprint, Fingerprint);
filter_from_inner_impl!(Name, String);
filter_from_inner_impl!(SignatureAlgorithm, SignatureAlgorithm);
filter_from_inner_impl!(KeyAlgorithm, KeyAlgorithm);

impl Filter {
    pub fn matches(&self, cert: &Certificate) -> bool {
        let cert = &cert.0;

        use Filter::*;
        match self {
            CountryCode(cc) => {
                for attr in cert.issuer_name().iter_country().chain(cert.subject_name().iter_country()) {
                    let val = &attr.value;
                    if let Ok(s) = val.to_string() {
                        if cc.as_ref() == s.as_str() {
                            return true;
                        }
                    } else if cc.as_ref().as_bytes() == val.as_slice() {
                        return true;
                    }
                }
            },
            PublicKey(pk) => {
                if pk == cert.public_key_data().as_ref() {
                    return true;
                }
            },
            SerialNumber(sn) => {
                if sn == cert.serial_number_asn1() {
                    return true;
                }
            },
            Fingerprint(fp) => {
                if let Ok(cert_fp) = cert.fingerprint(fp.into()) {
                    if fp == cert_fp.as_ref() {
                        return true;
                    }
                }
            },
            Name(name) => {
                let name = name.to_lowercase();
                let i = cert.issuer_name();
                let s = cert.subject_name();
                for cert_name in
                    i.iter_common_name().chain(s.iter_common_name())
                    .chain(i.iter_organization()).chain(s.iter_organization())
                    .chain(i.iter_organizational_unit()).chain(s.iter_organizational_unit())
                {
                    let val = &cert_name.value;
                    if let Ok(s) = val.to_string() {
                        if s.to_lowercase().contains(&name) {
                            return true;
                        }
                    } else {
                        let val = val.as_slice().to_ascii_lowercase();
                        if val.contains(name.as_bytes()) {
                            return true;
                        }
                    }
                }
            },
            SignatureAlgorithm(sa) => {
                if let Some(ref cert_sa) = cert.signature_algorithm() {
                    if sa == cert_sa {
                        return true;
                    }
                }
            },
            KeyAlgorithm(ka) => {
                if let Some(ref cert_ka) = cert.key_algorithm() {
                    if ka == cert_ka {
                        return true;
                    }
                }
            },
        }

        false
    }
}

/// A builder style for building a set of certificates.
#[derive(Debug, Clone)]
pub struct AnyPKI {
    blacklist: Option<HashSet<Filter>>,
    whitelist: Option<HashSet<Filter>>,

    readonly: bool,
}
impl Default for AnyPKI {
    fn default() -> Self {
        Self::new()
    }
}
impl AnyPKI {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            blacklist: None,
            whitelist: None,

            readonly: false,
        }
    }

    #[inline(always)]
    fn _rw_check(&self) {
        if self.readonly {
            panic!("try to modify a read-only (finalized) instance of AnyPKI.");
        }
    }

    #[inline(always)]
    fn _ro_check(&self) {
        if ! self.readonly {
            panic!("try to apply a modifiable (non-finalized) instance of AnyPKI.");
        }
    }

    pub fn clear(mut self) -> Self {
        self._rw_check();

        self.blacklist = None;
        self.whitelist = None;

        self
    }

    pub fn extend(mut self, other: &Self) -> Self {
        self._rw_check();

        if let Some(ref bl) = other.blacklist {
            self.blacklist.get_or_insert_with(Default::default).extend(bl.clone());
        }
        if let Some(ref wl) = other.whitelist {
            self.whitelist.get_or_insert_with(Default::default).extend(wl.clone());
        }

        self
    }

    /// removes any certificates matches the provided filter.
    #[inline(always)]
    pub fn blacklist(mut self, f: impl Into<Filter>) -> Self {
        self._rw_check();

        let blacklist = self.blacklist.get_or_insert_with(Default::default);
        blacklist.insert(f.into());
        self
    }
    #[inline(always)]
    pub fn ban(self, f: impl Into<Filter>) -> Self { self.blacklist(f) }
    #[inline(always)]
    pub fn disallow(self, f: impl Into<Filter>) -> Self { self.blacklist(f) }
    #[inline(always)]
    pub fn deny(self, f: impl Into<Filter>) -> Self { self.blacklist(f) }

    /// only allows certificates that matches provided filter.
    #[inline(always)]
    pub fn whitelist(mut self, f: impl Into<Filter>) -> Self {
        self._rw_check();

        let whitelist = self.whitelist.get_or_insert_with(Default::default);
        whitelist.insert(f.into());
        self
    }
    #[inline(always)]
    pub fn exclusive(self, f: impl Into<Filter>) -> Self { self.whitelist(f) }
    #[inline(always)]
    pub fn allow(self, f: impl Into<Filter>) -> Self { self.whitelist(f) }
    #[inline(always)]
    pub fn permit(self, f: impl Into<Filter>) -> Self { self.whitelist(f) }

    #[inline(always)]
    pub fn finalize(mut self) -> Self {
        self.readonly = true;

        self
    }
    #[inline(always)]
    pub fn build(self) -> Self { self.finalize() }
    #[inline(always)]
    pub fn freeze(self) -> Self { self.finalize() }
    #[inline(always)]
    pub fn readonly(self) -> Self { self.finalize() }

    /// Checks the provided certificate whether should be kept.
    #[inline(always)]
    pub fn is_valid(&self, cert: &Certificate) -> bool {
        self._ro_check();

        if let Some(ref wl) = self.whitelist {
            for allow in wl.iter() {
                if allow.matches(cert) {
                    return true;
                }
            }
            return false;
        }

        if let Some(ref bl) = self.blacklist {
            for deny in bl.iter() {
                if deny.matches(cert) {
                    return false;
                }
            }
            return true;
        }

        // no filter... default to allow
        true
    }

    /// Apply this filter to a list of certificates.
    #[inline(always)]
    pub fn apply(&self, iter: impl Iterator<Item=Certificate>) -> impl Iterator<Item=Certificate> {
        self._ro_check();

        let this = self.clone();
        iter.filter(move |x| { this.is_valid(x) })
    }

    /// retain provided Vec to make sure it only contains valid certificates.
    #[inline(always)]
    pub fn retain(&self, list: &mut Vec<Certificate>) {
        self._ro_check();

        list.retain(|x| { self.is_valid(x) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let ak = AnyPKI::new().ban(CountryCode::CN).ban(CountryCode::HK).build();
        let v = ak.is_valid(&Certificate::try_from(b"-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIEGErM1jANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJD
TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRUwEwYDVQQDDAxDRkNBIEVWIFJPT1QwHhcNMTIwODA4MDMwNzAxWhcNMjkx
MjMxMDMwNzAxWjBWMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5j
aWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQDDAxDRkNBIEVWIFJP
T1QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDXXWvNED8fBVnVBU03
sQ7smCuOFR36k0sXgiFxEFLXUWRwFsJVaU2OFW2fvwwbwuCjZ9YMrM8irq93VCpL
TIpTUnrD7i7es3ElweldPe6hL6P3KjzJIx1qqx2hp/Hz7KDVRM8Vz3IvHWOX6Jn5
/ZOkVIBMUtRSqy5J35DNuF++P96hyk0g1CXohClTt7GIH//62pCfCqktQT+x8Rgp
7hZZLDRJGqgG16iI0gNyejLi6mhNbiyWZXvKWfry4t3uMCz7zEasxGPrb382KzRz
EpR/38wmnvFyXVBlWY9ps4deMm/DGIq1lY+wejfeWkU7xzbh72fROdOXW3NiGUgt
hxwG+3SYIElz8AXSG7Ggo7cbcNOIabla1jj0Ytwli3i/+Oh+uFzJlU9fpy25IGvP
a931DfSCt/SyZi4QKPaXWnuWFo8BGS1sbn85WAZkgwGDg8NNkt0yxoekN+kWzqot
aK8KgWU6cMGbrU1tVMoqLUuFG7OA5nBFDWteNfB/O7ic5ARwiRIlk9oKmSJgamNg
TnYGmE69g60dWIolhdLHZR4tjsbftsbhf4oEIRUpdPA+nJCdDC7xij5aqgwJHsfV
PKPtl8MeNPo4+QgO48BdK4PRVmrJtqhUUy54Mmc9gn900PvhtgVguXDbjgv5E1hv
cWAQUhC5wUEJ73IfZzF4/5YFjQIDAQABo2MwYTAfBgNVHSMEGDAWgBTj/i39KNAL
tbq2osS/BqoFjJP7LzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAd
BgNVHQ4EFgQU4/4t/SjQC7W6tqLEvwaqBYyT+y8wDQYJKoZIhvcNAQELBQADggIB
ACXGumvrh8vegjmWPfBEp2uEcwPenStPuiB/vHiyz5ewG5zz13ku9Ui20vsXiObT
ej/tUxPQ4i9qecsAIyjmHjdXNYmEwnZPNDatZ8POQQaIxffu2Bq41gt/UP+TqhdL
jOztUmCypAbqTuv0axn96/Ua4CUqmtzHQTb3yHQFhDmVOdYLO6Qn+gjYXB74BGBS
ESgoA//vU2YApUo0FmZ8/Qmkrp5nGm9BC2sGE5uPhnEFtC+NiWYzKXZUmhH4J/qy
P5Hgzg0b8zAarb8iXRvTvyUFTeGSGn+ZnzxEk8rUQElsgIfXBDrDMlI1Dlb4pd19
xIsNER9Tyx6yF7Zod1rg1MvIB671Oi6ON7fQAUtDKXeMOZePglr4UeWJoBjnaH9d
Ci77o0cOPaYjesYBx4/IXr9tgFa+iiS6M+qf4TIRnvHST4D2G0CvOJ4RUHlzEhLN
5mydLIhyPDCBBpEi6lmt2hkuIsKNuYyH4Ga8cyNfIWRjgEj1oDwYPZTISEEdQLpe
/v5WOaHIz16eGWRGENoXkbcFgKyLmZJ956LYBws2J+dIeWCKw9cTXPhyQN9Ky8+Z
AAoACxGV2lZFA4gKn2fQ1XmxqI1AbQ3CekD6819kR5LLU7m7Wc5P/dAVUwHY3+vZ
5nbv0CO7O6l5s9UCKc2Jo5YPSjXnTkLAdc0Hz+Ys63su
-----END CERTIFICATE-----").unwrap());
        assert!(dbg!(v) == false);
    }
}
