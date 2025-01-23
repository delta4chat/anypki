pub mod rules;
pub use rules::*;

#[cfg(test)]
mod test;

use core::ops::Deref;

extern crate alloc;
use alloc::sync::Arc;

use hex_literal::hex;

use slice_find::SliceFind;

use country_code_enum::CountryCode;

use x509cert::{
    X509Certificate,
    KeyAlgorithm, SignatureAlgorithm, DigestAlgorithm,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Certificate(X509Certificate);

impl From<X509Certificate> for Certificate {
    #[inline(always)]
    fn from(val: X509Certificate) -> Self {
        Self(val)
    }
}
impl From<Certificate> for X509Certificate {
    #[inline(always)]
    fn from(val: Certificate) -> Self {
        val.0
    }
}

/*
impl TryFrom<rustls_pki_types::TrustAnchor<'_>> for Certificate {
    type Error = anyhow::Error;
    fn try_from(val: rustls_pki_types::TrustAnchor<'_>) -> anyhow::Result<Self> {
        val.subject.deref().try_into()
    }
}
*/
impl TryFrom<rustls_pki_types::CertificateDer<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: rustls_pki_types::CertificateDer<'_>) -> anyhow::Result<Self> {
        val.deref().try_into()
    }
}

impl TryFrom<&rustls_pki_types::CertificateDer<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: &rustls_pki_types::CertificateDer<'_>) -> anyhow::Result<Self> {
        val.deref().try_into()
    }
}

#[cfg(feature="native-tls")]
impl TryFrom<native_tls::Certificate> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: native_tls::Certificate) -> anyhow::Result<Self> {
        val.to_der()?.try_into()
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
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

    #[inline(always)]
    fn try_from(val: Vec<u8>) -> anyhow::Result<Self> {
        let val: &[u8] = val.as_ref();
        val.try_into()
    }
}
impl<const N: usize> TryFrom<&[u8; N]> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: &[u8; N]) -> anyhow::Result<Self> {
        let val: &[u8] = val.as_ref();
        val.try_into()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    SHA1([u8; 20]),
    SHA256([u8; 32]),
    SHA384([u8; 48]),
    SHA512([u8; 64]),
}
impl core::fmt::Debug for Fingerprint {
    #[inline(always)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        use Fingerprint::*;

        let mut out =
            String::from(match self {
                SHA1(_) => "SHA-1(",
                SHA256(_) => "SHA-256(",
                SHA384(_) => "SHA-384(",
                SHA512(_) => "SHA-512(",
            });

        out.push_str(hex::encode(self.as_ref()).as_ref());
        out.push(')');

        f.write_str(&out)
    }
}
impl PartialEq<[u8]> for Fingerprint {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        use Fingerprint::*;
        match self {
            SHA1(v)   => { &v[..] },
            SHA256(v) => { &v[..] },
            SHA384(v) => { &v[..] },
            SHA512(v) => { &v[..] },
        }
    }
}
impl TryFrom<&[u8]> for Fingerprint {
    type Error = anyhow::Error;

    #[inline(always)]
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
impl<const N: usize> TryFrom<&[u8; N]> for Fingerprint {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: &[u8; N]) -> anyhow::Result<Self> {
        let val: &[u8] = val.as_ref();
        val.try_into()
    }
}

impl From<&Fingerprint> for DigestAlgorithm {
    #[inline(always)]
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

/// A filter match certificates by country code, public key, serial number, fingerprint, signature algorithm, key algorithm, or name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Filter {
    Certificate(Certificate),

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


filter_from_inner_impl!(Certificate, Certificate);
filter_from_inner_impl!(CountryCode, CountryCode);
filter_from_inner_impl!(PublicKey, Vec<u8>);
filter_from_inner_impl!(SerialNumber, bcder::int::Integer);
filter_from_inner_impl!(Fingerprint, Fingerprint);
filter_from_inner_impl!(Name, String);
filter_from_inner_impl!(SignatureAlgorithm, SignatureAlgorithm);
filter_from_inner_impl!(KeyAlgorithm, KeyAlgorithm);

impl Filter {
    #[inline(always)]
    pub fn matches(&self, cert: &Certificate) -> bool {
        let cert = &cert.0;

        use Filter::*;
        match self {
            Certificate(c) => {
                return &c.0 == cert;
            },
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
    blacklist: Arc<scc::HashSet<Arc<Filter>>>,
    whitelist: Arc<scc::HashSet<Arc<Filter>>>,

    #[cfg(feature="rustls-verifier")]
    rustls_rcs: Arc<rustls::RootCertStore>,
    #[cfg(feature="rustls-verifier")]
    rustls_sv: Arc<scc::Stack<Arc<dyn rustls::client::danger::ServerCertVerifier>>>,
    #[cfg(feature="rustls-verifier")]
    rustls_cv: Option<(Arc<dyn rustls::server::danger::ClientCertVerifier>, Arc<Vec<rustls::DistinguishedName>>)>,
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
            blacklist: Arc::new(scc::HashSet::new()),
            whitelist: Arc::new(scc::HashSet::new()),

            #[cfg(feature="rustls-verifier")]
            rustls_rcs: Arc::new(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }),
            #[cfg(feature="rustls-verifier")]
            rustls_sv: Arc::new(Default::default()),
            #[cfg(feature="rustls-verifier")]
            rustls_cv: None,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.wlen().saturating_add(self.blen())
    }
    #[inline(always)]
    pub fn wlen(&self) -> usize {
        self.whitelist.len()
    }
    #[inline(always)]
    pub fn blen(&self) -> usize {
        self.blacklist.len()
    }

    #[inline(always)]
    pub fn clear(&self) -> Self {
        self.blacklist.clear();
        self.whitelist.clear();

        self.clone()
    }

    #[inline(always)]
    pub fn extend(&self, other: &Self) -> Self {
        other.blacklist.scan(|f| { let _ = self.blacklist.insert(f.clone()); });

        other.whitelist.scan(|f| { let _ = self.whitelist.insert(f.clone()); });

        self.clone()
    }

    /// removes any certificates matches the provided filter.
    #[inline(always)]
    pub fn blacklist(&self, f: impl Into<Filter>) -> Self {
        let _ = self.blacklist.insert(Arc::new(f.into()));
        self.clone()
    }
    #[inline(always)]
    pub fn ban(&self, f: impl Into<Filter>) -> Self { self.blacklist(f) }
    #[inline(always)]
    pub fn disallow(&self, f: impl Into<Filter>) -> Self { self.blacklist(f) }
    #[inline(always)]
    pub fn deny(&self, f: impl Into<Filter>) -> Self { self.blacklist(f) }

    /// only allows certificates that matches provided filter.
    #[inline(always)]
    pub fn whitelist(&self, f: impl Into<Filter>) -> Self {
        let _ = self.whitelist.insert(Arc::new(f.into()));
        self.clone()
    }
    #[inline(always)]
    pub fn exclusive(&self, f: impl Into<Filter>) -> Self { self.whitelist(f) }
    #[inline(always)]
    pub fn allow(&self, f: impl Into<Filter>) -> Self { self.whitelist(f) }
    #[inline(always)]
    pub fn permit(&self, f: impl Into<Filter>) -> Self { self.whitelist(f) }

    /// Checks the provided certificate whether should be kept.
    #[inline(always)]
    pub fn is_valid(&self, to_cert: impl TryInto<Certificate>) -> bool {
        let cert =
            if let Ok(c) = to_cert.try_into() {
                c
            } else {
                return false;
            };

        if ! self.whitelist.is_empty() {
            return self.whitelist.any(|wf| { wf.matches(&cert) });
        }

        if ! self.blacklist.is_empty() {
            return ! self.blacklist.any(|bf| { bf.matches(&cert) });
        }

        // no filter... default to allow
        true
    }

    /// Apply this filter to a list of certificates.
    #[inline(always)]
    pub fn apply(&self, iter: impl Iterator<Item=impl TryInto<Certificate>+Clone>) -> impl Iterator<Item=impl TryInto<Certificate>+Clone> {
        let this = self.clone();
        iter.filter(move |to_cert| { this.is_valid(to_cert.clone()) })
    }

    /// retain provided Vec to make sure it only contains valid certificates.
    #[inline(always)]
    pub fn retain(&self, list: &mut Vec<impl TryInto<Certificate>+Clone>) {
        list.retain(|cert| { self.is_valid(cert.clone()) })
    }
}

#[cfg(feature="rustls-verifier")]
mod _rustls_verifier_impl {
    use super::*;
    use rustls::{
        Error,
        CertificateError,
        DistinguishedName,
        pki_types::{
            CertificateDer,
            UnixTime,
            ServerName,
        },
        DigitallySignedStruct,
        SignatureScheme,
        client::{
            WebPkiServerVerifier,
            danger::{
                ServerCertVerifier,
                HandshakeSignatureValid,
                ServerCertVerified,
            },
        },
        server::{
            //ClientCertVerifierBuilder,
            danger::{
                ClientCertVerifier,
                ClientCertVerified,
            },
        },
    };

    impl AnyPKI {
        /* == public setters == */

        /// Provide ServerCertVerifier
        pub fn server_cert_verifier(&self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
            let _ = self.rustls_sv.push(verifier);
            self.clone()
        }
        /// Provide ClientCertVerifier
        pub fn client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) -> Self {
            let rhs = Arc::new(verifier.root_hint_subjects().to_vec());
            self.rustls_cv = Some((verifier, rhs));
            self.clone()
        }

        /* == private getters for trait == */
        fn _server_cert_verifier(&self) -> Result<Arc<dyn ServerCertVerifier>, Error> {
            if let Some(v) = self.rustls_sv.peek_with(|x| { x.map(|v| { v.deref().clone() }) }) {
                Ok(v)
            } else {
                WebPkiServerVerifier::builder(self.rustls_rcs.clone())
                .build()
                .map(|x| {
                    /*
                     * https://users.rust-lang.org/t/what-does-rust-error-you-could-box-the-found-value-and-coerce-it-to-the-trait-object-mean/112732
                     * https://safereddit.com/r/rust/comments/199cwx8/arcimpl_t_boxdyn_t/
                     */

                    let x: Arc<dyn ServerCertVerifier> = x;
                    x
                })
                .map_err(|err| { Error::General(err.to_string()) })
            }
        }

        fn _client_cert_verifier(&self)
            -> Result<(Arc<dyn ClientCertVerifier>, &[DistinguishedName]), Error>
        {
            if let Some(ref v) = self.rustls_cv {
                Ok((v.0.clone(), &v.1))
            } else {
                Err(Error::General(String::from("No ClientCertVerifier provided")))
            }
        }
    }

    impl ServerCertVerifier for AnyPKI {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let err = Err(Error::InvalidCertificate(CertificateError::Revoked));
            if ! self.is_valid(end_entity) {
                return err;
            }
            for im in intermediates.iter() {
                if ! self.is_valid(im) {
                    return err;
                }
            }
            self._server_cert_verifier()?
                .verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now
                )
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            if ! self.is_valid(cert) {
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
            }
            self._server_cert_verifier()?.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            if ! self.is_valid(cert) {
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
            }
            self._server_cert_verifier()?.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            if let Ok(v) = self._server_cert_verifier() {
                v.supported_verify_schemes()
            } else {
                Vec::new()
            }
        }
    }

    impl ClientCertVerifier for AnyPKI {
        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            now: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            let err = Err(Error::InvalidCertificate(CertificateError::Revoked));
            if ! self.is_valid(end_entity) {
                return err;
            }
            for im in intermediates.iter() {
                if ! self.is_valid(im) {
                    return err;
                }
            }
            self._client_cert_verifier()?.0.verify_client_cert(end_entity, intermediates, now)
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            if ! self.is_valid(cert) {
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
            }
            self._client_cert_verifier()?.0.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            if ! self.is_valid(cert) {
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
            }
            self._client_cert_verifier()?.0.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            if let Ok(ref v) = self._client_cert_verifier() {
                v.0.supported_verify_schemes()
            } else {
                Vec::new()
            }
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            if let Ok(ref v) = self._client_cert_verifier() {
                v.1
            } else {
                &[]
            }
        }
    }

}
