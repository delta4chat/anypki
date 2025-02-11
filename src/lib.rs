pub mod rules;
pub use rules::*;

#[cfg(test)]
mod test;

use core::ops::Deref;

extern crate alloc;
use alloc::sync::Arc;

use hex_literal::hex;

use slice_find::SliceFind;

use digest::Digest;

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

impl TryFrom<rustls_pki_types::CertificateDer<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: rustls_pki_types::CertificateDer<'_>) -> anyhow::Result<Self> {
        let val: &[u8] = val.deref();
        val.try_into()
    }
}
impl TryFrom<&rustls_pki_types::CertificateDer<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: &rustls_pki_types::CertificateDer<'_>) -> anyhow::Result<Self> {
        let val: &[u8] = val.deref();
        val.try_into()
    }
}

impl TryFrom<rustls_pki_types::Der<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: rustls_pki_types::Der<'_>) -> anyhow::Result<Self> {
        let val: &[u8] = val.deref();
        val.try_into()
    }
}
impl TryFrom<&rustls_pki_types::Der<'_>> for Certificate {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: &rustls_pki_types::Der<'_>) -> anyhow::Result<Self> {
        let val: &[u8] = val.deref();
        val.try_into()
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

#[derive(Copy, Clone, Hash)]
pub enum Fingerprint {
    /// SHA-1 hash, it is not secure!
    SHA1([u8; 20]),

    /// (SHA-2) SHA-256 hash.
    SHA256([u8; 32]),

    /// (SHA-2) SHA-384 hash.
    SHA384([u8; 48]),

    /// (SHA-2) SHA-512 hash.
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

impl PartialEq for Fingerprint {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(self.as_ref(), other.as_ref())
    }
}
impl Eq for Fingerprint {}

impl PartialEq<[u8]> for Fingerprint {
    #[inline(always)]
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(self.as_ref(), other)
    }
}

impl AsRef<[u8]> for Fingerprint {
    #[inline(always)]
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
impl<const N: usize> TryFrom<[u8; N]> for Fingerprint {
    type Error = anyhow::Error;

    #[inline(always)]
    fn try_from(val: [u8; N]) -> anyhow::Result<Self> {
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

    /// Special filter that will only matches if all provided filters are matched, otherwise the return value is considered to be false. like to cfg(all(...))
    All(Vec<Filter>),
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

filter_from_inner_impl!(All, Vec<Filter>);

impl Filter {
    #[inline(always)]
    pub fn matches(&self, certificate: &Certificate) -> bool {
        let cert = &certificate.0;

        use Filter::*;
        match self {
            All(filters) => {
                // this is necessary due to iter().all() will returns true if iterator is empty.
                // https://doc.rust-lang.org/1.84.0/src/core/slice/iter/macros.rs.html#262
                if filters.is_empty() {
                    return false;
                } else {
                    return filters.iter().all(|f| { f.matches(certificate) });
                }
            },

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
                if let Ok(cert_der) = cert.encode_der() {
                    use crate::Fingerprint::*;
                    match fp {
                        SHA1(_) => {
                            let cert_fp = sha1::Sha1::digest(&cert_der);
                            if fp == cert_fp.as_slice() {
                                return true;
                            }
                        },
                        SHA256(_) => {
                            let cert_fp = sha2::Sha256::digest(&cert_der);
                            if fp == cert_fp.as_slice() {
                                return true;
                            }
                        },
                        SHA384(_) => {
                            let cert_fp = sha2::Sha384::digest(&cert_der);
                            if fp == cert_fp.as_slice() {
                                return true;
                            }
                        },
                        SHA512(_) => {
                            let cert_fp = sha2::Sha512::digest(&cert_der);
                            if fp == cert_fp.as_slice() {
                                return true;
                            }
                        },
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

/// A builder style struct for building a set of certificates.
#[derive(Debug, Clone)]
pub struct AnyPKI {
    blacklist: Arc<scc2::HashSet<Arc<Filter>>>,
    whitelist: Arc<scc2::HashSet<Arc<Filter>>>,

    #[cfg(feature="rustls-verifier")]
    rustls_rcs: Arc<scc2::Atom<rustls::RootCertStore>>,
    #[cfg(feature="rustls-verifier")]
    rustls_sv: Arc<scc2::Atom<dyn rustls::client::danger::ServerCertVerifier>>,
    #[cfg(feature="rustls-verifier")]
    rustls_cv: Arc<scc2::Atom<(Box<dyn rustls::server::danger::ClientCertVerifier>, &'static [rustls::DistinguishedName])>>,
}
impl Default for AnyPKI {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
impl AnyPKI {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            blacklist: Arc::new(scc2::HashSet::new()),
            whitelist: Arc::new(scc2::HashSet::new()),

            #[cfg(feature="rustls-verifier")]
            rustls_rcs: Arc::new(Default::default()),
            #[cfg(feature="rustls-verifier")]
            rustls_sv: Arc::new(Default::default()),
            #[cfg(feature="rustls-verifier")]
            rustls_cv: Arc::new(Default::default()),
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.blen() < 1 && self.wlen() < 1
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.wlen().saturating_add(self.blen())
    }
    #[inline(always)]
    pub fn blen(&self) -> usize {
        self.blacklist.len()
    }
    #[inline(always)]
    pub fn wlen(&self) -> usize {
        self.whitelist.len()
    }

    #[inline(always)]
    pub fn clear(&self) -> Self {
        self.blacklist.clear();
        self.whitelist.clear();

        #[cfg(feature="rustls-verifier")]
        {
            self.rustls_rcs.take();
            self.rustls_sv.take();
            self.rustls_cv.take();
        }

        self.clone()
    }

    #[inline(always)]
    pub fn extend(&self, other: &Self) -> Self {
        other.blacklist.scan(|f| { let _ = self.blacklist.insert(f.clone()); });
        other.whitelist.scan(|f| { let _ = self.whitelist.insert(f.clone()); });

        #[cfg(feature="rustls-verifier")]
        {
            if let Some(rcs) = other.rustls_rcs.get() {
                self.root_cert_store(rcs);
            }
            if let Ok(cv) = other._client_cert_verifier() {
                self.rustls_cv.set_arc(cv);
            }
            if let Ok(sv) = other._server_cert_verifier() {
                self.server_cert_verifier(sv);
            }
        }

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
        list.retain(|to_cert| { self.is_valid(to_cert.clone()) })
    }
}

#[cfg(feature="rustls-verifier")]
mod _rustls_verifier_impl {
    use super::*;
    use rustls::{
        RootCertStore,
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

    static EMPTY_RHS: &'static [DistinguishedName] = &[];

    impl AnyPKI {
        /* == public setters == */

        /// Provide RootCertStore
        #[inline(always)]
        pub fn root_cert_store(&self, rcs: Arc<RootCertStore>) -> Self {
            self.rustls_rcs.set_arc(rcs);
            self.clone()
        }

        /// Provide ServerCertVerifier
        #[inline(always)]
        pub fn server_cert_verifier(&self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
            self.rustls_sv.set_arc(verifier);
            self.clone()
        }
        /// Provide ClientCertVerifier
        /// 
        /// ## <big>WARNING: be careful to call this method. if this method called by multiples, that may causes memory leak if allow_memory_leak=true</big>
        #[inline(always)]
        pub fn client_cert_verifier(
            &self,
            verifier: Box<dyn ClientCertVerifier>,
            allow_memory_leak: bool
        ) -> Self {
            if allow_memory_leak {
                let rhs = Box::leak(Box::new(verifier.root_hint_subjects().to_vec()));
                self.rustls_cv.set((verifier, rhs));
            } else {
                self.rustls_cv.set((verifier, EMPTY_RHS));
            }
            self.clone()
        }

        /* == private getters == */

        #[inline(always)]
        pub(crate) fn _root_cert_store(&self) -> Result<Arc<RootCertStore>, Error> {
            self.rustls_rcs.update(|maybe_rcs| {
                if maybe_rcs.is_none() {
                    Some(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
                } else {
                    None
                }
            });

            if let Some(rcs) = self.rustls_rcs.get() {
                Ok(rcs)
            } else {
                Err(Error::General("Unexpected no RootCertStore".to_string()))
            }
        }

        #[inline(always)]
        pub(crate) fn _server_cert_verifier(&self) -> Result<Arc<dyn ServerCertVerifier>, Error> {
            if let Some(v) = self.rustls_sv.get() {
                Ok(v)
            } else {
                WebPkiServerVerifier::builder(self._root_cert_store()?)
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

        #[inline(always)]
        pub(crate) fn _client_cert_verifier(&self)
            -> Result<Arc<(Box<dyn ClientCertVerifier>, &'static [DistinguishedName])>, Error>
        {
            if let Some(v) = self.rustls_cv.get() {
                Ok(v)
            } else {
                Err(Error::General(String::from("No ClientCertVerifier provided")))
            }
        }
    }

    impl ServerCertVerifier for AnyPKI {
        #[inline(always)]
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

        #[inline(always)]
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

        #[inline(always)]
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

        #[inline(always)]
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            if let Ok(v) = self._server_cert_verifier() {
                v.supported_verify_schemes()
            } else {
                Vec::new()
            }
        }
    }

    impl ClientCertVerifier for AnyPKI {
        #[inline(always)]
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

        #[inline(always)]
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

        #[inline(always)]
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

        #[inline(always)]
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            if let Ok(ref v) = self._client_cert_verifier() {
                v.0.supported_verify_schemes()
            } else {
                Vec::new()
            }
        }

        #[inline(always)]
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            if let Ok(ref v) = self._client_cert_verifier() {
                v.1
            } else {
                EMPTY_RHS
            }
        }
    }
}
