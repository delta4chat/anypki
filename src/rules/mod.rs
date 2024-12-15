use crate::*;

pub mod source;
use source::mozilla;

use source::revoke_suspicious_certs;
use source::caprogram_360;

/// Pre-defined rules of AnyPKI
pub struct DefaultRules;
// https://en.wikipedia.org/wiki/Internet_censorship_and_surveillance_by_country
impl DefaultRules {
    /// whitelisting the root CAs from Mozilla PKI Store, but exclude all suspicious certificates.
    #[inline(always)]
    pub fn mozilla_without_suspicious(extra: bool) -> AnyPKI {
        let out = AnyPKI::new();

        let mitm =
            if extra {
                Self::mitm_threats_extra()
            } else {
                Self::mitm_threats()
            };

        for fp in mozilla::FINGERPRINT_LIST.iter() {
            let f = Filter::Fingerprint(*fp);
            if mitm.blacklist.contains(&f) {
                continue;
            }
            out.allow(*fp);
        }

        out
    }

    /// blacklisting extremely possible MITM threats, including some countries with strictly censorship or well-known Bad Behavior CAs
    #[inline(always)]
    pub fn mitm_threats() -> AnyPKI {
        let out = AnyPKI::new();

        for fp in revoke_suspicious_certs::FINGERPRINT_LIST.iter() {
            out.ban(*fp);
        }
        for fp in caprogram_360::FINGERPRINT_LIST.iter() {
            out.ban(*fp);
        }

        out.ban(CountryCode::KZ) // Kazakhstan, well-known MITM country: https://en.wikipedia.org/wiki/Kazakhstan_man-in-the-middle_attack

           .ban(CountryCode::IR) // Iran, "Halal Intranet": https://en.wikipedia.org/wiki/2019_Internet_blackout_in_Iran
           .ban(CountryCode::KP) // North Korea, Kwangmyong Intranet: https://en.wikipedia.org/wiki/Kwangmyong_(network)

           .ban(CountryCode::RU) // Russia, Roskomnadzor: https://en.wikipedia.org/wiki/Roskomnadzor | https://blocklist.rkn.gov.ru/

           .ban(CountryCode::CN) // Mainland China, GFW-country: https://en.wikipedia.org/wiki/Great_Firewall_of_China
           .ban(CountryCode::HK) // HongKong, rule dominated by GFW-country: https://en.wikipedia.org/wiki/2020_Hong_Kong_national_security_law
           .ban(CountryCode::MO) // Macau, another "SAR" of GFW-country: https://en.wikipedia.org/wiki/Special_administrative_regions_of_China

           .ban(CountryCode::TM) // Turkmenistan, https://arxiv.org/pdf/2304.04835
        // TODO: update this CountryCode list
    }

    /// contains all of mitm_threats, but with extra list of Potential MITM threats.
    #[inline(always)]
    pub fn mitm_threats_extra() -> AnyPKI {
        // https://en.wikipedia.org/wiki/Freedom_on_the_Net
        Self::mitm_threats()
            .ban(CountryCode::AE) // United Arab Emirates
            .ban(CountryCode::YE) // Yemen
            .ban(CountryCode::CU) // Cuba
            .ban(CountryCode::SA) // Saudi Arabia
            .ban(CountryCode::TZ) // Tanzania
            .ban(CountryCode::MM) // Myanmar
            .ban(CountryCode::BN) // Bahrain
            .ban(CountryCode::SY) // Syria
            .ban(CountryCode::ET) // Ethiopia
            .ban(CountryCode::EG) // Egypt
            .ban(CountryCode::SD) // Sudan
            .ban(CountryCode::VN) // Vietnam
            .ban(CountryCode::UZ) // Uzbekistan
            .ban(CountryCode::TH) // Thailand
            .ban(CountryCode::TR) // Turkey
            .ban(CountryCode::BD) // Bangladesh
            .ban(CountryCode::PK) // Pakistan
    }
}
