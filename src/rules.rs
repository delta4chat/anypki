use crate::*;

/// Pre-defined rules of AnyPKI
pub struct DefaultRules;
impl DefaultRules {
    /// blacklisting Potential MITM threats, including some countries with strictly censorship or well-known Bad Behavior CAs
    pub fn mitm_threats() -> AnyPKI {
        AnyPKI::new()
            .ban(CountryCode::KZ) // well-known MITM country: https://en.wikipedia.org/wiki/Kazakhstan_man-in-the-middle_attacka

            .ban(CountryCode::IR) // "Halal Intranet": https://en.wikipedia.org/wiki/2019_Internet_blackout_in_Iran
            .ban(CountryCode::KP) // Kwangmyong Intranet: https://en.wikipedia.org/wiki/Kwangmyong_(network)

            .ban(CountryCode::RU) // Roskomnadzor: https://en.wikipedia.org/wiki/Roskomnadzor | https://blocklist.rkn.gov.ru/

            .ban(CountryCode::CN) // GFW-country: https://en.wikipedia.org/wiki/Great_Firewall_of_China
            .ban(CountryCode::HK) // SAR of GFW-country: https://en.wikipedia.org/wiki/Special_administrative_regions_of_China
            .ban(CountryCode::MO) // another SAR of GFW-country
        // TODO: update this list
    }
}
