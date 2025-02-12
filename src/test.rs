use crate::*;

#[cfg(feature="mozilla-root-ca")]
#[test]
fn moz() {
    eprintln!("Mozilla Original CAs: {:?}", mozilla_root_ca::x509cert_list().len());

    let m = DefaultRules::mitm_threats_extra();
    let ak = DefaultRules::mozilla_without_suspicious(true);
    eprintln!("Filtered (MITM_EXTRA): {:?}", ak.whitelist.len());

    let mut tp = String::new();

    ak.whitelist.scan(|f| {
        match f.as_ref() {
            Filter::Certificate(cert) => {
                tp.push_str(hex::encode(cert.0.sha256_fingerprint().unwrap()).as_ref());
                tp.push_str("|");
            }
            _ => {}
        }
    });
    if ! tp.is_empty() {
        tp.pop();
    }
    //eprintln!("trustedpki: {tp}");

    m.blacklist.scan(|cert| {
        assert!(ak.whitelist.contains(cert) == false);
    });

    let m = DefaultRules::mitm_threats();
    let ak = DefaultRules::mozilla_without_suspicious(false);
    eprintln!("Filtered (MITM_NO_EXTRA): {:?}", ak.whitelist.len());
    m.blacklist.scan(|cert| {
        assert!(ak.whitelist.contains(cert) == false);
    });
}

const CFCA: &[u8] = b"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----";

const GITHUB_MITM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICszCCAhygAwIBAgIBAzANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKU29tZS1TdGF0ZTETMBEGA1UECgwKZ2l0aHViLmNvbTETMBEGA1UE
CwwKZ2l0aHViLmNvbTETMBEGA1UEAwwKZ2l0aHViLmNvbTAeFw0xMzAxMjUwNjI5
MTJaFw0xNDAxMjUwNjI5MTJaMGExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21l
LVN0YXRlMRMwEQYDVQQKDApnaXRodWIuY29tMRMwEQYDVQQLDApnaXRodWIuY29t
MRMwEQYDVQQDDApnaXRodWIuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDHp0HWucGPUs3Mawr23dJM5hLLX90VaTkV29WZTcXnfwGxWuGZvJUrKIcT5Sof
ujOqJXopEGbrsDMqYhTbcudsJKSmIHvD1wiIJTF+zgmTogk52CIWZ1coSxF3r3i5
1R4ZOjcNMIrNdKl3lN8mDUsYIhY3UiGHlXUaRLVyJ3XNYwIDAQABo3sweTAJBgNV
HRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZp
Y2F0ZTAdBgNVHQ4EFgQUuD0FAGWs6+V2cJzEZhDnMq+MTaswHwYDVR0jBBgwFoAU
KBU3wAzcCtFAf2aj5ZRAdbXnwpgwDQYJKoZIhvcNAQEFBQADgYEAkPy6u/FEezIz
ZHESozwidrcEsBSUd9pZC1voib/RpM4/KneJnY3PygOiLkPgjVq5+YephIpSwCOg
Nr0BFgZIwmra/0EWfL6CJb1wl8qJKShfWyv3en9FiZwhACbJf53TRzdq0zAi5s0H
dU/SlEQPUcNwE2HkLxNTCqU0xcwC7uo=
-----END CERTIFICATE-----";

const WO_TRUST: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIEXzCCA0egAwIBAgIQJGs6VJEx1baIXJdYH+rCcTANBgkqhkiG9w0BAQUFADCB
lzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug
Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho
dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3Qt
SGFyZHdhcmUwHhcNMDYxMDAzMDAwMDAwWhcNMTkwNzA5MTgxOTIyWjBWMQswCQYD
VQQGEwJVUzEkMCIGA1UEChMbV290b25lIENvbW11bmljYXRpb25zLCBJbmMuMSEw
HwYDVQQDExhXb1RydXN0IFNlcnZlciBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCxJCDPT547dD3D7yO2gKlAdbIXAy+hcVJuQhtVVUmk
0SRmZOjLajcda17KJH2Nvt75EuvRX48T2i6Z2TL2oDroq9PBu/pLTILjAxqgk2DR
bukcjyHgwwKXukImrG1wdN//pjtXdUp4S3f4K4i/HqbYNf3Dsr9prPxgKuC4t/cI
2V1Y+97Pte0OgvAcXB023MX0voXCUQL5lyZAFRQ84eco/f60QXS+JUyV3YYHkba8
PVVLaObjLduiva/t3qA7IAAj713cpY1PbHb6ZO7RXA7rf/Dw+7PSTSrF42CskOIX
ukxqkCwew1TjR4UtTwvEtTSvgdOwTaOpHCjSnjZahMqNAgMBAAGjgeYwgeMwHwYD
VR0jBBgwFoAUoXJfJhsomEOVXQc31YWWnUvSw0UwHQYDVR0OBBYEFNBKtSeTG0br
qzhGfJBV4RZhH2/VMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEA
MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysG
AQQBsjEBAgIPMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0
LmNvbS9VVE4tVVNFUkZpcnN0LUhhcmR3YXJlLmNybDANBgkqhkiG9w0BAQUFAAOC
AQEAAJxvr7RytyWHp2HtTu58Hjyc88CFeFKMuJg9gSPNsjHJZVhrZS8lCSLp3JoN
hbnepoR6p4MChIrIiJ96Fku6GWNWpCLOUqMDdPoBXqpVAA9VVdVgW3ngTw8cb2J0
Sp2QLsFa/DwZzBPja1xy62fOyXBlGZtVLd20A8T32dKf4X7O6JJHTQz+XJZixLR3
7yLfkxivymtFt/tSIYw4jW4fCRvndVM5DDciPavJvSYgsqDRHWgKEE1Qg2Gjlnwe
gx81uzGbH0UMoUZCB62Zzc7IxfAHv1ifpg/6hChlCV0rLJoS/c/yGTbSLb5sYlaI
BrXE2Wa+Sg/HwbIWJLqj9455Bg==
-----END CERTIFICATE-----";

const ISRG_ROOT_X1: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UE
BhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQD
EwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQG
EwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMT
DElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54r
Vygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj1
3Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8K
b4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCN
Aymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ
4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf
1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFu
hjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQH
usEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/r
OPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4G
A1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY
9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV
0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwt
hDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJw
TdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nx
e5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZA
JzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahD
YVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9n
JEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJ
m+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----";

#[test]
fn is_valid() {
    let ak = DefaultRules::mitm_threats_extra();

    // CFCA (CA), filtered by country code
    let should_invalid = ak.is_valid(CFCA);
    assert!(dbg!(should_invalid) == false);

    // github.com MITM cert (leaf), filtered by fingerprint
    let should_invalid = ak.is_valid(GITHUB_MITM);
    assert!(dbg!(should_invalid) == false);

    // WoTrust (CA), filtered by fingerprint
    let should_invalid = ak.is_valid(WO_TRUST);
    assert!(dbg!(should_invalid) == false);

    // ISRG Root X1 (CA), should valid
    let should_valid = ak.is_valid(ISRG_ROOT_X1);

    assert!(dbg!(should_valid) == true);
}

#[test]
fn multi_filters() {
    /*
    serial=246B3A549131D5B6885C97581FEAC271
    issuer=C = US, ST = UT, L = Salt Lake City, O = The USERTRUST Network, OU = http://www.usertrust.com, CN = UTN-USERFirst-Hardware
    subject=C = US, O = "Wotone Communications, Inc.", CN = WoTrust Server Authority
    sha1 Fingerprint=33:7D:F9:64:18:F0:8A:93:55:87:05:13:AF:CE:BD:C6:8B:CE:D7:67
    sha256 Fingerprint=2C:A1:BF:84:73:64:11:F0:E1:2A:BB:38:72:7B:5F:DE:33:99:F1:ED:C4:3D:79:C4:DF:2A:A9:32:16:C3:3F:1B
    */
    let f1 = Filter::CountryCode(country_code_enum::CountryCode::US);
    let f2 = Filter::Name("Wotone Communications".to_string());
    let f3 = Filter::Fingerprint(hex!("337DF96418F08A9355870513AFCEBDC68BCED767").try_into().unwrap());
    let f = Filter::All(vec![f1, f2, f3]);

    let wo_trust: Certificate = WO_TRUST.try_into().unwrap();
    let should_match = f.matches(&wo_trust);
    assert!(dbg!(should_match) == true);

    let isrg_root_x1: Certificate = ISRG_ROOT_X1.try_into().unwrap();
    let should_mismatch = f.matches(&isrg_root_x1);
    assert!(dbg!(should_mismatch) == false);

    let f = Filter::All(vec![]);
    let should_mismatch = f.matches(&wo_trust);
    assert!(dbg!(should_mismatch) == false);
}
