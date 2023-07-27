use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use rand::thread_rng;
use rcgen::{DistinguishedName, DnType, DnValue, KeyPair, SanType};

use x509_parser::nom::{AsBytes, HexDisplay};
use x509_parser::pem::Pem;
use x509_parser::prelude::GeneralName;
use crate::prerenewal::SigAlg::{*};

#[derive(Debug)]
pub struct RsaKeyLength {
    bit_size: usize
}

pub static RSA2048: RsaKeyLength = RsaKeyLength {bit_size: 2048};
pub static RSA3072: RsaKeyLength = RsaKeyLength {bit_size: 3072};
pub static RSA4096: RsaKeyLength = RsaKeyLength {bit_size: 4096};

impl RsaKeyLength {
    pub fn size(self) -> usize {
        self.bit_size
    }
}

#[derive(Debug)]
pub enum SigAlg {
    Rsa(&'static RsaKeyLength),
    EcdsaP256,
    EcdsaP384,
}

impl Display for SigAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {

        match self {
            Rsa(bits) => {write!(f, "PKCS_RSA {}", bits.bit_size)?}
            EcdsaP256 => { write!(f, "PKCS_ECDSA_P256")?}
            EcdsaP384 => {write!(f, "PKCS_ECDSA_P384")?}
        };

        Ok(())
    }
}

pub struct Cert<'a> {
    pub old_cert: Option<x509_parser::certificate::X509Certificate<'a>>,
    pub renewed_cert: Option<x509_parser::certificate::X509Certificate<'a>>,
    pub priv_key: Option<rcgen::KeyPair>,
    csr: Option<rcgen::CertificateSigningRequest>,
    pub signature_alg: SigAlg, //&'a SignatureAlgorithm
}

impl <'a> Default for Cert<'a> {
    fn default() -> Self {
        Cert{
            old_cert: None,
            renewed_cert: None,
            priv_key: None,
            csr: None,
            signature_alg: Rsa(&RSA3072),
        }
    }
}

impl <'a> Cert<'a> {

    pub fn new(alg: SigAlg) -> Self {
        Cert{
            old_cert: None,
            renewed_cert: None,
            priv_key: None,
            csr: None,
            signature_alg: alg,
        }
    }

    pub fn load_old_cert(&mut self, pem: &'a Pem) -> Result<(), String> {

        let (_, old_cert) = x509_parser::parse_x509_certificate(pem.contents.as_bytes()).map_err(|e| e.to_string())?;

        self.old_cert = Some(old_cert);

        Ok(())
    }

    pub fn load_new_cert(&mut self, pem: &'a Pem) -> Result<(), String> {

        let (_, new_cert) = x509_parser::parse_x509_certificate(pem.contents.as_bytes()).map_err(|e| e.to_string())?;

        self.renewed_cert = Some(new_cert);

        Ok(())
    }

    pub fn generate_key_pair(&mut self) -> Result<(), String> {

        let signature_algorithm = match self.signature_alg {
            Rsa(bits) => {
                // from https://www.jscape.com/blog/should-i-start-using-4096-bit-rsa-keys and
                // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r4.pdf:
                // 2048-bit RSA keys are roughly equivalent to a Security Strength of 112
                // 3072-bit RSA keys are roughly equivalent to a Security Strength of 128
                //
                // algorithm/key-size combinations that have been estimated at a maximum
                // security strength of less than 112 bits (shaded in orange above) are no longer approved for
                // applying cryptographic protection on Federal government information thus 2048-bit
                // keys should be considered the bare minimum key length for RSA.
                let key = rsa::RsaPrivateKey::new(&mut thread_rng(), bits.bit_size).unwrap();
                let key_pem = key.to_pkcs8_pem(LineEnding::default()).unwrap();
                KeyPair::from_pem(key_pem.as_str()).map_err(|e| e.to_string())
            }
            EcdsaP256 => {
                let secret_key = p256::SecretKey::random(&mut OsRng);
                let secret_key_pem = secret_key.to_pkcs8_pem(LineEnding::default()).unwrap();

                KeyPair::from_pem(secret_key_pem.as_str()).map_err(|e| e.to_string())
            }
            EcdsaP384 => {
                let key = p384::SecretKey::random(&mut OsRng);
                let key_pem = key.to_pkcs8_pem(LineEnding::default()).unwrap();

                KeyPair::from_pem(key_pem.as_str()).map_err(|e| e.to_string())
            }
        };

        self.priv_key = Some(signature_algorithm.unwrap());
        Ok(())
    }

    pub fn with_signature_alg(&mut self, alg: SigAlg) -> Result<(), String> {

        self.signature_alg = alg;

        Ok(())
    }

    pub fn generate_signing_request(self) {
        println!("generate_signing_request");
        /*
            Rfc822Name(String),
            DnsName(String),
            URI(String),
            IpAddress(IpAddr),
        */

        /*
            ** no ** OtherName(Oid<'a>, &'a [u8]),

            /// More or less an e-mail, the format is not checked.
            Rfc822Name(String), -> RFC822Name(&'a str),

            /// A hostname, format is not checked.
            DnsName(String), -> DNSName(&'a str),

            /// X400Address,
            ** no ** X400Address(Any<'a>),

            /// RFC5280 defines several string types, we always try to parse as utf-8
            /// which is more or less a superset of the string types.
            ** no ** DirectoryName(X509Name<'a>),

            /// EDIPartyName
            ** no ** EDIPartyName(Any<'a>),

            /// An uniform resource identifier. The format is not checked.
            URI(String), -> URI(&'a str),

            /// An ip address, provided as encoded.
            IpAddress(IpAddr), -> IPAddress(&'a [u8]),
            RegisteredID(Oid<'a>),
        */
        let a: Vec<SanType> = self.old_cert.as_ref().unwrap().subject_alternative_name().unwrap().unwrap()
            .value
            .general_names.to_vec().into_iter()
                // convert between x509_parser and rcgen types
                // x509_parser defines more members for the san enum than rcgen so we will
                // have to consolidate
                .map(|item| {
                    match item {
                        GeneralName::RFC822Name(s) => {
                            println!("RFC822Name: {s}");
                            SanType::Rfc822Name(s.to_string())
                        },
                        GeneralName::DNSName(s) => {
                            println!("DNSName: {s}");
                            SanType::DnsName(s.to_string())
                        },
                        GeneralName::URI(u) => {
                            println!("URI: {u}");
                            SanType::URI(u.to_string())
                        },
                        GeneralName::IPAddress(bytes) => {
                            println!("IPAddress: {bytes:?}");
                            let xx: Vec<String> = bytes.into_iter().map(|byte| byte.to_string()).collect();

                            println!("xx: {:?}", xx.join(".").as_str());
                            let ipaddr = IpAddr::from_str(xx.join(".").as_str());
                            SanType::IpAddress(ipaddr.unwrap())
                        },
                        // best we can do is convert to string
                        x => {
                            SanType::Rfc822Name(x.to_string())
                        }
                    }
                }

                ).collect();

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = a;
        let mut dn = DistinguishedName::new();

        // this will add a single cn entry, may need to support multiple cn
        let cn = self.old_cert.unwrap().subject.iter_common_name().next().unwrap().as_str().unwrap().to_string();
        dn.push(DnType::CommonName, DnValue::PrintableString(cn));
        // TODO: need to add other dn entries

        params.distinguished_name = dn;
        params.key_pair = self.priv_key;
        match self.signature_alg {
            SigAlg::Rsa(_) => {params.alg = &rcgen::PKCS_RSA_SHA256}
            SigAlg::EcdsaP256 => {params.alg = &rcgen::PKCS_ECDSA_P256_SHA256}
            SigAlg::EcdsaP384 => {params.alg = &rcgen::PKCS_ECDSA_P384_SHA384},
        };

        let templ = rcgen::Certificate::from_params(params).unwrap();
        let csr = templ.serialize_request_pem().unwrap();
        println!("{csr}")
        // params.subject_alt_names
        // let old_cert: rcgen::Certificate = self.old_cert.unwrap();
    }
}

pub fn pem_to_der_bytes(path: PathBuf) -> Result<Pem, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(data.as_slice()).map_err(|e| e.to_string())?;

    Ok(pem)
}
