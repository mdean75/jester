use std::fmt::{Display, Formatter};
use std::{fs};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use rand::thread_rng;
use rcgen::{DistinguishedName, DnType, DnValue, KeyPair, SanType};

use x509_parser::nom::{AsBytes};
use x509_parser::pem::Pem;
use x509_parser::prelude::{GeneralName};
use crate::prerenewal::SigAlg::{*};

#[derive(Debug)]
pub struct RsaKeyLength {
    bit_size: usize
}

// static RsaKeyLength structs representing the only valid allowable values
pub static RSA2048: RsaKeyLength = RsaKeyLength {bit_size: 2048};
pub static RSA3072: RsaKeyLength = RsaKeyLength {bit_size: 3072};
pub static RSA4096: RsaKeyLength = RsaKeyLength {bit_size: 4096};

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
    pub old_cert_pem: Vec<u8>,
    pub renewed_cert: Option<x509_parser::certificate::X509Certificate<'a>>,
    // pub priv_key: Option<Rc<rcgen::KeyPair>>,
    pub priv_key: Option<rcgen::KeyPair>,
    pub priv_key_pem: Vec<u8>,
    pub old_priv_key_pem: Vec<u8>,
    pub csr: Option<rcgen::CertificateSigningRequest>,
    pub csr_pem: String,
    pub csr_der: Vec<u8>,
    pub signature_alg: SigAlg, //&'a SignatureAlgorithm
}

impl <'a> Default for Cert<'a> {
    fn default() -> Self {
        Cert{
            old_cert: None,
            old_cert_pem: vec![],
            renewed_cert: None,
            priv_key: None,
            priv_key_pem: vec![],
            old_priv_key_pem: vec![],
            csr: None,
            csr_pem: "".to_string(),
            csr_der: vec![],
            signature_alg: Rsa(&RSA3072),
        }
    }
}

impl <'a> Cert<'a> {
    pub fn new(alg: SigAlg) -> Self {
        Cert{
            old_cert: None,
            old_cert_pem: vec![],
            renewed_cert: None,
            priv_key: None,
            priv_key_pem: vec![],
            old_priv_key_pem: vec![],
            csr: None,
            csr_pem: "".to_string(),
            csr_der: vec![],
            signature_alg: alg,
        }
    }

    pub fn load_old_cert(&mut self, pem: &'a Pem) -> Result<(), String> {

        let (_, old_cert) = x509_parser::parse_x509_certificate(pem.contents.as_bytes()).map_err(|e| e.to_string())?;

        self.old_cert = Some(old_cert);
        self.old_cert_pem = pem.contents.to_vec();
        // self.old_cert_pem = pem.contents.as_slice().to_vec();
        // println!("load old cert pem: {}", self.old_cert_pem)

        Ok(())
    }

    pub fn load_privatekey(&mut self, path: PathBuf) -> Result<(), String> {

        let pem_bytes = fs::read(path).unwrap();
        self.old_priv_key_pem = pem_bytes.to_vec();

        // self.ol = Some(rcgen::KeyPair::from_pem(String::from_utf8(pem_bytes).unwrap().as_str()).unwrap());

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
                let mut rng = thread_rng();
                let key = rsa::RsaPrivateKey::new(&mut rng, bits.bit_size).map_err(|e| e.to_string())?;
                let key_pem = key.to_pkcs8_pem(LineEnding::default()).map_err(|e| e.to_string())?;

                self.priv_key_pem = key_pem.to_string().into_bytes();

                KeyPair::from_pem(key_pem.as_str()).map_err(|e| e.to_string())?
            }
            EcdsaP256 => {
                let secret_key = p256::SecretKey::random(&mut OsRng);
                let secret_key_pem = secret_key.to_pkcs8_pem(LineEnding::default()).map_err(|e| e.to_string())?;

                self.priv_key_pem = secret_key_pem.to_string().into_bytes();
                KeyPair::from_pem(secret_key_pem.as_str()).map_err(|e| e.to_string())?
            }
            EcdsaP384 => {
                let key = p384::SecretKey::random(&mut OsRng);
                let key_pem = key.to_pkcs8_pem(LineEnding::default()).map_err(|e| e.to_string())?;

                self.priv_key_pem = key_pem.to_string().into_bytes();
                KeyPair::from_pem(key_pem.as_str()).map_err(|e| e.to_string())?
            }
        };

        self.priv_key = Some(signature_algorithm);
        Ok(())
    }

    pub fn with_signature_alg(&mut self, alg: SigAlg) -> Result<(), String> {

        self.signature_alg = alg;

        Ok(())
    }

    pub fn generate_signing_request(&mut self) -> Result<(), String> { //-> Result<CertificateSigningRequest, String> {
        let mut params = rcgen::CertificateParams::default();

        if let Some(old_cert) = self.old_cert.as_ref() {
            if let Some(san) = old_cert.subject_alternative_name().map_err(|e| e.to_string())? {

                let san_type_list: Result<Vec<SanType>, String> = san.value.general_names
                    .iter()
                    .cloned()
                    .map(
                        |item| -> Result<SanType, String> {
                            match item {
                                GeneralName::RFC822Name(s) => {
                                    Ok(SanType::Rfc822Name(s.to_string()))
                                },
                                GeneralName::DNSName(s) => {
                                    Ok(SanType::DnsName(s.to_string()))
                                },
                                GeneralName::URI(u) => {
                                    Ok(SanType::URI(u.to_string()))
                                },
                                GeneralName::IPAddress(bytes) => {
                                    let octets: Vec<String> = bytes.iter().map(|byte| byte.to_string()).collect();

                                    let ipaddr = IpAddr::from_str(octets.join(".").as_str()).map_err(|e| e.to_string())?;
                                    Ok(SanType::IpAddress(ipaddr))
                                },
                                // best we can do is convert to string
                                x => {
                                    Ok(SanType::Rfc822Name(x.to_string()))
                                }
                            }
                        }
                    )
                    .collect();

                params.subject_alt_names = san_type_list?;

            }


            // let remote211 = IpAddr::from_str("192.168.40.211").unwrap();
            // let additional_sans: &mut Vec<SanType> = &mut vec![SanType::IpAddress(remote211)];
            //
            // params.subject_alt_names.append(additional_sans);


            let mut dn = DistinguishedName::new();

            if let Some(cn) = old_cert.subject.iter_common_name().next() {
                dn.push(DnType::CommonName, DnValue::Utf8String(cn.as_str().map_err(|e| e.to_string())?.to_string()))
            }

            if let Some(org) = old_cert.subject.iter_organization().next() {
                dn.push(DnType::OrganizationName, DnValue::Utf8String(org.as_str().map_err(|e| e.to_string())?.to_string()));
            }

            if let Some(org_unit) = old_cert.subject.iter_organizational_unit().next() {
                // let org_unit = old_cert.clone().subject.iter_organizational_unit().next().unwrap().as_str().unwrap().to_string();
                dn.push(DnType::OrganizationalUnitName, DnValue::Utf8String(org_unit.as_str().map_err(|e| e.to_string())?.to_string()));
            }

            if let Some(country) = old_cert.subject.iter_country().next() {
                // let country = old_cert.clone().subject.iter_country().next().unwrap().as_str().unwrap().to_string();
                dn.push(DnType::CountryName, DnValue::Utf8String(country.as_str().map_err(|e| e.to_string())?.to_string()));
            }

            if let Some(locality) = old_cert.subject.iter_locality().next() {
                // let locality = old_cert.clone().subject.iter_locality().next().unwrap().as_str().unwrap().to_string();
                dn.push(DnType::LocalityName, DnValue::Utf8String(locality.as_str().map_err(|e| e.to_string())?.to_string()));
            }

            if let Some(state_province) = old_cert.subject.iter_state_or_province().next() {
                // let state_province = old_cert.clone().subject.iter_state_or_province().next().unwrap().as_str().unwrap().to_string();
                dn.push(DnType::StateOrProvinceName, DnValue::Utf8String(state_province.as_str().map_err(|e| e.to_string())?.to_string()));
            }

            params.distinguished_name = dn;
        }

        let key_pair = &mut self.priv_key;
        params.key_pair = key_pair.take();
        match self.signature_alg {
            Rsa(_) => {params.alg = &rcgen::PKCS_RSA_SHA256}
            EcdsaP256 => {params.alg = &rcgen::PKCS_ECDSA_P256_SHA256}
            EcdsaP384 => {params.alg = &rcgen::PKCS_ECDSA_P384_SHA384},
        };

        let templ = rcgen::Certificate::from_params(params).map_err(|e| e.to_string())?;
        let csr_pem = templ.serialize_request_pem().map_err(|e| e.to_string())?;

        let csr_der = templ.serialize_request_der().map_err(|e| e.to_string())?;
        let csr = rcgen::CertificateSigningRequest::from_pem(csr_pem.as_str()).map_err(|e| e.to_string())?;

        self.csr_der = csr_der;
        self.csr = Some(csr);
        self.csr_pem = csr_pem;

        Ok(())

    }
}

pub fn pem_to_der_bytes(path: PathBuf) -> Result<(Pem, Vec<u8>), String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(data.as_slice()).map_err(|e| e.to_string())?;

    Ok((pem, data))
}


#[cfg(test)]
mod tests {
    use std::io::BufReader;
    use super::*;

    #[test]
    fn test_default_cert() {
        let cert = Cert::default();

        assert_eq!(cert.signature_alg.to_string(), Rsa(&RSA3072).to_string())
    }

    #[test]
    fn test_new_cert() {
        let cert = Cert::new(EcdsaP256);

        assert_eq!(cert.signature_alg.to_string(), EcdsaP256.to_string())
    }

    #[test]
    fn test_load_old_cert_should_succeed() {
        let mut buf = BufReader::new(CERT_BYTES);
        let pem = Pem::iter_from_buffer(CERT_BYTES).next().unwrap().unwrap();

        let mut cert = Cert::default();
        match cert.load_old_cert(&pem) {
            Ok(_) => {
                assert_eq!(cert.old_cert.is_some(), true)
            },
            Err(e) => panic!("load old cert failed: {e}"),
        }

    }

    #[test]
    fn test_load_new_cert_should_succeed() {
        let mut buf = BufReader::new(CERT_BYTES);
        let pem = Pem::iter_from_buffer(CERT_BYTES).next().unwrap().unwrap();

        let mut cert = Cert::default();
        match cert.load_new_cert(&pem) {
            Ok(_) => {
                assert_eq!(cert.renewed_cert.is_some(), true)
            },
            Err(e) => panic!("load old cert failed: {e}"),
        }

    }

    pub static CERT_BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBrjCCAVSgAwIBAgIILYaEFjUTHAQwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAxMX
SW50ZXJtZWRpYXRlIFNpZ25pbmcgY2EwHhcNMjIxMDMwMTQyMDU0WhcNMjMxMDMw
MTQyMDU0WjAyMQ8wDQYDVQQDEwZzZXJ2ZXIxCTAHBgNVBAoTADEJMAcGA1UECxMA
MQkwBwYDVQQGEwAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuhnXaI39USOub
BM2av6kx9hwSI3oK/c133Mz9u/1gFHsR5aGKA6A5wVf6d2XhOz8mD7jTsRRVo7yf
zudLjD9/o2QwYjALBgNVHREEBDACggAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBTdHM+wYXZtP3uJm+U1lXhrpmxa0DAPBgNV
HRMBAf8EBTADAQEAMAoGCCqGSM49BAMCA0gAMEUCIQDYCHPkBZvND2Jq0XR0oPl/
nlZq8x9WgzaSXSvs6FAt+AIgStMaHgyHPinpj+3HhSXHj/vNWYJO6OBxpG9fduRj
7YA=
-----END CERTIFICATE-----";

    pub static CERT_STR: &str = "-----BEGIN CERTIFICATE-----
MIIBrjCCAVSgAwIBAgIILYaEFjUTHAQwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAxMX
SW50ZXJtZWRpYXRlIFNpZ25pbmcgY2EwHhcNMjIxMDMwMTQyMDU0WhcNMjMxMDMw
MTQyMDU0WjAyMQ8wDQYDVQQDEwZzZXJ2ZXIxCTAHBgNVBAoTADEJMAcGA1UECxMA
MQkwBwYDVQQGEwAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuhnXaI39USOub
BM2av6kx9hwSI3oK/c133Mz9u/1gFHsR5aGKA6A5wVf6d2XhOz8mD7jTsRRVo7yf
zudLjD9/o2QwYjALBgNVHREEBDACggAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBTdHM+wYXZtP3uJm+U1lXhrpmxa0DAPBgNV
HRMBAf8EBTADAQEAMAoGCCqGSM49BAMCA0gAMEUCIQDYCHPkBZvND2Jq0XR0oPl/
nlZq8x9WgzaSXSvs6FAt+AIgStMaHgyHPinpj+3HhSXHj/vNWYJO6OBxpG9fduRj
7YA=
-----END CERTIFICATE-----";
}
