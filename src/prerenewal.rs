use std::fmt::{Display, Formatter};
use std::fs;
use std::path::PathBuf;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use rand::thread_rng;
use rcgen::{KeyPair};

use x509_parser::nom::AsBytes;
use x509_parser::pem::Pem;
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

    pub fn generate_signing_request() {

    }
}

pub fn pem_to_der_bytes(path: PathBuf) -> Result<Pem, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(data.as_slice()).map_err(|e| e.to_string())?;

    Ok(pem)
}
