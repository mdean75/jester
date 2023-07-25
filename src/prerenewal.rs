use std::fs;
use std::path::PathBuf;

use x509_parser::nom::AsBytes;
use x509_parser::pem::Pem;

#[derive(Default)]
pub struct Cert<'a> {
    pub old_cert: Option<x509_parser::certificate::X509Certificate<'a>>,
    pub renewed_cert: Option<x509_parser::certificate::X509Certificate<'a>>,
}

pub fn pem_to_der_bytes(path: PathBuf) -> Result<Pem, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(data.as_slice()).map_err(|e| e.to_string())?;

    Ok(pem)
}

impl <'a> Cert<'a> {

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
}
