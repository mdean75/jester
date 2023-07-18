use std::fs;
use std::path::PathBuf;

use rcgen::{DnType, DnValue};
use rcgen::DnValue::{*};

pub fn read_certificate_being_renewed(path: PathBuf) -> Result<Vec<u8>, String> {
    let cert_bytes = fs::read(path).map_err(|e| e.to_string())?;

    // let (_, old_cert) = x509_parser::parse_x509_certificate(cert_bytes.as_slice()).map_err(|e| e.to_string())?;

    Ok(cert_bytes)
}

pub fn extact_fields_from_certificate(cert_bytes: Vec<u8>, key_pair: rcgen::KeyPair) -> Result<(String, String, String, String), String> {
    let r = rcgen::CertificateParams::from_ca_cert_pem(String::from_utf8(cert_bytes).map_err(|e| e.to_string())?.as_str(), key_pair).map_err(|e| e.to_string())?;

    Ok(
        (dnvalue_to_string(r.distinguished_name.get(&DnType::CommonName).unwrap()),
         dnvalue_to_string(r.distinguished_name.get(&DnType::OrganizationName).unwrap()),
         dnvalue_to_string(r.distinguished_name.get(&DnType::OrganizationalUnitName).unwrap()),
         dnvalue_to_string(r.distinguished_name.get(&DnType::CountryName).unwrap()))
    )
}

pub fn dnvalue_to_string(val: &DnValue) -> String {
    match val {
        Utf8String(s) |
        PrintableString(s) => {
            s.to_string()
        }

        TeletexString(v) |
        UniversalString(v) |
        BmpString(v) => {
            String::from_utf8(v.to_vec()).unwrap()
        }

        _ => {"".to_string()}
    }
}
