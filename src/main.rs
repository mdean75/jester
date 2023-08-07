use std::fs;
use std::path::PathBuf;
use std::process::exit;
use crate::prerenewal::{SigAlg};

mod validate;
mod prerenewal;
mod http;


fn main() {

    println!("Git Branch: {}", env!("VERGEN_GIT_BRANCH"));
    println!("Git Commit: {}", env!("VERGEN_GIT_SHA"));
    println!("Build Timestamp: {}", env!("VERGEN_BUILD_TIMESTAMP"));
    println!("version: {}\n", env!("CARGO_PKG_VERSION"));

    let mut ccx = prerenewal::Cert::new(SigAlg::EcdsaP256);

    let (pem_bytes, raw_pem) = prerenewal::pem_to_der_bytes(PathBuf::from("renewed-cert.pem")).unwrap_or_else(|_| exit(2));

    ccx.load_old_cert(&pem_bytes);//.unwrap();
    ccx.old_cert_pem = raw_pem;
    ccx.load_privatekey(PathBuf::from("renewed-pkey.pem")).unwrap();
    ccx.load_cacerts(PathBuf::from("client-certs/server-ca-bundle.pem")).unwrap();

    ccx.generate_key_pair();//.unwrap();

    ccx.generate_signing_request();

    let new_cert = http::request_client_certificate(&mut ccx);

    fs::write("renewed-cert.pem", new_cert).unwrap();
    fs::write("renewed-pkey.pem", ccx.priv_key_pem.to_vec()).unwrap();

    println!("Successfully renewed and rekeyed certificate!")

}


