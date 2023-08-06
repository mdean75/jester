use std::{fs, io};
use std::io::{BufReader};
use std::process::Stdio;
use base64::{Engine};
use reqwest::header::{CONTENT_TYPE};
use rustls::OwnedTrustAnchor;
use x509_parser::nom::{AsBytes};
use picky::x509::pkcs7::Pkcs7;


use crate::prerenewal;


#[cfg(windows)]
const LINE_ENDING : &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING : &'static str = "\n";

/*
    What all do i need here?

    root cert pem -> can extract this from the bundle
    ca bundle pem
    current cert pem -> on prerenewal::Cert struct
    current private key pem

*/
// TODO: still need to get current cacerts
pub fn request_client_certificate(mut cert: prerenewal::Cert) {

    let current_ca_bundle = fs::read("client-certs/server-ca-bundle.pem").unwrap();

    let mut buf = Vec::new();
    buf.append(&mut cert.old_priv_key_pem);
    buf.append(&mut cert.old_cert_pem);
    buf.append(&mut current_ca_bundle.to_vec());

    let mut root_store = rustls::RootCertStore::empty();
    let cacerts = rustls_pemfile::certs(&mut BufReader::new(current_ca_bundle.as_slice())).unwrap();
    let trust_anchors = cacerts.iter().map(|cert| {
        let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    });

    root_store.add_server_trust_anchors(trust_anchors);

    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let id = reqwest::Identity::from_pem(buf.as_bytes()).unwrap();


    // extract the root ca cert to add to the client
    let mut buf_rdr = io::BufReader::new(current_ca_bundle.as_slice());
    let bundle_certs = rustls_pemfile::certs(&mut buf_rdr).unwrap();

    let req = reqwest::blocking::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(20)) // complete round trip timeout
        .connect_timeout(std::time::Duration::from_secs(10)) // connection only phase
        .identity(id)
        .add_root_certificate(reqwest::Certificate::from_der(bundle_certs.get(1).unwrap()).unwrap())
        .use_preconfigured_tls(tls_config)
        .use_rustls_tls()
        .build().unwrap();

    let mut bufx = String::new();
    base64::engine::general_purpose::STANDARD.encode_string(cert.csr_der, &mut bufx);
    let response = req.post("https://192.168.40.211:8443/.well-known/est/simplereenroll")
        .header(CONTENT_TYPE, "application/pkcs10")
        .header("Content-Transfer-Encoding", "base64")
        .body(bufx)
        .send();

    match response {
        Ok(res) => {

            let decoded_bytes = base64_decode(res.text().unwrap());

            let certificates = Pkcs7::from_der(decoded_bytes.as_slice()).unwrap()
                .decode_certificates();

            // only need to get the leaf cert which should always be first even if this is a bundle
            let pem_encoded_cert = certificates.get(0).unwrap().to_pem().unwrap();

            let mut pem_str = pem_encoded_cert.to_string();
            pem_str.push_str(LINE_ENDING); // need a newline at end for proper use of the cert

            fs::write("renewed-cert.pem", pem_str).unwrap();
            fs::write("renewed-pkey.pem", cert.priv_key_pem).unwrap();

            println!("Successfully renewed and rekeyed certificate!")
        },
        Err(e) => println!("err: {}", e.to_string())
    }
}

// this is backup solution and can be removed, leaving for now for further testing
fn openssl_convert_to_pem(encoded_cert: String) -> Vec<u8> {
    let echo_cert = std::process::Command::new("echo")
        .arg(encoded_cert)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let openssl_base64 = std::process::Command::new("openssl")
        .args(["base64", "-d"])
        .stdin(Stdio::from(echo_cert.stdout.unwrap()))
        .stdout(Stdio::piped())
        .spawn().unwrap();

    let openssl_pkcs7 = std::process::Command::new("openssl")
        .args(["pkcs7", "-inform", "DER", "-outform", "PEM", "-print_certs"])
        .stdin(Stdio::from(openssl_base64.stdout.unwrap()))
        .output()
        .unwrap();

    // println!("{}", String::from_utf8(openssl_pkcs7.stderr).unwrap());
    openssl_pkcs7.stdout

    // vec![]
}

#[cfg(target_os = "macos")]
fn base64_decode(encoded_data: String) -> Vec<u8> {
    let echo_data_cmd = std::process::Command::new("echo")
        .arg(encoded_data)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let base64_decode_cmd = std::process::Command::new("base64")
        .args(["-D"])
        .stdin(Stdio::from(echo_data_cmd.stdout.unwrap()))
        .output()
        .unwrap();

    base64_decode_cmd.stdout
}

#[cfg(target_os = "linux")]
fn base64_decode(encoded_data: String) -> Vec<u8> {
    let echo_data_cmd = std::process::Command::new("echo")
        .arg(encoded_data)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let base64_decode_cmd = std::process::Command::new("base64")
        .args(["-d"])
        .stdin(Stdio::from(echo_data_cmd.stdout.unwrap()))
        .output()
        .unwrap();

    base64_decode_cmd.stdout
}

// TODO: NEED TO CONFIRM THIS WORKS ON WINDOWS
#[cfg(target_os = "windows")]
fn base64_decode(encoded_data: String) -> Vec<u8> {
    let echo_data_cmd = std::process::Command::new("echo")
        .arg(encoded_data)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let base64_decode_cmd = std::process::Command::new("certutil")
        .args(["-decode"])
        .stdin(Stdio::from(echo_data_cmd.stdout.unwrap()))
        .output()
        .unwrap();

    base64_decode_cmd.stdout
}
