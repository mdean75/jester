use base64_light::{base64_decode, base64_encode_bytes};
use picky::x509::pkcs7::Pkcs7;
use reqwest::blocking::{Client, Response};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Identity, IntoUrl, Method};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use std::io;
use std::io::BufReader;
use x509_parser::nom::AsBytes;

use crate::{certificate, config};

#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";

pub fn refresh_cacert<U: IntoUrl>(
    ca_bundle: &[u8],
    priv_key: &[u8],
    client_cert: &[u8],
    url: U,
) -> Result<String, String> {
    let client = make_client(priv_key, client_cert, ca_bundle);

    let cacert_response = request_current_cacerts(&client, url).map_err(|e| e.to_string())?;
    let b64 = base64_decode(cacert_response.text().map_err(|e| e.to_string())?.as_str());

//    println!("{}", String::from_utf8_lossy(b64.as_bytes()));

      let certs: String = Pkcs7::from_der(&b64).map_err(|e| e.to_string())?
            .decode_certificates()
            .iter()
            .map(|ca| format!("{}\n", ca.to_pem().unwrap().to_string()))
            .collect();

    Ok(certs)
}

pub fn request_client_certificate<U: IntoUrl>(
    cert: &mut certificate::Renewal,
    url: U,
) -> Result<String, String> {
        cert.ca_bundle_pem = refresh_cacert(
            &cert.ca_bundle_pem,
           &cert.current_priv_key_pem,
            &cert.current_cert_pem,
            url.as_str(),
        )?
        .into_bytes();

    let client = make_client(
        &cert.current_priv_key_pem,
        &cert.current_cert_pem,
        &cert.ca_bundle_pem,
    );

    let b64_encoded_signing_request =
        base64_encode_bytes(cert.signing_request_der.to_vec().as_bytes());

    let response = request_reenroll(&client, b64_encoded_signing_request, url.as_str()).map_err(|e| e.to_string())?;
    Ok(decode_pkcs7_cert(response.text().map_err(|e| e.to_string())?))
}

fn decode_pkcs7_cert(encoded_cert: String) -> String {
    let decoded_str = base64_decode(encoded_cert.as_str());

    let certificates = Pkcs7::from_der(decoded_str.as_bytes())
        .unwrap()
        .decode_certificates();

    // only need to get the leaf cert which should always be first even if this is a bundle
    let pem_encoded_cert = certificates.first().unwrap().to_pem().unwrap();

    let mut pem_str = pem_encoded_cert.to_string();
    pem_str.push_str(LINE_ENDING); // need a newline at end for proper use of the cert

    pem_str
}

fn request_current_cacerts<U: IntoUrl>(client: &Client, url: U) -> reqwest::Result<Response> {
    client
        .get(format!("{}/.well-known/est/cacerts", url.as_str()))
        .header(CONTENT_TYPE, "application/pkcs7-mime")
        .header("Content-Transfer-Encoding", "base64")
        .send()
}

fn request_reenroll<U: IntoUrl>(
    client: &Client,
    b64_encoded_signing_request: String,
    url: U,
) -> reqwest::Result<Response> {
    client
        .post(format!("{}/.well-known/est/simplereenroll", url.as_str()))
        .header(CONTENT_TYPE, "application/pkcs10")
        .header("Content-Transfer-Encoding", "base64")
        .body(b64_encoded_signing_request)
        .send()
}

fn make_client(priv_key: &[u8], client_cert: &[u8], cabundle: &[u8]) -> Client {
    let root_store = build_root_trust_store(cabundle).unwrap();

    let tls_config = build_tls_config(root_store);

    let root_cert = root_cacert(cabundle);

    let identity = build_identity_pem(priv_key, client_cert, cabundle).unwrap();

    reqwest::blocking::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(20)) // complete round trip
        .connect_timeout(std::time::Duration::from_secs(10)) // connection only
        .identity(identity)
        .add_root_certificate(root_cert)
        .use_preconfigured_tls(tls_config)
        .use_rustls_tls()
        .build()
        .unwrap()
}

fn build_identity_pem(
    priv_key: &[u8],
    client_cert: &[u8],
    cabundle: &[u8],
) -> reqwest::Result<Identity> {
    let mut cert_chain_with_privatekey: Vec<u8> = Vec::new();
    cert_chain_with_privatekey.extend(priv_key);
    cert_chain_with_privatekey.extend(client_cert);
    cert_chain_with_privatekey.extend(cabundle);

    Identity::from_pem(cert_chain_with_privatekey.as_bytes())
}

fn build_root_trust_store(bundle_pem: &[u8]) -> Result<RootCertStore, String> {
    let mut root_store = RootCertStore::empty();
    let cacerts =
        rustls_pemfile::certs(&mut BufReader::new(bundle_pem)).map_err(|e| e.to_string())?;
    let trust_anchors = cacerts.iter().map(|cert| {
        let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    });

    root_store.add_server_trust_anchors(trust_anchors);

    Ok(root_store)
}

fn build_tls_config(root_store: RootCertStore) -> ClientConfig {
    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn root_cacert(cabundle: &[u8]) -> reqwest::Certificate {
    // extract the root ca cert to add to the client
    let mut buf_rdr = io::BufReader::new(cabundle);
    let bundle_certs = rustls_pemfile::certs(&mut buf_rdr).unwrap();

    reqwest::Certificate::from_der(bundle_certs.last().unwrap()).unwrap()
}
