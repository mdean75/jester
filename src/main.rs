use std::{fmt, fs};
use std::fmt::Formatter;
use std::ops::Deref;
use std::path::PathBuf;
use std::slice::Iter;
use std::vec::IntoIter;
use rcgen::{DnType, DnValue};
use crate::prerenewal::{RSA2048, RSA3072, RSA4096, SigAlg};

mod validate;
mod prerenewal;


fn main() {

    // Your initial iterator of some type (let's assume it's called `iter`).
    // For this example, let's assume it's an iterator of integers.
    let iter: IntoIter<i32> = vec![].into_iter();

    // Use the `map` function to convert each element to a string.
    let string_iter: Vec<String> = iter.map(|item| item.to_string()).collect();

    // Convert the `Vec<String>` into an `Option<Vec<String>>`.
    let result: Option<Vec<String>> = if string_iter.is_empty() {None} else { Some(string_iter) };//Option::from(string_iter);

    // If the original iterator is empty, `result` will be `None`.
    println!("{:?}", result); // Output: Some(["1", "2", "3", "4", "5"])

    println!("Hello, world!");
    println!("Git Branch: {}", env!("VERGEN_GIT_BRANCH"));
    println!("Git Commit: {}", env!("VERGEN_GIT_SHA"));
    println!("Build Timestamp: {}", env!("VERGEN_BUILD_TIMESTAMP"));

    let priv_key_str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz1CrJYfBgwhY8B8K
bDibjnPiB/eQId1/65C2fn1LZ3GhRANCAASuhnXaI39USOubBM2av6kx9hwSI3oK
/c133Mz9u/1gFHsR5aGKA6A5wVf6d2XhOz8mD7jTsRRVo7yfzudLjD9/
-----END PRIVATE KEY-----";

    let cert_bytes = b"-----BEGIN CERTIFICATE-----
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

    let cert_str = "-----BEGIN CERTIFICATE-----
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


    let bad_key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsc61hFNRxArpb2uL
zxj/3k1VRhzBBD8Db78FRRurFS6hRANCAAQpENsVS0j9fPROTMQOMyY5DHUsV5kG
cg5iXC/wd76lfWsRZZ1rwPxrtHrB8vwolsZjAX+OqlbR8e/UE+r7PWnW
-----END PRIVATE KEY-----";

    // let pkey = rcgen::KeyPair::from_pem(priv_key_str).unwrap();
    // let cert_der = pem::parse(cert_bytes).unwrap();
    // let (_, cert) = x509_parser::parse_x509_certificate(cert_der.contents()).unwrap();
    //
    // validate::validate(cert.clone(), cert, pkey, 10).unwrap();

    // let r = rcgen::CertificateParams::from_ca_cert_pem(cert_str, pkey).unwrap();
    // let cn = r.distinguished_name.get(&DnType::CommonName).unwrap();
    // let scn = prerenewal::dnvalue_to_string(cn);
    // println!("{}", scn);

    // let cert_bytes = prerenewal::read_certificate_being_renewed(PathBuf::from("1667140022/server.crt")).unwrap();
    //
    // let key = fs::read_to_string("1667140022/server.key").unwrap();
    // let priv_key = rcgen::KeyPair::from_pem(key.as_str()).unwrap();
    // let (cn, o, ou, c) = prerenewal::extact_fields_from_certificate(cert_bytes, priv_key).unwrap();

    // println!("Cert fields: common name: {cn}, org: {o}, org unit: {ou}, country: {c}");

    // let mut certx = prerenewal::CertFields {
    //     old_cert_subject: None,
    // };
    // let mut certx = prerenewal::CertFields::default();
    // certx.old_cert_subject = None;
    //
    // certx.load_subject(PathBuf::from("example.com.crt")).unwrap();
    //
    // println!("from certx: {:?}", certx.old_cert_subject);

    // let mut cx = prerenewal::Cert::default();
    // println!("cx: {}", cx.signature_alg);

    // let key_pair = cx.generate_key_pair().unwrap();

    // println!("{:?}", key_pair.public_key_pem());
    // let pem_bytes = prerenewal::pem_to_der_bytes(PathBuf::from("example.com.crt")).unwrap();
    // cx.load_old_cert(&pem_bytes).unwrap();
    //
    // cx.with_signature_alg(SigAlg::PkcsRsaSha256).unwrap();

    // println!("cx result: {}", cx.old_cert.unwrap().subject.to_string());

    // let test = &rcgen::PKCS_RSA_SHA256;
    // let test2 = test.c
    // let ccx = prerenewal::Cert::generate_key_pair(&rcgen::PKCS_RSA_SHA256.).unwrap();

    let mut ccx = prerenewal::Cert::new(SigAlg::Rsa(&RSA4096));
    println!("ccx: {}", ccx.signature_alg);

    // ccx.with_signature_alg(SigAlg::PkcsEd25519).unwrap();
    // println!("ccx: {}", ccx.signature_alg);
    ccx.generate_key_pair().unwrap();

    println!("ccx priv key: \n{}", ccx.priv_key.unwrap().serialize_pem())
    // prerenewal::generate_key_pair(&rcgen::PKCS_RSA_SHA256);
}


