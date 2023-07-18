use std::{fmt, fs};
use std::fmt::Formatter;
use std::path::PathBuf;
use rcgen::{DnType, DnValue};

mod validate;
mod prerenewal;


fn main() {
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

    let pkey = rcgen::KeyPair::from_pem(priv_key_str).unwrap();
    let cert_der = pem::parse(cert_bytes).unwrap();
    // let (_, cert) = x509_parser::parse_x509_certificate(cert_der.contents()).unwrap();
    //
    // validate::validate(cert.clone(), cert, pkey, 10).unwrap();

    let r = rcgen::CertificateParams::from_ca_cert_pem(cert_str, pkey).unwrap();
    let cn = r.distinguished_name.get(&DnType::CommonName).unwrap();
    let scn = prerenewal::dnvalue_to_string(cn);
    println!("{}", scn);

    let cert_bytes = prerenewal::read_certificate_being_renewed(PathBuf::from("1667140022/server.crt")).unwrap();

    let key = fs::read_to_string("1667140022/server.key").unwrap();
    let priv_key = rcgen::KeyPair::from_pem(key.as_str()).unwrap();
    let (cn, o, ou, c) = prerenewal::extact_fields_from_certificate(cert_bytes, priv_key).unwrap();

    println!("Cert fields: common name: {cn}, org: {o}, org unit: {ou}, country: {c}")

}


