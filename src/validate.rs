use std::time::Duration;
use x509_parser::nom::AsBytes;
use x509_parser::certificate::X509Certificate;
use rcgen::KeyPair;

pub fn validate(old: &X509Certificate, new: X509Certificate, priv_key: &KeyPair, expire_days: u64) -> Result<String, String> {
    // check expiration
    if !minimum_valid_period(&new, expire_days) {
        return Err("certificate validity period is less than required grace period".to_string())
    }

    // check valid fields
    if !cert_fields_match(&old, &new) {
        return Err("renewed certificate fields are not the same".to_string())
    }

    // valid keypair
    if !keypair_matches_cert_publickey(&priv_key, &new) {
        return Err("private key public key and certificate public key are not the same".to_string())
    }

    Ok("Renewed certificate passed all validation steps".to_string())
}

fn minimum_valid_period(cert: &X509Certificate, grace_period_days: u64) -> bool {
    let minimum_days_before_expiration = Duration::from_secs(60*60*24*grace_period_days);//Duration::new(60*60*24* grace_period_days, 0);
    // todo: get rid of this unwrap
    if let Some(duration_to_expiration) = cert.validity.time_to_expiration() {
        duration_to_expiration >= minimum_days_before_expiration
    } else {
        false
    }


}

fn cert_fields_match(old: &X509Certificate, new: &X509Certificate) -> bool {
    old.subject == new.subject &&
        old.issuer == new.issuer &&
        old.is_ca() == new.is_ca() &&
        old.key_usage() == new.key_usage()
}

fn keypair_matches_cert_publickey(pkey: &KeyPair, cert: &X509Certificate) -> bool {
    pkey.public_key_raw() == cert.public_key().subject_public_key.data.as_bytes()
}

#[cfg(test)]
mod tests {
    use pkcs8::{EncodePrivateKey};
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, DnValue, KeyPair};
    use x509_parser::parse_x509_certificate;
    use crate::validate::{cert_fields_match, keypair_matches_cert_publickey, minimum_valid_period, validate};

    #[test]
    fn validate_all_checks_passed() {
        // new, old, pkey, expire days
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone = KeyPair::from_der(pkey_der.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;
        params.not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();

        let cert = Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();

        // want both certs to match so use the same cert_der for both old and new
        let (_, old_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();
        let (_, new_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();

        assert_eq!(validate(&old_cert, new_cert, &key_pair_clone, 10), Ok("Renewed certificate passed all validation steps".to_string()))
    }

    #[test]
    fn validate_fails_for_too_short_valid_period() {
        // new, old, pkey, expire days
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone = KeyPair::from_der(pkey_der.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;
        params.not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();

        let cert = Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();

        // want both certs to match so use the same cert_der for both old and new
        let (_, old_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();
        let (_, new_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();

        assert_eq!(validate(&old_cert, new_cert, &key_pair_clone, 50), Err("certificate validity period is less than required grace period".to_string()))
    }

    #[test]
    fn validate_fails_when_cert_fields_not_match() {
        // new, old, pkey, expire days
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone2 = KeyPair::from_der(pkey_der.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;
        params.not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();

        let mut old_dn = DistinguishedName::new();
        old_dn.push(DnType::CommonName, DnValue::PrintableString("test".to_string()));
        old_dn.push(DnType::OrganizationName, DnValue::PrintableString("my org".to_string()));
        old_dn.push(DnType::OrganizationalUnitName, DnValue::PrintableString("my org unit".to_string()));
        old_dn.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));

        params.distinguished_name = old_dn;

        let mut new_params = CertificateParams::default();

        new_params.key_pair = Some(key_pair_clone2);
        new_params.alg = &rcgen::PKCS_RSA_SHA256;
        new_params.not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();


        let cert = Certificate::from_params(params).unwrap();
        let new_cert = Certificate::from_params(new_params).unwrap();

        let cert_der = cert.serialize_der().unwrap();
        let new_cert_der = new_cert.serialize_der().unwrap();

        // want both certs to match so use the same cert_der for both old and new
        let (_, old_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();
        let (_, new_cert) = parse_x509_certificate(new_cert_der.as_slice()).unwrap();

        assert_eq!(validate(&old_cert, new_cert, &key_pair_clone, 10), Err("renewed certificate fields are not the same".to_string()))
    }

    #[test]
    fn validate_fails_for_invalid_publickey() {
        // new, old, pkey, expire days
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone = KeyPair::from_der(pkey_der.as_bytes()).unwrap();

        let mut rng = rand::thread_rng();
        let bad_pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let bad_pkey_der = bad_pkey.to_pkcs8_der().unwrap();

        let bad_key_pair = KeyPair::from_der(bad_pkey_der.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;
        params.not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();

        let cert = Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();

        // want both certs to match so use the same cert_der for both old and new
        let (_, old_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();
        let (_, new_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();

        assert_eq!(validate(&old_cert, new_cert, &bad_key_pair, 10), Err("private key public key and certificate public key are not the same".to_string()))
    }

    #[test]
    fn has_minimum_valid_period() {

        let mut params = CertificateParams::default();

        let cert_not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();
        params.not_after = cert_not_after;

        let cert_templ = Certificate::from_params(params).unwrap();

        let der = cert_templ.serialize_der().unwrap();

        let (_, cert) = x509_parser::parse_x509_certificate(der.as_slice()).unwrap();

        assert_eq!(minimum_valid_period(&cert, 20), true)
    }

    #[test]
    fn does_not_have_minimum_valid_period() {

        let mut params = CertificateParams::default();

        let cert_not_after = time::OffsetDateTime::now_utc().checked_add(time::Duration::new(60*60*24*40, 0)).unwrap();
        params.not_after = cert_not_after;

        let cert_templ = Certificate::from_params(params).unwrap();

        let der = cert_templ.serialize_der().unwrap();

        let (_, cert) = x509_parser::parse_x509_certificate(der.as_slice()).unwrap();

        assert_eq!(minimum_valid_period(&cert, 50), false)
    }

    #[test]
    fn cert_fields_do_match() {
        let mut old_dn = DistinguishedName::new();
        old_dn.push(DnType::CommonName, DnValue::PrintableString("test".to_string()));
        old_dn.push(DnType::OrganizationName, DnValue::PrintableString("my org".to_string()));
        old_dn.push(DnType::OrganizationalUnitName, DnValue::PrintableString("my org unit".to_string()));
        old_dn.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));

        let mut old_params = CertificateParams::default();
        old_params.is_ca = rcgen::IsCa::NoCa;
        old_params.distinguished_name = old_dn;
        // TODO: WHEN SETTING KEY USAGES IN RCGEN CERT, IT DOES NOT PERSIST IN X509_PARSER CERTIFICATE
        old_params.key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);

        let old = Certificate::from_params(old_params).unwrap();

        let mut new_dn = DistinguishedName::new();
        new_dn.push(DnType::CommonName, DnValue::PrintableString("test".to_string()));
        new_dn.push(DnType::OrganizationName, DnValue::PrintableString("my org".to_string()));
        new_dn.push(DnType::OrganizationalUnitName, DnValue::PrintableString("my org unit".to_string()));
        new_dn.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));

        let mut new_params = CertificateParams::default();
        new_params.is_ca = rcgen::IsCa::NoCa;
        new_params.distinguished_name = new_dn;

        let new = Certificate::from_params(new_params).unwrap();

        let old_der = old.serialize_der().unwrap();
        let new_der = new.serialize_der().unwrap();

        let (_, old_x509) = x509_parser::parse_x509_certificate(&*old_der).unwrap();
        let (_, new_x509) = x509_parser::parse_x509_certificate(&*new_der).unwrap();

        let old_key_usage = old_x509.key_usage();

        assert_eq!(cert_fields_match(&old_x509, &new_x509), true)
    }

    #[test]
    fn cert_fields_do_not_match() {
        let mut old_dn = DistinguishedName::new();
        old_dn.push(DnType::CommonName, DnValue::PrintableString("test".to_string()));
        old_dn.push(DnType::OrganizationName, DnValue::PrintableString("your org".to_string()));
        old_dn.push(DnType::OrganizationalUnitName, DnValue::PrintableString("my org unit".to_string()));
        old_dn.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));

        let mut old_params = CertificateParams::default();
        old_params.is_ca = rcgen::IsCa::NoCa;
        old_params.distinguished_name = old_dn;

        let old = Certificate::from_params(old_params).unwrap();

        let mut new_dn = DistinguishedName::new();
        new_dn.push(DnType::CommonName, DnValue::PrintableString("test".to_string()));
        new_dn.push(DnType::OrganizationName, DnValue::PrintableString("my org".to_string()));
        new_dn.push(DnType::OrganizationalUnitName, DnValue::PrintableString("my org unit".to_string()));
        new_dn.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));

        let mut new_params = CertificateParams::default();
        new_params.is_ca = rcgen::IsCa::NoCa;
        new_params.distinguished_name = new_dn;

        let new = Certificate::from_params(new_params).unwrap();

        let old_der = old.serialize_der().unwrap();
        let new_der = new.serialize_der().unwrap();

        let (_, old_x509) = x509_parser::parse_x509_certificate(old_der.as_slice()).unwrap();
        let (_, new_x509) = x509_parser::parse_x509_certificate(new_der.as_slice()).unwrap();
        assert_eq!(cert_fields_match(&old_x509, &new_x509), false)
    }

    #[test]
    fn privatekey_publickey_and_cert_publickey_matches() {
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair_clone = KeyPair::from_der(pkey_der.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;

        let cert = Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();
        let (_, x509_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();

        assert_eq!(keypair_matches_cert_publickey(&key_pair_clone, &x509_cert), true)
    }

    #[test]
    fn privatekey_publickey_and_cert_publickey_not_matched() {
        let mut rng = rand::thread_rng();
        let pkey = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der = pkey.to_pkcs8_der().unwrap();

        let pkey2 = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkey_der2 = pkey2.to_pkcs8_der().unwrap();

        let key_pair = KeyPair::from_der(pkey_der.as_bytes()).unwrap();
        let key_pair2 = KeyPair::from_der(pkey_der2.as_bytes()).unwrap();

        let mut params = CertificateParams::default();

        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;

        let cert = Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();
        let (_, x509_cert) = parse_x509_certificate(cert_der.as_slice()).unwrap();

        assert_eq!(keypair_matches_cert_publickey(&key_pair2, &x509_cert), false)
    }

}
