use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;
use serde::Deserialize;
use crossbeam_channel::{select};
use crate::certificate;
use crate::certificate::SigAlg;
use crate::config::{AutorenewCommand, PrivateKeyType, RenewCommand, RsaKeyLengthOption};

const DEFAULT_RENEWAL_LOOP_FREQUENCY_HOURS: u64 = 24; //Duration = Duration::from_secs(60*60*24);

fn default_renewal_loop_frequency_hours() -> u64 {
    DEFAULT_RENEWAL_LOOP_FREQUENCY_HOURS
}

#[derive(Deserialize, Default)]
#[serde(rename_all="camelCase")]
struct CertificateConfig {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub cabundle_path: PathBuf,
    pub renew_grace_period: u64,
    pub post_renewal_script: String,
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
struct AutorenewalConfig {
    pub server_url: String,
    pub server_port: String,
    pub log_file: String,
    #[serde(default = "default_renewal_loop_frequency_hours")]
    autorenew_frequency: u64,
    pub certificates: Vec<CertificateConfig>,
    key_type: PrivateKeyType,
    rsa_key_length: RsaKeyLengthOption
}

pub fn renew_once(renew_cert: &RenewCommand) -> Result<(), String> {

    let key_type = match renew_cert.key_type {
        PrivateKeyType::Rsa => {
            match renew_cert.rsa_key_length.as_ref().unwrap() {
                RsaKeyLengthOption::Rsa2048 => SigAlg::Rsa(&certificate::RSA2048),
                RsaKeyLengthOption::Rsa3072 => SigAlg::Rsa(&certificate::RSA3072),
                RsaKeyLengthOption::Rsa4096 => SigAlg::Rsa(&certificate::RSA4096),
            }
        },
        PrivateKeyType::Ecdsa256 => {SigAlg::EcdsaP256},
        PrivateKeyType::Ecdsa384 => {SigAlg::EcdsaP384},
    };

    let conf = CertificateConfig{
        certificate_path: renew_cert.client_cert_path.to_path_buf(),
        private_key_path: renew_cert.client_private_key_path.to_path_buf(),
        cabundle_path: renew_cert.cabundle_path.to_path_buf(),
        renew_grace_period: 10,
        post_renewal_script: "".to_string(),
    };

    match  renew(&conf, renew_cert.server.as_str(), renew_cert.force, key_type) {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e)
    }

    Ok(())
}

pub fn auto_renew(renewal_config: &AutorenewCommand) -> Result<(), String> {

    println!("getting autorenew configuration");

    let file = fs::File::open(renewal_config.configuration_file_path.as_path()).map_err(|e| e.to_string())?;
    let rdr = BufReader::new(file);

    let config: AutorenewalConfig = serde_json::from_reader(rdr).map_err(|e| e.to_string())?;

    let tickerx = crossbeam_channel::tick(
        chrono::Duration::hours(config.autorenew_frequency as i64)
            .to_std()
            .map_err(|e| e.to_string())?
    );

    // run the auto-renewal immediately
    renew_all_certs(&config);

    loop {
        select! {
            recv(tickerx) -> _ => {renew_all_certs(&config);}
        }
    }
}

fn renew_all_certs(config: &AutorenewalConfig) {
    for certificate in config.certificates.as_slice() {

        let key_type = match config.key_type {
            PrivateKeyType::Rsa => {
                match config.rsa_key_length {
                    RsaKeyLengthOption::Rsa2048 => SigAlg::Rsa(&certificate::RSA2048),
                    RsaKeyLengthOption::Rsa3072 => SigAlg::Rsa(&certificate::RSA3072),
                    RsaKeyLengthOption::Rsa4096 => SigAlg::Rsa(&certificate::RSA4096),
                }
            },
            PrivateKeyType::Ecdsa256 => {SigAlg::EcdsaP256},
            PrivateKeyType::Ecdsa384 => {SigAlg::EcdsaP384},
        };

        match  renew(certificate, &config.server_url, false, key_type) {
            Ok(msg) => println!("{}", msg),
            Err(e) => println!("{}", e)
        }
    }
}

fn renew(conf: &CertificateConfig, server_url: &str, force: bool, key_type: SigAlg) -> Result<String, String> {
    let mut ccx = certificate::Renewal::new(key_type);
    let (pem_bytes, raw_pem) = certificate::pem_to_der_bytes(&conf.certificate_path).unwrap_or_else(|_| exit(2));

    ccx.load_old_cert(&pem_bytes).unwrap();

    // we want to allow forcing the renewal
    if force || ccx.current_cert.as_ref().unwrap().validity.time_to_expiration().unwrap() <= Duration::from_secs(60*60*24*conf.renew_grace_period) {
        ccx.current_cert_pem = raw_pem;
        ccx.load_privatekey(conf.private_key_path.to_path_buf()).unwrap();
        ccx.load_cacerts(conf.cabundle_path.to_path_buf()).unwrap();

        ccx.generate_key_pair().unwrap();

        ccx.generate_signing_request().unwrap();

        let new_cert_pem = ccx.renew(server_url);

        fs::write(conf.certificate_path.to_path_buf(), new_cert_pem).unwrap();
        fs::write(conf.private_key_path.to_path_buf(), ccx.new_priv_key.unwrap().serialize_pem()).unwrap();

        Ok(format!("Succesfully renewed certificate: {}", conf.certificate_path.to_str().unwrap()))
    } else {
        Ok("Not time to renew".to_string())
    }
}
