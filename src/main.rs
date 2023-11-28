use std::{thread};
use std::process::exit;
use clap::Parser;
use signal_hook::consts::SIGINT;
use signal_hook::iterator::{Signals};
use crate::config::{PrivateKeyType, Subcommands};

mod validate;
mod certificate;
mod http;
mod config;
mod autorenew;


fn main() {

    let app_config = config::CliArgs::parse();
    config::APP_CONFIG.set(app_config).unwrap();

    let conf = config::APP_CONFIG.get().unwrap();

    if config::APP_CONFIG.get().unwrap().build {
        println!("{}", build_info());
        exit(0)
    }

    match &conf.subcommand {
        Some(Subcommands::Renew(renew_cert)) => {
            // let key_type = match renew_cert.key_type {
            //     PrivateKeyType::Rsa => {certificate::SigAlg::Rsa(&certificate::RSA2048)},
            //     PrivateKeyType::Ecdsa256 => {certificate::SigAlg::EcdsaP256},
            //     PrivateKeyType::Ecdsa384 => {certificate::SigAlg::EcdsaP384},
            // };

            match autorenew::renew_once(renew_cert) {
                Ok(_) => {
                    // println!("Successfully renewed and rekeyed certificate!");
                    exit(0)
                },
                Err(e) => {
                    println!("Certificate renewal failed: {}", e);
                    exit(1)
                }
            }
        },
        Some(Subcommands::Autorenew(autorenew_config)) => {
            thread::spawn(move || {
                println!("starting autorenew monitor");
                autorenew::auto_renew(autorenew_config).unwrap(); // currently this blocks, we will likely want to use asyn
            });
        }
        None => {}
    }

    let sigint = Signals::new(vec![SIGINT]);
    sigint.unwrap().wait();


    println!("signal SIGINT caught ... exiting Jester")

}

fn build_info() -> String {
    let branch = env!("VERGEN_GIT_BRANCH");
    let commit = env!("VERGEN_GIT_SHA");
    let build_ts = env!("VERGEN_BUILD_TIMESTAMP");
    let version = env!("CARGO_PKG_VERSION");

    format!("Version: Jester {version}\nBuild Timestamp: {build_ts}\nBranch: {branch}\nCommit: {commit}\n")
}
