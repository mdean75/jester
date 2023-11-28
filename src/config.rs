use std::path::PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};
use once_cell::sync::OnceCell;
use serde::Deserialize;

pub static APP_CONFIG: OnceCell<CliArgs> = OnceCell::new();

#[derive(Parser, Default, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    // #[arg(short,long,default_value = "127.0.0.1")]
    // pub server: String,
    //
    // #[arg(short,long)]
    // pub client_cert_path: Option<PathBuf>,
    //
    // #[arg(short='k',long)]
    // pub client_private_key_path: Option<PathBuf>,
    //
    // #[arg(short='a',long)]
    // pub cabundle_path: Option<PathBuf>,
    //
    #[arg(short)]
    pub build: bool,

    #[command(subcommand)]
    pub subcommand: Option<Subcommands>,
}

#[derive(Subcommand, Debug)]
pub enum Subcommands {
    /// Renew a certificate and exit
    Renew(RenewCommand),

    // run server or run daemon or -d for autorenew daemon
    /// Run auto renewal daemon
    Autorenew(AutorenewCommand)
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum PrivateKeyType {
    Rsa,
    Ecdsa256,
    Ecdsa384
}

#[derive(Args, Debug)]
pub struct RenewCommand {
    #[arg(short,long,default_value = "127.0.0.1")]
    pub server: String,

    #[arg(short,long)]
    pub client_cert_path: PathBuf,

    #[arg(short='k',long)]
    pub client_private_key_path: PathBuf,

    #[arg(short='a',long)]
    pub cabundle_path: PathBuf,

    #[arg(short, long)]
    pub force: bool,

    #[arg(short='x', long, value_enum, default_value = "ecdsa256")]
    pub key_type: PrivateKeyType,

    #[arg(short,long,required_if_eq("key_type", "rsa"))]
    pub rsa_key_length: Option<RsaKeyLengthOption>
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
#[derive(ValueEnum, Clone, Debug)]
pub enum RsaKeyLengthOption {
    #[value(name="2048")]
    #[serde(rename="2048")]
    Rsa2048,
    #[value(name="3072")]
    #[serde(rename="3072")]
    Rsa3072,
    #[value(name="4096")]
    #[serde(rename="4096")]
    Rsa4096
}

#[derive(Args, Debug)]
pub struct AutorenewCommand {
    #[arg(short,long)]
    pub configuration_file_path: PathBuf,
}
