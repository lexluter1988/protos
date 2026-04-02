use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Parser, Subcommand};
use common::{init_tracing, load_relay_config};
use tg_relay::telegram_fetch::{
    fetch_telegram_artifacts, DEFAULT_TELEGRAM_PROXY_CONFIG_URL,
    DEFAULT_TELEGRAM_PROXY_SECRET_URL,
};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(
        long,
        env = "TG_RELAY_CONFIG",
        default_value = "config/relay.example.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    FetchTelegramConfig(FetchTelegramConfigArgs),
}

#[derive(Debug, ClapArgs)]
struct FetchTelegramConfigArgs {
    #[arg(
        long,
        env = "TG_RELAY_TELEGRAM_CONFIG_URL",
        default_value = DEFAULT_TELEGRAM_PROXY_CONFIG_URL
    )]
    config_url: String,
    #[arg(
        long,
        env = "TG_RELAY_TELEGRAM_CONFIG_OUT",
        default_value = "var/telegram/proxy-multi.conf"
    )]
    output: PathBuf,
    #[arg(
        long,
        env = "TG_RELAY_TELEGRAM_SECRET_URL",
        default_value = DEFAULT_TELEGRAM_PROXY_SECRET_URL
    )]
    secret_url: String,
    #[arg(long, env = "TG_RELAY_TELEGRAM_SECRET_OUT")]
    secret_out: Option<PathBuf>,
    #[arg(long, env = "TG_RELAY_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::FetchTelegramConfig(args)) => {
            init_tracing(&args.log_level)?;
            let summary = fetch_telegram_artifacts(
                &args.config_url,
                &args.output,
                args.secret_out.as_ref().map(|_| args.secret_url.as_str()),
                args.secret_out.as_deref(),
            )
            .await?;
            println!(
                "Downloaded {} bytes of Telegram proxy config to {} ({} proxy entries across {} clusters).",
                summary.config_bytes,
                args.output.display(),
                summary.config_summary.proxy_entries,
                summary.config_summary.dc_clusters
            );
            if let Some(secret_bytes) = summary.secret_bytes {
                if let Some(secret_out) = &args.secret_out {
                    println!(
                        "Downloaded {} bytes of Telegram proxy secret to {}.",
                        secret_bytes,
                        secret_out.display()
                    );
                }
            }
            Ok(())
        }
        None => {
            let config = load_relay_config(&cli.config)?;
            init_tracing(&config.log_level)?;
            tg_relay::run(config).await
        }
    }
}
