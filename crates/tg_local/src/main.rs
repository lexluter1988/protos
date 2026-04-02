use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use common::{init_tracing, load_local_config};

#[derive(Debug, Parser)]
struct Args {
    #[arg(
        long,
        env = "TG_LOCAL_CONFIG",
        default_value = "config/local.example.toml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = load_local_config(&args.config)?;
    init_tracing(&config.log_level)?;
    tg_local::run(config).await
}
