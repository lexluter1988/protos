pub mod config;
pub mod io;
pub mod mtproxy;
pub mod protocol;
pub mod socks;
pub mod telemetry;
pub mod tls;

pub use config::{
    load_local_config, load_relay_config, DestinationPolicyConfig, LocalConfig,
    MtProxyBackendMode, MtProxyConfig, MtProxyDcEndpointConfig, OfficialMtProxyConfig,
    RelayConfig, RelayMode, SocksAuthConfig,
};
pub use protocol::{
    ConnectRequest, ConnectResponse, ConnectStatus, DnsMode, TargetAddr, MAX_HANDSHAKE_OVERHEAD,
    MAX_TOKEN_LEN,
};

use anyhow::Result;
use tracing_subscriber::EnvFilter;

pub fn init_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level).or_else(|_| EnvFilter::try_new("info"))?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
    Ok(())
}
