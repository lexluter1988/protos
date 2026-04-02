use std::env;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use crate::mtproxy::{parse_mtproxy_secret, parse_obfuscated_secret};
use crate::protocol::{DnsMode, MAX_TOKEN_LEN};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SocksAuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    Tunnel,
    #[default]
    DirectSocks5,
    #[serde(alias = "mtproxy")]
    MtProxy,
}

impl fmt::Display for RelayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tunnel => write!(f, "tunnel"),
            Self::DirectSocks5 => write!(f, "direct_socks5"),
            Self::MtProxy => write!(f, "mtproxy"),
        }
    }
}

impl FromStr for RelayMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tunnel" => Ok(Self::Tunnel),
            "direct_socks5" => Ok(Self::DirectSocks5),
            "mtproxy" => Ok(Self::MtProxy),
            _ => Err(anyhow!(
                "expected relay mode tunnel, direct_socks5, or mtproxy, got {s}"
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MtProxyDcEndpointConfig {
    pub id: i16,
    pub addr: String,
    #[serde(default)]
    pub obfuscated_secret: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MtProxyBackendMode {
    #[default]
    StaticDc,
    Official,
}

impl fmt::Display for MtProxyBackendMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticDc => write!(f, "static_dc"),
            Self::Official => write!(f, "official"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OfficialMtProxyConfig {
    pub binary_path: PathBuf,
    #[serde(default = "default_telegram_proxy_config_path")]
    pub proxy_config_path: PathBuf,
    #[serde(default = "default_telegram_proxy_secret_path")]
    pub proxy_secret_path: PathBuf,
    #[serde(default = "default_official_mtproxy_stats_port")]
    pub stats_port: u16,
    #[serde(default = "default_official_mtproxy_workers")]
    pub workers: usize,
    #[serde(default)]
    pub run_as_user: Option<String>,
    #[serde(default)]
    pub proxy_tag: Option<String>,
    #[serde(default = "default_true")]
    pub auto_refresh: bool,
    #[serde(default = "default_telegram_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_telegram_proxy_config_url")]
    pub config_url: String,
    #[serde(default = "default_telegram_proxy_secret_url")]
    pub secret_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MtProxyConfig {
    pub secret: String,
    #[serde(default)]
    pub backend: MtProxyBackendMode,
    #[serde(default)]
    pub dc_endpoints: Vec<MtProxyDcEndpointConfig>,
    #[serde(default)]
    pub official: Option<OfficialMtProxyConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DestinationPolicyConfig {
    #[serde(default)]
    pub allow_private_destinations: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_domain_suffixes: Vec<String>,
    #[serde(default)]
    pub allowed_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalConfig {
    #[serde(default = "default_local_listen_addr")]
    pub listen_addr: String,
    pub relay_addr: String,
    pub relay_server_name: String,
    pub auth_token: String,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub dns_mode: DnsMode,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub socks_auth: Option<SocksAuthConfig>,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_relay_listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub mode: RelayMode,
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub socks_auth: Option<SocksAuthConfig>,
    #[serde(default)]
    pub mtproxy: Option<MtProxyConfig>,
    #[serde(default)]
    pub destination_policy: DestinationPolicyConfig,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub outbound_connect_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
    #[serde(default = "default_max_handshake_size")]
    pub max_handshake_size: usize,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl LocalConfig {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
        apply_string_override("TG_LOCAL_LISTEN_ADDR", &mut self.listen_addr);
        apply_string_override("TG_LOCAL_RELAY_ADDR", &mut self.relay_addr);
        apply_string_override("TG_LOCAL_RELAY_SERVER_NAME", &mut self.relay_server_name);
        apply_string_override("TG_LOCAL_AUTH_TOKEN", &mut self.auth_token);
        apply_u64_override(
            "TG_LOCAL_HANDSHAKE_TIMEOUT_SECS",
            &mut self.handshake_timeout_secs,
        )?;
        apply_u64_override(
            "TG_LOCAL_CONNECT_TIMEOUT_SECS",
            &mut self.connect_timeout_secs,
        )?;
        apply_u64_override("TG_LOCAL_IDLE_TIMEOUT_SECS", &mut self.idle_timeout_secs)?;
        apply_dns_mode_override("TG_LOCAL_DNS_MODE", &mut self.dns_mode)?;
        apply_string_override("TG_LOCAL_LOG_LEVEL", &mut self.log_level);
        apply_optional_path_override("TG_LOCAL_CA_CERT_PATH", &mut self.ca_cert_path);
        apply_socks_auth_override(
            "TG_LOCAL_SOCKS_USERNAME",
            "TG_LOCAL_SOCKS_PASSWORD",
            &mut self.socks_auth,
        )?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.listen_addr.trim().is_empty() {
            return Err(anyhow!("local listen_addr must not be empty"));
        }
        if self.relay_addr.trim().is_empty() {
            return Err(anyhow!("local relay_addr must not be empty"));
        }
        if self.relay_server_name.trim().is_empty() {
            return Err(anyhow!("local relay_server_name must not be empty"));
        }
        validate_auth_token(&self.auth_token)?;
        validate_timeout("handshake_timeout_secs", self.handshake_timeout_secs)?;
        validate_timeout("connect_timeout_secs", self.connect_timeout_secs)?;
        validate_timeout("idle_timeout_secs", self.idle_timeout_secs)?;
        validate_socks_auth(self.socks_auth.as_ref())?;
        Ok(())
    }
}

impl RelayConfig {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    pub fn outbound_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.outbound_connect_timeout_secs)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    pub fn is_tunnel_mode(&self) -> bool {
        self.mode == RelayMode::Tunnel
    }

    pub fn is_official_mtproxy_mode(&self) -> bool {
        self.mode == RelayMode::MtProxy
            && self
                .mtproxy
                .as_ref()
                .map(|mtproxy| mtproxy.backend == MtProxyBackendMode::Official)
                .unwrap_or(false)
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
        apply_string_override("TG_RELAY_LISTEN_ADDR", &mut self.listen_addr);
        apply_enum_override("TG_RELAY_MODE", &mut self.mode)?;
        apply_optional_path_override("TG_RELAY_TLS_CERT_PATH", &mut self.tls_cert_path);
        apply_optional_path_override("TG_RELAY_TLS_KEY_PATH", &mut self.tls_key_path);
        apply_optional_string_override("TG_RELAY_AUTH_TOKEN", &mut self.auth_token);
        apply_socks_auth_override(
            "TG_RELAY_SOCKS_USERNAME",
            "TG_RELAY_SOCKS_PASSWORD",
            &mut self.socks_auth,
        )?;
        apply_bool_override(
            "TG_RELAY_ALLOW_PRIVATE_DESTINATIONS",
            &mut self.destination_policy.allow_private_destinations,
        )?;
        apply_u64_override(
            "TG_RELAY_HANDSHAKE_TIMEOUT_SECS",
            &mut self.handshake_timeout_secs,
        )?;
        apply_u64_override(
            "TG_RELAY_OUTBOUND_CONNECT_TIMEOUT_SECS",
            &mut self.outbound_connect_timeout_secs,
        )?;
        apply_u64_override("TG_RELAY_IDLE_TIMEOUT_SECS", &mut self.idle_timeout_secs)?;
        apply_usize_override(
            "TG_RELAY_MAX_CONCURRENT_STREAMS",
            &mut self.max_concurrent_streams,
        )?;
        apply_usize_override("TG_RELAY_MAX_HANDSHAKE_SIZE", &mut self.max_handshake_size)?;
        apply_string_override("TG_RELAY_LOG_LEVEL", &mut self.log_level);
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.listen_addr.trim().is_empty() {
            return Err(anyhow!("relay listen_addr must not be empty"));
        }
        validate_timeout("handshake_timeout_secs", self.handshake_timeout_secs)?;
        validate_timeout(
            "outbound_connect_timeout_secs",
            self.outbound_connect_timeout_secs,
        )?;
        validate_timeout("idle_timeout_secs", self.idle_timeout_secs)?;
        if self.max_concurrent_streams == 0 {
            return Err(anyhow!("max_concurrent_streams must be greater than zero"));
        }
        if self.max_handshake_size < crate::protocol::MAX_HANDSHAKE_OVERHEAD {
            return Err(anyhow!(
                "max_handshake_size must be at least {} bytes",
                crate::protocol::MAX_HANDSHAKE_OVERHEAD
            ));
        }

        validate_socks_auth(self.socks_auth.as_ref())?;
        validate_destination_policy(&self.destination_policy)?;

        match self.mode {
            RelayMode::Tunnel => {
                validate_auth_token(
                    self.auth_token
                        .as_deref()
                        .ok_or_else(|| anyhow!("auth_token is required in tunnel mode"))?,
                )?;
                if self.tls_cert_path.is_none() {
                    return Err(anyhow!("tls_cert_path is required in tunnel mode"));
                }
                if self.tls_key_path.is_none() {
                    return Err(anyhow!("tls_key_path is required in tunnel mode"));
                }
            }
            RelayMode::DirectSocks5 => {
                if self.socks_auth.is_none() {
                    return Err(anyhow!(
                        "socks_auth is required in direct_socks5 mode to avoid an open relay"
                    ));
                }
            }
            RelayMode::MtProxy => {
                let mtproxy = self
                    .mtproxy
                    .as_ref()
                    .ok_or_else(|| anyhow!("mtproxy section is required in mtproxy mode"))?;
                validate_mtproxy_config(mtproxy, &self.listen_addr)?;
            }
        }

        Ok(())
    }
}

pub fn load_local_config(path: &Path) -> Result<LocalConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read local config from {}", path.display()))?;
    let mut config: LocalConfig = toml::from_str(&contents)
        .with_context(|| format!("failed to parse local config {}", path.display()))?;
    config.apply_env_overrides()?;
    config.validate()?;
    Ok(config)
}

pub fn load_relay_config(path: &Path) -> Result<RelayConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read relay config from {}", path.display()))?;
    let mut config: RelayConfig = toml::from_str(&contents)
        .with_context(|| format!("failed to parse relay config {}", path.display()))?;
    config.apply_env_overrides()?;
    config.validate()?;
    Ok(config)
}

fn default_local_listen_addr() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_relay_listen_addr() -> String {
    "0.0.0.0:443".to_string()
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn default_connect_timeout_secs() -> u64 {
    10
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_max_concurrent_streams() -> usize {
    1024
}

fn default_max_handshake_size() -> usize {
    2048
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_telegram_proxy_config_path() -> PathBuf {
    PathBuf::from("var/telegram/proxy-multi.conf")
}

fn default_telegram_proxy_secret_path() -> PathBuf {
    PathBuf::from("var/telegram/proxy-secret")
}

fn default_official_mtproxy_stats_port() -> u16 {
    8888
}

fn default_official_mtproxy_workers() -> usize {
    0
}

fn default_telegram_refresh_interval_secs() -> u64 {
    86_400
}

fn default_telegram_proxy_config_url() -> String {
    "https://core.telegram.org/getProxyConfig".to_string()
}

fn default_telegram_proxy_secret_url() -> String {
    "https://core.telegram.org/getProxySecret".to_string()
}

fn default_true() -> bool {
    true
}

fn validate_auth_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(anyhow!("auth_token must not be empty"));
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(anyhow!("auth_token exceeds {} bytes", MAX_TOKEN_LEN));
    }
    Ok(())
}

fn validate_socks_auth(auth: Option<&SocksAuthConfig>) -> Result<()> {
    if let Some(auth) = auth {
        if auth.username.is_empty() || auth.password.is_empty() {
            return Err(anyhow!(
                "socks_auth username and password must not be empty"
            ));
        }
        if auth.username.len() > u8::MAX as usize || auth.password.len() > u8::MAX as usize {
            return Err(anyhow!(
                "socks_auth username and password must fit RFC1929 one-byte length fields"
            ));
        }
    }
    Ok(())
}

fn validate_destination_policy(policy: &DestinationPolicyConfig) -> Result<()> {
    for domain in &policy.allowed_domains {
        if domain.trim().is_empty() {
            return Err(anyhow!("allowed_domains entries must not be empty"));
        }
    }
    for suffix in &policy.allowed_domain_suffixes {
        if suffix.trim().is_empty() {
            return Err(anyhow!("allowed_domain_suffixes entries must not be empty"));
        }
    }
    Ok(())
}

fn validate_mtproxy_config(config: &MtProxyConfig, listen_addr: &str) -> Result<()> {
    let parsed_secret = parse_mtproxy_secret(&config.secret)?;

    match config.backend {
        MtProxyBackendMode::StaticDc => {
            if config.dc_endpoints.is_empty() {
                return Err(anyhow!(
                    "mtproxy.dc_endpoints must contain at least one Telegram DC mapping when backend = \"static_dc\""
                ));
            }
            for endpoint in &config.dc_endpoints {
                if endpoint.id == 0 {
                    return Err(anyhow!("mtproxy dc endpoint id must not be zero"));
                }
                if endpoint.addr.trim().is_empty() {
                    return Err(anyhow!("mtproxy dc endpoint addr must not be empty"));
                }
                if let Some(secret) = &endpoint.obfuscated_secret {
                    parse_obfuscated_secret(secret)?;
                }
            }
        }
        MtProxyBackendMode::Official => {
            let official = config.official.as_ref().ok_or_else(|| {
                anyhow!("mtproxy.official section is required when backend = \"official\"")
            })?;
            validate_official_mtproxy_config(official, listen_addr, &parsed_secret)?;
        }
    }

    Ok(())
}

fn validate_official_mtproxy_config(
    config: &OfficialMtProxyConfig,
    listen_addr: &str,
    parsed_secret: &crate::mtproxy::ParsedMtProxySecret,
) -> Result<()> {
    if config.binary_path.as_os_str().is_empty() {
        return Err(anyhow!("mtproxy.official.binary_path must not be empty"));
    }
    if config.proxy_config_path.as_os_str().is_empty() {
        return Err(anyhow!(
            "mtproxy.official.proxy_config_path must not be empty"
        ));
    }
    if config.proxy_secret_path.as_os_str().is_empty() {
        return Err(anyhow!(
            "mtproxy.official.proxy_secret_path must not be empty"
        ));
    }
    if config.stats_port == 0 {
        return Err(anyhow!("mtproxy.official.stats_port must be non-zero"));
    }
    if config.workers > 1024 {
        return Err(anyhow!(
            "mtproxy.official.workers must not exceed 1024"
        ));
    }
    if config.auto_refresh {
        validate_timeout(
            "mtproxy.official.refresh_interval_secs",
            config.refresh_interval_secs,
        )?;
    }
    if let Some(user) = &config.run_as_user {
        if user.trim().is_empty() {
            return Err(anyhow!("mtproxy.official.run_as_user must not be empty"));
        }
    }
    if let Some(proxy_tag) = &config.proxy_tag {
        validate_hex_secret("mtproxy.official.proxy_tag", proxy_tag, 16)?;
    }

    let listen: SocketAddr = listen_addr.parse().with_context(|| {
        format!(
            "mtproxy official backend requires listen_addr to be a concrete IP:port, got {listen_addr}"
        )
    })?;
    if !listen.ip().is_unspecified() {
        return Err(anyhow!(
            "mtproxy official backend requires listen_addr to use an unspecified bind address such as 0.0.0.0:443"
        ));
    }
    if listen.port() == 0 {
        return Err(anyhow!(
            "mtproxy official backend requires a non-zero listen port"
        ));
    }
    if let Some(domain) = parsed_secret.fake_tls_domain() {
        validate_fake_tls_domain_for_official_backend(domain)?;
        if config.workers > 0 {
            return Err(anyhow!(
                "mtproxy.official.workers must be 0 for ee fake-TLS mode; upstream MTProxy worker mode is not stable there"
            ));
        }
    }

    Ok(())
}

fn validate_hex_secret(name: &str, value: &str, expected_bytes: usize) -> Result<()> {
    let bytes = hex::decode(value).with_context(|| format!("{name} must be valid hex"))?;
    if bytes.len() != expected_bytes {
        return Err(anyhow!(
            "{name} must be exactly {} bytes ({} hex characters)",
            expected_bytes,
            expected_bytes * 2
        ));
    }
    Ok(())
}

fn validate_fake_tls_domain_for_official_backend(domain: &str) -> Result<()> {
    if domain.trim().is_empty() {
        return Err(anyhow!(
            "mtproxy fake-TLS secret must include a non-empty domain"
        ));
    }
    Ok(())
}

fn validate_timeout(name: &str, secs: u64) -> Result<()> {
    if secs == 0 {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(())
}

fn apply_string_override(name: &str, value: &mut String) {
    if let Ok(override_value) = env::var(name) {
        *value = override_value;
    }
}

fn apply_optional_string_override(name: &str, value: &mut Option<String>) {
    if let Ok(override_value) = env::var(name) {
        *value = Some(override_value);
    }
}

fn apply_optional_path_override(name: &str, value: &mut Option<PathBuf>) {
    if let Some(override_value) = env::var_os(name) {
        *value = Some(PathBuf::from(override_value));
    }
}

fn apply_u64_override(name: &str, value: &mut u64) -> Result<()> {
    if let Ok(override_value) = env::var(name) {
        *value = override_value
            .parse()
            .with_context(|| format!("failed to parse {name} as u64"))?;
    }
    Ok(())
}

fn apply_usize_override(name: &str, value: &mut usize) -> Result<()> {
    if let Ok(override_value) = env::var(name) {
        *value = override_value
            .parse()
            .with_context(|| format!("failed to parse {name} as usize"))?;
    }
    Ok(())
}

fn apply_bool_override(name: &str, value: &mut bool) -> Result<()> {
    if let Ok(override_value) = env::var(name) {
        *value = override_value
            .parse()
            .with_context(|| format!("failed to parse {name} as bool"))?;
    }
    Ok(())
}

fn apply_enum_override<T>(name: &str, value: &mut T) -> Result<()>
where
    T: FromStr<Err = anyhow::Error>,
{
    if let Ok(override_value) = env::var(name) {
        *value = override_value
            .parse()
            .with_context(|| format!("failed to parse {name}"))?;
    }
    Ok(())
}

fn apply_socks_auth_override(
    username_key: &str,
    password_key: &str,
    value: &mut Option<SocksAuthConfig>,
) -> Result<()> {
    let username = env::var(username_key).ok();
    let password = env::var(password_key).ok();
    match (username, password) {
        (Some(username), Some(password)) => {
            *value = Some(SocksAuthConfig { username, password });
        }
        (None, None) => {}
        _ => {
            return Err(anyhow!(
                "set both {username_key} and {password_key} or neither"
            ));
        }
    }
    Ok(())
}

fn apply_dns_mode_override(name: &str, value: &mut DnsMode) -> Result<()> {
    if let Ok(override_value) = env::var(name) {
        *value = override_value
            .parse()
            .with_context(|| format!("failed to parse {name} as dns mode"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_relay_config, MtProxyBackendMode};
    use std::fs;

    #[test]
    fn official_mtproxy_backend_accepts_missing_dc_endpoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.toml");
        fs::write(
            &config_path,
            r#"
listen_addr = "0.0.0.0:443"
mode = "mtproxy"

[mtproxy]
secret = "dd00112233445566778899aabbccddeeff"
backend = "official"

[mtproxy.official]
binary_path = "/opt/MTProxy/objs/bin/mtproto-proxy"
"#,
        )
        .expect("write config");

        let config = load_relay_config(&config_path).expect("config");
        let mtproxy = config.mtproxy.expect("mtproxy");
        assert_eq!(mtproxy.backend, MtProxyBackendMode::Official);
        assert!(mtproxy.dc_endpoints.is_empty());
    }

    #[test]
    fn static_mtproxy_backend_requires_dc_endpoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.toml");
        fs::write(
            &config_path,
            r#"
listen_addr = "0.0.0.0:443"
mode = "mtproxy"

[mtproxy]
secret = "dd00112233445566778899aabbccddeeff"
backend = "static_dc"
"#,
        )
        .expect("write config");

        let error = load_relay_config(&config_path).expect_err("missing dc_endpoints");
        assert!(
            error
                .to_string()
                .contains("mtproxy.dc_endpoints must contain at least one Telegram DC mapping")
        );
    }

    #[test]
    fn official_fake_tls_backend_rejects_workers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("relay.toml");
        fs::write(
            &config_path,
            r#"
listen_addr = "0.0.0.0:443"
mode = "mtproxy"

[mtproxy]
secret = "ee00112233445566778899aabbccddeeff7777772e74656c656772616d2e6f7267"
backend = "official"

[mtproxy.official]
binary_path = "/opt/MTProxy/objs/bin/mtproto-proxy"
workers = 1
"#,
        )
        .expect("write config");

        let error = load_relay_config(&config_path).expect_err("workers in ee mode");
        assert!(
            error
                .to_string()
                .contains("mtproxy.official.workers must be 0 for ee fake-TLS mode")
        );
    }
}
