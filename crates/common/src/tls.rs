use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use webpki_roots::TLS_SERVER_ROOTS;

pub fn load_client_config(ca_cert_path: Option<&Path>) -> Result<ClientConfig> {
    install_rustls_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = ca_cert_path {
        for certificate in load_certificates(path)? {
            roots.add(certificate).map_err(|error| {
                anyhow!("failed to add CA certificate {}: {error}", path.display())
            })?;
        }
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"tg-relay/1".to_vec()];
    Ok(config)
}

pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    install_rustls_provider();
    let certificates = load_certificates(cert_path)?;
    let private_key = load_private_key(key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("failed to build rustls server config")?;
    config.alpn_protocols = vec![b"tg-relay/1".to_vec()];
    Ok(config)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open certificate {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open private key {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("no supported private key found in {}", path.display()))
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
