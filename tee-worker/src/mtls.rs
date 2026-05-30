//! mTLS listener for the worker intake socket (closes T18, T19).
//!
//! The production worker accepts intents only from clients that present a
//! valid client certificate signed by the configured CA. Server identity is
//! pinned by the operator-supplied server cert + key. We use `tokio-rustls`
//! on top of `tokio::net::TcpListener` so the rest of `main.rs::handle_connection`
//! can keep using `AsyncRead`/`AsyncWrite` over the wrapped stream without
//! caring that TLS is in front of it.

use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A bound TCP listener pre-wrapped with a rustls `TlsAcceptor`. Callers
/// `listener.accept()` then `acceptor.accept(stream)` to upgrade each
/// connection. The `acceptor` is exposed as `Arc` so it can be cheaply
/// cloned per-connection.
pub struct MtlsListener {
    pub listener: TcpListener,
    pub acceptor: Arc<TlsAcceptor>,
    pub local_addr: SocketAddr,
}

impl MtlsListener {
    /// Bind a TCP listener at `addr` and configure rustls to:
    /// - serve with `server_cert_pem` + `server_key_pem`,
    /// - require + verify a client cert signed by `client_ca_pem`.
    ///
    /// `addr`, `server_cert_pem`, `server_key_pem`, `client_ca_pem` are all
    /// filesystem paths to PEM files.
    pub async fn new(
        addr: &str,
        server_cert_pem: &str,
        server_key_pem: &str,
        client_ca_pem: &str,
    ) -> Result<Self> {
        // rustls requires a crypto provider be installed before any TLS work.
        // `aws_lc_rs` is the default provider in rustls 0.23; install it once
        // and ignore the "already installed" error path. (`process_default()`
        // returns Err if a provider was already installed — that's benign.)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let server_certs = load_certs(server_cert_pem)
            .with_context(|| format!("loading server cert from {}", server_cert_pem))?;
        let server_key = load_private_key(server_key_pem)
            .with_context(|| format!("loading server key from {}", server_key_pem))?;
        let client_ca_certs = load_certs(client_ca_pem)
            .with_context(|| format!("loading client CA from {}", client_ca_pem))?;

        let mut roots = RootCertStore::empty();
        for cert in client_ca_certs {
            roots
                .add(cert)
                .map_err(|e| anyhow!("failed to add client CA cert: {e}"))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow!("failed to build client verifier: {e}"))?;

        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, server_key)
            .map_err(|e| anyhow!("failed to build TLS server config: {e}"))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed binding mTLS listener at {addr}"))?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            acceptor: Arc::new(acceptor),
            local_addr,
        })
    }

    /// Accept the next plain TCP connection and upgrade it to TLS. Returns
    /// `Err` if either accept or the TLS handshake fails (the caller should
    /// log + drop the connection — never proceed without a valid cert).
    pub async fn accept_tls(&self) -> Result<(TlsStream<TcpStream>, SocketAddr)> {
        let (stream, peer) = self
            .listener
            .accept()
            .await
            .context("tcp accept failed before TLS handshake")?;
        let acceptor = Arc::clone(&self.acceptor);
        let tls = acceptor
            .accept(stream)
            .await
            .with_context(|| format!("TLS handshake failed for peer {peer}"))?;
        Ok((tls, peer))
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).with_context(|| format!("opening {path}"))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parsing PEM certs from {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("opening {path}"))?;
    let mut reader = BufReader::new(file);
    // Try PKCS8 first, then RSA, then SEC1.
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .transpose()
        .with_context(|| format!("parsing PKCS8 from {path}"))?
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    let file = fs::File::open(path).with_context(|| format!("re-opening {path}"))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .next()
        .transpose()
        .with_context(|| format!("parsing RSA from {path}"))?
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }
    let file = fs::File::open(path).with_context(|| format!("re-opening {path}"))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)
        .next()
        .transpose()
        .with_context(|| format!("parsing EC from {path}"))?
    {
        return Ok(PrivateKeyDer::Sec1(key));
    }
    anyhow::bail!("no private key found in {path}")
}
