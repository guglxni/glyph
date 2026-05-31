//! WS-5 — mTLS listener integration test.
//!
//! Acceptance:
//! - Connection with valid client cert succeeds.
//! - Connection without a client cert fails (TLS handshake rejected).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use glyph_tee_worker::mtls::MtlsListener;

/// Mint a CA + (server cert signed by CA) + (client cert signed by CA).
/// Returns paths to the PEM files in a tempdir kept alive by the caller.
struct Certs {
    _dir: tempfile::TempDir,
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_der: CertificateDer<'static>,
    client_key_der: PrivateKeyDer<'static>,
    ca_cert_der: CertificateDer<'static>,
}

fn mint_certs() -> Certs {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let dir = tempfile::tempdir().unwrap();

    // CA
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "GLYPH Test Root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_kp = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let ca_pem_str = ca_cert.pem();

    // Server
    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let srv_kp = KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_kp, &ca_cert, &ca_kp).unwrap();
    let srv_cert_pem = srv_cert.pem();
    let srv_key_pem = srv_kp.serialize_pem();

    // Client
    let mut cli_params = CertificateParams::new(vec!["client.test".to_string()]).unwrap();
    cli_params
        .distinguished_name
        .push(DnType::CommonName, "client.test");
    let cli_kp = KeyPair::generate().unwrap();
    let cli_cert = cli_params.signed_by(&cli_kp, &ca_cert, &ca_kp).unwrap();

    // Write PEM files
    let ca_path = dir.path().join("ca.pem");
    let server_cert_path = dir.path().join("server.crt");
    let server_key_path = dir.path().join("server.key");
    std::fs::write(&ca_path, ca_pem_str.as_bytes()).unwrap();
    std::fs::write(&server_cert_path, srv_cert_pem.as_bytes()).unwrap();
    std::fs::write(&server_key_path, srv_key_pem.as_bytes()).unwrap();

    let client_cert_der = CertificateDer::from(cli_cert.der().to_vec());
    let client_key_der = PrivateKeyDer::Pkcs8(cli_kp.serialize_der().into());
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    Certs {
        _dir: dir,
        ca_pem: ca_path.to_string_lossy().to_string(),
        server_cert_pem: server_cert_path.to_string_lossy().to_string(),
        server_key_pem: server_key_path.to_string_lossy().to_string(),
        client_cert_der,
        client_key_der,
        ca_cert_der,
    }
}

async fn spawn_listener(certs: &Certs) -> (Arc<MtlsListener>, u16) {
    let listener = MtlsListener::new(
        "127.0.0.1:0",
        &certs.server_cert_pem,
        &certs.server_key_pem,
        &certs.ca_pem,
    )
    .await
    .expect("listener must start");
    let port = listener.local_addr.port();
    let l = Arc::new(listener);

    let echo = Arc::clone(&l);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept_tls().await {
            let _ = stream.write_all(b"GLYPH-OK").await;
            let _ = stream.shutdown().await;
        }
    });
    (l, port)
}

#[tokio::test]
async fn valid_client_cert_succeeds() {
    let certs = mint_certs();
    let (_listener, port) = spawn_listener(&certs).await;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_cert_der.clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![certs.client_cert_der.clone()],
            certs.client_key_der.clone_key(),
        )
        .expect("client config with cert");
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .expect("handshake within timeout")
        .expect("handshake must succeed with valid client cert");
    let mut buf = [0u8; 8];
    tls.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"GLYPH-OK");
}

#[tokio::test]
async fn missing_client_cert_fails() {
    let certs = mint_certs();
    let (_listener, port) = spawn_listener(&certs).await;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_cert_der.clone()).unwrap();
    // NOTE: no client cert configured.
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let res =
        tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await;
    // The handshake either errors out or, depending on rustls version, gives
    // us a stream whose first read returns CertificateRequired. Either is a
    // valid rejection.
    match res {
        Ok(Ok(mut tls)) => {
            let mut buf = [0u8; 1];
            let r = tls.read(&mut buf).await;
            assert!(
                r.is_err() || r.unwrap() == 0,
                "missing client cert must not yield bytes from server"
            );
        }
        Ok(Err(_)) => {
            // Handshake error — acceptable.
        }
        Err(_) => panic!("test timed out — handshake should fail quickly"),
    }
    // suppress unused warning on stderr writer
    let _ = std::io::stderr().flush();
}
