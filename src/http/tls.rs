//! TLS support: client configuration and an explicit opt-in insecure verifier.

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    /// Accept any certificate. Required for scanning self-signed targets and
    /// for the proxy's own MITM certificate.
    pub insecure: bool,
    /// Additional trust anchors (DER), e.g. a proxy CA.
    pub extra_roots: Vec<CertificateDer<'static>>,
}

pub fn client_config(opts: &TlsOptions) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    if opts.insecure {
        let verifier = Arc::new(NoCertificateVerification {
            provider: provider.clone(),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol configuration failed")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in &opts.extra_roots {
        roots
            .add(cert.clone())
            .context("failed to add extra trust anchor")?;
    }
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol configuration failed")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn load_certs_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("cannot open certificate '{}'", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.with_context(|| format!("cannot parse certificate '{}'", path.display()))
}

pub fn load_private_key_pem(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("cannot open private key '{}'", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("cannot parse private key '{}'", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in '{}'", path.display()))
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name '{host}'"))
}

#[derive(Debug)]
struct NoCertificateVerification {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl fmt::Display for TlsOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.insecure {
            write!(f, "insecure")
        } else {
            write!(f, "verified")
        }
    }
}
