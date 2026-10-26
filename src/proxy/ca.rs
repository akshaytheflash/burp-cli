//! Certificate authority used for TLS interception.
//!
//! A private CA is generated on first use and stored in the project directory.
//! Leaf certificates for intercepted hosts are generated and cached in memory.
//! The CA is only trusted by clients that explicitly install
//! `ca/burpcli-ca.pem`.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct CertificateAuthority {
    cert: Certificate,
    key: KeyPair,
    pem: String,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// Load the project CA, creating one when it does not exist yet.
    pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self> {
        if cert_path.exists() && key_path.exists() {
            return Self::load(cert_path, key_path);
        }
        let key = KeyPair::generate().context("cannot generate CA key")?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "burpcli interception CA");
        name.push(DnType::OrganizationName, "burpcli");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params
            .self_signed(&key)
            .context("cannot create CA certificate")?;
        let pem = cert.pem();
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create CA directory '{}'", parent.display()))?;
        }
        crate::config::atomic_write(cert_path, pem.as_bytes())?;
        crate::config::atomic_write(key_path, key.serialize_pem().as_bytes())?;
        Ok(Self {
            cert,
            key,
            pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("cannot read CA certificate '{}'", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("cannot read CA key '{}'", key_path.display()))?;
        let key = KeyPair::from_pem(&key_pem).context("cannot parse CA private key")?;
        // Reconstruct an in-memory certificate object from the stored PEM. The
        // key pair is unchanged, so leaf certificates remain valid.
        let params =
            CertificateParams::from_ca_cert_pem(&pem).context("cannot parse CA certificate")?;
        let cert = params
            .self_signed(&key)
            .context("cannot rebuild CA certificate")?;
        Ok(Self {
            cert,
            key,
            pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// Server configuration presenting a certificate for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        if let Some(config) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&host)
        {
            return Ok(config.clone());
        }

        let leaf_key = KeyPair::generate().context("cannot generate leaf key")?;
        let mut params = CertificateParams::new(vec![host.clone()])
            .with_context(|| format!("invalid certificate name '{host}'"))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host.clone());
        name.push(DnType::OrganizationName, "burpcli");
        params.distinguished_name = name;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .context("cannot sign leaf certificate")?;

        let cert_chain = vec![CertificateDer::from(leaf.der().to_vec())];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS server configuration failed")?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("cannot build TLS server configuration")?;
        let config = Arc::new(config);
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host, config.clone());
        Ok(config)
    }

    /// Number of cached host certificates (used by tests and `proxy ca info`).
    pub fn cached_hosts(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Export the CA certificate so it can be installed in a browser or OS.
    pub fn export(&self, path: &Path) -> Result<()> {
        crate::config::atomic_write(path, self.pem.as_bytes())
    }

    pub fn paths(project: &crate::storage::Project) -> (PathBuf, PathBuf) {
        (project.ca_cert_path(), project.ca_key_path())
    }

    pub fn from_project(project: &crate::storage::Project) -> Result<Self> {
        let (cert, key) = Self::paths(project);
        Self::load_or_create(&cert, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reloads_ca() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("ca.pem");
        let key = dir.path().join("ca.key");
        let ca = CertificateAuthority::load_or_create(&cert, &key).unwrap();
        assert!(ca.pem().contains("BEGIN CERTIFICATE"));
        assert!(cert.exists() && key.exists());
        let reloaded = CertificateAuthority::load(&cert, &key).unwrap();
        assert_eq!(reloaded.pem().trim(), ca.pem().trim());
    }

    #[test]
    fn issues_and_caches_leaf_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(
            &dir.path().join("ca.pem"),
            &dir.path().join("ca.key"),
        )
        .unwrap();
        let first = ca.server_config("example.com").unwrap();
        let second = ca.server_config("example.com").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(ca.cached_hosts(), 1);
        let third = ca.server_config("127.0.0.1").unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(ca.cached_hosts(), 2);
    }
}
