use std::net::SocketAddr;
use std::sync::LazyLock;

use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};

use anyhow::Result;
use anyhow::anyhow;

const CONNECT_ATTEMPTS: u32 = 3;

static MOZILLA_ROOTS_PEM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cacert.pem"));

static MOZILLA_ROOTS: LazyLock<Vec<X509>> = LazyLock::new(|| {
    X509::stack_from_pem(MOZILLA_ROOTS_PEM).expect("bundled cacert.pem is invalid")
});

use crate::scanner::utils;

pub struct Certificate {
    pub cert: X509,
    pub secure: bool,
}

impl Certificate {
    pub fn fetch(sni: &str, addr: &SocketAddr) -> Result<Self> {
        match fetch_with_verify(sni, addr, true) {
            Ok(cert) => Ok(Self { cert, secure: true }),
            Err(_) => {
                let cert = fetch_with_verify(sni, addr, false)?;
                Ok(Self {
                    cert,
                    secure: false,
                })
            }
        }
    }
}

fn fetch_with_verify(sni: &str, addr: &SocketAddr, verify: bool) -> Result<X509> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1))?;
    if verify {
        builder.set_cert_store(mozilla_store()?);
    } else {
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_security_level(0);
        builder.set_cipher_list("ALL:@SECLEVEL=0")?;
    }
    let connector = builder.build();

    utils::retry(CONNECT_ATTEMPTS, || {
        let stream = utils::connect(addr)?;
        let mut sslconnector = connector
            .configure()
            .map_err(|e| utils::RetryError::Definitive(e.into()))?;
        sslconnector.set_use_server_name_indication(true);
        sslconnector.set_verify_hostname(verify);
        let ssl_conn = sslconnector
            .connect(sni, stream)
            .map_err(|e| utils::RetryError::Definitive(anyhow!("{e}")))?;
        ssl_conn
            .ssl()
            .peer_certificate()
            .ok_or_else(|| utils::RetryError::Definitive(anyhow!("failed to fetch cert")))
    })
}

fn mozilla_store() -> Result<X509Store> {
    let mut b = X509StoreBuilder::new()?;
    for cert in MOZILLA_ROOTS.iter() {
        b.add_cert(cert.clone())?;
    }
    Ok(b.build())
}
