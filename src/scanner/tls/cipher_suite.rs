use std::fmt::Display;

use console::Style;

use super::ciphers;
use super::version::TlsVersion;

const NEVER_OFFER: &[u16] = &[
    0x0000, // TLS_NULL_WITH_NULL_NULL
    0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    0x5600, // TLS_FALLBACK_SCSV
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Security {
    Insecure,
    Weak,
    Secure,
    Recommended,
}

impl Security {
    fn as_color(&self) -> Style {
        match self {
            Security::Secure | Security::Recommended => Style::new().green(),
            Security::Weak => Style::new().yellow(),
            Security::Insecure => Style::new().red(),
        }
    }
}

impl Display for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Security::Insecure => "insecure",
            Security::Weak => "weak",
            Security::Secure => "secure",
            Security::Recommended => "recommended",
        };
        f.write_str(s)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    pub code: u16,
    pub iana_name: &'static str,
    pub openssl_name: &'static str,
    pub gnutls_name: &'static str,
    pub protocol_version: &'static str,
    pub kex_algorithm: &'static str,
    pub auth_algorithm: &'static str,
    pub enc_algorithm: &'static str,
    pub hash_algorithm: &'static str,
    pub security: Security,
    pub tls_versions: &'static [TlsVersion],
}

impl CipherSuite {
    #[inline]
    pub fn is_offerable(&self) -> bool {
        !NEVER_OFFER.contains(&self.code)
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{} (0x{:04x}) {}", self.iana_name, self.code, self.security);
        let styled = self.security.as_color().apply_to(s);
        write!(f, "{}", styled)?;
        Ok(())
    }
}

pub fn by_code(code: u16) -> Option<&'static CipherSuite> {
    ciphers::BY_CODE.get(&code).map(|&i| &ciphers::ALL[i])
}

pub fn by_version(v: TlsVersion) -> impl Iterator<Item = &'static CipherSuite> {
    let idxs: &'static [usize] = match v {
        TlsVersion::Ssl20 => ciphers::INDICES_SSL20,
        TlsVersion::Ssl30 => ciphers::INDICES_SSL30,
        TlsVersion::Tls10 => ciphers::INDICES_TLS10,
        TlsVersion::Tls11 => ciphers::INDICES_TLS11,
        TlsVersion::Tls12 => ciphers::INDICES_TLS12,
        TlsVersion::Tls13 => ciphers::INDICES_TLS13,
    };
    idxs.iter().map(|&i| &ciphers::ALL[i])
}

pub fn offerable_codes_for_version(v: TlsVersion) -> Vec<u16> {
    by_version(v)
        .filter(|c| c.is_offerable())
        .map(|c| c.code)
        .collect()
}
