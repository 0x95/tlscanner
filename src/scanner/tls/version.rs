use strum_macros::{EnumIter, IntoStaticStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter, IntoStaticStr)]
#[repr(u16)]
pub enum TlsVersion {
    #[strum(serialize = "SSL 2.0")]
    Ssl20 = 0x0200,
    #[strum(serialize = "SSL 3.0")]
    Ssl30 = 0x0300,
    #[strum(serialize = "TLS 1.0")]
    Tls10 = 0x0301,
    #[strum(serialize = "TLS 1.1")]
    Tls11 = 0x0302,
    #[strum(serialize = "TLS 1.2")]
    Tls12 = 0x0303,
    #[strum(serialize = "TLS 1.3")]
    Tls13 = 0x0304,
}

impl TlsVersion {
    pub fn name(self) -> &'static str {
        self.into()
    }

    pub fn legacy_wire(self) -> u16 {
        match self {
            TlsVersion::Tls13 => TlsVersion::Tls12 as u16,
            v => v as u16,
        }
    }
}
