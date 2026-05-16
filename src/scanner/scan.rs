use std::{
    fmt::{self, Display},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
};

use anyhow::{Result, anyhow};
use strum::IntoEnumIterator;
use tls_parser::{
    TlsMessage, TlsMessageHandshake, TlsPlaintext, TlsRecordType, nom, parse_tls_plaintext,
};

use std::fmt::Write as FmtWrite;

use crate::scanner::{
    cert::certificate::Certificate,
    tls::{self, CipherSuite, TlsVersion, clienthello::TLSClientHello},
    utils::{self, RetryError},
};

type VersionResult = (TlsVersion, Option<Vec<&'static CipherSuite>>);

pub struct TlsScanResults {
    results: Vec<VersionResult>,
    certificate: Certificate,
}

pub struct TlsScan<'a> {
    sni: &'a str,
    addr: SocketAddr,
}

impl<'a> TlsScan<'a> {
    pub fn new(host: &'a str) -> Self {
        let (sni, addr) = utils::resolve(host);
        Self { sni, addr }
    }

    pub fn run(&self) -> Result<TlsScanResults> {
        let results = TlsVersion::iter()
            .rev()
            .filter(|v| *v >= TlsVersion::Tls10)
            .map(|v| (v, Probe::new(self.sni, self.addr, v).accepted_ciphers()))
            .collect();
        Ok(TlsScanResults {
            results,
            certificate: Certificate::fetch(self.sni, &self.addr)?,
        })
    }
}

struct Probe<'a> {
    sni: &'a str,
    addr: SocketAddr,
    version: TlsVersion,
}

impl<'a> Probe<'a> {
    const MAX_ATTEMPTS: u32 = 3;

    fn new(sni: &'a str, addr: SocketAddr, version: TlsVersion) -> Self {
        Self { sni, addr, version }
    }

    fn accepted_ciphers(&mut self) -> Option<Vec<&'static CipherSuite>> {
        let mut remaining = tls::cipher_suite::offerable_codes_for_version(self.version);
        let mut accepted: Vec<&'static CipherSuite> = Vec::new();

        while !remaining.is_empty() {
            let Ok(cipher) = utils::retry(Self::MAX_ATTEMPTS, || self.send_hello(&remaining))
            else {
                break;
            };
            if let Some(pos) = remaining.iter().position(|c| *c == cipher.code) {
                remaining.swap_remove(pos);
            }
            accepted.push(cipher);
        }

        (!accepted.is_empty()).then_some(accepted)
    }

    fn send_hello(&self, ciphers: &[u16]) -> Result<&'static CipherSuite, RetryError> {
        let mut stream = utils::connect(&self.addr)?;
        let payload = TLSClientHello::new(self.sni, self.version, ciphers)
            .build_tls_payload()
            .map_err(RetryError::Definitive)?;
        stream.write_all(&payload)?;
        read_server_hello(&mut stream)
    }
}

impl Display for TlsScanResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "certificate:")?;
        {
            let mut i = utils::indent(f, "   ");
            write!(i, "{}", self.certificate)?;
        }

        writeln!(f)?;
        writeln!(f, "protocols:")?;
        {
            let mut i = utils::indent(f, "   ");
            for (v, ciphers) in &self.results {
                writeln!(i, "{}: {}", v.name(), ciphers.is_some())?;
            }
        }

        writeln!(f)?;
        writeln!(f, "cipher suites:")?;
        {
            let mut i1 = utils::indent(f, "   ");
            for (v, ciphers) in &self.results {
                let Some(ciphers) = ciphers else { continue };
                writeln!(i1, "# {}", v.name())?;
                for c in ciphers {
                    let mut i2 = utils::indent(&mut i1, "   ");
                    writeln!(i2, "{c}")?;
                }
            }
        }

        Ok(())
    }
}

fn read_server_hello(stream: &mut TcpStream) -> Result<&'static CipherSuite, RetryError> {
    let mut tmp = [0u8; 1024];
    let mut buf = Vec::with_capacity(1024);

    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(RetryError::Transient(anyhow!("server closed connection")));
        }
        buf.extend_from_slice(&tmp[..n]);

        match parse_tls_plaintext(&buf) {
            Ok((_, TlsPlaintext { hdr, msg })) => {
                if hdr.record_type == TlsRecordType::Alert {
                    return Err(RetryError::Definitive(anyhow!("server sent alert")));
                }
                return msg
                    .iter()
                    .find_map(|m| match m {
                        TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                            tls::cipher_suite::by_code(sh.cipher.0)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| RetryError::Transient(anyhow!("no ServerHello in response")));
            }
            Err(nom::Err::Incomplete(_)) => continue,
            Err(e) => return Err(RetryError::Transient(anyhow!("parse error: {e}"))),
        }
    }
}
