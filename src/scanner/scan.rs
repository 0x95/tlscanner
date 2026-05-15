use std::{
    fmt::{self, Display},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
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
    utils,
};

const PROBE_ATTEMPTS: u32 = 3;

enum ProbeError {
    Transient(anyhow::Error),
    Definitive(anyhow::Error),
}

impl From<std::io::Error> for ProbeError {
    fn from(e: std::io::Error) -> Self {
        ProbeError::Transient(e.into())
    }
}

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
        let results = tls::version::TlsVersion::iter()
            .rev()
            .filter(|v| *v >= TlsVersion::Tls10)
            .map(|v| (v, probe_version(self.sni, &self.addr, v)))
            .collect();
        Ok(TlsScanResults {
            results,
            certificate: Certificate::fetch(self.sni, &self.addr)?,
        })
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

fn probe_version(
    sni: &str,
    addr: &SocketAddr,
    version: TlsVersion,
) -> Option<Vec<&'static CipherSuite>> {
    let mut remaining = super::tls::cipher_suite::offerable_codes_for_version(version);
    let mut accepted: Vec<&'static CipherSuite> = Vec::new();

    while !remaining.is_empty() {
        let Ok(cipher) = probe_with_retry(sni, addr, version, &remaining) else {
            break;
        };
        // force the server to pick a different cipher next round.
        if let Some(pos) = remaining.iter().position(|c| *c == cipher.code) {
            remaining.swap_remove(pos);
        }
        accepted.push(cipher);
    }

    (!accepted.is_empty()).then_some(accepted)
}

fn probe_with_retry(
    sni: &str,
    addr: &SocketAddr,
    version: TlsVersion,
    ciphers: &[u16],
) -> Result<&'static CipherSuite> {
    let mut last_err: Option<anyhow::Error> = None;
    for i in 0..PROBE_ATTEMPTS {
        match probe_once(sni, addr, version, ciphers) {
            Ok(c) => return Ok(c),
            Err(ProbeError::Definitive(e)) => return Err(e),
            Err(ProbeError::Transient(e)) => {
                last_err = Some(e);
                if i + 1 < PROBE_ATTEMPTS {
                    thread::sleep(utils::BACKOFF_STEP * (i + 1));
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("probe failed after {PROBE_ATTEMPTS} attempts")))
}

fn probe_once(
    sni: &str,
    addr: &SocketAddr,
    version: TlsVersion,
    ciphers: &[u16],
) -> Result<&'static CipherSuite, ProbeError> {
    let mut stream = TcpStream::connect_timeout(addr, utils::SOCKET_TIMEOUT)?;
    stream.set_read_timeout(Some(utils::SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(utils::SOCKET_TIMEOUT))?;

    let payload = TLSClientHello::new(sni, version, ciphers)
        .build_tls_payload()
        .map_err(ProbeError::Definitive)?;
    stream.write_all(&payload)?;
    read_server_hello(&mut stream)
}

fn read_server_hello(stream: &mut TcpStream) -> Result<&'static CipherSuite, ProbeError> {
    let mut tmp = [0u8; 1024];
    let mut buf = Vec::with_capacity(1024);

    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(ProbeError::Transient(anyhow!("server closed connection")));
        }
        buf.extend_from_slice(&tmp[..n]);

        match parse_tls_plaintext(&buf) {
            Ok((_, TlsPlaintext { hdr, msg })) => {
                if hdr.record_type == TlsRecordType::Alert {
                    return Err(ProbeError::Definitive(anyhow!("server sent alert")));
                }
                return msg
                    .iter()
                    .find_map(|m| match m {
                        TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                            super::tls::cipher_suite::by_code(sh.cipher.0)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| ProbeError::Transient(anyhow!("no ServerHello in response")));
            }
            Err(nom::Err::Incomplete(_)) => continue,
            Err(e) => return Err(ProbeError::Transient(anyhow!("parse error: {e}"))),
        }
    }
}
