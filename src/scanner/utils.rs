use std::{
    fmt, io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::Duration,
};

use std::fmt::Write;

use anyhow::{Result, anyhow};

pub(super) const SOCKET_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) const BACKOFF_STEP: Duration = Duration::from_millis(200);

pub(super) fn with_u16_length<T>(buf: &mut Vec<u8>, f: T) -> Result<()>
where
    T: FnOnce(&mut Vec<u8>) -> Result<()>,
{
    let off = buf.len();
    buf.extend_from_slice(&[0, 0]);
    f(buf)?;
    let len = (buf.len() - off - 2) as u16;
    buf[off..off + 2].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

pub(super) fn resolve(host: &str) -> (&str, SocketAddr) {
    match host.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(addr) => {
            let domain = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
            (domain, addr)
        }
        None => {
            let addr = (host, 443u16)
                .to_socket_addrs()
                .expect("failed to resolve host")
                .next()
                .expect("no addresses returned");
            (host, addr)
        }
    }
}

pub(super) fn retry_connect(addr: &SocketAddr, attempts: u32) -> Result<TcpStream> {
    retry(attempts, || {
        let stream = TcpStream::connect_timeout(addr, SOCKET_TIMEOUT)?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        Ok(stream)
    })
}

fn retry<T, F>(attempts: u32, mut op: F) -> Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    let mut last_err: Option<io::Error> = None;
    for i in 0..attempts {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if i + 1 < attempts {
                    thread::sleep(BACKOFF_STEP * (i + 1));
                }
            }
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("operation failed after {attempts} attempts")))
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(super) struct Indented<'a> {
    inner: &'a mut dyn Write,
    indent: &'static str,
    at_line_start: bool,
}

impl<'a> Write for Indented<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for (i, line) in s.split('\n').enumerate() {
            if i > 0 {
                self.inner.write_char('\n')?;
                self.at_line_start = true;
            }
            if !line.is_empty() {
                if self.at_line_start {
                    self.inner.write_str(self.indent)?;
                    self.at_line_start = false;
                }
                self.inner.write_str(line)?;
            }
        }
        Ok(())
    }
}

pub(super) fn indent<'a, W: Write>(w: &'a mut W, prefix: &'static str) -> Indented<'a> {
    Indented {
        inner: w,
        indent: prefix,
        at_line_start: true,
    }
}
