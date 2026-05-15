use anyhow::Result;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::scanner::{tls::TlsVersion, utils};

pub struct TLSClientHello<'a> {
    sni: &'a str,
    version: TlsVersion,
    ciphers: &'a [u16],
    pubkey: Option<PublicKey>,
}

impl<'a> TLSClientHello<'a> {
    pub fn new(sni: &'a str, version: TlsVersion, ciphers: &'a [u16]) -> Self {
        let pubkey = match version {
            TlsVersion::Tls13 => {
                let secret = EphemeralSecret::random();
                Some(PublicKey::from(&secret))
            }
            _ => None,
        };
        Self {
            sni,
            version,
            ciphers,
            pubkey,
        }
    }

    pub fn build_tls_payload(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(512);

        // record header
        payload.push(0x16);
        // yes this one should always be tls 1.0 (0x0301)
        payload.extend_from_slice(&(TlsVersion::Tls10 as u16).to_be_bytes());
        let record_len_offset = payload.len();
        payload.extend_from_slice(&[0, 0]); // record length placeholder

        // handshake header
        payload.push(0x01); // client_hello
        let handshake_len_offset = payload.len();
        payload.extend_from_slice(&[0, 0, 0]); // handshake length placeholder (24-bit)

        let body_start = payload.len();
        self.write_tls_body(&mut payload)?;
        let body_len = payload.len() - body_start;

        // update lengths
        let record_len = (body_len + 4) as u16;
        payload[record_len_offset..record_len_offset + 2]
            .copy_from_slice(&record_len.to_be_bytes());

        let hs_len = body_len as u32;
        payload[handshake_len_offset] = (hs_len >> 16) as u8;
        payload[handshake_len_offset + 1] = (hs_len >> 8) as u8;
        payload[handshake_len_offset + 2] = hs_len as u8;

        Ok(payload)
    }

    fn write_tls_body(&self, body: &mut Vec<u8>) -> Result<()> {
        body.extend_from_slice(&self.version.legacy_wire().to_be_bytes());

        // random: 32 bytes.
        let random = [0x42u8; 32];
        body.extend_from_slice(&random);

        // session_id length + session_id
        if self.version == TlsVersion::Tls13 {
            body.push(0x20); // 32 bytes
            let mut session_id = [0u8; 32];
            rand::fill(&mut session_id);
            body.extend_from_slice(&session_id);
        } else {
            body.push(0x00);
        }

        // cipher_suites: list of u16
        utils::with_u16_length(body, |b| {
            self.ciphers
                .iter()
                .for_each(|cs| b.extend_from_slice(&cs.to_be_bytes()));
            Ok(())
        })?;

        // compression length
        body.push(0x01);
        // compression - null compression
        body.push(0x00);

        // extensions
        utils::with_u16_length(body, |b| {
            Extension::server_name(self.sni).write_to(b);
            Extension::extended_master_secret().write_to(b);
            Extension::renegotiation_info().write_to(b);
            Extension::supported_groups().write_to(b);
            Extension::status_request().write_to(b);

            match self.version {
                TlsVersion::Tls12 => {
                    Extension::ec_point_formats().write_to(b);
                    Extension::encrypt_then_mac().write_to(b);
                    Extension::session_ticket().write_to(b);
                    Extension::signature_algorithms().write_to(b);
                }
                TlsVersion::Tls13 => {
                    Extension::signature_algorithms().write_to(b);
                    Extension::supported_versions_13().write_to(b);
                    Extension::psk_key_exchange_modes().write_to(b);
                    Extension::key_share(self.pubkey.unwrap()).write_to(b);
                }
                _ => {
                    // TLS 1.0 / 1.1: no signature_algorithms (1.2+ only)
                    Extension::ec_point_formats().write_to(b);
                    Extension::session_ticket().write_to(b);
                }
            }
            Ok(())
        })?;

        Ok(())
    }
}

struct Extension {
    ty: u16,
    data: Vec<u8>,
}

impl Extension {
    fn server_name(host: &str) -> Self {
        let host_len = host.len() as u16;
        // entry = 1 (name_type) + 2 (host_len) + host bytes
        let entry_len = 1 + 2 + host_len;
        let mut data = Vec::with_capacity(2 + entry_len as usize);
        data.extend_from_slice(&entry_len.to_be_bytes()); // list_length
        data.push(0x00); // name_type = host_name
        data.extend_from_slice(&host_len.to_be_bytes()); // host_name_length
        data.extend_from_slice(host.as_bytes()); // host_name
        Self { ty: 0x0000, data }
    }

    fn supported_groups() -> Self {
        const GROUPS: [u16; 10] = [
            0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
        ];
        let groups_len = (GROUPS.len() * 2) as u16;
        let mut data = Vec::with_capacity(2 + groups_len as usize);
        data.extend_from_slice(&groups_len.to_be_bytes());
        GROUPS
            .iter()
            .for_each(|g| data.extend_from_slice(&g.to_be_bytes()));
        Self { ty: 0x000a, data }
    }

    fn ec_point_formats() -> Self {
        Self {
            ty: 0x000b,
            data: Vec::from([0x01, 0x00]), // len 01, value 00 - uncompressed
        }
    }

    fn extended_master_secret() -> Self {
        Self {
            ty: 0x0017,
            data: Vec::new(),
        }
    }

    fn renegotiation_info() -> Self {
        Self {
            ty: 0xff01,
            data: Vec::from([0x00]),
        }
    }

    fn encrypt_then_mac() -> Self {
        Self {
            ty: 0x0016,
            data: Vec::new(),
        }
    }

    fn session_ticket() -> Self {
        Self {
            ty: 0x0023,
            data: Vec::new(),
        }
    }

    fn status_request() -> Self {
        // status_type=ocsp(1), responder_id_list empty, request_extensions empty
        Self {
            ty: 0x0005,
            data: Vec::from([0x01, 0x00, 0x00, 0x00, 0x00]),
        }
    }

    fn signature_algorithms() -> Self {
        const SIG_ALGS: [u16; 20] = [
            // Modern preferred
            0x0804, 0x0805, 0x0806, // RSA-PSS-RSAE SHA256/384/512
            0x0403, 0x0503, 0x0603, // ECDSA SHA256/384/512
            0x0807, 0x0808, // Ed25519, Ed448
            0x0809, 0x080a, 0x080b, // RSA-PSS-PSS SHA256/384/512
            // Still fine
            0x0401, 0x0501, 0x0601, // RSA-PKCS1 SHA256/384/512
            // Niche
            0x081a, 0x081b, 0x081c, // ECDSA brainpool
            // Legacy (last)
            0x0201, 0x0203, 0x0202, // SHA1 RSA/ECDSA/DSA
        ];
        let algorithms_len = (SIG_ALGS.len() * 2) as u16;
        let mut data = Vec::with_capacity(2 + SIG_ALGS.len() * 2);
        data.extend_from_slice(&algorithms_len.to_be_bytes());
        SIG_ALGS
            .iter()
            .for_each(|alg| data.extend_from_slice(&alg.to_be_bytes()));
        Self { ty: 0x000d, data }
    }

    fn supported_versions_13() -> Self {
        // 0x02 - list length (in bytes), 0x03 0x04 - TLS 1.3
        const PAYLOAD: [u8; 3] = [0x02, 0x03, 0x04];
        Self {
            ty: 0x002b,
            data: Vec::from(PAYLOAD),
        }
    }

    fn key_share(pubkey: PublicKey) -> Self {
        let mut key_share_entry = Vec::new();
        key_share_entry.extend_from_slice(&[0x00, 0x24]);
        key_share_entry.extend_from_slice(&[0x00, 0x1d]); // NamedGroup::x25519
        key_share_entry.extend_from_slice(&[0x00, 0x20]); // key length = 32
        key_share_entry.extend_from_slice(pubkey.as_bytes());
        Self {
            ty: 0x0033,
            data: key_share_entry,
        }
    }

    fn psk_key_exchange_modes() -> Self {
        Self {
            ty: 0x002d,
            data: Vec::from([0x01, 0x01]), // 0x01 = list length, 0x01 = psk_dhe_ke
        }
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.ty.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);
    }
}
