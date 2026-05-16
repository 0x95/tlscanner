use anyhow::Result;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::scanner::{tls::TlsVersion, utils};

pub struct TLSClientHello<'a> {
    sni: &'a str,
    version: TlsVersion,
    ciphers: &'a [u16],
    pubkey: Option<PublicKey>,
    payload: Vec<u8>,
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
            payload: Vec::with_capacity(512),
        }
    }

    pub fn build_tls_payload(mut self) -> Result<Vec<u8>> {
        // record header
        self.payload.push(0x16);
        // yes this one should always be tls 1.0 (0x0301)
        self.payload
            .extend_from_slice(&(TlsVersion::Tls10 as u16).to_be_bytes());
        let record_len_offset = self.payload.len();
        self.payload.extend_from_slice(&[0, 0]); // record length placeholder

        // handshake header
        self.payload.push(0x01); // client_hello
        let handshake_len_offset = self.payload.len();
        self.payload.extend_from_slice(&[0, 0, 0]); // handshake length placeholder (24-bit)

        let body_start = self.payload.len();
        self.write_tls_body()?;
        let body_len = self.payload.len() - body_start;

        // update lengths
        let record_len = (body_len + 4) as u16;
        self.payload[record_len_offset..record_len_offset + 2]
            .copy_from_slice(&record_len.to_be_bytes());

        let hs_len = body_len as u32;
        self.payload[handshake_len_offset] = (hs_len >> 16) as u8;
        self.payload[handshake_len_offset + 1] = (hs_len >> 8) as u8;
        self.payload[handshake_len_offset + 2] = hs_len as u8;

        Ok(self.payload)
    }

    fn write_tls_body(&mut self) -> Result<()> {
        self.payload
            .extend_from_slice(&self.version.legacy_wire().to_be_bytes());

        // random: 32 bytes.
        let random = [0x42u8; 32];
        #[cfg(not(debug_assertions))]
        {
            use openssl::rand::rand_bytes;
            rand_bytes(&mut random)?;
        }

        self.payload.extend_from_slice(&random);

        // session_id length + session_id
        if self.version == TlsVersion::Tls13 {
            self.payload.push(0x20); // 32 bytes
            let mut session_id = [0u8; 32];
            rand::fill(&mut session_id);
            self.payload.extend_from_slice(&session_id);
        } else {
            self.payload.push(0x00);
        }

        // cipher_suites: list of u16
        utils::with_u16_length(self.payload.as_mut(), |b| {
            self.ciphers
                .iter()
                .for_each(|cs| b.extend_from_slice(&cs.to_be_bytes()));
            Ok(())
        })?;

        // compression length
        self.payload.push(0x01);
        // compression - null compression
        self.payload.push(0x00);

        // extensions
        utils::with_u16_length(self.payload.as_mut(), |b| {
            Extensions::ServerName(self.sni).write_to(b)?;
            Extensions::ExtendedMasterSecret.write_to(b)?;
            Extensions::RenegotiationInfo.write_to(b)?;
            Extensions::SupportedGroups.write_to(b)?;
            Extensions::StatusRequest.write_to(b)?;

            match self.version {
                TlsVersion::Tls12 => {
                    Extensions::EcPointFormats.write_to(b)?;
                    Extensions::EncryptThenMac.write_to(b)?;
                    Extensions::SessionTicket.write_to(b)?;
                    Extensions::SignatureAlgorithms.write_to(b)?;
                }
                TlsVersion::Tls13 => {
                    Extensions::SignatureAlgorithms.write_to(b)?;
                    Extensions::SupportedVersions13.write_to(b)?;
                    Extensions::PskKeyExchangeModes.write_to(b)?;
                    Extensions::KeyShare(&self.pubkey.unwrap()).write_to(b)?;
                }
                _ => {
                    // TLS 1.0 / 1.1: no signature_algorithms (1.2+ only)
                    Extensions::EcPointFormats.write_to(b)?;
                    Extensions::SessionTicket.write_to(b)?;
                }
            }
            Ok(())
        })?;

        Ok(())
    }
}

pub enum Extensions<'a> {
    ServerName(&'a str),
    StatusRequest,
    SupportedGroups,
    EcPointFormats,
    SignatureAlgorithms,
    EncryptThenMac,
    ExtendedMasterSecret,
    SessionTicket,
    SupportedVersions13,
    PskKeyExchangeModes,
    KeyShare(&'a PublicKey),
    RenegotiationInfo,
}

impl Extensions<'_> {
    pub fn write_to(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::ServerName(host) => {
                // server_name (rfc 6066)
                buf.extend_from_slice(&0x0000u16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // server_name_list
                    utils::with_u16_length(b, |b| {
                        b.push(0x00); // name_type = host_name
                        // host_name
                        utils::with_u16_length(b, |b| {
                            b.extend_from_slice(host.as_bytes());
                            Ok(())
                        })
                    })
                })?;
            }

            Self::StatusRequest => {
                // status_request (rfc 6066) - oscp stapling
                buf.extend_from_slice(&0x0005u16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    b.push(0x01); // status_type = ocsp
                    b.extend_from_slice(&0u16.to_be_bytes()); // responder_id_list (empty)
                    b.extend_from_slice(&0u16.to_be_bytes()); // request_extensions (empty)
                    Ok(())
                })?;
            }

            Self::SupportedGroups => {
                // supported_groups / named curves (rfc 8422, 7919)
                const GROUPS: [u16; 10] = [
                    0x001d, // x25519
                    0x0017, // secp256r1
                    0x0018, // secp384r1
                    0x0019, // secp521r1
                    0x001e, // x448
                    0x0100, // ffdhe2048
                    0x0101, // ffdhe3072
                    0x0102, // ffdhe4096
                    0x0103, // ffdhe6144
                    0x0104, // ffdhe8192
                ];
                buf.extend_from_slice(&0x000au16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // named_group_list
                    utils::with_u16_length(b, |b| {
                        for g in GROUPS {
                            b.extend_from_slice(&g.to_be_bytes());
                        }
                        Ok(())
                    })
                })?;
            }

            Self::EcPointFormats => {
                // ec_point_formats (rfc 8422)
                buf.extend_from_slice(&0x000bu16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // ec_point_format_list (u8-length prefixed)
                    b.push(0x01); // 1 format
                    b.push(0x00); // uncompressed
                    Ok(())
                })?;
            }

            Self::SignatureAlgorithms => {
                // signature_algorithms (rfc 8446)
                const SIG_ALGS: [u16; 20] = [
                    0x0804, // rsa_pss_rsae_sha256
                    0x0805, // rsa_pss_rsae_sha384
                    0x0806, // rsa_pss_rsae_sha512
                    0x0403, // ecdsa_secp256r1_sha256
                    0x0503, // ecdsa_secp384r1_sha384
                    0x0603, // ecdsa_secp521r1_sha512
                    0x0807, // ed25519
                    0x0808, // ed448
                    0x0809, // rsa_pss_pss_sha256
                    0x080a, // rsa_pss_pss_sha384
                    0x080b, // rsa_pss_pss_sha512
                    0x0401, // rsa_pkcs1_sha256
                    0x0501, // rsa_pkcs1_sha384
                    0x0601, // rsa_pkcs1_sha512
                    0x081a, // ecdsa_brainpoolP256r1tls13_sha256
                    0x081b, // ecdsa_brainpoolP384r1tls13_sha384
                    0x081c, // ecdsa_brainpoolP512r1tls13_sha512
                    0x0201, // rsa_pkcs1_sha1 (legacy)
                    0x0203, // ecdsa_sha1 (legacy)
                    0x0202, // dsa_sha1 (legacy)
                ];
                buf.extend_from_slice(&0x000du16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // supported_signature_algorithms
                    utils::with_u16_length(b, |b| {
                        for a in SIG_ALGS {
                            b.extend_from_slice(&a.to_be_bytes());
                        }
                        Ok(())
                    })
                })?;
            }

            Self::EncryptThenMac => {
                // encrypt_then_mac (rfc 7366) - empty body
                buf.extend_from_slice(&0x0016u16.to_be_bytes());
                buf.extend_from_slice(&0u16.to_be_bytes());
            }

            Self::ExtendedMasterSecret => {
                // extended_master_secret (rfc 7627) - empty body
                buf.extend_from_slice(&0x0017u16.to_be_bytes());
                buf.extend_from_slice(&0u16.to_be_bytes());
            }

            Self::SessionTicket => {
                // session_ticket (rfc 5077) - empty body = request a ticket
                buf.extend_from_slice(&0x0023u16.to_be_bytes());
                buf.extend_from_slice(&0u16.to_be_bytes());
            }

            Self::SupportedVersions13 => {
                // supported_versions (rfc 8446)
                buf.extend_from_slice(&0x002bu16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // versions list (u8-length prefixed)
                    b.push(0x02); // 2 bytes follow
                    b.extend_from_slice(&0x0304u16.to_be_bytes()); // tls 1.3
                    Ok(())
                })?;
            }

            Self::PskKeyExchangeModes => {
                // psk_key_exchange_modes (rfc 8446)
                buf.extend_from_slice(&0x002du16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // ke_modes list (u8-length prefixed)
                    b.push(0x01); // 1 mode
                    b.push(0x01); // psk_dhe_ke
                    Ok(())
                })?;
            }

            Self::KeyShare(pubkey) => {
                // key_share (rfc 8446)
                buf.extend_from_slice(&0x0033u16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // client_shares: list of KeyShareEntry
                    utils::with_u16_length(b, |b| {
                        b.extend_from_slice(&0x001du16.to_be_bytes()); // group = x25519
                        // key_exchange: (32 bytes for x25519)
                        utils::with_u16_length(b, |b| {
                            b.extend_from_slice(pubkey.as_bytes());
                            Ok(())
                        })
                    })
                })?;
            }

            Self::RenegotiationInfo => {
                // renegotiation_info (rfc 5746)
                buf.extend_from_slice(&0xff01u16.to_be_bytes());
                utils::with_u16_length(buf, |b| {
                    // renegotiated_connection: empty for initial handshake
                    b.push(0x00);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}
