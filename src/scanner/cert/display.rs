use std::fmt::Display;

use console::truncate_str;
use openssl::{hash::MessageDigest, nid::Nid, pkey::Id};

use crate::scanner::{cert::certificate::Certificate, utils};

impl Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject_cn = self
            .cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".into());

        let sans: Vec<String> = self
            .cert
            .subject_alt_names()
            .map(|stack| {
                stack
                    .iter()
                    .filter_map(|n| {
                        n.dnsname()
                            .map(str::to_string)
                            .or_else(|| n.ipaddress().map(|ip| format!("{:?}", ip)))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let serial_hex = self
            .cert
            .serial_number()
            .to_bn()
            .and_then(|bn| bn.to_hex_str().map(|s| s.to_string()))
            .unwrap_or_else(|_| "<unknown>".into())
            .to_lowercase();

        let not_before = self.cert.not_before().to_string();
        let not_after = self.cert.not_after().to_string();

        let issuer_cn = self
            .cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".into());

        let issuer_url = self.cert.authority_info().and_then(|aia| {
            aia.iter()
                .find(|ad| ad.method().nid() == Nid::AD_CA_ISSUERS)
                .and_then(|ad| ad.location().uri())
                .map(|s| s.to_string())
        });

        let issuer_display = match issuer_url {
            Some(url) => format!("{} ({})", issuer_cn, url),
            None => issuer_cn,
        };

        let pubkey = self.cert.public_key().ok();
        let key_str = match &pubkey {
            Some(pk) => {
                let bits = pk.bits();
                let name = match pk.id() {
                    Id::RSA => "RSA",
                    Id::DSA => "DSA",
                    Id::EC => "EC",
                    Id::ED25519 => "Ed25519",
                    Id::ED448 => "Ed448",
                    Id::X25519 => "X25519",
                    Id::X448 => "X448",
                    Id::HMAC => "HMAC",
                    other => {
                        let nid = openssl::nid::Nid::from_raw(other.as_raw());
                        let name = nid.long_name().unwrap_or("<unknown>");
                        name
                    }
                };
                format!("{} {} bits", name, bits)
            }
            None => "<unknown>".into(),
        };

        let sig_alg = self.cert.signature_algorithm().object().to_string();

        let fp_sha256 = self
            .cert
            .digest(MessageDigest::sha256())
            .map(|d| utils::hex_lower(&d))
            .unwrap_or_else(|_| "<unknown>".into());

        let pin_sha256 = pubkey
            .as_ref()
            .and_then(|pk| pk.public_key_to_der().ok())
            .map(|der| {
                use openssl::sha::sha256;
                base64::encode(&sha256(&der))
            })
            .unwrap_or_else(|| "<unknown>".into());

        let trusted = self.secure;

        writeln!(f, "Subject:            {subject_cn}")?;
        if !sans.is_empty() {
            writeln!(
                f,
                "Alternative names:  {}",
                truncate_str(&sans.join(" "), 64, "...")
            )?;
        }
        writeln!(f, "Serial Number:      {serial_hex}")?;
        writeln!(f, "Valid from:         {not_before}")?;
        writeln!(f, "Valid until:        {not_after}")?;
        writeln!(f, "Issuer:             {issuer_display}")?;
        writeln!(f, "Key:                {key_str}")?;
        writeln!(f, "Signature:          {sig_alg}")?;
        writeln!(f, "Fingerprint SHA256: {fp_sha256}")?;
        writeln!(f, "Pin SHA256:         {pin_sha256}")?;
        writeln!(f, "Trusted:            {trusted}")?;
        Ok(())
    }
}
