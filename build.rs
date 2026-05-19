use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const API_URL: &str = "https://ciphersuite.info/api/cs/";
const CACERT_URL: &str = "https://curl.se/ca/cacert.pem";

#[derive(Debug, Deserialize)]
struct ApiResponse {
    ciphersuites: Vec<BTreeMap<String, RawSuite>>,
}

#[derive(Debug, Deserialize)]
struct RawSuite {
    #[serde(default)]
    gnutls_name: String,
    #[serde(default)]
    openssl_name: String,
    hex_byte_1: String,
    hex_byte_2: String,
    #[serde(default)]
    protocol_version: String,
    #[serde(default)]
    kex_algorithm: String,
    #[serde(default)]
    auth_algorithm: String,
    #[serde(default)]
    enc_algorithm: String,
    #[serde(default)]
    hash_algorithm: String,
    security: String,
    #[serde(default)]
    tls_version: Vec<String>,
}

fn parse_hex_byte(s: &str) -> u8 {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    u8::from_str_radix(t, 16).unwrap_or_else(|e| panic!("bad hex byte {s:?}: {e}"))
}

fn security_variant(s: &str) -> &'static str {
    match s {
        "recommended" => "Security::Recommended",
        "secure" => "Security::Secure",
        "weak" => "Security::Weak",
        "insecure" => "Security::Insecure",
        other => panic!("unknown security level from API: {other:?}"),
    }
}

fn tls_version_variant(s: &str) -> Option<&'static str> {
    match s {
        "SSL2.0" | "SSL2" => Some("TlsVersion::Ssl20"),
        "SSL3.0" | "SSL3" => Some("TlsVersion::Ssl30"),
        "TLS1.0" => Some("TlsVersion::Tls10"),
        "TLS1.1" => Some("TlsVersion::Tls11"),
        "TLS1.2" => Some("TlsVersion::Tls12"),
        "TLS1.3" => Some("TlsVersion::Tls13"),
        "" => None,
        other => panic!("unknown tls_version from API: {other:?}"),
    }
}

fn rust_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// SSLv3 backfill
// ---------------------------------------------------------------------------
//
// ciphersuite.info does NOT expose "SSL3.0" in its tls_version field at all,
// so every suite that was usable over SSL 3.0 looks TLS-only in the raw data.
// In reality, the SSLv3 record layer can carry any cipher whose primitives do
// not depend on machinery that was introduced strictly after SSLv3.
//
// We therefore apply an *inverted* rule: assume every cipher the API tags as
// TLS1.0-capable is also SSL3.0-capable, and then disqualify any cipher that
// requires post-SSLv3 machinery:
//
//   1. AEAD ciphers (GCM, CCM, CCM_8, ChaCha20-Poly1305). SSLv3 has no AEAD
//      record layer -- that was introduced in TLS 1.2 (RFC 5246).
//   2. SHA-2 MACs (SHA256, SHA384). The "_SHA256" / "_SHA384" suites are
//      TLS 1.2+ only by definition; SSLv3's PRF is hardcoded MD5+SHA1.
//   3. ECDH/ECDHE key exchange. RFC 4492 / RFC 8422 require the Supported
//      Elliptic Curves and Supported Point Formats extensions -- SSLv3 has
//      no TLS extensions framework, so the server MUST NOT negotiate an ECC
//      cipher.
//   4. Suites that exist only in TLS 1.3 (codes 0x1301..0x1305).
//   5. PSK / SRP / KRB5 / ARIA-GCM / Camellia-GCM / etc. that depend on
//      TLS-era handshake extensions or TLS 1.2 PRF. (Conservative -- some
//      of these could *technically* work over SSLv3, but no real stack does
//      this and the API never marks them SSL3.)
//
// In addition, the FORTEZZA suites at 0x001C..0x001E from RFC 6101 Appendix
// A.6 never received TLS names and the API does not return them at all.
// They are synthesized below.
//
// Note: 0x001E is a known conflict. RFC 6101 assigned it to
// SSL_FORTEZZA_KEA_WITH_RC4_128_SHA, but RFC 2712 reassigned it to
// TLS_KRB5_WITH_DES_CBC_SHA. The IANA registry follows RFC 2712, and so does
// the API. We only synthesize a FORTEZZA entry for a code if the API did not
// return anything for it.

/// FORTEZZA suites from RFC 6101 Appendix A.6 that have no TLS name.
const RFC6101_FORTEZZA_SUITES: &[(u16, &str, &str, &str)] = &[
    // (code, iana_name, enc_algorithm, hash_algorithm)
    (0x001C, "SSL_FORTEZZA_KEA_WITH_NULL_SHA", "NULL", "SHA"),
    (
        0x001D,
        "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
        "FORTEZZA_CBC",
        "SHA",
    ),
    (
        0x001E,
        "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA",
        "RC4_128",
        "SHA",
    ),
];

/// True if the cipher's MAC/PRF is a SHA-2 hash that was introduced for
/// TLS 1.2. SSLv3 has no SHA-2-based MAC mode.
fn hash_is_tls12_only(hash: &str) -> bool {
    matches!(
        hash.to_ascii_uppercase().as_str(),
        "SHA256" | "SHA384" | "SHA512"
    )
}

/// True if the cipher uses an AEAD bulk encryption mode. SSLv3's record
/// layer is MAC-then-encrypt with a separate MAC; AEAD modes (GCM, CCM,
/// ChaCha20-Poly1305) require the TLS 1.2 AEAD record layer.
fn enc_is_aead(enc: &str) -> bool {
    let u = enc.to_ascii_uppercase();
    u.contains("GCM")
        || u.contains("CCM")
        || u.contains("CHACHA20_POLY1305")
        || u.contains("CHACHA20-POLY1305")
        || u.contains("POLY1305")
}

/// True if the cipher uses any form of elliptic curve key exchange. ECC
/// suites need TLS extensions (RFC 4492 / 8422), which SSLv3 lacks.
fn kex_requires_extensions(kex: &str, name: &str) -> bool {
    let ku = kex.to_ascii_uppercase();
    if ku.starts_with("ECDH") || ku == "ECCPWD" {
        return true;
    }
    // Defensive: rely on the IANA name too, in case the API has empty kex.
    let nu = name.to_ascii_uppercase();
    nu.contains("ECDH_") || nu.contains("ECDHE_") || nu.contains("ECCPWD")
}

/// TLS 1.3 dedicated code points (RFC 8446 Appendix B.4). These suites have
/// no SSLv3 / TLS 1.2 semantics at all.
fn is_tls13_only_code(code: u16) -> bool {
    matches!(code, 0x1301..=0x1305)
}

/// True if the API named this suite a PSK / SRP / KRB5 / anonymous-ECDH /
/// etc. that we conservatively refuse to tag with SSL3.0. Real-world stacks
/// don't negotiate these over SSLv3 even when the primitives might fit.
fn name_is_post_sslv3_only(name: &str, kex: &str, auth: &str) -> bool {
    let n = name.to_ascii_uppercase();
    let k = kex.to_ascii_uppercase();
    let a = auth.to_ascii_uppercase();

    // PSK family always needs extensions (psk_identity_hint, etc).
    if n.contains("_PSK") || k.contains("PSK") || a.contains("PSK") {
        return true;
    }
    // SRP, GOST CNT/MAGMA/KUZNYECHIK, ECCPWD, etc.
    if n.contains("_SRP_")
        || n.starts_with("TLS_SRP_")
        || k.contains("SRP")
        || n.contains("GOST")
        || k.contains("GOSTR")
        || n.contains("ECCPWD")
        || n.contains("SHA256_SHA256") // weird TLS 1.3-era profiles
        || n.contains("SHA384_SHA384")
    {
        return true;
    }
    false
}

/// Decide whether a suite (as returned by the API) is also negotiable over
/// SSL 3.0. Inverted-rule: it must already be TLS1.0-capable AND fail every
/// disqualifying check above.
fn suite_is_sslv3_capable(code: u16, name: &str, raw: &RawSuite) -> bool {
    if is_tls13_only_code(code) {
        return false;
    }
    // Must have been negotiable in TLS 1.0 to begin with. (SSLv3 and TLS 1.0
    // share the same record framing and cipher format.)
    let has_tls10 = raw.tls_version.iter().any(|v| v == "TLS1.0");
    if !has_tls10 {
        return false;
    }
    if hash_is_tls12_only(&raw.hash_algorithm) {
        return false;
    }
    if enc_is_aead(&raw.enc_algorithm) {
        return false;
    }
    if kex_requires_extensions(&raw.kex_algorithm, name) {
        return false;
    }
    if name_is_post_sslv3_only(name, &raw.kex_algorithm, &raw.auth_algorithm) {
        return false;
    }
    true
}

/// Build a synthetic RawSuite for a FORTEZZA cipher.
fn make_fortezza_suite(enc: &str, hash: &str) -> RawSuite {
    RawSuite {
        gnutls_name: String::new(),
        openssl_name: String::new(),
        hex_byte_1: String::new(), // not used; we already have the code
        hex_byte_2: String::new(),
        protocol_version: "SSL".to_string(),
        kex_algorithm: "KEA".to_string(),
        auth_algorithm: "KEA".to_string(),
        enc_algorithm: enc.to_string(),
        hash_algorithm: hash.to_string(),
        security: "insecure".to_string(), // FORTEZZA is decades dead
        tls_version: vec!["SSL3.0".to_string()],
    }
}

/// Mutate `suites` in place: tag every SSLv3-capable suite with SSL3.0 and
/// append any missing FORTEZZA suites from RFC 6101 Appendix A.6.
fn apply_sslv3_backfill(suites: &mut Vec<(u16, String, RawSuite)>) {
    use std::collections::HashSet;

    let present: HashSet<u16> = suites.iter().map(|(c, _, _)| *c).collect();

    let mut tagged = 0usize;
    for (code, name, raw) in suites.iter_mut() {
        if suite_is_sslv3_capable(*code, name, raw)
            && !raw.tls_version.iter().any(|v| v == "SSL3.0")
        {
            raw.tls_version.push("SSL3.0".to_string());
            tagged += 1;
        }
    }

    let mut appended = 0usize;
    for &(code, iana, enc, hash) in RFC6101_FORTEZZA_SUITES {
        if !present.contains(&code) {
            suites.push((code, iana.to_string(), make_fortezza_suite(enc, hash)));
            appended += 1;
        } else {
            // Already known under a different name (e.g. 0x001E =
            // TLS_KRB5_WITH_DES_CBC_SHA). Skip; do not invent a duplicate.
            eprintln!(
                "note: skipping FORTEZZA backfill for 0x{:04x}; API already returned a name for it",
                code
            );
        }
    }

    eprintln!(
        "ssl3 backfill: tagged {tagged} existing suite(s) with SSL3.0, appended {appended} FORTEZZA suite(s)"
    );
}

fn fetch_cacert(out_dir: &Path) {
    println!("cargo:rerun-if-env-changed=CACERT_URL");

    let url = env::var("CACERT_URL").unwrap_or_else(|_| CACERT_URL.to_string());
    let body = ureq::get(&url)
        .header("User-Agent", "tls-scanner-build/0.1 (+build.rs)")
        .call()
        .unwrap_or_else(|e| panic!("failed to fetch {url}: {e}"))
        .into_body()
        .read_to_string()
        .expect("failed to read cacert response body");

    assert!(
        body.contains("-----BEGIN CERTIFICATE-----"),
        "downloaded cacert.pem looks malformed (no PEM block found)"
    );

    fs::write(out_dir.join("cacert.pem"), body.as_bytes())
        .expect("failed to write cacert.pem to OUT_DIR");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CIPHERSUITE_API_URL");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    fs::create_dir_all(&out_dir).ok();

    fetch_cacert(&out_dir);

    let url = env::var("CIPHERSUITE_API_URL").unwrap_or_else(|_| API_URL.to_string());

    let body = ureq::get(&url)
        .header("User-Agent", "tls-scanner-build/0.1 (+build.rs)")
        .header("Accept", "application/json")
        .call()
        .unwrap_or_else(|e| panic!("failed to fetch {url}: {e}"))
        .into_body()
        .read_to_string()
        .expect("failed to read API response body");

    let parsed: ApiResponse =
        serde_json::from_str(&body).expect("API returned unexpected JSON shape");

    let mut suites: Vec<(u16, String, RawSuite)> = parsed
        .ciphersuites
        .into_iter()
        .flat_map(|m| m.into_iter())
        .map(|(name, raw)| {
            let b1 = parse_hex_byte(&raw.hex_byte_1);
            let b2 = parse_hex_byte(&raw.hex_byte_2);
            let code = (u16::from(b1) << 8) | u16::from(b2);
            (code, name, raw)
        })
        .collect();

    assert!(!suites.is_empty(), "API returned zero cipher suites");

    // Inject SSL3.0 tags and FORTEZZA backfill BEFORE sorting / dedup-checking,
    // so the synthesized entries flow through the same downstream logic.
    apply_sslv3_backfill(&mut suites);

    suites.sort_by_key(|(code, name, _)| (*code, name.clone()));

    {
        let mut seen = std::collections::HashSet::new();
        for (code, name, _) in &suites {
            if !seen.insert(*code) {
                eprintln!("warning: duplicate cipher code 0x{code:04x} ({name})");
            }
        }
    }

    let mut out = String::new();
    out.push_str("// @generated by build.rs from https://ciphersuite.info/api/cs/\n");
    out.push_str("// SSL 3.0 cipher suites (RFC 6101 Appendix A.6) are backfilled at build\n");
    out.push_str("// time: API-returned codes 0x0000..0x001B get an extra SSL3.0 tag, and the\n");
    out.push_str("// FORTEZZA suites 0x001C..0x001E are synthesized when not already present.\n");
    out.push_str("#![allow(dead_code)]\n");
    out.push_str("use super::{CipherSuite, Security, TlsVersion};\n\n");
    out.push_str(&format!("pub const COUNT: usize = {};\n\n", suites.len()));

    out.push_str("pub static ALL: &[CipherSuite] = &[\n");
    for (code, name, r) in &suites {
        let versions: Vec<&'static str> = r
            .tls_version
            .iter()
            .filter_map(|v| tls_version_variant(v))
            .collect();
        let versions_lit = if versions.is_empty() {
            "&[]".to_string()
        } else {
            format!("&[{}]", versions.join(", "))
        };
        out.push_str(&format!(
            "    CipherSuite {{\n\
             \x20       code: 0x{code:04x},\n\
             \x20       iana_name: {name},\n\
             \x20       openssl_name: {openssl},\n\
             \x20       gnutls_name: {gnutls},\n\
             \x20       protocol_version: {proto},\n\
             \x20       kex_algorithm: {kex},\n\
             \x20       auth_algorithm: {auth},\n\
             \x20       enc_algorithm: {enc},\n\
             \x20       hash_algorithm: {hash},\n\
             \x20       security: {sec},\n\
             \x20       tls_versions: {versions_lit},\n\
             \x20   }},\n",
            code = code,
            name = rust_str(name),
            openssl = rust_str(&r.openssl_name),
            gnutls = rust_str(&r.gnutls_name),
            proto = rust_str(&r.protocol_version),
            kex = rust_str(&r.kex_algorithm),
            auth = rust_str(&r.auth_algorithm),
            enc = rust_str(&r.enc_algorithm),
            hash = rust_str(&r.hash_algorithm),
            sec = security_variant(&r.security),
            versions_lit = versions_lit,
        ));
    }
    out.push_str("];\n\n");

    // -- phf map: code -> index into ALL
    {
        let mut m = phf_codegen::Map::<u16>::new();
        let owned: Vec<String> = (0..suites.len()).map(|i| i.to_string()).collect();
        for ((code, _, _), v) in suites.iter().zip(owned.iter()) {
            m.entry(*code, v);
        }
        out.push_str("pub static BY_CODE: phf::Map<u16, usize> = ");
        out.push_str(&m.build().to_string());
        out.push_str(";\n\n");
    }

    // -- phf map: iana name -> index
    {
        let mut m = phf_codegen::Map::<&str>::new();
        let owned: Vec<(String, String)> = suites
            .iter()
            .enumerate()
            .map(|(idx, (_, name, _))| (name.clone(), idx.to_string()))
            .collect();
        for (k, v) in &owned {
            m.entry(k.as_str(), v);
        }
        out.push_str("pub static BY_NAME: phf::Map<&'static str, usize> = ");
        out.push_str(&m.build().to_string());
        out.push_str(";\n\n");
    }

    let versions = [
        ("SSL20", "Ssl20"),
        ("SSL30", "Ssl30"),
        ("TLS10", "Tls10"),
        ("TLS11", "Tls11"),
        ("TLS12", "Tls12"),
        ("TLS13", "Tls13"),
    ];
    for (const_name, variant) in versions {
        let idxs: Vec<usize> = suites
            .iter()
            .enumerate()
            .filter_map(|(i, (_, _, r))| {
                let has = r
                    .tls_version
                    .iter()
                    .filter_map(|v| tls_version_variant(v))
                    .any(|v| v == format!("TlsVersion::{variant}"));
                if has { Some(i) } else { None }
            })
            .collect();
        out.push_str(&format!(
            "pub static INDICES_{const_name}: &[usize] = &{idxs:?};\n\n"
        ));
    }

    for (label, variant) in [
        ("RECOMMENDED", "recommended"),
        ("SECURE", "secure"),
        ("WEAK", "weak"),
        ("INSECURE", "insecure"),
    ] {
        let idxs: Vec<usize> = suites
            .iter()
            .enumerate()
            .filter_map(|(i, (_, _, r))| (r.security == variant).then_some(i))
            .collect();
        out.push_str(&format!(
            "pub static INDICES_{label}: &[usize] = &{idxs:?};\n\n"
        ));
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    fs::create_dir_all(&out_dir).ok();
    fs::write(out_dir.join("ciphers_generated.rs"), &out)
        .expect("failed to write generated file to OUT_DIR");

    let src_path = PathBuf::from("src/scanner/tls/ciphers.rs");
    fs::create_dir_all(src_path.parent().unwrap()).ok();
    // Only rewrite if changed -- keeps mtime stable and avoids fighting rust-analyzer.
    let prev = fs::read_to_string(&src_path).unwrap_or_default();
    if prev != out {
        fs::write(&src_path, &out).expect("failed to write src/tls/ciphers.rs");
    }
}
