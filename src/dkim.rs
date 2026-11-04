//! DKIM (RFC 6376): tag parsing, canonicalisation, body hash (offline) and the RSA signature
//! check with the public key from DNS.

use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

/// Value of a `tag=value` in a DKIM/ARC header or DNS record (whitespace removed for
/// base64 values).
pub fn tag(value: &str, name: &str) -> Option<String> {
    value.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            Some(if matches!(name, "b" | "bh" | "p") {
                v.chars().filter(|c| !c.is_whitespace()).collect()
            } else {
                v.split_whitespace().collect::<Vec<_>>().join(" ")
            })
        } else {
            None
        }
    })
}

/// The message with CRLF line endings (files saved with LF only are converted).
fn crlf(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 40);
    let mut prev = 0u8;
    for &b in raw {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

/// Header fields as written (each with its CRLF) and the body.
fn split(raw: &[u8]) -> (Vec<(String, Vec<u8>)>, &[u8]) {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 2);
    let body = raw.get(end + 2..).unwrap_or(&[]);
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    for line in raw[..end].split_inclusive(|&b| b == b'\n') {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(last) = fields.last_mut() {
                last.1.extend_from_slice(line);
            }
        } else if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon])
                .trim()
                .to_ascii_lowercase();
            fields.push((name, line.to_vec()));
        }
    }
    (fields, body)
}

fn relaxed_header(field: &[u8]) -> Vec<u8> {
    let colon = field.iter().position(|&b| b == b':').unwrap_or(field.len());
    let name = String::from_utf8_lossy(&field[..colon])
        .trim()
        .to_ascii_lowercase();
    let value: Vec<u8> = field[(colon + 1).min(field.len())..]
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let mut v = Vec::with_capacity(value.len());
    let mut ws = false;
    for b in value {
        if b == b' ' || b == b'\t' {
            ws = true;
        } else {
            if ws && !v.is_empty() {
                v.push(b' ');
            }
            ws = false;
            v.push(b);
        }
    }
    let mut out = name.into_bytes();
    out.push(b':');
    out.extend_from_slice(&v);
    out.extend_from_slice(b"\r\n");
    out
}

fn canon_body(body: &[u8], relaxed: bool) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec())
        .collect();
    // split() leaves an empty last element after the final CRLF
    if body.ends_with(b"\n") {
        lines.pop();
    }
    if relaxed {
        for l in &mut lines {
            let mut out = Vec::with_capacity(l.len());
            let mut ws = false;
            for &b in l.iter() {
                if b == b' ' || b == b'\t' {
                    ws = true;
                } else {
                    if ws {
                        out.push(b' ');
                    }
                    ws = false;
                    out.push(b);
                }
            }
            *l = out;
        }
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut out = Vec::new();
    for l in &lines {
        out.extend_from_slice(l);
        out.extend_from_slice(b"\r\n");
    }
    if out.is_empty() && !relaxed {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Removes the value of the `b=` tag (not `bh=`) from a DKIM-Signature field.
fn strip_b(field: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(field).into_owned();
    let colon = s.find(':').map_or(0, |c| c + 1);
    let (head, value) = s.split_at(colon);
    let mut out = head.to_string();
    for (i, part) in value.split(';').enumerate() {
        if i > 0 {
            out.push(';');
        }
        match part.split_once('=') {
            Some((k, _)) if k.trim().eq_ignore_ascii_case("b") => {
                out.push_str(k);
                out.push('=');
                // keep a trailing line break of the field
                if part.ends_with("\r\n") {
                    out.push_str("\r\n");
                }
            }
            _ => out.push_str(part),
        }
    }
    out.into_bytes()
}

/// One DKIM signature of a message.
#[derive(Clone, Debug, Default)]
pub struct Sig {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub canon: String,
    pub headers: String,
    /// Body hash matches: the body is unchanged since signing (offline check).
    pub body_ok: Option<bool>,
    /// Part of the body that was signed (`l=`), if limited.
    pub length: Option<usize>,
    /// Problem that prevents a check.
    pub note: String,
    /// Index among the DKIM-Signature fields (top to bottom).
    pub index: usize,
}

/// All DKIM signatures with the offline body-hash check.
pub fn signatures(raw: &[u8]) -> Vec<Sig> {
    let raw = crlf(raw);
    let (fields, body) = split(&raw);
    let mut out = Vec::new();
    for (index, (_, f)) in fields
        .iter()
        .filter(|(n, _)| n == "dkim-signature")
        .enumerate()
    {
        let text = String::from_utf8_lossy(f);
        let value = text.split_once(':').map_or("", |(_, v)| v);
        let canon = tag(value, "c").unwrap_or_else(|| "simple/simple".into());
        let body_relaxed = canon.split('/').nth(1).unwrap_or("simple") == "relaxed";
        let algorithm = tag(value, "a").unwrap_or_default();
        let mut s = Sig {
            domain: tag(value, "d").unwrap_or_default(),
            selector: tag(value, "s").unwrap_or_default(),
            algorithm: algorithm.clone(),
            canon,
            headers: tag(value, "h").unwrap_or_default(),
            length: tag(value, "l").and_then(|l| l.parse().ok()),
            index,
            ..Default::default()
        };
        let bh = tag(value, "bh").unwrap_or_default();
        if algorithm == "rsa-sha256" || algorithm == "ed25519-sha256" {
            let mut c = canon_body(body, body_relaxed);
            if let Some(l) = s.length {
                c.truncate(l);
            }
            let ours = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&c));
            s.body_ok = Some(ours == bh);
        } else {
            s.note = format!("algorithm {algorithm} is not supported");
        }
        out.push(s);
    }
    out
}

/// Checks the signature `index` with the DNS key record (`v=DKIM1; k=rsa; p=…`).
/// Ok(true) = valid, Ok(false) = invalid, Err = cannot be checked.
pub fn verify(raw: &[u8], index: usize, key_record: &str) -> Result<bool, String> {
    let raw = crlf(raw);
    let (fields, _) = split(&raw);
    let sig_field = fields
        .iter()
        .filter(|(n, _)| n == "dkim-signature")
        .nth(index)
        .map(|(_, f)| f.clone())
        .ok_or("signature not found")?;
    let text = String::from_utf8_lossy(&sig_field).into_owned();
    let value = text.split_once(':').map_or("", |(_, v)| v);
    let algorithm = tag(value, "a").unwrap_or_default();
    if algorithm != "rsa-sha256" {
        return Err(format!("algorithm {algorithm} is not supported"));
    }
    let header_relaxed = tag(value, "c")
        .unwrap_or_default()
        .split('/')
        .next()
        .unwrap_or("simple")
        == "relaxed";
    let p = tag(key_record, "p").ok_or("the DNS record has no key (p=)")?;
    if p.is_empty() {
        return Err("the key has been revoked (empty p=)".into());
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(&p)
        .map_err(|e| format!("key: {e}"))?;
    let key = {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs8::DecodePublicKey;
        RsaPublicKey::from_public_key_der(&der)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(&der))
            .map_err(|e| format!("key: {e}"))?
    };
    // Header fields named in h=, each instance used from the bottom up.
    let mut data = Vec::new();
    let mut used: std::collections::HashMap<String, usize> = Default::default();
    let canon = |f: &[u8]| {
        if header_relaxed {
            relaxed_header(f)
        } else {
            f.to_vec()
        }
    };
    for name in tag(value, "h").unwrap_or_default().split(':') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let n = used.entry(name.clone()).or_insert(0);
        let instances: Vec<&Vec<u8>> = fields
            .iter()
            .filter(|(fname, _)| *fname == name)
            .map(|(_, f)| f)
            .collect();
        if *n < instances.len() {
            data.extend(canon(instances[instances.len() - 1 - *n]));
        }
        *n += 1;
    }
    let mut own = canon(&strip_b(&sig_field));
    while own.ends_with(b"\r\n") {
        own.truncate(own.len() - 2);
    }
    data.extend(own);
    let sig = base64::engine::general_purpose::STANDARD
        .decode(tag(value, "b").unwrap_or_default())
        .map_err(|e| format!("signature: {e}"))?;
    let sig = Signature::try_from(sig.as_slice()).map_err(|e| format!("signature: {e}"))?;
    Ok(VerifyingKey::<Sha256>::new(key).verify(&data, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAXED: &[u8] = include_bytes!("../tests/data/dkim-relaxed.eml");
    const SIMPLE: &[u8] = include_bytes!("../tests/data/dkim-simple.eml");
    const KEY: &str = include_str!("../tests/data/dkim-key.txt");

    #[test]
    fn tags() {
        assert_eq!(
            tag("v=1; d=Example.org; b=ab c\r\n d", "b").unwrap(),
            "abcd"
        );
        assert_eq!(tag("v=1; d=example.org", "d").unwrap(), "example.org");
        assert_eq!(tag("v=1", "x"), None);
    }

    #[test]
    fn canonicalisation() {
        assert_eq!(canon_body(b"a  b \r\n\r\n\r\n", true), b"a b\r\n");
        assert_eq!(canon_body(b"", true), b"");
        assert_eq!(canon_body(b"", false), b"\r\n");
        assert_eq!(canon_body(b"x \r\n\r\n", false), b"x \r\n");
        assert_eq!(
            relaxed_header(b"SubJect:  a \r\n\tb  \r\n"),
            b"subject:a b\r\n"
        );
    }

    #[test]
    fn signed_by_dkimpy() {
        for raw in [RELAXED, SIMPLE] {
            let s = signatures(raw);
            assert_eq!(s.len(), 1);
            assert_eq!(
                (s[0].domain.as_str(), s[0].selector.as_str()),
                ("shop.example", "mail2026")
            );
            assert_eq!(s[0].body_ok, Some(true), "{}", s[0].canon);
            assert_eq!(verify(raw, 0, KEY), Ok(true), "{}", s[0].canon);
        }
        // Changed body: body hash fails. Changed subject: signature fails.
        let body = String::from_utf8_lossy(RELAXED).replace("unterwegs", "storniert");
        assert_eq!(signatures(body.as_bytes())[0].body_ok, Some(false));
        let subj = String::from_utf8_lossy(RELAXED).replace("Bestellung \r\n", "Rechnung \r\n");
        assert_eq!(verify(subj.as_bytes(), 0, KEY), Ok(false));
        // Relaxed tolerates re-folded whitespace and LF line endings.
        let lf = String::from_utf8_lossy(RELAXED).replace("\r\n", "\n");
        assert_eq!(verify(lf.as_bytes(), 0, KEY), Ok(true));
        assert!(verify(RELAXED, 0, "v=DKIM1; p=")
            .unwrap_err()
            .contains("revoked"));
    }
}
