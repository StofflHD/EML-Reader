//! Outlook `.msg` files (OLE compound files, MS-OXMSG): converted to an RFC 5322 message so the
//! whole viewer and analysis work on them. The original transport headers are kept when the
//! file has them.

use std::io::{Cursor, Read};

use base64::Engine;

fn utf16le(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
        .trim_end_matches('\0')
        .to_string()
}

fn eight_bit(b: &[u8]) -> String {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => mail_parser::decoders::charsets::decode(b"windows-1252", b).into_owned(),
    }
}

struct Ole {
    cf: cfb::CompoundFile<Cursor<Vec<u8>>>,
}

impl Ole {
    fn stream(&mut self, path: &str) -> Option<Vec<u8>> {
        let mut s = self.cf.open_stream(path).ok()?;
        let mut v = Vec::new();
        s.read_to_end(&mut v).ok()?;
        Some(v)
    }

    /// A string property (`001F` Unicode or `001E` 8-bit) of the storage `dir`.
    fn string(&mut self, dir: &str, id: &str) -> Option<String> {
        if let Some(b) = self.stream(&format!("{dir}/__substg1.0_{id}001F")) {
            return Some(utf16le(&b));
        }
        self.stream(&format!("{dir}/__substg1.0_{id}001E"))
            .map(|b| eight_bit(&b))
    }

    fn binary(&mut self, dir: &str, id: &str) -> Option<Vec<u8>> {
        self.stream(&format!("{dir}/__substg1.0_{id}0102"))
    }

    /// Fixed-size property `id` (hex, e.g. 0x0C15) from the properties stream.
    fn fixed(&mut self, dir: &str, id: u16, header: usize) -> Option<[u8; 8]> {
        let p = self.stream(&format!("{dir}/__properties_version1.0"))?;
        p.get(header..)?.as_chunks::<16>().0.iter().find_map(|e| {
            let tag = u32::from_le_bytes(e[0..4].try_into().ok()?);
            ((tag >> 16) as u16 == id)
                .then(|| e[8..16].try_into().ok())
                .flatten()
        })
    }

    fn children(&self, dir: &str, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .cf
            .read_storage(if dir.is_empty() { "/" } else { dir })
            .map(|it| {
                it.filter(|e| e.is_storage() && e.name().starts_with(prefix))
                    .map(|e| e.path().to_string_lossy().replace('\\', "/"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// RFC 2047 encoding for header text that is not plain ASCII.
fn encode_word(s: &str) -> String {
    if s.is_ascii() && !s.contains(['\r', '\n']) {
        s.to_string()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(s.replace(['\r', '\n'], " "))
        )
    }
}

fn mailbox(name: &str, addr: &str) -> String {
    let name = name.trim();
    let addr = addr.trim();
    if addr.is_empty() {
        encode_word(name)
    } else if name.is_empty() || name == addr {
        format!("<{addr}>")
    } else if name.is_ascii() {
        format!("\"{}\" <{addr}>", name.replace('"', "'"))
    } else {
        format!("{} <{addr}>", encode_word(name))
    }
}

fn filetime_to_rfc2822(ft: u64) -> Option<String> {
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.format("%a, %d %b %Y %H:%M:%S +0000").to_string())
}

fn b64_lines(data: &[u8]) -> String {
    let s = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(s.len() + s.len() / 76 * 2 + 2);
    for chunk in s.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// Whether the data is an OLE compound file (Outlook .msg).
pub fn is_msg(data: &[u8]) -> bool {
    data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// Converts an Outlook .msg file into an RFC 5322 message.
pub fn to_eml(data: &[u8]) -> Result<Vec<u8>, String> {
    let cf = cfb::CompoundFile::open(Cursor::new(data.to_vec()))
        .map_err(|e| format!("Not a readable Outlook file: {e}"))?;
    let mut o = Ole { cf };
    let root = "";
    let subject = o.string(root, "0037").unwrap_or_default();
    if o.stream("/__properties_version1.0").is_none() && o.string(root, "001A").is_none() {
        return Err("The file is an OLE document, but not an Outlook message.".into());
    }
    let mut head = String::new();
    // Original transport headers: everything except the MIME structure fields.
    let transport = o.string(root, "007D").unwrap_or_default();
    let has = |name: &str, head: &String| {
        head.lines().any(|l| {
            l.to_ascii_lowercase()
                .starts_with(&format!("{}:", name.to_ascii_lowercase()))
        })
    };
    if !transport.trim().is_empty() {
        let mut skip = false;
        for line in transport.replace("\r\n", "\n").lines() {
            if line.is_empty() {
                break;
            }
            if !line.starts_with([' ', '\t']) {
                let l = line.to_ascii_lowercase();
                skip = l.starts_with("content-type:")
                    || l.starts_with("content-transfer-encoding:")
                    || l.starts_with("mime-version:");
            }
            if !skip {
                head.push_str(line);
                head.push_str("\r\n");
            }
        }
    }
    if !has("From", &head) {
        let name = o.string(root, "0C1A").unwrap_or_default();
        let addr = o
            .string(root, "5D01")
            .or_else(|| o.string(root, "0C1F"))
            .filter(|a| a.contains('@'))
            .unwrap_or_default();
        head.push_str(&format!("From: {}\r\n", mailbox(&name, &addr)));
    }
    if !has("To", &head) || !has("Cc", &head) {
        let (mut to, mut cc) = (Vec::new(), Vec::new());
        for r in o.children(root, "__recip_version1.0_") {
            let name = o.string(&r, "3001").unwrap_or_default();
            let addr = o
                .string(&r, "39FE")
                .or_else(|| o.string(&r, "3003"))
                .filter(|a| a.contains('@'))
                .unwrap_or_default();
            let kind = o
                .fixed(&r, 0x0C15, 8)
                .map(|v| i32::from_le_bytes(v[0..4].try_into().unwrap()))
                .unwrap_or(1);
            let m = mailbox(&name, &addr);
            match kind {
                2 => cc.push(m),
                3 => {}
                _ => to.push(m),
            }
        }
        if !has("To", &head) && !to.is_empty() {
            head.push_str(&format!("To: {}\r\n", to.join(", ")));
        }
        if !has("Cc", &head) && !cc.is_empty() {
            head.push_str(&format!("Cc: {}\r\n", cc.join(", ")));
        }
    }
    if !has("Subject", &head) {
        head.push_str(&format!("Subject: {}\r\n", encode_word(&subject)));
    }
    if !has("Date", &head) {
        let t = o
            .fixed(root, 0x0039, 32)
            .or_else(|| o.fixed(root, 0x0E06, 32))
            .and_then(|v| filetime_to_rfc2822(u64::from_le_bytes(v)));
        if let Some(t) = t {
            head.push_str(&format!("Date: {t}\r\n"));
        }
    }
    if !has("Message-ID", &head) {
        if let Some(id) = o.string(root, "1035").filter(|s| !s.is_empty()) {
            head.push_str(&format!("Message-ID: {id}\r\n"));
        }
    }
    head.push_str("X-Converted-From: Outlook .msg (EML Reader)\r\n");
    head.push_str("MIME-Version: 1.0\r\n");

    let text = o.string(root, "1000").filter(|t| !t.trim().is_empty());
    let html = o
        .binary(root, "1013")
        .map(|b| eight_bit(&b))
        .or_else(|| o.string(root, "1013"))
        .filter(|t| !t.trim().is_empty());
    let mut atts = Vec::new();
    for a in o.children(root, "__attach_version1.0_") {
        let Some(data) = o.binary(&a, "3701") else {
            continue;
        };
        let name = o
            .string(&a, "3707")
            .or_else(|| o.string(&a, "3704"))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("attachment-{}", atts.len() + 1));
        let mime = o
            .string(&a, "370E")
            .filter(|m| m.contains('/'))
            .unwrap_or_else(|| "application/octet-stream".into());
        let cid = o.string(&a, "3712").unwrap_or_default();
        atts.push((name, mime, cid, data));
    }

    let mut body = String::new();
    let alt = "=_alt_eml_reader";
    let mixed = "=_mixed_eml_reader";
    let alternative = |body: &mut String| {
        body.push_str(&format!(
            "Content-Type: multipart/alternative; boundary=\"{alt}\"\r\n\r\n"
        ));
        if let Some(t) = &text {
            body.push_str(&format!(
                "--{alt}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
                b64_lines(t.as_bytes())
            ));
        }
        if let Some(h) = &html {
            body.push_str(&format!(
                "--{alt}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
                b64_lines(h.as_bytes())
            ));
        }
        body.push_str(&format!("--{alt}--\r\n"));
    };
    if atts.is_empty() {
        alternative(&mut body);
    } else {
        body.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{mixed}\"\r\n\r\n--{mixed}\r\n"
        ));
        alternative(&mut body);
        for (name, mime, cid, data) in &atts {
            let fname = encode_word(name).replace('"', "'");
            let inline = !cid.is_empty()
                && html
                    .as_deref()
                    .is_some_and(|h| h.contains(&format!("cid:{cid}")));
            body.push_str(&format!(
                "--{mixed}\r\nContent-Type: {mime}; name=\"{fname}\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: {}; filename=\"{fname}\"\r\n",
                if inline { "inline" } else { "attachment" }
            ));
            if !cid.is_empty() {
                body.push_str(&format!(
                    "Content-ID: <{}>\r\n",
                    cid.trim_matches(['<', '>'])
                ));
            }
            body.push_str("\r\n");
            body.push_str(&b64_lines(data));
        }
        body.push_str(&format!("--{mixed}--\r\n"));
    }
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    Ok(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;

    fn u16s(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// A small Outlook message built with the cfb writer.
    pub fn sample_msg() -> Vec<u8> {
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        let put = |cf: &mut cfb::CompoundFile<Cursor<Vec<u8>>>, path: &str, data: &[u8]| {
            cf.create_stream(path).unwrap().write_all(data).unwrap();
        };
        put(&mut cf, "/__substg1.0_0037001F", &u16s("Angebot für Sie"));
        put(&mut cf, "/__substg1.0_0C1A001F", &u16s("Jürgen Händler"));
        put(
            &mut cf,
            "/__substg1.0_5D01001F",
            &u16s("juergen@haendler.example"),
        );
        put(
            &mut cf,
            "/__substg1.0_1000001F",
            &u16s("Hallo,\r\nanbei das Angebot.\r\n"),
        );
        put(
            &mut cf,
            "/__substg1.0_10130102",
            b"<p>Hallo, <b>anbei</b> das Angebot.</p>",
        );
        // properties: 32-byte header, ClientSubmitTime (0x0039, PT_SYSTIME)
        let mut props = vec![0u8; 32];
        props.extend_from_slice(&0x0039_0040u32.to_le_bytes());
        props.extend_from_slice(&6u32.to_le_bytes());
        // 2026-11-04 09:30:00 UTC as FILETIME
        let ft: u64 = (1_793_784_600 + 11_644_473_600) * 10_000_000;
        props.extend_from_slice(&ft.to_le_bytes());
        put(&mut cf, "/__properties_version1.0", &props);
        for (i, (name, addr, kind)) in [
            ("Max Muster", "max@example.com", 1i32),
            ("Team", "team@example.com", 2),
        ]
        .iter()
        .enumerate()
        {
            let dir = format!("/__recip_version1.0_#{i:08X}");
            cf.create_storage(&dir).unwrap();
            put(&mut cf, &format!("{dir}/__substg1.0_3001001F"), &u16s(name));
            put(&mut cf, &format!("{dir}/__substg1.0_39FE001F"), &u16s(addr));
            let mut p = vec![0u8; 8];
            p.extend_from_slice(&0x0C15_0003u32.to_le_bytes());
            p.extend_from_slice(&6u32.to_le_bytes());
            p.extend_from_slice(&kind.to_le_bytes());
            p.extend_from_slice(&[0; 4]);
            put(&mut cf, &format!("{dir}/__properties_version1.0"), &p);
        }
        let dir = "/__attach_version1.0_#00000000";
        cf.create_storage(dir).unwrap();
        put(
            &mut cf,
            &format!("{dir}/__substg1.0_3707001F"),
            &u16s("Angebot 2026.pdf"),
        );
        put(
            &mut cf,
            &format!("{dir}/__substg1.0_370E001F"),
            &u16s("application/pdf"),
        );
        put(
            &mut cf,
            &format!("{dir}/__substg1.0_37010102"),
            b"%PDF-1.4 test",
        );
        cf.flush().unwrap();
        cf.into_inner().into_inner()
    }

    #[test]
    fn converts_outlook_message() {
        let msg = sample_msg();
        assert!(is_msg(&msg));
        let eml = to_eml(&msg).unwrap();
        let m = crate::mail::Mail::parse(eml).unwrap();
        assert_eq!(m.subject, "Angebot für Sie");
        assert_eq!(m.from[0].name, "Jürgen Händler");
        assert_eq!(m.from[0].addr, "juergen@haendler.example");
        assert_eq!(m.to[0].addr, "max@example.com");
        assert_eq!(m.cc[0].addr, "team@example.com");
        assert_eq!(m.date.unwrap().ts, 1_793_784_600);
        assert!(m.text.unwrap().contains("anbei das Angebot"));
        assert!(m.html.unwrap().contains("<b>anbei</b>"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name, "Angebot 2026.pdf");
        assert_eq!(m.attachments[0].data, b"%PDF-1.4 test");
        assert!(to_eml(b"not an ole file").is_err());
    }
}
