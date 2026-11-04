//! E-mail model: everything the viewer shows, extracted once from the parsed message
//! (mail-parser), so the user interface works on plain owned data.

use mail_parser::{
    AddressList, DateTime, HeaderForm, Host, MessageParser, MessagePart, MessageRef, PartKind,
};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mailbox {
    pub name: String,
    pub addr: String,
}

impl Mailbox {
    /// `Name <addr>`, or whichever of the two is present.
    pub fn display(&self) -> String {
        match (self.name.is_empty(), self.addr.is_empty()) {
            (true, _) => self.addr.clone(),
            (false, true) => self.name.clone(),
            (false, false) => format!("{} <{}>", self.name, self.addr),
        }
    }

    pub fn domain(&self) -> Option<String> {
        domain_of(&self.addr)
    }
}

/// Domain part of an address, lower case.
pub fn domain_of(addr: &str) -> Option<String> {
    let d = addr
        .trim()
        .trim_matches(['<', '>'])
        .rsplit_once('@')?
        .1
        .trim();
    (!d.is_empty()).then(|| d.to_ascii_lowercase())
}

/// A point in time with the zone offset it was written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
    pub ts: i64,
    pub offset_min: i32,
}

impl Date {
    fn from_mp(d: DateTime) -> Option<Date> {
        if !d.is_valid() {
            return None;
        }
        let off = d.tz_hour as i32 * 60 + d.tz_minute as i32;
        Some(Date {
            ts: d.to_timestamp(),
            offset_min: if d.tz_before_gmt { -off } else { off },
        })
    }
}

/// One header field.
#[derive(Clone, Debug, Default)]
pub struct Field {
    pub name: String,
    /// Unfolded, with RFC 2047 encoded words decoded.
    pub value: String,
    /// Unfolded, as written.
    pub raw: String,
}

/// One `Received:` hop.
#[derive(Clone, Debug, Default)]
pub struct Hop {
    pub from: String,
    pub from_ip: String,
    pub by: String,
    pub with: String,
    pub tls: String,
    pub id: String,
    pub for_: String,
    pub date: Option<Date>,
    pub raw: String,
}

#[derive(Clone, Debug, Default)]
pub struct Attachment {
    pub name: String,
    /// `type/subtype`, lower case.
    pub mime: String,
    pub data: Vec<u8>,
    pub inline: bool,
    /// Content-ID without the angle brackets (referenced as `cid:` in HTML).
    pub content_id: String,
    /// A forwarded message (`message/rfc822`).
    pub is_message: bool,
}

impl Attachment {
    pub fn is_image(&self) -> bool {
        self.mime.starts_with("image/")
    }

    pub fn is_text(&self) -> bool {
        self.mime.starts_with("text/")
            || matches!(
                self.mime.as_str(),
                "application/json" | "application/xml" | "application/pgp-signature"
            )
    }
}

/// A node of the MIME tree (flattened, with its depth).
#[derive(Clone, Debug, Default)]
pub struct Part {
    pub depth: usize,
    pub mime: String,
    pub name: String,
    pub size: usize,
    pub encoding: String,
    pub charset: String,
    pub role: String,
}

#[derive(Clone, Debug, Default)]
pub struct Mail {
    pub raw: Vec<u8>,
    pub subject: String,
    pub from: Vec<Mailbox>,
    pub sender: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub date: Option<Date>,
    pub message_id: String,
    pub fields: Vec<Field>,
    /// The header block as written.
    pub header_text: String,
    /// Plain-text body (the text/plain parts).
    pub text: Option<String>,
    /// HTML body (the text/html parts, as HTML source).
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub parts: Vec<Part>,
    /// Received hops in chronological order (the first server first).
    pub hops: Vec<Hop>,
}

impl Mail {
    pub fn parse(raw: Vec<u8>) -> Result<Mail, String> {
        let mut mail = {
            let msg = MessageParser::new()
                .parse(&raw)
                .ok_or("The file is empty or not an e-mail message.")?;
            if msg.header_count() == 0 {
                return Err("The file contains no e-mail header fields.".into());
            }
            extract(msg.root())
        };
        mail.raw = raw;
        Ok(mail)
    }

    /// All values of a header field (case-insensitive name), top to bottom.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Field> + 'a {
        self.fields
            .iter()
            .filter(move |f| f.name.eq_ignore_ascii_case(name))
    }

    /// The first value of a header field.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value.as_str())
    }
}

/// Joins folded header lines.
pub fn unfold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for line in s.split('\n') {
        let line = line.trim_end_matches('\r');
        if out.is_empty() && !pending_space {
            out.push_str(line.trim());
        } else {
            let t = line.trim();
            if !t.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(t);
            }
        }
        pending_space = true;
    }
    out.trim().to_string()
}

fn boxes(list: Option<AddressList<'_>>) -> Vec<Mailbox> {
    list.map(|l| {
        l.mailboxes()
            .map(|m| Mailbox {
                name: m.name().unwrap_or("").trim().to_string(),
                addr: m.address().unwrap_or("").trim().to_string(),
            })
            .filter(|m| !m.name.is_empty() || !m.addr.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn host(h: Option<Host<'_>>) -> String {
    match h {
        Some(Host::Name(n)) => n.to_string(),
        Some(Host::IpAddr(ip)) => ip.to_string(),
        None => String::new(),
    }
}

fn mime_of(p: &MessagePart<'_>) -> String {
    match p.content_type() {
        Some(ct) => match ct.subtype() {
            Some(st) => format!("{}/{}", ct.ctype(), st).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        },
        None if p.is_message() => "message/rfc822".into(),
        None => "text/plain".into(),
    }
}

fn extract(root: MessageRef<'_>) -> Mail {
    let headers = root.headers();
    let mut fields = Vec::new();
    let mut hops = Vec::new();
    for h in headers.iter() {
        let raw_bytes = h.raw_value();
        let raw = unfold(&String::from_utf8_lossy(raw_bytes));
        let parsed = HeaderForm::Text.parse(raw_bytes);
        let value = parsed
            .value()
            .as_text()
            .map(unfold)
            .filter(|v| !v.is_empty() || raw.is_empty())
            .unwrap_or_else(|| raw.clone());
        let name = h.raw_name().trim().to_string();
        if name.eq_ignore_ascii_case("Received") {
            let mut hop = Hop {
                raw: raw.clone(),
                ..Default::default()
            };
            if let Some(r) = HeaderForm::Received.parse(raw_bytes).value().as_received() {
                hop.from = host(r.from());
                if hop.from.is_empty() {
                    hop.from = host(r.helo());
                }
                hop.from_ip = r.from_ip().map(|ip| ip.to_string()).unwrap_or_default();
                // "from [10.0.0.12] (pc12.lan [10.0.0.12])": show the reverse name.
                if hop
                    .from
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok()
                {
                    if let Some(rev) = r.from_iprev().filter(|n| !n.is_empty()) {
                        hop.from = rev.to_string();
                    }
                }
                hop.by = host(r.by());
                hop.with = r.with().map(|w| w.as_str().to_string()).unwrap_or_default();
                hop.tls = match (r.tls_version(), r.tls_cipher()) {
                    (Some(v), Some(c)) => format!("{} {c}", v.as_str()),
                    (Some(v), None) => v.as_str().to_string(),
                    (None, Some(c)) => c.to_string(),
                    (None, None) => String::new(),
                };
                hop.id = r.id().unwrap_or("").to_string();
                hop.for_ = r.for_().unwrap_or("").to_string();
                hop.date = r.date().and_then(Date::from_mp);
            }
            hops.push(hop);
        }
        fields.push(Field { name, value, raw });
    }
    hops.reverse();

    let join = |parts: Vec<String>| {
        let s = parts.join("\n");
        (!s.trim().is_empty()).then_some(s)
    };
    let text = join(
        root.text_body()
            .filter(|p| matches!(p.kind(), PartKind::Text))
            .filter_map(|p| p.text().map(|t| t.into_owned()))
            .collect(),
    );
    let html = join(
        root.html_body()
            .filter(|p| matches!(p.kind(), PartKind::Html))
            .filter_map(|p| p.text().map(|t| t.into_owned()))
            .collect(),
    );

    let mut attachments = Vec::new();
    for (i, p) in root.attachments().enumerate() {
        let mime = mime_of(&p);
        let nested = p.nested();
        let is_message = nested.is_some() || mime == "message/rfc822";
        let name = p
            .attachment_name()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .or_else(|| {
                nested
                    .and_then(|m| m.subject().map(|s| format!("{}.eml", s.trim())))
                    .filter(|n| n.len() > 4)
            })
            .unwrap_or_else(|| format!("part-{}{}", i + 1, default_ext(&mime)));
        let data = match nested {
            // The nested message itself (with its header block).
            Some(m) => m.raw().to_vec(),
            None => p.decoded().into_owned(),
        };
        attachments.push(Attachment {
            name,
            mime,
            data,
            inline: p.is_inline(),
            content_id: p
                .content_id()
                .unwrap_or("")
                .trim()
                .trim_matches(['<', '>'])
                .to_string(),
            is_message,
        });
    }

    let mut parts = Vec::new();
    walk(&root.root_part(), 0, &mut parts);

    Mail {
        raw: Vec::new(),
        subject: root.subject().unwrap_or("").trim().to_string(),
        from: boxes(root.from()),
        sender: boxes(root.sender()),
        to: boxes(root.to()),
        cc: boxes(root.cc()),
        bcc: boxes(root.bcc()),
        reply_to: boxes(root.reply_to()),
        date: root.date().and_then(Date::from_mp),
        message_id: root.message_id().unwrap_or("").to_string(),
        fields,
        header_text: String::from_utf8_lossy(root.root_part().raw_headers()).into_owned(),
        text,
        html,
        attachments,
        parts,
        hops,
    }
}

fn walk(p: &MessagePart<'_>, depth: usize, out: &mut Vec<Part>) {
    let role = if p.is_multipart() {
        String::new()
    } else if p.is_attachment() {
        if p.is_inline() {
            "inline".into()
        } else {
            "attachment".into()
        }
    } else if p.in_text_body() || p.in_html_body() {
        "body".into()
    } else {
        String::new()
    };
    out.push(Part {
        depth,
        mime: mime_of(p),
        name: p.attachment_name().unwrap_or("").to_string(),
        size: if p.is_multipart() {
            p.raw().len()
        } else {
            p.decoded_len()
        },
        encoding: p
            .content_transfer_encoding()
            .unwrap_or("")
            .to_ascii_lowercase(),
        charset: p
            .content_type()
            .and_then(|ct| ct.attribute("charset"))
            .unwrap_or("")
            .to_string(),
        role,
    });
    if let Some(m) = p.nested() {
        walk(&m.root_part(), depth + 1, out);
    }
    for c in p.children() {
        walk(&c, depth + 1, out);
    }
}

fn default_ext(mime: &str) -> &'static str {
    match mime {
        "message/rfc822" => ".eml",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "text/calendar" => ".ics",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "application/pdf" => ".pdf",
        _ => ".bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &[u8] = include_bytes!("../tests/data/sample.eml");

    #[test]
    fn parses_sample() {
        let m = Mail::parse(SAMPLE.to_vec()).unwrap();
        assert_eq!(m.subject, "Quartalsbericht Q3 – Entwurf ☕");
        assert_eq!(
            m.from,
            vec![Mailbox {
                name: "Erika Mustermann".into(),
                addr: "erika@example.org".into()
            }]
        );
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.cc[0].addr, "team@example.org");
        assert_eq!(m.reply_to[0].domain().as_deref(), Some("example.net"));
        let d = m.date.unwrap();
        assert_eq!((d.ts, d.offset_min), (1_793_784_600, 60));
        assert_eq!(m.message_id, "20261104103000.4711@example.org");
        assert!(m.text.as_deref().unwrap().contains("anbei der Entwurf"));
        assert!(m.html.as_deref().unwrap().contains("<b>Entwurf</b>"));
        // Attachments in document order: inline image, PDF, forwarded message.
        let names: Vec<_> = m.attachments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["logo.png", "Bericht Q3.pdf", "Weitergeleitet.eml"]);
        assert_eq!(&m.attachments[1].data[..5], b"%PDF-");
        assert!(m.attachments[0].is_image() && m.attachments[0].inline);
        assert_eq!(m.attachments[0].content_id, "logo@example.org");
        let fwd = &m.attachments[2];
        assert!(fwd.is_message);
        let nested = Mail::parse(fwd.data.clone()).unwrap();
        assert_eq!(nested.subject, "Alte Zahlen");
        // Header fields: decoded and unfolded.
        assert_eq!(m.get("subject"), Some("Quartalsbericht Q3 – Entwurf ☕"));
        assert!(m.all("Received").count() == 3 && m.hops.len() == 3);
        assert_eq!(m.hops[0].by, "smtp.example.org");
        assert_eq!(m.hops[0].from, "pc12.lan.example.org");
        assert_eq!(m.hops[0].from_ip, "10.0.0.12");
        assert_eq!(m.hops[2].by, "mx.example.com");
        assert!(m.hops[2].date.unwrap().ts > m.hops[0].date.unwrap().ts);
        assert!(m.header_text.starts_with("Return-Path:"));
        assert!(m.parts[0].mime == "multipart/mixed" && m.parts.len() >= 7);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Mail::parse(Vec::new()).is_err());
    }

    #[test]
    fn unfolding() {
        assert_eq!(unfold(" a\r\n\tb\r\n  c\r\n"), "a b c");
        assert_eq!(domain_of("<X@Example.ORG>").as_deref(), Some("example.org"));
        assert_eq!(domain_of("nobody"), None);
    }
}
