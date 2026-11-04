//! Header analysis and helpers for the viewer: authentication results (SPF/DKIM/DMARC),
//! warnings about suspicious messages, links of the HTML body, search, formatting.

use std::ops::Range;

use crate::mail::{domain_of, Attachment, Date, Mail};

// ------------------------------------------------------------ authentication

/// One result of an `Authentication-Results` field, e.g. `spf=pass smtp.mailfrom=x@y`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthResult {
    /// `spf`, `dkim`, `dmarc`, `arc`, … (lower case).
    pub method: String,
    /// `pass`, `fail`, `softfail`, `neutral`, `none`, … (lower case).
    pub result: String,
    /// Properties such as `header.d=example.org`.
    pub props: String,
    /// Text of the comments in parentheses.
    pub comment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Weak,
    Neutral,
}

impl AuthResult {
    pub fn verdict(&self) -> Verdict {
        match self.result.as_str() {
            "pass" => Verdict::Pass,
            "fail" | "permerror" | "hardfail" => Verdict::Fail,
            "softfail" | "temperror" | "policy" => Verdict::Weak,
            _ => Verdict::Neutral,
        }
    }

    /// The domain the result is about (`header.d`, `header.from`, `smtp.mailfrom`).
    pub fn domain(&self) -> String {
        for key in ["header.d=", "header.from=", "smtp.mailfrom=", "header.i="] {
            if let Some(v) = self
                .props
                .split_whitespace()
                .find_map(|p| p.strip_prefix(key))
            {
                let v = v.trim_matches(['"', ';']);
                return domain_of(v).unwrap_or_else(|| v.trim_start_matches('@').to_string());
            }
        }
        String::new()
    }
}

/// Splits at `sep` outside of parentheses and quotes.
fn split_outside(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for c in s.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' && depth == 0 {
            quoted = !quoted;
        } else if !quoted && c == '(' {
            depth += 1;
        } else if !quoted && c == ')' {
            depth = depth.saturating_sub(1);
        } else if !quoted && depth == 0 && c == sep {
            out.push(std::mem::take(&mut cur));
            continue;
        }
        cur.push(c);
    }
    out.push(cur);
    out
}

/// Removes comments `( … )` and returns (text, comments).
fn strip_comments(s: &str) -> (String, String) {
    let (mut text, mut comment) = (String::new(), String::new());
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '(' => {
                if depth > 0 {
                    comment.push(c);
                } else if !comment.is_empty() {
                    comment.push_str("; ");
                }
                depth += 1;
            }
            ')' if depth > 0 => {
                depth -= 1;
                if depth > 0 {
                    comment.push(c);
                }
            }
            _ if depth > 0 => comment.push(c),
            _ => text.push(c),
        }
    }
    let norm = |s: String| s.split_whitespace().collect::<Vec<_>>().join(" ");
    (norm(text), norm(comment))
}

/// Parses the value of an `Authentication-Results` field (RFC 8601).
/// Returns (authserv-id, results).
pub fn parse_auth_results(value: &str) -> (String, Vec<AuthResult>) {
    let mut segs = split_outside(value, ';').into_iter();
    let first = segs.next().unwrap_or_default();
    let mut results = Vec::new();
    let mut server = String::new();
    let handle = |seg: &str, results: &mut Vec<AuthResult>| {
        let (text, comment) = strip_comments(seg);
        let mut words = text.split_whitespace();
        let Some((method, result)) = words.next().and_then(|w| w.split_once('=')) else {
            return false;
        };
        if method.contains('.') {
            return false;
        }
        results.push(AuthResult {
            method: method.to_ascii_lowercase(),
            result: result.to_ascii_lowercase(),
            props: words.collect::<Vec<_>>().join(" "),
            comment,
        });
        true
    };
    if !handle(&first, &mut results) {
        server = strip_comments(&first)
            .0
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
    }
    for seg in segs {
        handle(&seg, &mut results);
    }
    results.retain(|r| r.method != "none" && !r.result.is_empty());
    (server, results)
}

/// Results of the topmost `Authentication-Results` field (added by the receiving server),
/// plus `Received-SPF` when there is no SPF result. Returns (authserv-id, results).
pub fn auth_summary(mail: &Mail) -> (String, Vec<AuthResult>) {
    let (server, mut results) = mail
        .get("Authentication-Results")
        .map(parse_auth_results)
        .unwrap_or_default();
    if !results.iter().any(|r| r.method == "spf") {
        if let Some(v) = mail.get("Received-SPF") {
            let (text, comment) = strip_comments(v);
            let mut w = text.split_whitespace();
            if let Some(result) = w.next() {
                results.push(AuthResult {
                    method: "spf".into(),
                    result: result.to_ascii_lowercase(),
                    props: w.collect::<Vec<_>>().join(" "),
                    comment,
                });
            }
        }
    }
    (server, results)
}

// ------------------------------------------------------------------- links

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Link {
    pub text: String,
    pub url: String,
    pub host: String,
    /// Why the link looks deceptive (empty = fine).
    pub warning: String,
}

/// Decodes the common HTML entities.
pub fn unescape_html(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[..rest.len().min(12)].find(';');
        let decoded = end.and_then(|e| {
            let ent = &rest[1..e];
            let c = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            c.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Host of a URL (lower case, without user info and port); for `mailto:` the domain.
pub fn url_host(url: &str) -> String {
    let u = url.trim();
    if let Some(m) = u
        .strip_prefix("mailto:")
        .or_else(|| u.strip_prefix("MAILTO:"))
    {
        return domain_of(m.split('?').next().unwrap_or("")).unwrap_or_default();
    }
    let Some((_, rest)) = u.split_once("://") else {
        return String::new();
    };
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = auth.rsplit('@').next().unwrap_or("");
    let host = if host.starts_with('[') {
        host.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or("")
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn has_userinfo(url: &str) -> bool {
    url.split_once("://")
        .map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("").contains('@'))
        .unwrap_or(false)
}

/// The host a link text pretends to point to (`www.bank.de`, `https://bank.de/login`).
fn text_host(text: &str) -> Option<String> {
    let t = text.trim().trim_end_matches(['.', ',', ')']);
    if t.is_empty() || t.contains(char::is_whitespace) || !t.contains('.') {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(url_host(t)).filter(|h| !h.is_empty());
    }
    if lower.starts_with("www.") {
        return Some(url_host(&format!("http://{t}")));
    }
    None
}

fn same_site(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("www.");
    let b = b.trim_start_matches("www.");
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// The `<a href>` links of an HTML body, in order, without duplicates.
pub fn extract_links(html: &str) -> Vec<Link> {
    let lower = html.to_ascii_lowercase();
    let mut out: Vec<Link> = Vec::new();
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("<a") {
        let start = pos + i;
        pos = start + 2;
        if !lower[pos..].starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let Some(tag_end) = lower[pos..].find('>').map(|e| pos + e) else {
            break;
        };
        let tag = &html[pos..tag_end];
        let tag_l = &lower[pos..tag_end];
        let Some(h) = tag_l.find("href") else {
            pos = tag_end;
            continue;
        };
        let after = tag[h + 4..].trim_start();
        let Some(after) = after.strip_prefix('=') else {
            pos = tag_end;
            continue;
        };
        let after = after.trim_start();
        let url = match after.chars().next() {
            Some(q @ ('"' | '\'')) => after[1..].split(q).next().unwrap_or(""),
            _ => after
                .split(|c: char| c.is_whitespace())
                .next()
                .unwrap_or(""),
        };
        let url = unescape_html(url.trim());
        let close = lower[tag_end..]
            .find("</a")
            .map_or(html.len(), |c| tag_end + c);
        let text = unescape_html(&strip_tags(&html[tag_end + 1..close.max(tag_end + 1)]));
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        pos = close;
        if url.is_empty() || url.starts_with('#') || url.to_ascii_lowercase().starts_with("cid:") {
            continue;
        }
        if out.iter().any(|l| l.url == url) {
            continue;
        }
        let host = url_host(&url);
        let mut warning = String::new();
        if has_userinfo(&url) {
            warning = format!("The address hides its real destination: {host}");
        } else if let Some(th) = text_host(&text) {
            if !host.is_empty() && !same_site(&th, &host) {
                warning = format!("The text shows {th}, but the link goes to {host}");
            }
        }
        out.push(Link {
            text,
            url,
            host,
            warning,
        });
        if out.len() >= 1000 {
            break;
        }
    }
    out
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

// ------------------------------------------------------------------- hints

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Warn,
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hint {
    pub level: Level,
    pub text: String,
}

/// File types that run code when opened.
pub fn is_risky(name: &str) -> bool {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "exe"
            | "com"
            | "bat"
            | "cmd"
            | "scr"
            | "pif"
            | "msi"
            | "msp"
            | "js"
            | "jse"
            | "vbs"
            | "vbe"
            | "wsf"
            | "wsh"
            | "ps1"
            | "hta"
            | "jar"
            | "lnk"
            | "reg"
            | "sh"
            | "bash"
            | "run"
            | "bin"
            | "desktop"
            | "appimage"
            | "deb"
            | "rpm"
            | "apk"
            | "iso"
            | "img"
            | "vhd"
            | "docm"
            | "xlsm"
            | "pptm"
            | "xlam"
            | "dotm"
            | "py"
            | "pl"
            | "elf"
            | "dll"
            | "cpl"
            | "chm"
    )
}

/// Things worth pointing out about a message.
pub fn hints(mail: &Mail, auth: &[AuthResult], links: &[Link], now: i64) -> Vec<Hint> {
    let mut out = Vec::new();
    let warn = |t: String| Hint {
        level: Level::Warn,
        text: t,
    };
    let info = |t: String| Hint {
        level: Level::Info,
        text: t,
    };
    let from = mail.from.first();
    let from_domain = from.and_then(|f| f.domain());
    if from.is_none() {
        out.push(warn("The message has no sender (From).".into()));
    }
    for r in auth {
        match r.verdict() {
            Verdict::Fail => out.push(warn(format!(
                "{} check failed ({}){}.",
                r.method.to_uppercase(),
                r.result,
                dom_suffix(&r.domain())
            ))),
            Verdict::Weak => out.push(warn(format!(
                "{} check not passed ({}){}.",
                r.method.to_uppercase(),
                r.result,
                dom_suffix(&r.domain())
            ))),
            _ => {}
        }
    }
    if auth.is_empty() && !mail.hops.is_empty() {
        out.push(info(
            "No authentication results (SPF/DKIM/DMARC): the receiving server did not record any."
                .into(),
        ));
    }
    if let Some(f) = from {
        // A display name that contains a different address ("PayPal <x@evil>" tricks).
        let n = f.name.to_ascii_lowercase();
        if let Some(addr) = n.split_whitespace().find(|w| w.contains('@')) {
            let addr = addr.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.');
            if !addr.is_empty() && addr != f.addr.to_ascii_lowercase() {
                out.push(warn(format!(
                    "The sender name shows the address {addr}, but the message comes from {}.",
                    f.addr
                )));
            }
        }
    }
    if let (Some(fd), Some(r)) = (&from_domain, mail.reply_to.first()) {
        if let Some(rd) = r.domain() {
            if !same_site(fd, &rd) {
                out.push(warn(format!(
                    "Replies go to a different domain: {} (sender: {fd}).",
                    r.addr
                )));
            }
        }
    }
    if let (Some(fd), Some(rp)) = (&from_domain, mail.get("Return-Path")) {
        if let Some(rd) = domain_of(rp) {
            if !same_site(fd, &rd) {
                out.push(info(format!(
                    "Bounces go to {rd} (Return-Path), the sender is {fd} – usual for newsletters \
                     and mailing services."
                )));
            }
        }
    }
    if let Some(d) = mail.date {
        if d.ts > now + 86_400 {
            out.push(info("The date of the message lies in the future.".into()));
        }
    } else {
        out.push(info("The message has no valid date.".into()));
    }
    let deceptive = links.iter().filter(|l| !l.warning.is_empty()).count();
    if deceptive > 0 {
        out.push(warn(format!(
            "{deceptive} link(s) lead somewhere else than their text shows (see Links)."
        )));
    }
    for a in &mail.attachments {
        if is_risky(&a.name) {
            out.push(warn(format!(
                "The attachment \"{}\" is a program or script type – only open it if you trust \
                 the sender.",
                a.name
            )));
        } else if a.name.matches('.').count() >= 2
            && a.name.rsplit('.').nth(1).is_some_and(|e| {
                matches!(
                    e.to_ascii_lowercase().as_str(),
                    "pdf" | "doc" | "docx" | "jpg" | "png" | "txt" | "xls" | "xlsx"
                )
            })
            && !a.is_image()
            && a.mime != "application/pdf"
        {
            out.push(warn(format!(
                "The attachment \"{}\" has a double file extension.",
                a.name
            )));
        }
    }
    out
}

fn dom_suffix(d: &str) -> String {
    if d.is_empty() {
        String::new()
    } else {
        format!(" for {d}")
    }
}

// ------------------------------------------------------------------ search

/// Byte ranges of all case-insensitive matches of `needle` in `hay`.
pub fn find_all(hay: &str, needle: &str) -> Vec<Range<usize>> {
    let fold = |c: char| c.to_lowercase().next().unwrap_or(c);
    let n: Vec<char> = needle.chars().map(fold).collect();
    if n.is_empty() {
        return Vec::new();
    }
    let chars: Vec<(usize, char)> = hay.char_indices().map(|(i, c)| (i, fold(c))).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + n.len() <= chars.len() {
        if chars[i..i + n.len()]
            .iter()
            .map(|(_, c)| *c)
            .eq(n.iter().copied())
        {
            let start = chars[i].0;
            let end = chars.get(i + n.len()).map_or(hay.len(), |(b, _)| *b);
            out.push(start..end);
            i += n.len();
            if out.len() >= 10_000 {
                break;
            }
        } else {
            i += 1;
        }
    }
    out
}

// -------------------------------------------------------------- formatting

pub fn human_size(n: usize) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if v < 10.0 {
        format!("{v:.1} {}", UNITS[u])
    } else {
        format!("{v:.0} {}", UNITS[u])
    }
}

/// The date as written in the message (with its zone offset).
pub fn fmt_original(d: Date) -> String {
    let Some(off) = chrono::FixedOffset::east_opt(d.offset_min * 60) else {
        return String::new();
    };
    chrono::DateTime::from_timestamp(d.ts, 0)
        .map(|t| {
            t.with_timezone(&off)
                .format("%a, %d %b %Y %H:%M:%S %z")
                .to_string()
        })
        .unwrap_or_default()
}

/// The date in the local time zone.
pub fn fmt_local(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%a, %d.%m.%Y %H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

pub fn fmt_time_local(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

/// "3 days ago", "in 5 minutes".
pub fn relative(ts: i64, now: i64) -> String {
    let d = now - ts;
    let a = d.abs();
    let (n, unit) = match a {
        0..=59 => return "just now".into(),
        60..=3599 => (a / 60, "minute"),
        3600..=86_399 => (a / 3600, "hour"),
        86_400..=2_591_999 => (a / 86_400, "day"),
        2_592_000..=31_535_999 => (a / 2_592_000, "month"),
        _ => (a / 31_536_000, "year"),
    };
    let s = if n == 1 { "" } else { "s" };
    if d >= 0 {
        format!("{n} {unit}{s} ago")
    } else {
        format!("in {n} {unit}{s}")
    }
}

/// Delay between two hops: "+2 s", "+1 min 5 s", "−3 s" (clock skew).
pub fn fmt_delay(secs: i64) -> String {
    let sign = if secs < 0 { "−" } else { "+" };
    let a = secs.abs();
    let body = if a < 60 {
        format!("{a} s")
    } else if a < 3600 {
        format!("{} min {} s", a / 60, a % 60)
    } else if a < 86_400 {
        format!("{} h {} min", a / 3600, (a % 3600) / 60)
    } else {
        format!("{} d {} h", a / 86_400, (a % 86_400) / 3600)
    };
    format!("{sign}{body}")
}

/// A file name that is safe to write (no path separators or control characters).
pub fn safe_file_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == '\0' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim().trim_start_matches('.').to_string();
    if s.is_empty() {
        "attachment".into()
    } else {
        s
    }
}

/// HTML body with `cid:` images replaced by data URIs (for viewing in a browser).
pub fn html_with_inline_images(html: &str, attachments: &[Attachment]) -> String {
    use base64::Engine;
    let mut out = html.to_string();
    for a in attachments.iter().filter(|a| !a.content_id.is_empty()) {
        let cid = format!("cid:{}", a.content_id);
        if out.contains(&cid) {
            let uri = format!(
                "data:{};base64,{}",
                a.mime,
                base64::engine::general_purpose::STANDARD.encode(&a.data)
            );
            out = out.replace(&cid, &uri);
        }
    }
    out
}

/// The message as plain text: the main header fields, then the body.
pub fn as_text(mail: &Mail, body: &str) -> String {
    let list =
        |v: &[crate::mail::Mailbox]| v.iter().map(|m| m.display()).collect::<Vec<_>>().join(", ");
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        if !v.is_empty() {
            s.push_str(&format!("{k:<9}{v}\n"));
        }
    };
    line("From:", list(&mail.from));
    line("To:", list(&mail.to));
    line("Cc:", list(&mail.cc));
    line("Date:", mail.date.map(fmt_original).unwrap_or_default());
    line("Subject:", mail.subject.clone());
    let names: Vec<_> = mail.attachments.iter().map(|a| a.name.as_str()).collect();
    line("Attach.:", names.join(", "));
    s.push('\n');
    s.push_str(body);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_results() {
        let v = "mx.google.com; dkim=pass header.i=@github.com header.s=pf2023 header.b=x; \
                 spf=softfail (google.com: domain of a@b.c does not designate 1.2.3.4) \
                 smtp.mailfrom=a@b.c; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=evil.com";
        let (server, r) = parse_auth_results(v);
        assert_eq!(server, "mx.google.com");
        assert_eq!(r.len(), 3);
        assert_eq!(
            (r[0].method.as_str(), r[0].verdict()),
            ("dkim", Verdict::Pass)
        );
        assert_eq!(r[0].domain(), "github.com");
        assert_eq!(r[1].verdict(), Verdict::Weak);
        assert_eq!(r[1].domain(), "b.c");
        assert!(r[1].comment.starts_with("google.com: domain of"));
        assert_eq!(
            (r[2].verdict(), r[2].domain().as_str()),
            (Verdict::Fail, "evil.com")
        );
        let (s, r) = parse_auth_results("mail.example.com 1; none");
        assert_eq!((s.as_str(), r.len()), ("mail.example.com", 0));
    }

    #[test]
    fn links_and_deception() {
        let html = r##"<p><A HREF="https://evil.example.net/x?a=1&amp;b=2">https://bank.example.de/login</a>
            <a class=x href='https://www.bank.example.de/'>www.bank.example.de</a>
            <a href=https://user@evil.test/>Bank</a><a href="#top">top</a>
            <a href="mailto:Info@Example.org?subject=x">Mail <b>us</b></a></p>"##;
        let l = extract_links(html);
        assert_eq!(l.len(), 4);
        assert_eq!(l[0].url, "https://evil.example.net/x?a=1&b=2");
        assert_eq!(l[0].host, "evil.example.net");
        assert!(l[0].warning.contains("bank.example.de"));
        assert!(l[1].warning.is_empty(), "same site with and without www");
        assert!(l[2].warning.contains("hides"));
        assert_eq!(
            (l[3].host.as_str(), l[3].text.as_str()),
            ("example.org", "Mail us")
        );
    }

    #[test]
    fn search() {
        let r = find_all("Grüße, GRÜSSE und grüße", "grüße");
        assert_eq!(r.len(), 2);
        assert_eq!(&"Grüße, GRÜSSE und grüße"[r[1].clone()], "grüße");
        assert!(find_all("abc", "").is_empty());
        assert_eq!(find_all("aaaa", "aa").len(), 2);
    }

    #[test]
    fn formatting() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(25 * 1024 * 1024), "25 MB");
        assert_eq!(relative(0, 30), "just now");
        assert_eq!(relative(0, 7200), "2 hours ago");
        assert_eq!(relative(86_400, 0), "in 1 day");
        assert_eq!(fmt_delay(5), "+5 s");
        assert_eq!(fmt_delay(65), "+1 min 5 s");
        assert_eq!(fmt_delay(-3), "−3 s");
        assert_eq!(
            fmt_original(Date {
                ts: 1_793_784_600,
                offset_min: 60
            }),
            "Wed, 04 Nov 2026 10:30:00 +0100"
        );
        assert_eq!(safe_file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(unescape_html("a&lt;b&#x263A;&#65;&bogus;"), "a<b☺A&bogus;");
        assert_eq!(url_host("https://u:p@Host.Example:8080/p"), "host.example");
        assert!(is_risky("invoice.PDF.exe") && !is_risky("report.pdf"));
    }

    #[test]
    fn sample_hints() {
        let m = Mail::parse(include_bytes!("../tests/data/sample.eml").to_vec()).unwrap();
        let (server, auth) = auth_summary(&m);
        assert_eq!(server, "mx.example.com");
        assert_eq!(auth.len(), 3);
        assert!(auth.iter().all(|r| r.verdict() == Verdict::Pass));
        let links = extract_links(m.html.as_deref().unwrap());
        assert_eq!(links.len(), 2);
        let h = hints(&m, &auth, &links, 1_793_784_600);
        let texts: Vec<_> = h.iter().map(|h| h.text.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.starts_with("Replies go to")),
            "{texts:?}"
        );
        assert!(texts.iter().any(|t| t.contains("link(s)")), "{texts:?}");
        assert!(
            !texts.iter().any(|t| t.starts_with("Bounces")),
            "subdomain is fine"
        );
        let html = html_with_inline_images(m.html.as_deref().unwrap(), &m.attachments);
        assert!(html.contains("src=\"data:image/png;base64,iVBOR"));
    }
}
