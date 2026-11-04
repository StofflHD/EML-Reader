//! Deeper header analysis: the sender's IP address, implausible timestamps, the ARC chain
//! and the verdicts of spam filters (SpamAssassin, Rspamd, Microsoft).

use std::net::IpAddr;

use crate::analysis::{parse_auth_results, AuthResult};
use crate::mail::Mail;

/// Private, loopback, link-local or shared address space.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The first public IP address of the route (chronological): the sender's server or
/// computer as seen by the first server outside its network. (hop index, ip)
pub fn sender_ip(mail: &Mail) -> Option<(usize, IpAddr)> {
    mail.hops.iter().enumerate().find_map(|(i, h)| {
        let ip: IpAddr = h.from_ip.parse().ok()?;
        (!is_private(&ip)).then_some((i, ip))
    })
}

/// Implausible times in the route and the Date field.
pub fn time_anomalies(mail: &Mail) -> Vec<String> {
    let mut out = Vec::new();
    let dated: Vec<(usize, i64)> = mail
        .hops
        .iter()
        .enumerate()
        .filter_map(|(i, h)| h.date.map(|d| (i, d.ts)))
        .collect();
    for w in dated.windows(2) {
        let ((a, ta), (b, tb)) = (w[0], w[1]);
        let d = tb - ta;
        if d < -60 {
            out.push(format!(
                "Hop {} is dated {} before hop {} (wrong clock or forged hop).",
                b + 1,
                crate::analysis::fmt_delay(d).trim_start_matches('−'),
                a + 1
            ));
        } else if d > 3600 {
            out.push(format!(
                "The message waited {} between hop {} and hop {}.",
                crate::analysis::fmt_delay(d).trim_start_matches('+'),
                a + 1,
                b + 1
            ));
        }
    }
    if let (Some(date), Some(&(i, first))) = (mail.date, dated.first()) {
        if date.ts > first + 600 {
            out.push(format!(
                "The Date field is {} later than the first server received the message (hop {}).",
                crate::analysis::fmt_delay(date.ts - first).trim_start_matches('+'),
                i + 1
            ));
        } else if first - date.ts > 86_400 {
            out.push(format!(
                "The message reached the first server {} after its Date.",
                crate::analysis::fmt_delay(first - date.ts).trim_start_matches('+')
            ));
        }
    }
    out
}

// --------------------------------------------------------------------- ARC

/// One instance (`i=`) of the ARC chain (forwarding servers that vouch for the checks).
#[derive(Clone, Debug, Default)]
pub struct ArcSet {
    pub instance: u32,
    /// `cv=` of the seal: none (first), pass, fail.
    pub cv: String,
    pub sealer: String,
    pub signer: String,
    pub server: String,
    pub results: Vec<AuthResult>,
}

fn instance_of(value: &str) -> Option<u32> {
    crate::dkim::tag(value, "i")?.parse().ok()
}

pub fn arc_chain(mail: &Mail) -> Vec<ArcSet> {
    let mut sets: Vec<ArcSet> = Vec::new();
    fn get(sets: &mut Vec<ArcSet>, i: u32) -> &mut ArcSet {
        if let Some(p) = sets.iter().position(|s| s.instance == i) {
            return &mut sets[p];
        }
        sets.push(ArcSet {
            instance: i,
            ..Default::default()
        });
        sets.last_mut().unwrap()
    }
    for f in &mail.fields {
        let name = f.name.to_ascii_lowercase();
        match name.as_str() {
            "arc-seal" => {
                if let Some(i) = instance_of(&f.raw) {
                    let s = get(&mut sets, i);
                    s.cv = crate::dkim::tag(&f.raw, "cv")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    s.sealer = crate::dkim::tag(&f.raw, "d").unwrap_or_default();
                }
            }
            "arc-message-signature" => {
                if let Some(i) = instance_of(&f.raw) {
                    get(&mut sets, i).signer = crate::dkim::tag(&f.raw, "d").unwrap_or_default();
                }
            }
            "arc-authentication-results" => {
                // "i=1; mx.google.com; dkim=pass …"
                let v = f.value.trim();
                if let Some(rest) = v.strip_prefix("i=").or_else(|| v.strip_prefix("I=")) {
                    if let Some((num, tail)) = rest.split_once(';') {
                        if let Ok(i) = num.trim().parse() {
                            let (server, results) = parse_auth_results(tail);
                            let s = get(&mut sets, i);
                            s.server = server;
                            s.results = results;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    sets.sort_by_key(|s| s.instance);
    sets
}

// -------------------------------------------------------------------- spam

#[derive(Clone, Debug, Default)]
pub struct SpamRule {
    pub name: String,
    pub score: Option<f64>,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct SpamInfo {
    pub engine: String,
    pub verdict: String,
    pub score: Option<f64>,
    pub required: Option<f64>,
    pub rules: Vec<SpamRule>,
}

fn kv_num(s: &str, key: &str) -> Option<f64> {
    s.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .find_map(|w| w.strip_prefix(key))
        .and_then(|v| v.parse().ok())
}

/// What a Microsoft anti-spam field value means.
fn ms_explain(key: &str, val: &str) -> String {
    match (key, val) {
        ("SCL", v) => match v.parse::<i32>().unwrap_or(-2) {
            -1 => "spam confidence level −1: trusted sender, filtering skipped".into(),
            0 | 1 => format!("spam confidence level {v}: not spam"),
            5 | 6 => format!("spam confidence level {v}: spam"),
            9 => "spam confidence level 9: high confidence spam".into(),
            _ => format!("spam confidence level {v}"),
        },
        ("SFV", "NSPM") => "spam filter verdict: not spam".into(),
        ("SFV", "SPM") => "spam filter verdict: spam".into(),
        ("SFV", "SKS") => "marked as spam by a mail flow rule".into(),
        ("SFV", "SKN") => "marked as not spam (allow list or rule)".into(),
        ("SFV", "SKI") => "skipped: intra-organisation message".into(),
        ("SFV", "BLK") => "sender is on the user's blocked list".into(),
        ("SFV", "SFE") => "sender is on the user's safe list".into(),
        ("CTRY", v) => format!("country of the connecting IP: {v}"),
        ("LANG", v) => format!("language of the message: {v}"),
        ("CIP", v) => format!("connecting IP: {v}"),
        ("IPV", "NLI") => "IP address not on any reputation list".into(),
        ("IPV", "CAL") => "IP address on the allow list".into(),
        ("PTR", v) => format!("reverse DNS of the IP: {v}"),
        ("CAT", v) => format!(
            "category: {}",
            match v {
                "NONE" => "none",
                "SPM" => "spam",
                "HSPM" => "high confidence spam",
                "PHSH" => "phishing",
                "HPHSH" => "high confidence phishing",
                "BULK" => "bulk mail",
                "MALW" => "malware",
                "SPOOF" => "spoofing",
                "DIMP" => "domain impersonation",
                "UIMP" => "user impersonation",
                _ => v,
            }
        ),
        ("BCL", v) => format!("bulk complaint level {v} (0 = no bulk mail, 9 = many complaints)"),
        ("SRV", "BULK") => "classified as bulk mail".into(),
        _ => String::new(),
    }
}

pub fn spam_info(mail: &Mail) -> Vec<SpamInfo> {
    let mut out = Vec::new();
    // SpamAssassin
    if let Some(status) = mail.get("X-Spam-Status") {
        let mut s = SpamInfo {
            engine: "SpamAssassin".into(),
            verdict: status.split([',', ' ']).next().unwrap_or("").to_string(),
            score: kv_num(status, "score=").or_else(|| kv_num(status, "hits=")),
            required: kv_num(status, "required="),
            ..Default::default()
        };
        if let Some(t) = status
            .split_whitespace()
            .find_map(|w| w.strip_prefix("tests="))
        {
            // tests may be folded with spaces after commas
            let start = status.find("tests=").unwrap() + 6;
            let rest = &status[start..];
            let end = rest
                .find(" autolearn=")
                .or_else(|| rest.find(" version="))
                .unwrap_or(rest.len());
            let _ = t;
            s.rules = rest[..end]
                .split(',')
                .map(|r| r.trim())
                .filter(|r| !r.is_empty() && *r != "none")
                .map(|r| SpamRule {
                    name: r.to_string(),
                    ..Default::default()
                })
                .collect();
        }
        // X-Spam-Report: " *  3.5 BAYES_99 BODY: Bayes spam probability"
        if let Some(report) = mail.all("X-Spam-Report").next() {
            let text = report.raw.replace('*', "\n");
            for line in text.lines() {
                let mut w = line.split_whitespace();
                let (Some(score), Some(name)) = (w.next(), w.next()) else {
                    continue;
                };
                let Ok(score) = score.parse::<f64>() else {
                    continue;
                };
                let detail = w.collect::<Vec<_>>().join(" ");
                match s.rules.iter_mut().find(|r| r.name == name) {
                    Some(r) => {
                        r.score = Some(score);
                        r.detail = detail;
                    }
                    None => s.rules.push(SpamRule {
                        name: name.to_string(),
                        score: Some(score),
                        detail,
                    }),
                }
            }
        }
        out.push(s);
    } else if let Some(score) = mail.get("X-Spam-Score") {
        out.push(SpamInfo {
            engine: "Spam filter".into(),
            verdict: mail.get("X-Spam-Flag").unwrap_or("").to_string(),
            score: score.trim().parse().ok(),
            ..Default::default()
        });
    }
    // Rspamd: "default: False [3.40 / 15.00]; R_SPF_ALLOW(-0.20)[+ip4:…]; …"
    if let Some(res) = mail
        .get("X-Spamd-Result")
        .or_else(|| mail.get("X-Rspamd-Result"))
    {
        let mut s = SpamInfo {
            engine: "Rspamd".into(),
            ..Default::default()
        };
        let mut parts = res.split(';');
        if let Some(head) = parts.next() {
            if let Some((v, nums)) = head.split_once('[') {
                s.verdict = v.split(':').nth(1).unwrap_or(v).trim().to_string();
                let nums = nums.trim_end_matches(']');
                let mut n = nums.split('/').map(|x| x.trim().parse::<f64>().ok());
                s.score = n.next().flatten();
                s.required = n.next().flatten();
            }
        }
        for p in parts {
            let p = p.trim();
            let Some(open) = p.find('(') else { continue };
            let name = p[..open].trim().to_string();
            let close = p[open..].find(')').map_or(p.len(), |c| open + c);
            let score = p[open + 1..close].parse().ok();
            let detail = p[close..]
                .trim_start_matches(')')
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            s.rules.push(SpamRule {
                name,
                score,
                detail,
            });
        }
        s.rules.sort_by(|a, b| {
            b.score
                .unwrap_or(0.0)
                .abs()
                .partial_cmp(&a.score.unwrap_or(0.0).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.push(s);
    } else if let Some(score) = mail.get("X-Rspamd-Score") {
        out.push(SpamInfo {
            engine: "Rspamd".into(),
            score: score.trim().parse().ok(),
            ..Default::default()
        });
    }
    // Microsoft 365 / Exchange Online
    let ms = mail
        .get("X-Forefront-Antispam-Report")
        .or_else(|| mail.get("X-Microsoft-Antispam-Mailbox-Delivery"));
    let scl = mail.get("X-MS-Exchange-Organization-SCL");
    if ms.is_some() || scl.is_some() {
        let mut s = SpamInfo {
            engine: "Microsoft 365".into(),
            ..Default::default()
        };
        for part in ms.unwrap_or("").split(';') {
            if let Some((k, v)) = part.split_once(':') {
                let (k, v) = (k.trim().to_ascii_uppercase(), v.trim());
                if v.is_empty() {
                    continue;
                }
                let detail = ms_explain(&k, v);
                if k == "SCL" {
                    s.score = v.parse().ok();
                }
                if k == "SFV" {
                    s.verdict = v.to_string();
                }
                if !detail.is_empty() {
                    s.rules.push(SpamRule {
                        name: format!("{k}:{v}"),
                        score: None,
                        detail,
                    });
                }
            }
        }
        if let Some(scl) = scl {
            if s.score.is_none() {
                s.score = scl.trim().parse().ok();
                s.rules.push(SpamRule {
                    name: format!("SCL:{}", scl.trim()),
                    score: None,
                    detail: ms_explain("SCL", scl.trim()),
                });
            }
        }
        s.required = Some(5.0);
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(headers: &str) -> Mail {
        Mail::parse(format!("{headers}From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n").into_bytes())
            .unwrap()
    }

    #[test]
    fn private_ranges() {
        for ip in [
            "10.1.2.3",
            "192.168.0.1",
            "172.20.0.1",
            "127.0.0.1",
            "100.64.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_private(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.0.2.25", "8.8.8.8", "2a00:1450::1"] {
            assert!(!is_private(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn sample_route() {
        let m = Mail::parse(include_bytes!("../tests/data/sample.eml").to_vec()).unwrap();
        let (i, ip) = sender_ip(&m).unwrap();
        assert_eq!((i, ip.to_string().as_str()), (1, "192.0.2.25"));
        assert!(time_anomalies(&m).is_empty());
    }

    #[test]
    fn spam_reports() {
        let m = mail(
            "X-Spam-Status: Yes, score=7.2 required=5.0 tests=BAYES_99,\r\n\tHTML_MESSAGE,URIBL_BLACK autolearn=no version=3.4.6\r\n\
             X-Spam-Report: \r\n\t*  3.5 BAYES_99 BODY: Bayes spam probability is 99 to 100%\r\n\t*  1.7 URIBL_BLACK Contains an URL listed in the URIBL blacklist\r\n\
             X-Spamd-Result: default: False [3.40 / 15.00]; R_SPF_ALLOW(-0.20)[+ip4:192.0.2.0/24]; BAYES_SPAM(5.10)[99.9%]; MIME_GOOD(-0.10)[text/plain]\r\n\
             X-Forefront-Antispam-Report: CIP:192.0.2.25;CTRY:DE;LANG:de;SCL:1;SRV:;IPV:NLI;SFV:NSPM;CAT:NONE;\r\n",
        );
        let s = spam_info(&m);
        assert_eq!(s.len(), 3);
        assert_eq!(
            (s[0].verdict.as_str(), s[0].score, s[0].required),
            ("Yes", Some(7.2), Some(5.0))
        );
        assert_eq!(s[0].rules.len(), 3);
        assert_eq!(s[0].rules[0].score, Some(3.5));
        assert!(s[0].rules[0].detail.starts_with("BODY: Bayes"));
        assert_eq!(
            (s[1].score, s[1].rules[0].name.as_str()),
            (Some(3.4), "BAYES_SPAM")
        );
        assert_eq!(s[1].rules[0].detail, "99.9%");
        assert_eq!(s[2].score, Some(1.0));
        assert!(s[2]
            .rules
            .iter()
            .any(|r| r.detail.contains("country of the connecting IP: DE")));
    }

    #[test]
    fn arc_and_times() {
        let m = mail(
            "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=lists.example; s=arc; b=x\r\n\
             ARC-Message-Signature: i=2; a=rsa-sha256; d=lists.example; s=arc; h=from; bh=x; b=y\r\n\
             ARC-Authentication-Results: i=2; lists.example; dkim=pass header.d=shop.example; spf=fail\r\n\
             ARC-Seal: i=1; a=rsa-sha256; cv=none; d=relay.example; s=arc; b=x\r\n\
             ARC-Authentication-Results: i=1; relay.example; dmarc=pass header.from=shop.example\r\n\
             Received: from b.example (b.example [192.0.2.9]) by c.example; Wed, 04 Nov 2026 09:00:00 +0000\r\n\
             Received: from a.example (a.example [192.0.2.8]) by b.example; Wed, 04 Nov 2026 11:00:00 +0000\r\n\
             Date: Wed, 04 Nov 2026 12:00:00 +0000\r\n",
        );
        let arc = arc_chain(&m);
        assert_eq!(arc.len(), 2);
        assert_eq!(
            (arc[0].instance, arc[0].cv.as_str(), arc[0].sealer.as_str()),
            (1, "none", "relay.example")
        );
        assert_eq!(
            (arc[1].server.as_str(), arc[1].results.len()),
            ("lists.example", 2)
        );
        assert_eq!(arc[1].signer, "lists.example");
        let t = time_anomalies(&m);
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(t[0].starts_with("Hop 2 is dated"));
        assert!(t[1].starts_with("The Date field"));
    }
}
