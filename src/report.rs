//! Analysis report (HTML or plain text) for passing on, e.g. to the IT department.

use crate::analysis::{self, Level};
use crate::checks::{Checks, Rating};
use crate::domains::Relation;
use crate::mail::Mail;
use crate::online;

/// A report section: title and rows (key, value). An empty key continues the previous row.
struct Section {
    title: String,
    rows: Vec<(String, String)>,
}

fn sections(mail: &Mail, c: &Checks, on: Option<&online::Report>) -> Vec<Section> {
    let mut out = Vec::new();
    let mut s = |title: &str, rows: Vec<(String, String)>| {
        if !rows.is_empty() {
            out.push(Section {
                title: title.into(),
                rows,
            });
        }
    };
    let list =
        |v: &[crate::mail::Mailbox]| v.iter().map(|m| m.display()).collect::<Vec<_>>().join(", ");
    let kv = |k: &str, v: String| (k.to_string(), v);

    let mut ov = vec![
        kv("Rating", c.rating.label().to_string()),
        kv("Subject", mail.subject.clone()),
        kv("From", list(&mail.from)),
    ];
    if !mail.reply_to.is_empty() {
        ov.push(kv("Reply-To", list(&mail.reply_to)));
    }
    ov.push(kv("To", list(&mail.to)));
    if !mail.cc.is_empty() {
        ov.push(kv("Cc", list(&mail.cc)));
    }
    if let Some(d) = mail.date {
        ov.push(kv("Date", analysis::fmt_original(d)));
    }
    ov.push(kv("Message-ID", mail.message_id.clone()));
    if let Some((i, ip)) = c.sender_ip {
        ov.push(kv("Sender IP", format!("{ip} (hop {})", i + 1)));
    }
    s("Overview", ov);

    s(
        "Notes",
        c.hints
            .iter()
            .map(|h| {
                let k = match h.level {
                    Level::Danger => "DANGER",
                    Level::Warn => "Warning",
                    Level::Info => "Info",
                };
                kv(k, h.text.clone())
            })
            .collect(),
    );

    let mut auth: Vec<(String, String)> = c
        .auth
        .iter()
        .map(|r| {
            (
                r.method.to_uppercase(),
                format!("{} {} {}", r.result, r.domain(), r.props)
                    .trim()
                    .to_string(),
            )
        })
        .collect();
    for d in &c.dkim {
        auth.push((
            format!("DKIM body ({})", d.domain),
            match d.body_ok {
                Some(true) => "unchanged since signing".into(),
                Some(false) => "does NOT match the signature".into(),
                None => d.note.clone(),
            },
        ));
    }
    for a in &c.arc {
        auth.push((
            format!("ARC i={}", a.instance),
            format!(
                "cv={} sealed by {}; {}",
                a.cv,
                a.sealer,
                a.results
                    .iter()
                    .map(|r| format!("{}={}", r.method, r.result))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ));
    }
    s("Authentication", auth);

    s(
        "Domains",
        c.domains
            .iter()
            .map(|d| {
                let rel = match d.relation {
                    Relation::Same => "same as From",
                    Relation::Related => "same organisation as From",
                    Relation::Different => "DIFFERENT from From",
                };
                let mut v = format!("{} – {rel}", d.domain);
                if let Some(l) = &d.lookalike {
                    v.push_str(&format!(" – LOOK-ALIKE: {l}"));
                }
                (d.role.clone(), v)
            })
            .collect(),
    );

    let mut route = Vec::new();
    let mut prev: Option<i64> = None;
    for (i, h) in mail.hops.iter().enumerate() {
        let time = h
            .date
            .map(|d| {
                let delay = prev
                    .map(|p| format!(" ({})", analysis::fmt_delay(d.ts - p)))
                    .unwrap_or_default();
                prev = Some(d.ts);
                format!("{}{delay}", analysis::fmt_original(d))
            })
            .unwrap_or_default();
        route.push((
            format!("Hop {}", i + 1),
            format!(
                "{}{} → {}  {} {} {}",
                h.from,
                if h.from_ip.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", h.from_ip)
                },
                h.by,
                h.with,
                h.tls,
                time
            )
            .trim()
            .to_string(),
        ));
    }
    for t in &c.times {
        route.push(("Note".into(), t.clone()));
    }
    s("Delivery route (oldest first)", route);

    let mut att = Vec::new();
    for (a, f) in mail.attachments.iter().zip(&c.files) {
        let mut v = format!(
            "{} · {} · real type: {} · SHA-256 {}",
            a.mime,
            analysis::human_size(a.data.len()),
            f.kind_name,
            f.sha256
        );
        if let Some(m) = &f.mismatch {
            v.push_str(&format!(" · DISGUISED: {m}"));
        }
        if f.macros {
            v.push_str(" · MACROS");
        }
        if f.encrypted {
            v.push_str(" · password-protected");
        }
        if !f.entries.is_empty() {
            v.push_str(&format!(
                " · contains: {}",
                f.entries
                    .iter()
                    .take(20)
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        att.push((a.name.clone(), v));
    }
    s("Attachments", att);

    let mut links: Vec<(String, String)> = c
        .links
        .iter()
        .map(|l| {
            let mut v = l.url.clone();
            if !l.text.is_empty() && l.text != l.url {
                v = format!("\"{}\" → {v}", l.text);
            }
            if !l.warning.is_empty() {
                v.push_str(&format!(" – WARNING: {}", l.warning));
            }
            (l.host.clone(), v)
        })
        .collect();
    links.truncate(200);
    s("Links", links);

    let mut html = Vec::new();
    for (why, t) in &c.html.hidden {
        html.push((format!("Hidden ({why})"), t.clone()));
    }
    for p in &c.html.pixels {
        html.push(("Tracking pixel".into(), p.clone()));
    }
    for (h, n) in &c.html.remote {
        html.push(("Remote images".into(), format!("{h} ({n})")));
    }
    for f in &c.html.forms {
        html.push(("Form".into(), f.clone()));
    }
    s("HTML content", html);

    let mut spam = Vec::new();
    for sp in &c.spam {
        spam.push((
            sp.engine.clone(),
            format!(
                "{} score {} / {}",
                sp.verdict,
                sp.score.map_or("?".into(), |x| format!("{x:.1}")),
                sp.required.map_or("?".into(), |x| format!("{x:.1}"))
            ),
        ));
        for r in sp.rules.iter().take(30) {
            spam.push((
                String::new(),
                format!(
                    "{} {} {}",
                    r.name,
                    r.score.map(|x| format!("({x:+.1})")).unwrap_or_default(),
                    r.detail
                ),
            ));
        }
    }
    s("Spam filters", spam);

    if let Some(o) = on {
        let mut rows = Vec::new();
        for x in &o.spf {
            rows.push((
                format!("SPF {}", x.domain),
                format!("{} – {}", x.result, x.detail),
            ));
            if let Some(r) = &x.record {
                rows.push((String::new(), r.clone()));
            }
        }
        if let Some(d) = &o.dmarc {
            rows.push((format!("DMARC {}", d.domain), d.explain.clone()));
            if let Some(r) = &d.record {
                rows.push((String::new(), r.clone()));
            }
        }
        for d in &o.dkim {
            rows.push((
                format!("DKIM {}/{}", d.domain, d.selector),
                match &d.valid {
                    Ok(true) => "signature valid".into(),
                    Ok(false) => "signature INVALID".into(),
                    Err(e) => format!("not checked: {e}"),
                },
            ));
        }
        for i in &o.ips {
            rows.push((
                i.ip.clone(),
                format!(
                    "{} · AS{} {} · {} · {}",
                    i.ptr, i.asn, i.org, i.prefix, i.country
                ),
            ));
        }
        for e in &o.errors {
            rows.push(("Error".into(), e.clone()));
        }
        s("Online check (DNS)", rows);
    }

    s(
        "All header fields",
        mail.fields
            .iter()
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect(),
    );
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn html(mail: &Mail, c: &Checks, on: Option<&online::Report>) -> String {
    let (badge_bg, badge_fg) = match c.rating {
        Rating::Safe => ("#dcf0de", "#185e28"),
        Rating::Suspicious => ("#faecce", "#825000"),
        Rating::Dangerous => ("#fadeda", "#a01e14"),
    };
    let mut h = String::new();
    h.push_str(&format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Analysis: {}</title>\n<style>\
         body{{font-family:system-ui,sans-serif;background:#fbf9f6;color:#1f1b18;margin:2em auto;max-width:1000px;padding:0 1em}}\
         h1{{font-size:1.4em}} h2{{color:#b8411b;font-size:1.1em;margin-top:1.6em;border-bottom:1px solid #d6cdc4}}\
         table{{border-collapse:collapse;width:100%}} td{{padding:3px 8px;vertical-align:top;word-break:break-word}}\
         tr:nth-child(even){{background:#f0ebe5}} td:first-child{{color:#5e554d;width:190px;white-space:nowrap}}\
         .badge{{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:bold;background:{badge_bg};color:{badge_fg}}}\
         .mono{{font-family:monospace}} footer{{color:#5e554d;font-size:.85em;margin-top:2em}}</style></head><body>\n",
        esc(&mail.subject)
    ));
    h.push_str(&format!(
        "<h1>{}</h1>\n<p><span class=\"badge\">{}</span></p>\n",
        esc(if mail.subject.is_empty() {
            "(no subject)"
        } else {
            &mail.subject
        }),
        c.rating.label()
    ));
    for sec in sections(mail, c, on) {
        let mono = sec.title == "All header fields";
        h.push_str(&format!("<h2>{}</h2>\n<table>\n", esc(&sec.title)));
        for (k, v) in &sec.rows {
            let style = if k == "DANGER" {
                " style=\"color:#a01e14;font-weight:bold\""
            } else if k == "Warning" {
                " style=\"color:#825000\""
            } else {
                ""
            };
            h.push_str(&format!(
                "<tr><td{style}>{}</td><td{}>{}</td></tr>\n",
                esc(k),
                if mono { " class=\"mono\"" } else { "" },
                esc(v)
            ));
        }
        h.push_str("</table>\n");
    }
    h.push_str(&format!(
        "<footer>Created with EML Reader {} · {}</footer>\n</body></html>\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%d.%m.%Y %H:%M")
    ));
    h
}

pub fn text(mail: &Mail, c: &Checks, on: Option<&online::Report>) -> String {
    let mut t = format!(
        "E-MAIL ANALYSIS – {}\nRating: {}\n",
        if mail.subject.is_empty() {
            "(no subject)"
        } else {
            &mail.subject
        },
        c.rating.label()
    );
    for sec in sections(mail, c, on) {
        t.push_str(&format!("\n== {} ==\n", sec.title));
        let w = sec
            .rows
            .iter()
            .map(|(k, _)| k.chars().count())
            .max()
            .unwrap_or(0)
            .min(28);
        for (k, v) in &sec.rows {
            t.push_str(&format!("{k:<w$}  {v}\n"));
        }
    }
    t.push_str(&format!("\n-- EML Reader {}\n", env!("CARGO_PKG_VERSION")));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports() {
        let m = Mail::parse(include_bytes!("../tests/data/sample.eml").to_vec()).unwrap();
        let c = Checks::run(&m, 1_793_784_600);
        let h = html(&m, &c, None);
        assert!(h.contains("<span class=\"badge\">Dangerous</span>"));
        assert!(h.contains("<h2>Delivery route (oldest first)</h2>"));
        assert!(h.contains("SHA-256"));
        assert!(!h.contains("<script"));
        let t = text(&m, &c, None);
        assert!(t.contains("== Domains =="));
        assert!(t.contains("Reply-To"));
    }
}
