//! All offline checks of one message and the overall rating (safe / suspicious / dangerous).

use std::net::IpAddr;

use crate::analysis::{self, AuthResult, Hint, Level, Link};
use crate::dkim::Sig;
use crate::domains::{DomainRow, Relation};
use crate::files::FileCheck;
use crate::htmlcheck::HtmlCheck;
use crate::mail::Mail;
use crate::trace::{ArcSet, SpamInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rating {
    Safe,
    Suspicious,
    Dangerous,
}

impl Rating {
    pub fn label(self) -> &'static str {
        match self {
            Rating::Safe => "Inconspicuous",
            Rating::Suspicious => "Suspicious",
            Rating::Dangerous => "Dangerous",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Checks {
    pub auth_server: String,
    pub auth: Vec<AuthResult>,
    pub links: Vec<Link>,
    pub domains: Vec<DomainRow>,
    /// One per attachment (same order).
    pub files: Vec<FileCheck>,
    pub html: HtmlCheck,
    pub sender_ip: Option<(usize, IpAddr)>,
    pub times: Vec<String>,
    pub arc: Vec<ArcSet>,
    pub spam: Vec<SpamInfo>,
    pub dkim: Vec<Sig>,
    pub hints: Vec<Hint>,
    pub rating: Rating,
}

impl Checks {
    pub fn run(mail: &Mail, now: i64) -> Checks {
        let links = mail
            .html
            .as_deref()
            .map(analysis::extract_links)
            .unwrap_or_default();
        let (auth_server, auth) = analysis::auth_summary(mail);
        let mut hints = analysis::hints(mail, &auth, &links, now);
        let domains = crate::domains::domain_rows(mail, &auth);
        let files: Vec<FileCheck> = mail
            .attachments
            .iter()
            .map(|a| crate::files::check(&a.name, &a.data))
            .collect();
        let html = mail
            .html
            .as_deref()
            .map(crate::htmlcheck::check)
            .unwrap_or_default();
        let dkim = crate::dkim::signatures(&mail.raw);
        let push = |hints: &mut Vec<Hint>, level: Level, text: String| {
            if !hints.iter().any(|h| h.text == text) {
                hints.push(Hint { level, text });
            }
        };

        // Look-alike domains (sender side is dangerous, links are dangerous too).
        let mut seen = Vec::new();
        for d in &domains {
            if let Some(why) = &d.lookalike {
                if seen.contains(&d.domain) {
                    continue;
                }
                seen.push(d.domain.clone());
                let level = if matches!(d.role.as_str(), "From" | "Reply-To" | "Sender") {
                    Level::Danger
                } else {
                    Level::Warn
                };
                push(&mut hints, level, format!("{}: {why}.", d.role));
            }
        }
        for l in &links {
            if let Some(why) = crate::domains::lookalike(&l.host) {
                push(&mut hints, Level::Danger, format!("Link: {why}."));
            }
        }
        if let Some(dk) = domains.iter().find(|d| d.role == "DKIM signature") {
            if dk.relation == Relation::Different
                && !domains
                    .iter()
                    .any(|d| d.role == "DKIM signature" && d.relation != Relation::Different)
            {
                push(
                    &mut hints,
                    Level::Info,
                    format!(
                        "Signed by {} (DKIM), not by the sender's domain – usual for mailing services.",
                        dk.domain
                    ),
                );
            }
        }
        // Attachments
        for (a, f) in mail.attachments.iter().zip(&files) {
            if let Some(m) = &f.mismatch {
                let level = if f.is_program {
                    Level::Danger
                } else {
                    Level::Warn
                };
                push(
                    &mut hints,
                    level,
                    format!("Attachment \"{}\" is disguised: {m}.", a.name),
                );
            }
            if f.macros {
                push(
                    &mut hints,
                    Level::Danger,
                    format!(
                        "Attachment \"{}\" contains macros (program code in an Office document).",
                        a.name
                    ),
                );
            }
            if f.encrypted {
                push(
                    &mut hints,
                    Level::Warn,
                    format!(
                        "Attachment \"{}\" is a password-protected archive – virus scanners cannot look inside.",
                        a.name
                    ),
                );
            }
            if !f.risky_entries.is_empty() {
                push(
                    &mut hints,
                    Level::Danger,
                    format!(
                        "Archive \"{}\" contains program files: {}.",
                        a.name,
                        f.risky_entries.join(", ")
                    ),
                );
            }
            if f.pdf_active
                .iter()
                .any(|w| w.contains("JavaScript") || w.contains("Launch"))
            {
                push(
                    &mut hints,
                    Level::Warn,
                    format!(
                        "PDF \"{}\" contains active content: {}.",
                        a.name,
                        f.pdf_active.join(", ")
                    ),
                );
            }
        }
        // HTML
        if !html.forms.is_empty() {
            push(
                &mut hints,
                Level::Warn,
                "The message contains a form – never enter passwords or payment data in an e-mail."
                    .into(),
            );
        }
        if !html.hidden.is_empty() {
            push(
                &mut hints,
                Level::Warn,
                format!(
                    "{} hidden text block(s) – often used to fool spam filters.",
                    html.hidden.len()
                ),
            );
        }
        if !html.pixels.is_empty() {
            push(
                &mut hints,
                Level::Info,
                format!("{} tracking pixel(s): the sender learns when the message is opened in a mail program that loads images.", html.pixels.len()),
            );
        }
        if html.scripts > 0 {
            push(
                &mut hints,
                Level::Warn,
                "The HTML part contains scripts.".into(),
            );
        }
        // DKIM body hash
        for s in &dkim {
            if s.body_ok == Some(false) && s.length.is_none() {
                push(
                    &mut hints,
                    Level::Warn,
                    format!(
                        "The body does not match the DKIM signature of {} – changed after signing (or by a forwarding server).",
                        s.domain
                    ),
                );
            }
        }
        // Route
        let times = crate::trace::time_anomalies(mail);
        for t in &times {
            push(&mut hints, Level::Info, t.clone());
        }
        let spam = crate::trace::spam_info(mail);
        for s in &spam {
            if let (Some(score), Some(req)) = (s.score, s.required) {
                if score >= req {
                    push(
                        &mut hints,
                        Level::Warn,
                        format!(
                            "{} rates the message as spam ({score:.1} of {req:.1}).",
                            s.engine
                        ),
                    );
                }
            }
        }
        hints.sort_by_key(|h| match h.level {
            Level::Danger => 0,
            Level::Warn => 1,
            Level::Info => 2,
        });
        let rating = if hints.iter().any(|h| h.level == Level::Danger) {
            Rating::Dangerous
        } else if hints.iter().filter(|h| h.level == Level::Warn).count() >= 1 {
            Rating::Suspicious
        } else {
            Rating::Safe
        };
        Checks {
            auth_server,
            auth,
            links,
            domains,
            files,
            html,
            sender_ip: crate::trace::sender_ip(mail),
            times,
            arc: crate::trace::arc_chain(mail),
            spam,
            dkim,
            hints,
            rating,
        }
    }

    /// The reasons shown next to the rating.
    pub fn reasons(&self) -> Vec<&Hint> {
        let lvl = match self.rating {
            Rating::Dangerous => Level::Danger,
            Rating::Suspicious => Level::Warn,
            Rating::Safe => return Vec::new(),
        };
        self.hints.iter().filter(|h| h.level == lvl).collect()
    }

    /// The job for the online check.
    pub fn online_job(&self, mail: &Mail, proxy: &str) -> crate::online::Job {
        let from_domain = mail
            .from
            .first()
            .and_then(|m| m.domain())
            .unwrap_or_default();
        let mailfrom_domain = self
            .auth
            .iter()
            .find(|r| r.method == "spf")
            .map(|r| r.domain())
            .filter(|d| !d.is_empty())
            .or_else(|| mail.get("Return-Path").and_then(crate::mail::domain_of))
            .unwrap_or_else(|| from_domain.clone());
        let mut ips: Vec<IpAddr> = Vec::new();
        for h in &mail.hops {
            if let Ok(ip) = h.from_ip.parse::<IpAddr>() {
                if !crate::trace::is_private(&ip) && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        crate::online::Job {
            raw: mail.raw.clone(),
            from_domain,
            mailfrom_domain,
            sender_ip: self.sender_ip.map(|(_, ip)| ip),
            dkim: self
                .dkim
                .iter()
                .filter(|s| !s.domain.is_empty() && !s.selector.is_empty())
                .map(|s| (s.index, s.domain.clone(), s.selector.clone()))
                .collect(),
            ips,
            proxy: proxy.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_rating() {
        let m = Mail::parse(include_bytes!("../tests/data/sample.eml").to_vec()).unwrap();
        let c = Checks::run(&m, 1_793_784_600);
        assert_eq!(c.rating, Rating::Dangerous, "{:?}", c.hints);
        assert!(c.reasons().iter().any(|h| h.text.contains("link(s)")));
        assert_eq!(c.files.len(), 3);
        assert_eq!(c.files[1].kind_name, "PDF document");
        assert_eq!(c.domains[0].role, "From");
        assert!(c
            .domains
            .iter()
            .any(|d| d.role == "Reply-To" && d.relation == Relation::Different));
        // The sample's DKIM signature is fake: the body hash does not match.
        assert_eq!(c.dkim.len(), 1);
        assert_eq!(c.dkim[0].body_ok, Some(false));
        let job = c.online_job(&m, "");
        assert_eq!(job.mailfrom_domain, "mailer.example.org");
        assert_eq!(job.sender_ip.unwrap().to_string(), "192.0.2.25");
    }

    #[test]
    fn signed_message_is_safe() {
        let m = Mail::parse(include_bytes!("../tests/data/dkim-relaxed.eml").to_vec()).unwrap();
        let c = Checks::run(&m, 1_793_784_600);
        assert_eq!(c.rating, Rating::Safe, "{:?}", c.hints);
        assert_eq!(c.dkim[0].body_ok, Some(true));
    }
}
