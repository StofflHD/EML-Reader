//! The Analysis view (rating, notes, domains, attachments, HTML content, online check),
//! the DKIM/ARC and spam parts of the Headers view, the compare window and the mailbox panel.

use eframe::egui::{self, Align, Color32, Layout, Margin, RichText, Sense, Ui};

use super::{
    key_label, kv_row, links_section, section, tone, verdict_colors, Action, App, Doc, MboxEntry,
    KEY_W,
};
use crate::analysis::{self, Level, Verdict};
use crate::checks::{Checks, Rating};
use crate::domains::Relation;

fn rating_colors(ui: &Ui, r: Rating) -> (Color32, Color32) {
    verdict_colors(
        ui,
        match r {
            Rating::Safe => Verdict::Pass,
            Rating::Suspicious => Verdict::Weak,
            Rating::Dangerous => Verdict::Fail,
        },
    )
}

fn level_icon(ui: &Ui, l: Level) -> (&'static str, Color32) {
    match l {
        Level::Danger => ("⛔", ui.visuals().error_fg_color),
        Level::Warn => ("⚠", ui.visuals().warn_fg_color),
        Level::Info => ("ℹ", ui.visuals().weak_text_color()),
    }
}

/// The coloured rating strip above the views. Returns true when clicked.
pub(super) fn rating_banner(ui: &mut Ui, c: &Checks) -> bool {
    let (bg, fg) = rating_colors(ui, c.rating);
    let reasons = c.reasons();
    let icon = match c.rating {
        Rating::Safe => "✔",
        Rating::Suspicious => "⚠",
        Rating::Dangerous => "⛔",
    };
    let r = egui::Frame::none()
        .fill(bg)
        .rounding(5.0)
        .inner_margin(Margin::symmetric(10.0, 5.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("{icon} {}", c.rating.label()))
                        .color(fg)
                        .strong(),
                );
                let text = match reasons.len() {
                    0 => {
                        let infos = c.hints.len();
                        if infos == 0 {
                            "No problems found.".to_string()
                        } else {
                            format!("No problems found ({infos} note(s)).")
                        }
                    }
                    1 => reasons[0].text.clone(),
                    n => format!("{} (+{} more)", reasons[0].text, n - 1),
                };
                ui.label(RichText::new(text).color(fg));
            });
        })
        .response
        .interact(Sense::click())
        .on_hover_text("Show the analysis (Ctrl+2)");
    r.clicked()
}

pub(super) fn analysis_view(
    ui: &mut Ui,
    ctx: &egui::Context,
    doc: &mut Doc,
    actions: &mut Vec<Action>,
) {
    let _ = ctx;
    egui::ScrollArea::vertical()
        .id_salt("analysis")
        .auto_shrink(false)
        .show(ui, |ui| {
            let c = &doc.checks;
            let m = &doc.mail;
            // ---- rating & notes
            section(ui, "Rating", true, |ui| {
                let (bg, fg) = rating_colors(ui, c.rating);
                egui::Frame::none()
                    .fill(bg)
                    .rounding(6.0)
                    .inner_margin(Margin::symmetric(14.0, 8.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new(c.rating.label()).size(20.0).strong().color(fg));
                    });
                ui.add_space(4.0);
                if c.hints.is_empty() {
                    ui.label("No problems found.");
                }
                for h in &c.hints {
                    let (icon, color) = level_icon(ui, h.level);
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new(icon).color(color).strong());
                        let t = RichText::new(&h.text);
                        ui.add(egui::Label::new(if h.level == Level::Danger { t.strong() } else { t }).wrap());
                    });
                }
                ui.label(
                    RichText::new(
                        "The rating is a hint, not a guarantee: a message without findings can still be fraudulent.",
                    )
                    .small()
                    .weak(),
                );
            });

            // ---- domains
            section(ui, "Domains", true, |ui| {
                for (n, d) in c.domains.iter().enumerate() {
                    kv_row(
                        ui,
                        120.0,
                        n % 2 == 1,
                        |ui| {
                            key_label(ui, &d.role);
                        },
                        |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(&d.domain).strong());
                                let uni = crate::domains::to_unicode(&d.domain);
                                if uni != d.domain {
                                    ui.label(RichText::new(format!("= {uni}")).color(ui.visuals().warn_fg_color));
                                }
                                if d.role != "From" {
                                    let dark = ui.visuals().dark_mode;
                                    let (t, col) = match d.relation {
                                        Relation::Same => ("same as sender", tone(dark, (24, 94, 40), (196, 240, 200))),
                                        Relation::Related => ("same organisation", ui.visuals().weak_text_color()),
                                        Relation::Different => ("different domain", ui.visuals().warn_fg_color),
                                    };
                                    ui.label(RichText::new(t).small().color(col));
                                }
                            });
                            if let Some(l) = &d.lookalike {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("⛔ {l}")).color(ui.visuals().error_fg_color),
                                    )
                                    .wrap(),
                                );
                            }
                        },
                    );
                }
                if let Some((i, ip)) = c.sender_ip {
                    kv_row(ui, 120.0, c.domains.len() % 2 == 1, |ui| key_label(ui, "Sender IP"), |ui| {
                        ui.label(format!("{ip} (hop {})", i + 1));
                    });
                }
            });

            // ---- attachments
            if !m.attachments.is_empty() {
                section(ui, &format!("Attachments ({})", m.attachments.len()), true, |ui| {
                    for (i, (a, f)) in m.attachments.iter().zip(&c.files).enumerate() {
                        kv_row(
                            ui,
                            160.0,
                            i % 2 == 1,
                            |ui| {
                                let t = RichText::new(&a.name).strong();
                                ui.add(egui::Label::new(if f.is_program || f.mismatch.is_some() || f.macros {
                                    t.color(ui.visuals().error_fg_color)
                                } else {
                                    t
                                }).wrap());
                                ui.label(RichText::new(analysis::human_size(a.data.len())).small().weak());
                            },
                            |ui| {
                                ui.label(format!("Real type: {}", f.kind_name));
                                ui.label(RichText::new(format!("Declared: {}", a.mime)).weak());
                                let err = ui.visuals().error_fg_color;
                                let warn = ui.visuals().warn_fg_color;
                                if let Some(mm) = &f.mismatch {
                                    ui.label(RichText::new(format!("⛔ Disguised: {mm}")).color(err));
                                }
                                if f.macros {
                                    ui.label(RichText::new("⛔ Contains macros").color(err));
                                }
                                if f.encrypted {
                                    ui.label(RichText::new("⚠ Password-protected archive").color(warn));
                                }
                                if !f.pdf_active.is_empty() {
                                    ui.label(RichText::new(format!("⚠ PDF: {}", f.pdf_active.join(", "))).color(warn));
                                }
                                if !f.entries.is_empty() {
                                    egui::CollapsingHeader::new(format!("Archive contents ({})", f.entries.len()))
                                        .id_salt(("zip", i))
                                        .show(ui, |ui| {
                                            for e in f.entries.iter().take(500) {
                                                let risky = f.risky_entries.contains(&e.name);
                                                let t = RichText::new(format!(
                                                    "{}{}  {}",
                                                    if e.encrypted { "🔒 " } else { "" },
                                                    e.name,
                                                    analysis::human_size(e.size as usize)
                                                ))
                                                .monospace()
                                                .small();
                                                ui.label(if risky { t.color(err) } else { t });
                                            }
                                        });
                                }
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(RichText::new(format!("SHA-256 {}", f.sha256)).monospace().small().weak());
                                });
                                ui.horizontal(|ui| {
                                    if ui.small_button("Copy SHA-256").clicked() {
                                        actions.push(Action::Copy(f.sha256.clone()));
                                    }
                                    if ui
                                        .small_button("Look up on VirusTotal …")
                                        .on_hover_text("Opens virustotal.com with the hash only – the file is not uploaded.")
                                        .clicked()
                                    {
                                        actions.push(Action::OpenUrl(
                                            format!("https://www.virustotal.com/gui/file/{}", f.sha256),
                                            false,
                                        ));
                                    }
                                    if ui.small_button("Preview").clicked() {
                                        actions.push(Action::Preview(i));
                                    }
                                });
                            },
                        );
                    }
                });
            }

            // ---- HTML
            if m.html.is_some() {
                let h = &c.html;
                let n = h.hidden.len() + h.pixels.len() + h.forms.len() + usize::from(h.scripts > 0);
                section(ui, &format!("HTML Content ({n} findings)"), true, |ui| {
                    let mut stripe = false;
                    let mut row = |ui: &mut Ui, k: &str, f: &dyn Fn(&mut Ui)| {
                        kv_row(ui, 140.0, stripe, |ui| key_label(ui, k), f);
                        stripe = !stripe;
                    };
                    for (why, t) in &h.hidden {
                        row(ui, "Hidden text", &|ui| {
                            ui.add(egui::Label::new(format!("“{t}”")).wrap());
                            ui.label(RichText::new(why).small().weak());
                        });
                    }
                    for p in &h.pixels {
                        row(ui, "Tracking pixel", &|ui| {
                            ui.add(egui::Label::new(RichText::new(p).monospace().small()).wrap());
                        });
                    }
                    if !h.remote.is_empty() {
                        row(ui, "Remote images", &|ui| {
                            for (host, cnt) in &h.remote {
                                ui.label(format!("{host}  ({cnt})"));
                            }
                        });
                    }
                    for f in &h.forms {
                        row(ui, "Form", &|ui| {
                            ui.label(RichText::new(format!("sends to {f}")).color(ui.visuals().warn_fg_color));
                        });
                    }
                    if h.scripts > 0 {
                        row(ui, "Scripts", &|ui| {
                            ui.label(format!("{} <script> element(s)", h.scripts));
                        });
                    }
                    if n == 0 && h.remote.is_empty() {
                        ui.label(RichText::new("No hidden text, tracking pixels, forms or scripts.").weak());
                    }
                });
            }

            // ---- links
            if !c.links.is_empty() {
                links_section(ui, &c.links, actions);
                ui.add_space(6.0);
            }

            // ---- online
            section(ui, "Online Check (DNS)", true, |ui| {
                online_section(ui, doc_online(doc), doc.online_rx.is_some(), actions);
            });
        });
}

fn doc_online(doc: &Doc) -> Option<&crate::online::Report> {
    doc.online.as_ref()
}

fn online_section(
    ui: &mut Ui,
    report: Option<&crate::online::Report>,
    busy: bool,
    actions: &mut Vec<Action>,
) {
    ui.horizontal(|ui| {
        if busy {
            ui.spinner();
            ui.label("Querying DNS …");
        } else if ui
            .button(if report.is_some() {
                "Check Again …"
            } else {
                "Check Online …"
            })
            .clicked()
        {
            actions.push(Action::OnlineCheck(false));
        }
    });
    ui.label(
        RichText::new(
            "Looks up the SPF, DMARC and DKIM records of the domains and the network of the route's \
             IP addresses (DNS over HTTPS at Cloudflare). The sender learns nothing about it.",
        )
        .small()
        .weak(),
    );
    let Some(r) = report else { return };
    ui.add_space(4.0);
    let mut n = 0;
    let mut row = |ui: &mut Ui, k: &str, f: &dyn Fn(&mut Ui)| {
        kv_row(ui, 140.0, n % 2 == 1, |ui| key_label(ui, k), f);
        n += 1;
    };
    let verdict = |res: &str| match res {
        "pass" => Verdict::Pass,
        "fail" | "permerror" => Verdict::Fail,
        "softfail" | "temperror" => Verdict::Weak,
        _ => Verdict::Neutral,
    };
    for s in &r.spf {
        row(ui, &format!("SPF {}", s.domain), &|ui| {
            let (_, fg) = verdict_colors(ui, verdict(&s.result));
            ui.label(RichText::new(&s.result).strong().color(fg));
            ui.add(egui::Label::new(&s.detail).wrap());
            if let Some(rec) = &s.record {
                ui.add(egui::Label::new(RichText::new(rec).monospace().small().weak()).wrap());
            }
        });
    }
    if let Some(d) = &r.dmarc {
        row(ui, &format!("DMARC {}", d.domain), &|ui| {
            let v = match d.policy.as_str() {
                "reject" | "quarantine" => Verdict::Pass,
                "none" => Verdict::Weak,
                _ => Verdict::Fail,
            };
            let (_, fg) = verdict_colors(ui, v);
            ui.label(
                RichText::new(if d.policy.is_empty() {
                    "no policy"
                } else {
                    &d.policy
                })
                .strong()
                .color(fg),
            );
            ui.add(egui::Label::new(&d.explain).wrap());
            if let Some(rec) = &d.record {
                ui.add(egui::Label::new(RichText::new(rec).monospace().small().weak()).wrap());
            }
        });
    }
    for d in &r.dkim {
        row(ui, &format!("DKIM {}", d.domain), &|ui| {
            let (v, t) = match &d.valid {
                Ok(true) => (
                    Verdict::Pass,
                    "signature valid – header fields unchanged since signing".to_string(),
                ),
                Ok(false) => (
                    Verdict::Fail,
                    "signature INVALID – the message was changed or forged".to_string(),
                ),
                Err(e) => (Verdict::Neutral, format!("not checked: {e}")),
            };
            let (_, fg) = verdict_colors(ui, v);
            ui.add(egui::Label::new(RichText::new(t).color(fg).strong()).wrap());
            ui.label(
                RichText::new(format!("selector {}", d.selector))
                    .small()
                    .weak(),
            );
            if let Some(rec) = &d.record {
                ui.add(egui::Label::new(RichText::new(rec).monospace().small().weak()).wrap());
            }
        });
    }
    for i in &r.ips {
        row(ui, &i.ip, &|ui| {
            let mut s = Vec::new();
            if !i.ptr.is_empty() {
                s.push(i.ptr.clone());
            }
            if !i.country.is_empty() {
                s.push(format!("country {}", i.country));
            }
            ui.add(egui::Label::new(s.join(" · ")).wrap());
            if !i.asn.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("AS{} {} · {}", i.asn, i.org, i.prefix)).weak(),
                    )
                    .wrap(),
                );
            }
        });
    }
    for e in &r.errors {
        row(ui, "Error", &|ui| {
            ui.label(RichText::new(e).color(ui.visuals().error_fg_color));
        });
    }
}

/// DKIM signatures (with the offline body-hash check) and the ARC chain.
pub(super) fn dkim_arc_rows(ui: &mut Ui, c: &Checks) {
    for s in &c.dkim {
        kv_row(
            ui,
            KEY_W,
            false,
            |ui| key_label(ui, "DKIM sig."),
            |ui| {
                ui.label(
                    RichText::new(format!(
                        "{} · selector {} · {} · {}",
                        s.domain, s.selector, s.algorithm, s.canon
                    ))
                    .strong(),
                );
                let (v, t) = match s.body_ok {
                    Some(true) => (
                        Verdict::Pass,
                        "✔ body unchanged since signing (body hash matches)".to_string(),
                    ),
                    Some(false) => (
                        Verdict::Weak,
                        "⚠ body does not match the signed body hash".to_string(),
                    ),
                    None => (Verdict::Neutral, s.note.clone()),
                };
                let (_, fg) = verdict_colors(ui, v);
                ui.label(RichText::new(t).color(fg));
                if let Some(l) = s.length {
                    ui.label(
                    RichText::new(format!("⚠ only the first {l} bytes of the body are signed (l=) – text may have been appended"))
                        .color(ui.visuals().warn_fg_color),
                );
                }
                ui.label(
                    RichText::new(format!("signed fields: {}", s.headers))
                        .small()
                        .weak(),
                );
            },
        );
    }
    if !c.arc.is_empty() {
        ui.add_space(4.0);
        ui.label(RichText::new("ARC chain (forwarding servers)").strong());
        for a in &c.arc {
            kv_row(
                ui,
                KEY_W,
                a.instance % 2 == 0,
                |ui| key_label(ui, &format!("ARC i={}", a.instance)),
                |ui| {
                    let v = match a.cv.as_str() {
                        "pass" | "none" => Verdict::Pass,
                        "fail" => Verdict::Fail,
                        _ => Verdict::Neutral,
                    };
                    let (_, fg) = verdict_colors(ui, v);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(if a.server.is_empty() {
                                &a.sealer
                            } else {
                                &a.server
                            })
                            .strong(),
                        );
                        ui.label(RichText::new(format!("cv={}", a.cv)).color(fg));
                    });
                    let res: Vec<String> = a
                        .results
                        .iter()
                        .map(|r| format!("{}={} {}", r.method, r.result, r.domain()))
                        .collect();
                    if !res.is_empty() {
                        ui.add(egui::Label::new(RichText::new(res.join(" · ")).small()).wrap());
                    }
                },
            );
        }
    }
}

pub(super) fn spam_section(ui: &mut Ui, c: &Checks) {
    if c.spam.is_empty() {
        return;
    }
    section(ui, "Spam Filters", true, |ui| {
        for s in &c.spam {
            let over = matches!((s.score, s.required), (Some(a), Some(b)) if a >= b);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&s.engine).strong());
                let score = match (s.score, s.required) {
                    (Some(a), Some(b)) => format!("score {a:.1} / {b:.1}"),
                    (Some(a), None) => format!("score {a:.1}"),
                    _ => String::new(),
                };
                let (_, fg) = verdict_colors(ui, if over { Verdict::Fail } else { Verdict::Pass });
                ui.label(RichText::new(score).color(fg));
                if !s.verdict.is_empty() {
                    ui.label(RichText::new(format!("({})", s.verdict)).weak());
                }
            });
            for (n, r) in s.rules.iter().enumerate() {
                kv_row(
                    ui,
                    200.0,
                    n % 2 == 1,
                    |ui| {
                        ui.add(egui::Label::new(RichText::new(&r.name).monospace().small()).wrap());
                    },
                    |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if let Some(x) = r.score {
                                let dark = ui.visuals().dark_mode;
                                let col = if x > 0.0 {
                                    ui.visuals().error_fg_color
                                } else {
                                    tone(dark, (24, 94, 40), (196, 240, 200))
                                };
                                ui.label(RichText::new(format!("{x:+.2}")).monospace().color(col));
                            }
                            ui.add(egui::Label::new(&r.detail).wrap());
                        });
                    },
                );
            }
            ui.add_space(6.0);
        }
    });
}

/// The messages of an mbox file with subject, sender and date for the list.
pub(super) fn read_mbox(data: Vec<u8>) -> Vec<MboxEntry> {
    let mut entries = Vec::new();
    for m in mail_parser::mailbox::mbox::MessageIterator::new(std::io::Cursor::new(data)) {
        let Ok(m) = m else { continue };
        let raw = m.unwrap_contents();
        let (subject, from, date) = match mail_parser::MessageParser::new().parse_headers(&raw) {
            Some(p) => (
                p.subject().unwrap_or("").to_string(),
                p.from()
                    .and_then(|f| f.first())
                    .map(|f| f.name().or(f.address()).unwrap_or("").to_string())
                    .unwrap_or_default(),
                p.date().map(|d| d.to_timestamp()),
            ),
            None => Default::default(),
        };
        entries.push(MboxEntry {
            raw,
            subject,
            from,
            date,
        });
    }
    entries
}

// ------------------------------------------------------------------ App parts

impl App {
    pub(super) fn start_online(&mut self, ctx: &egui::Context) {
        let proxy = self.s.update_proxy.clone();
        let Some(doc) = self.docs.get_mut(self.active) else {
            return;
        };
        let job = doc.checks.online_job(&doc.mail, &proxy);
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        crate::online::spawn(job, tx, move || ctx2.request_repaint());
        doc.online_rx = Some(rx);
        doc.view = super::View::Analysis;
    }

    pub(super) fn poll_online(&mut self) {
        for d in &mut self.docs {
            if let Some(rx) = &d.online_rx {
                if let Ok(r) = rx.try_recv() {
                    d.online = Some(r);
                    d.online_rx = None;
                }
            }
        }
    }

    /// Reads an mbox file into the side panel.
    pub(super) fn open_mailbox(
        &mut self,
        path: &std::path::Path,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let entries = read_mbox(data);
        if entries.is_empty() {
            return Err(format!(
                "{}: no messages found in the mailbox.",
                path.display()
            ));
        }
        self.mailbox = Some(super::Mailbox_ {
            path: path.to_path_buf(),
            entries,
            filter: String::new(),
            current: None,
        });
        Ok(())
    }

    pub(super) fn mailbox_panel(&mut self, ctx: &egui::Context) {
        let Some(mb) = &mut self.mailbox else { return };
        let mut actions = Vec::new();
        egui::SidePanel::left("mailbox")
            .resizable(true)
            .default_width(300.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let name = mb
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    ui.label(RichText::new(format!("📂 {name}")).strong())
                        .on_hover_text(mb.path.display().to_string());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button("✖")
                            .on_hover_text("Close mailbox")
                            .clicked()
                        {
                            actions.push(Action::CloseMailbox);
                        }
                    });
                });
                ui.add(
                    egui::TextEdit::singleline(&mut mb.filter)
                        .hint_text("🔍 Filter")
                        .desired_width(f32::INFINITY),
                );
                let f = mb.filter.to_lowercase();
                let shown: Vec<usize> = (0..mb.entries.len())
                    .filter(|&i| {
                        let e = &mb.entries[i];
                        f.is_empty()
                            || e.subject.to_lowercase().contains(&f)
                            || e.from.to_lowercase().contains(&f)
                    })
                    .collect();
                ui.label(
                    RichText::new(format!("{} of {} messages", shown.len(), mb.entries.len()))
                        .small()
                        .weak(),
                );
                ui.separator();
                let row_h = 40.0;
                egui::ScrollArea::vertical().auto_shrink(false).show_rows(
                    ui,
                    row_h,
                    shown.len(),
                    |ui, range| {
                        for &i in &shown[range] {
                            let e = &mb.entries[i];
                            let sel = mb.current == Some(i);
                            let (rect, resp) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), row_h),
                                Sense::click(),
                            );
                            let v = ui.visuals();
                            if sel {
                                ui.painter().rect_filled(rect, 3.0, v.selection.bg_fill);
                            } else if resp.hovered() {
                                ui.painter()
                                    .rect_filled(rect, 3.0, v.widgets.hovered.bg_fill);
                            }
                            let fg = if sel {
                                v.selection.stroke.color
                            } else {
                                v.text_color()
                            };
                            let weak = if sel {
                                v.selection.stroke.color
                            } else {
                                v.weak_text_color()
                            };
                            let subj = if e.subject.is_empty() {
                                "(no subject)"
                            } else {
                                &e.subject
                            };
                            let p = ui.painter_at(rect.shrink(4.0));
                            p.text(
                                rect.left_top() + egui::vec2(6.0, 4.0),
                                egui::Align2::LEFT_TOP,
                                subj,
                                egui::FontId::proportional(14.0),
                                fg,
                            );
                            let date = e.date.map(analysis::fmt_local).unwrap_or_default();
                            p.text(
                                rect.left_top() + egui::vec2(6.0, 22.0),
                                egui::Align2::LEFT_TOP,
                                &e.from,
                                egui::FontId::proportional(12.0),
                                weak,
                            );
                            p.text(
                                rect.right_top() + egui::vec2(-6.0, 22.0),
                                egui::Align2::RIGHT_TOP,
                                date,
                                egui::FontId::proportional(11.0),
                                weak,
                            );
                            if resp.clicked() {
                                actions.push(Action::OpenMailboxEntry(i));
                            }
                        }
                    },
                );
            });
        self.actions.extend(actions);
    }

    pub(super) fn open_mailbox_entry(&mut self, i: usize) -> Result<(), String> {
        let Some(mb) = &mut self.mailbox else {
            return Ok(());
        };
        let Some(e) = mb.entries.get(i) else {
            return Ok(());
        };
        mb.current = Some(i);
        let key = format!("{}#{}", mb.path.display(), i + 1);
        if let Some(pos) = self.docs.iter().position(|d| {
            d.path
                .as_deref()
                .is_some_and(|p| p.to_string_lossy() == key)
        }) {
            self.active = pos;
            return Ok(());
        }
        let mail = crate::mail::Mail::parse(e.raw.clone())?;
        let title = if mail.subject.is_empty() {
            format!("Message {}", i + 1)
        } else {
            mail.subject.clone()
        };
        self.docs
            .push(Doc::new(mail, Some(std::path::PathBuf::from(key)), title));
        self.active = self.docs.len() - 1;
        Ok(())
    }

    /// Side-by-side comparison of the header fields of two open messages.
    pub(super) fn compare_window(&mut self, ctx: &egui::Context) {
        let Some(mut other) = self.compare else {
            return;
        };
        if self.docs.len() < 2 {
            self.compare = None;
            return;
        }
        if other >= self.docs.len() || other == self.active {
            other = (0..self.docs.len())
                .find(|&i| i != self.active)
                .unwrap_or(0);
        }
        let mut open = true;
        let a = &self.docs[self.active];
        let titles: Vec<String> = self.docs.iter().map(|d| d.title.clone()).collect();
        let b = &self.docs[other];
        let diff_only = &mut self.compare_diff_only;
        egui::Window::new("Compare Headers")
            .open(&mut open)
            .default_size([900.0, 600.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("A:").strong());
                    ui.label(&a.title);
                    ui.add_space(12.0);
                    ui.label(RichText::new("B:").strong());
                    egui::ComboBox::from_id_salt("cmp-b")
                        .selected_text(&titles[other])
                        .width(260.0)
                        .show_ui(ui, |ui| {
                            for (i, t) in titles.iter().enumerate() {
                                if i != self.active {
                                    ui.selectable_value(&mut other, i, t);
                                }
                            }
                        });
                    ui.checkbox(diff_only, "Only differences");
                });
                ui.separator();
                let rows = compare_rows(a, b);
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        let w = (ui.available_width() - 170.0) / 2.0;
                        for (n, (name, va, vb)) in rows
                            .iter()
                            .filter(|(_, x, y)| !*diff_only || x != y)
                            .enumerate()
                        {
                            let differ = va != vb;
                            let fill = if n % 2 == 1 {
                                ui.visuals().faint_bg_color
                            } else {
                                Color32::TRANSPARENT
                            };
                            egui::Frame::none()
                                .fill(fill)
                                .inner_margin(Margin::symmetric(6.0, 3.0))
                                .show(ui, |ui| {
                                    ui.horizontal_top(|ui| {
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(150.0, 0.0),
                                            Layout::top_down(Align::Min),
                                            |ui| {
                                                ui.set_width(150.0);
                                                let t = RichText::new(name).strong();
                                                ui.add(
                                                    egui::Label::new(if differ {
                                                        t.color(ui.visuals().warn_fg_color)
                                                    } else {
                                                        t.color(crate::theme::accent(
                                                            ui.visuals().dark_mode,
                                                        ))
                                                    })
                                                    .wrap(),
                                                );
                                            },
                                        );
                                        for v in [va, vb] {
                                            ui.allocate_ui_with_layout(
                                                egui::vec2(w, 0.0),
                                                Layout::top_down(Align::Min),
                                                |ui| {
                                                    ui.set_width(w - 8.0);
                                                    let t = RichText::new(if v.is_empty() {
                                                        "–"
                                                    } else {
                                                        v.as_str()
                                                    })
                                                    .monospace()
                                                    .small();
                                                    ui.add(
                                                        egui::Label::new(if v.is_empty() {
                                                            t.weak()
                                                        } else {
                                                            t
                                                        })
                                                        .wrap(),
                                                    );
                                                },
                                            );
                                        }
                                    });
                                });
                        }
                    });
            });
        self.compare = open.then_some(other);
    }
}

/// (field, value A, value B): rating, domains, then all header fields by name and occurrence.
fn compare_rows(a: &Doc, b: &Doc) -> Vec<(String, String, String)> {
    let mut rows = vec![
        (
            "Rating".to_string(),
            a.checks.rating.label().to_string(),
            b.checks.rating.label().to_string(),
        ),
        (
            "Sender IP".into(),
            a.checks
                .sender_ip
                .map(|(_, ip)| ip.to_string())
                .unwrap_or_default(),
            b.checks
                .sender_ip
                .map(|(_, ip)| ip.to_string())
                .unwrap_or_default(),
        ),
        (
            "Hops".into(),
            a.mail.hops.len().to_string(),
            b.mail.hops.len().to_string(),
        ),
    ];
    let auth = |d: &Doc| {
        d.checks
            .auth
            .iter()
            .map(|r| format!("{}={}", r.method, r.result))
            .collect::<Vec<_>>()
            .join(" ")
    };
    rows.push(("Authentication".into(), auth(a), auth(b)));
    let mut names: Vec<String> = Vec::new();
    for f in a.mail.fields.iter().chain(&b.mail.fields) {
        let n = f.name.to_ascii_lowercase();
        if !names.contains(&n) {
            names.push(n);
        }
    }
    for n in names {
        let va: Vec<&str> = a.mail.all(&n).map(|f| f.value.as_str()).collect();
        let vb: Vec<&str> = b.mail.all(&n).map(|f| f.value.as_str()).collect();
        let display = a
            .mail
            .all(&n)
            .chain(b.mail.all(&n))
            .next()
            .map(|f| f.name.clone())
            .unwrap_or(n.clone());
        for i in 0..va.len().max(vb.len()) {
            let label = if va.len().max(vb.len()) > 1 {
                format!("{display} #{}", i + 1)
            } else {
                display.clone()
            };
            rows.push((
                label,
                va.get(i).unwrap_or(&"").to_string(),
                vb.get(i).unwrap_or(&"").to_string(),
            ));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    #[test]
    fn mbox() {
        let e = super::read_mbox(include_bytes!("../../tests/data/sample.mbox").to_vec());
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].subject, "Erste Nachricht");
        assert_eq!(e[1].from, "Bob");
        assert!(crate::mail::Mail::parse(e[1].raw.clone())
            .unwrap()
            .text
            .unwrap()
            .contains("From here on quoted"));
    }
}
