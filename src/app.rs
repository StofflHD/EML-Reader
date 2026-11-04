//! The viewer window: menus, tabs of open messages, message / header / structure / source views.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use eframe::egui::{
    self, text::CCursor, text::LayoutJob, Align, Align2, Color32, FontId, Key, Layout, Margin,
    Modifiers, RichText, Sense, TextFormat, TextStyle, Ui, Vec2,
};
use serde::{Deserialize, Serialize};

use crate::analysis::{self, AuthResult, Link, Verdict};
use crate::checks::Checks;
use crate::mail::{Attachment, Mail, Mailbox};
use crate::{online, update};

mod analysis_view;

/// Full text of the GPL-3.0, shown in the About window (CR are dropped when shown: Windows
/// checkouts may have CRLF line endings).
const LICENSE: &str = include_str!("../LICENSE");
const RECENT_LEN: usize = 12;
/// The source view shows at most this much of a message.
const SOURCE_LIMIT: usize = 8 * 1024 * 1024;
const KEY_W: f32 = 92.0;

/// Everything that survives a restart.
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    dark: bool,
    /// Show the HTML part (converted to text) when a message has both.
    prefer_html: bool,
    monospace: bool,
    show_images: bool,
    /// Header table: decoded values (or as written).
    header_decoded: bool,
    recent: Vec<String>,
    last_dir: String,
    /// Look for a new release at start-up (at most once a day).
    update_auto_check: bool,
    /// Unix time of the last automatic check.
    update_last_check: i64,
    /// Version the user chose to skip (the automatic check stays quiet about it).
    update_skip: String,
    /// Proxy for the updater, e.g. `http://proxy:3128` (empty = none).
    update_proxy: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark: false,
            prefer_html: true,
            monospace: false,
            show_images: true,
            header_decoded: true,
            recent: Vec::new(),
            last_dir: String::new(),
            update_auto_check: true,
            update_last_check: 0,
            update_skip: String::new(),
            update_proxy: String::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum View {
    Message,
    Analysis,
    Headers,
    Structure,
    Source,
}

impl View {
    const ALL: [(View, &'static str); 5] = [
        (View::Message, "Message"),
        (View::Analysis, "Analysis"),
        (View::Headers, "Headers"),
        (View::Structure, "Structure"),
        (View::Source, "Source"),
    ];
}

/// One open message.
struct Doc {
    path: Option<PathBuf>,
    title: String,
    mail: Mail,
    view: View,
    /// Body choice when the message has a text and an HTML part (None = settings).
    html: Option<bool>,
    /// HTML converted to text: (columns, text).
    html_text: Option<(usize, String)>,
    /// All offline checks and the rating.
    checks: Checks,
    /// Result of the online check (DNS), when run.
    online: Option<online::Report>,
    online_rx: Option<Receiver<online::Report>>,
    /// Decoded image attachments (None = not an image we can show).
    textures: HashMap<usize, Option<egui::TextureHandle>>,
    source: Option<String>,
    header_filter: String,
    show_raw_header: bool,
}

impl Doc {
    fn new(mail: Mail, path: Option<PathBuf>, title: String) -> Doc {
        let checks = Checks::run(&mail, now());
        Doc {
            path,
            title,
            mail,
            view: View::Message,
            html: None,
            html_text: None,
            checks,
            online: None,
            online_rx: None,
            textures: HashMap::new(),
            source: None,
            header_filter: String::new(),
            show_raw_header: false,
        }
    }

    fn shows_html(&self, prefer: bool) -> bool {
        match (&self.mail.text, &self.mail.html) {
            (Some(_), Some(_)) => self.html.unwrap_or(prefer),
            (None, Some(_)) => true,
            _ => false,
        }
    }

    /// The body as displayed (HTML only once converted).
    fn body(&self, prefer_html: bool) -> &str {
        if self.shows_html(prefer_html) {
            self.html_text.as_ref().map_or("", |(_, t)| t.as_str())
        } else {
            self.mail.text.as_deref().unwrap_or("")
        }
    }

    fn ensure_html(&mut self, cols: usize) {
        if self.html_text.as_ref().is_some_and(|(c, _)| *c == cols) {
            return;
        }
        let Some(html) = &self.mail.html else { return };
        let text = html2text::config::plain_no_decorate()
            .link_footnotes(true)
            .string_from_read(html.as_bytes(), cols)
            .unwrap_or_else(|_| mail_parser::decoders::html::html_to_text(html));
        self.html_text = Some((cols, text.trim_end().to_string()));
    }

    fn source(&mut self) -> &str {
        let raw = &self.mail.raw;
        self.source.get_or_insert_with(|| {
            let mut s = String::from_utf8_lossy(&raw[..raw.len().min(SOURCE_LIMIT)]).into_owned();
            if raw.len() > SOURCE_LIMIT {
                s.push_str(&format!(
                    "\n\n[… {} not shown]",
                    analysis::human_size(raw.len() - SOURCE_LIMIT)
                ));
            }
            s
        })
    }

    fn texture(&mut self, ctx: &egui::Context, i: usize) -> Option<egui::TextureHandle> {
        if let Some(t) = self.textures.get(&i) {
            return t.clone();
        }
        let t = self
            .mail
            .attachments
            .get(i)
            .filter(|a| a.is_image())
            .and_then(|a| image::load_from_memory(&a.data).ok())
            .map(|img| {
                let img = if img.width() > 2048 || img.height() > 2048 {
                    img.thumbnail(2048, 2048)
                } else {
                    img
                };
                let rgba = img.to_rgba8();
                let ci = egui::ColorImage::from_rgba_unmultiplied(
                    [rgba.width() as usize, rgba.height() as usize],
                    rgba.as_raw(),
                );
                ctx.load_texture(format!("att-{i}"), ci, egui::TextureOptions::LINEAR)
            });
        self.textures.insert(i, t.clone());
        t
    }
}

/// Something the user asked for; carried out after the frame's UI code.
#[derive(Clone)]
enum Action {
    OpenDialog,
    OpenPath(PathBuf),
    Close(usize),
    Preview(usize),
    /// Open an attachment with the default application (true = risk confirmed).
    OpenExternal(usize, bool),
    Save(usize),
    SaveAll,
    OpenNested(usize),
    /// Open the HTML body in the browser (true = confirmed).
    OpenHtml(bool),
    ExportText,
    SaveEml,
    OpenUrl(String, bool),
    Copy(String),
    /// Analysis report as HTML or text file.
    ExportReport,
    /// DNS queries for SPF/DMARC/DKIM/IPs (true = confirmed).
    OnlineCheck(bool),
    Compare,
    /// Open message `n` of the mailbox in a tab.
    OpenMailboxEntry(usize),
    CloseMailbox,
}

/// One message of an opened mbox file.
struct MboxEntry {
    raw: Vec<u8>,
    subject: String,
    from: String,
    date: Option<i64>,
}

/// An opened mailbox (mbox file): list in the side panel.
struct Mailbox_ {
    path: PathBuf,
    entries: Vec<MboxEntry>,
    filter: String,
    /// Entry opened last (highlighted).
    current: Option<usize>,
}

struct Confirm {
    title: String,
    text: String,
    button: String,
    action: Action,
}

enum UpdateState {
    Checking,
    UpToDate,
    Available(update::Release),
    Installing,
    Installed(PathBuf),
    Error(String),
}

struct UpdateDlg {
    state: UpdateState,
    /// Opened from the menu (an automatic check only shows a found update).
    manual: bool,
}

/// Search in the message or source text.
#[derive(Default)]
struct Find {
    open: bool,
    text: String,
    current: usize,
    scroll: bool,
    focus: bool,
    /// (key, matches) of the last search.
    cache: Option<(String, Vec<Range<usize>>)>,
}

pub struct App {
    s: Settings,
    docs: Vec<Doc>,
    active: usize,
    actions: Vec<Action>,
    find: Find,
    preview: Option<usize>,
    confirm: Option<Confirm>,
    error: Option<String>,
    about: bool,
    logo: egui::TextureHandle,
    title: String,
    update: Option<UpdateDlg>,
    update_rx: Option<Receiver<update::Msg>>,
    /// "Updater Proxy" dialog (edited value).
    proxy_dlg: Option<String>,
    /// AppImage to start once this process has exited ("Restart Now" after an update).
    restart_exe: Option<PathBuf>,
    mailbox: Option<Mailbox_>,
    /// Compare-headers window: index of the second message.
    compare: Option<usize>,
    compare_diff_only: bool,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, files: Vec<PathBuf>) -> Self {
        let s: Settings = cc
            .storage
            .and_then(|st| eframe::get_value(st, eframe::APP_KEY))
            .unwrap_or_default();
        crate::theme::apply(&cc.egui_ctx, s.dark);
        crate::fonts::apply(&cc.egui_ctx);
        let mut app = Self {
            s,
            docs: Vec::new(),
            active: 0,
            actions: files.into_iter().map(Action::OpenPath).collect(),
            find: Find::default(),
            preview: None,
            confirm: None,
            error: None,
            about: false,
            logo: load_logo(&cc.egui_ctx),
            title: String::new(),
            update: None,
            update_rx: None,
            proxy_dlg: None,
            restart_exe: None,
            mailbox: None,
            compare: None,
            compare_diff_only: false,
        };
        clean_temp();
        // Automatic update check (at most once a day, in the background).
        let now = now();
        if app.s.update_auto_check
            && std::env::var_os("EML_NO_UPDATE").is_none()
            && now - app.s.update_last_check >= 86_400
        {
            app.s.update_last_check = now;
            app.start_update_check(&cc.egui_ctx, false);
        }
        app
    }

    // ------------------------------------------------------------- opening

    fn open_path(&mut self, path: &Path) {
        // Already open: just switch to it.
        if let Some(i) = self
            .docs
            .iter()
            .position(|d| d.path.as_deref() == Some(path))
        {
            self.active = i;
            return;
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                self.error = Some(format!(
                    "{}:
{e}",
                    path.display()
                ));
                return;
            }
        };
        // mbox: several messages, shown in the side panel.
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(ext.as_str(), "mbox" | "mbx")
            || (data.starts_with(b"From ") && !data.starts_with(b"From: "))
        {
            if let Err(e) = self.open_mailbox(path, data) {
                self.error = Some(e);
            } else {
                let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
                self.remember(&abs);
                self.actions.push(Action::OpenMailboxEntry(0));
            }
            return;
        }
        let result = if crate::msg::is_msg(&data) {
            crate::msg::to_eml(&data)
        } else {
            Ok(data)
        }
        .and_then(Mail::parse);
        match result {
            Ok(mail) => {
                let title = if mail.subject.is_empty() {
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                } else {
                    mail.subject.clone()
                };
                let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
                self.remember(&abs);
                self.docs.push(Doc::new(mail, Some(abs), title));
                self.active = self.docs.len() - 1;
            }
            Err(e) => {
                self.error = Some(format!("{}:\n{e}", path.display()));
                let p = path.display().to_string();
                self.s.recent.retain(|r| *r != p);
            }
        }
    }

    fn remember(&mut self, path: &Path) {
        let p = path.display().to_string();
        self.s.recent.retain(|r| *r != p);
        self.s.recent.insert(0, p);
        self.s.recent.truncate(RECENT_LEN);
        if let Some(dir) = path.parent() {
            self.s.last_dir = dir.display().to_string();
        }
    }

    fn dialog(&self) -> rfd::FileDialog {
        let d = rfd::FileDialog::new();
        if !self.s.last_dir.is_empty() && Path::new(&self.s.last_dir).is_dir() {
            d.set_directory(&self.s.last_dir)
        } else {
            d
        }
    }

    fn run_actions(&mut self, ctx: &egui::Context) {
        for action in std::mem::take(&mut self.actions) {
            if let Err(e) = self.run(ctx, action) {
                self.error = Some(e);
            }
        }
    }

    fn run(&mut self, ctx: &egui::Context, action: Action) -> Result<(), String> {
        let prefer_html = self.s.prefer_html;
        match action {
            Action::OpenDialog => {
                if let Some(files) = self
                    .dialog()
                    .add_filter(
                        "E-mail messages",
                        &["eml", "EML", "msg", "MSG", "mbox", "mbx", "mht"],
                    )
                    .add_filter("All files", &["*"])
                    .pick_files()
                {
                    for f in files {
                        self.open_path(&f);
                    }
                }
            }
            Action::OpenPath(p) => self.open_path(&p),
            Action::Close(i) => {
                if i < self.docs.len() {
                    self.docs.remove(i);
                    if self.active >= i && self.active > 0 {
                        self.active -= 1;
                    }
                    self.preview = None;
                }
            }
            Action::Preview(i) => self.preview = Some(i),
            Action::OpenExternal(i, confirmed) => {
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let Some(a) = doc.mail.attachments.get(i) else {
                    return Ok(());
                };
                if analysis::is_risky(&a.name) && !confirmed {
                    self.confirm = Some(Confirm {
                        title: "Open Attachment".into(),
                        text: format!(
                            "\"{}\" is a program or script type. Opening it can run code on \
                             this computer.\n\nOnly continue if you trust the sender.",
                            a.name
                        ),
                        button: "Open Anyway".into(),
                        action: Action::OpenExternal(i, true),
                    });
                    return Ok(());
                }
                let path = write_temp(&a.name, &a.data)?;
                open_external(&path)?;
            }
            Action::Save(i) => {
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let Some(a) = doc.mail.attachments.get(i) else {
                    return Ok(());
                };
                if let Some(p) = self
                    .dialog()
                    .set_file_name(analysis::safe_file_name(&a.name))
                    .save_file()
                {
                    std::fs::write(&p, &a.data).map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            Action::SaveAll => {
                let Some(dir) = self.dialog().pick_folder() else {
                    return Ok(());
                };
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                for a in &doc.mail.attachments {
                    let p = unique_path(&dir, &analysis::safe_file_name(&a.name));
                    std::fs::write(&p, &a.data).map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            Action::OpenNested(i) => {
                let Some(a) = self
                    .docs
                    .get(self.active)
                    .and_then(|d| d.mail.attachments.get(i))
                else {
                    return Ok(());
                };
                let name = a.name.clone();
                let mail = Mail::parse(a.data.clone())?;
                let title = if mail.subject.is_empty() {
                    name
                } else {
                    mail.subject.clone()
                };
                self.docs.push(Doc::new(mail, None, title));
                self.active = self.docs.len() - 1;
            }
            Action::OpenHtml(confirmed) => {
                if !confirmed {
                    self.confirm = Some(Confirm {
                        title: "Open in Browser".into(),
                        text: "The browser loads remote content of the message (images, \
                               tracking pixels), so the sender may learn that and when the \
                               message was opened.\n\nEmbedded images are included."
                            .into(),
                        button: "Open in Browser".into(),
                        action: Action::OpenHtml(true),
                    });
                    return Ok(());
                }
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let Some(html) = &doc.mail.html else {
                    return Ok(());
                };
                let html = analysis::html_with_inline_images(html, &doc.mail.attachments);
                let html = if html.to_ascii_lowercase().contains("<meta charset") {
                    html
                } else {
                    format!("<meta charset=\"utf-8\">\n{html}")
                };
                let path = write_temp("message.html", html.as_bytes())?;
                open_external(&path)?;
            }
            Action::ExportText => {
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let text = analysis::as_text(&doc.mail, doc.body(prefer_html));
                let name = format!("{}.txt", analysis::safe_file_name(&doc.title));
                if let Some(p) = self.dialog().set_file_name(name).save_file() {
                    std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            Action::SaveEml => {
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let name = format!("{}.eml", analysis::safe_file_name(&doc.title));
                if let Some(p) = self.dialog().set_file_name(name).save_file() {
                    std::fs::write(&p, &doc.mail.raw)
                        .map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            Action::OpenUrl(url, confirmed) => {
                if !confirmed {
                    let host = analysis::url_host(&url);
                    self.confirm = Some(Confirm {
                        title: "Open Link".into(),
                        text: format!(
                            "Open this address in the browser?\n\n{url}\n\nServer: {host}"
                        ),
                        button: "Open Link".into(),
                        action: Action::OpenUrl(url, true),
                    });
                    return Ok(());
                }
                ctx.open_url(egui::OpenUrl::new_tab(url));
            }
            Action::Copy(text) => ctx.copy_text(text),
            Action::ExportReport => {
                let Some(doc) = self.docs.get(self.active) else {
                    return Ok(());
                };
                let name = format!("Analysis {}.html", analysis::safe_file_name(&doc.title));
                if let Some(p) = self
                    .dialog()
                    .set_file_name(name)
                    .add_filter("HTML report", &["html"])
                    .add_filter("Text report", &["txt"])
                    .save_file()
                {
                    let txt = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt"));
                    let content = if txt {
                        crate::report::text(&doc.mail, &doc.checks, doc.online.as_ref())
                    } else {
                        crate::report::html(&doc.mail, &doc.checks, doc.online.as_ref())
                    };
                    std::fs::write(&p, content).map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            Action::OnlineCheck(confirmed) => {
                if self.docs.is_empty() {
                    return Ok(());
                }
                if !confirmed {
                    self.confirm = Some(Confirm {
                        title: "Online Check".into(),
                        text: "EML Reader asks Cloudflare's DNS service (cloudflare-dns.com) for \
                               the SPF, DMARC and DKIM records of the message's domains, the \
                               reverse names of the route's IP addresses and their network \
                               (Team Cymru).\n\nOnly domain names and IP addresses are sent – no \
                               content of the message. The sender is not contacted."
                            .into(),
                        button: "Check Online".into(),
                        action: Action::OnlineCheck(true),
                    });
                    return Ok(());
                }
                self.start_online(ctx);
            }
            Action::Compare => {
                if self.docs.len() < 2 {
                    return Err("Open a second message to compare.".into());
                }
                self.compare = Some((self.active + 1) % self.docs.len());
            }
            Action::OpenMailboxEntry(i) => self.open_mailbox_entry(i)?,
            Action::CloseMailbox => self.mailbox = None,
        }
        Ok(())
    }

    // ---------------------------------------------------------------- keys

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let cmd = Modifiers::COMMAND;
        let shift = Modifiers::COMMAND | Modifiers::SHIFT;
        let (open, close, next, prev, find, f3, sf3, esc, quit) = ctx.input_mut(|i| {
            (
                i.consume_key(cmd, Key::O),
                i.consume_key(cmd, Key::W),
                i.consume_key(cmd, Key::Tab) || i.consume_key(cmd, Key::PageDown),
                i.consume_key(shift, Key::Tab) || i.consume_key(cmd, Key::PageUp),
                i.consume_key(cmd, Key::F),
                i.consume_key(Modifiers::NONE, Key::F3),
                i.consume_key(Modifiers::SHIFT, Key::F3),
                self.find.open && i.consume_key(Modifiers::NONE, Key::Escape),
                i.consume_key(cmd, Key::Q),
            )
        });
        let views = ctx.input_mut(|i| {
            [
                (Key::Num1, View::Message),
                (Key::Num2, View::Analysis),
                (Key::Num3, View::Headers),
                (Key::Num4, View::Structure),
                (Key::Num5, View::Source),
                (Key::U, View::Source),
                (Key::H, View::Headers),
            ]
            .into_iter()
            .find(|(k, _)| i.consume_key(cmd, *k))
            .map(|(_, v)| v)
        });
        if open {
            self.actions.push(Action::OpenDialog);
        }
        if close && !self.docs.is_empty() {
            self.actions.push(Action::Close(self.active));
        }
        let n = self.docs.len();
        if n > 0 && next {
            self.active = (self.active + 1) % n;
        }
        if n > 0 && prev {
            self.active = (self.active + n - 1) % n;
        }
        if let (Some(v), Some(d)) = (views, self.docs.get_mut(self.active)) {
            d.view = if d.view == v && v != View::Message {
                View::Message
            } else {
                v
            };
        }
        if find && !self.docs.is_empty() {
            self.find.open = true;
            self.find.focus = true;
            if let Some(d) = self.docs.get_mut(self.active) {
                if !matches!(d.view, View::Message | View::Source) {
                    d.view = View::Message;
                }
            }
        }
        if f3 || sf3 {
            self.find.open = true;
            self.step_find(if sf3 { -1 } else { 1 });
        }
        if esc {
            self.find.open = false;
        }
        if quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    // ---------------------------------------------------------------- find

    /// The searched text and its matches (cached).
    fn find_matches(&mut self) -> Vec<Range<usize>> {
        if !self.find.open || self.find.text.is_empty() {
            return Vec::new();
        }
        let prefer = self.s.prefer_html;
        let active = self.active;
        let needle = self.find.text.clone();
        let Some(doc) = self.docs.get_mut(active) else {
            return Vec::new();
        };
        let (kind, text): (&str, String) = match doc.view {
            View::Source => ("src", doc.source().to_string()),
            View::Message => ("msg", doc.body(prefer).to_string()),
            _ => return Vec::new(),
        };
        let key = format!("{active}\0{kind}\0{}\0{needle}", text.len());
        if let Some((k, m)) = &self.find.cache {
            if *k == key {
                return m.clone();
            }
        }
        let m = analysis::find_all(&text, &needle);
        self.find.cache = Some((key, m.clone()));
        if self.find.current >= m.len() {
            self.find.current = 0;
        }
        m
    }

    fn step_find(&mut self, dir: i32) {
        let n = self.find_matches().len();
        if n == 0 {
            return;
        }
        self.find.current = if dir < 0 {
            (self.find.current + n - 1) % n
        } else {
            (self.find.current + 1) % n
        };
        self.find.scroll = true;
    }

    fn find_bar(&mut self, ui: &mut Ui) {
        let matches = self.find_matches();
        let mut step = 0;
        ui.horizontal(|ui| {
            ui.label("Find:");
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.find.text)
                    .desired_width(240.0)
                    .hint_text("text in the message"),
            );
            if self.find.focus {
                r.request_focus();
                self.find.focus = false;
            }
            if r.changed() {
                self.find.current = 0;
                self.find.scroll = true;
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                step = if ui.input(|i| i.modifiers.shift) {
                    -1
                } else {
                    1
                };
                r.request_focus();
            }
            if ui
                .button("▲")
                .on_hover_text("Previous (Shift+F3)")
                .clicked()
            {
                step = -1;
            }
            if ui.button("▼").on_hover_text("Next (F3)").clicked() {
                step = 1;
            }
            if !self.find.text.is_empty() {
                let t = if matches.is_empty() {
                    RichText::new("No matches").color(ui.visuals().error_fg_color)
                } else {
                    RichText::new(format!("{} of {}", self.find.current + 1, matches.len())).weak()
                };
                ui.label(t);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("✖").on_hover_text("Close (Esc)").clicked() {
                    self.find.open = false;
                }
            });
        });
        if step != 0 {
            self.step_find(step);
        }
    }

    // ---------------------------------------------------------------- menu

    fn menu(&mut self, ui: &mut Ui) {
        let has_doc = !self.docs.is_empty();
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui
                    .add(egui::Button::new("Open …").shortcut_text("Ctrl+O"))
                    .clicked()
                {
                    self.actions.push(Action::OpenDialog);
                    ui.close_menu();
                }
                ui.add_enabled_ui(!self.s.recent.is_empty(), |ui| {
                    ui.menu_button("Recent Files", |ui| {
                        for r in self.s.recent.clone() {
                            if ui.button(&r).clicked() {
                                self.actions.push(Action::OpenPath(PathBuf::from(r)));
                                ui.close_menu();
                            }
                        }
                        ui.separator();
                        if ui.button("Clear List").clicked() {
                            self.s.recent.clear();
                            ui.close_menu();
                        }
                    });
                });
                ui.separator();
                let has_att = self
                    .docs
                    .get(self.active)
                    .is_some_and(|d| !d.mail.attachments.is_empty());
                if ui
                    .add_enabled(has_att, egui::Button::new("Save All Attachments …"))
                    .clicked()
                {
                    self.actions.push(Action::SaveAll);
                    ui.close_menu();
                }
                if ui
                    .add_enabled(has_doc, egui::Button::new("Export as Text …"))
                    .clicked()
                {
                    self.actions.push(Action::ExportText);
                    ui.close_menu();
                }
                if ui
                    .add_enabled(has_doc, egui::Button::new("Save Message As … (.eml)"))
                    .clicked()
                {
                    self.actions.push(Action::SaveEml);
                    ui.close_menu();
                }
                let has_html = self
                    .docs
                    .get(self.active)
                    .is_some_and(|d| d.mail.html.is_some());
                if ui
                    .add_enabled(has_html, egui::Button::new("Open HTML in Browser …"))
                    .clicked()
                {
                    self.actions.push(Action::OpenHtml(false));
                    ui.close_menu();
                }
                if ui
                    .add_enabled(has_doc, egui::Button::new("Export Analysis Report …"))
                    .clicked()
                {
                    self.actions.push(Action::ExportReport);
                    ui.close_menu();
                }
                ui.separator();
                if ui
                    .add_enabled(has_doc, egui::Button::new("Close").shortcut_text("Ctrl+W"))
                    .clicked()
                {
                    self.actions.push(Action::Close(self.active));
                    ui.close_menu();
                }
                if ui
                    .add(egui::Button::new("Exit").shortcut_text("Ctrl+Q"))
                    .clicked()
                {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("View", |ui| {
                let mut view = self.docs.get(self.active).map(|d| d.view);
                for (i, (v, name)) in View::ALL.iter().enumerate() {
                    if ui
                        .add_enabled(has_doc, egui::SelectableLabel::new(view == Some(*v), *name))
                        .clicked()
                    {
                        view = Some(*v);
                        ui.close_menu();
                    }
                    let _ = i;
                }
                if let (Some(v), Some(d)) = (view, self.docs.get_mut(self.active)) {
                    d.view = v;
                }
                ui.label(
                    RichText::new("Ctrl+1 … 5, Ctrl+H headers, Ctrl+U source")
                        .small()
                        .weak(),
                );
                ui.separator();
                if ui
                    .add_enabled(has_doc, egui::Button::new("Find …").shortcut_text("Ctrl+F"))
                    .clicked()
                {
                    self.find.open = true;
                    self.find.focus = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui
                    .checkbox(&mut self.s.prefer_html, "Prefer HTML Part")
                    .on_hover_text(
                        "Messages with a plain-text and an HTML part show the HTML part \
                         (converted to text, links listed below).",
                    )
                    .changed()
                {
                    for d in &mut self.docs {
                        d.html = None;
                    }
                }
                ui.checkbox(&mut self.s.monospace, "Monospace Font for Text");
                ui.checkbox(&mut self.s.show_images, "Show Attached Images");
                ui.separator();
                if ui.checkbox(&mut self.s.dark, "Dark Theme").changed() {
                    crate::theme::apply(ui.ctx(), self.s.dark);
                }
                ui.horizontal(|ui| {
                    ui.label("Zoom:");
                    if ui.button("−").clicked() {
                        egui::gui_zoom::zoom_out(ui.ctx());
                    }
                    ui.label(format!("{:.0} %", ui.ctx().zoom_factor() * 100.0));
                    if ui.button("+").clicked() {
                        egui::gui_zoom::zoom_in(ui.ctx());
                    }
                    if ui.button("100 %").clicked() {
                        ui.ctx().set_zoom_factor(1.0);
                    }
                });
            });
            ui.menu_button("Tools", |ui| {
                if ui
                    .add_enabled(has_doc, egui::Button::new("Online Check (DNS) …"))
                    .on_hover_text("SPF/DMARC/DKIM records, DKIM signature, IP networks")
                    .clicked()
                {
                    self.actions.push(Action::OnlineCheck(false));
                    ui.close_menu();
                }
                if ui
                    .add_enabled(self.docs.len() > 1, egui::Button::new("Compare Headers …"))
                    .on_hover_text("Two open messages side by side")
                    .clicked()
                {
                    self.actions.push(Action::Compare);
                    ui.close_menu();
                }
                if ui
                    .add_enabled(has_doc, egui::Button::new("Export Analysis Report …"))
                    .clicked()
                {
                    self.actions.push(Action::ExportReport);
                    ui.close_menu();
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("Check for Updates …").clicked() {
                    self.start_update_check(ui.ctx(), true);
                    ui.close_menu();
                }
                ui.checkbox(
                    &mut self.s.update_auto_check,
                    "Check for Updates at Start-up",
                );
                if ui.button("Updater Proxy …").clicked() {
                    self.proxy_dlg = Some(self.s.update_proxy.clone());
                    ui.close_menu();
                }
                if !self.s.update_skip.is_empty()
                    && ui
                        .button(format!("Stop Skipping Version {}", self.s.update_skip))
                        .clicked()
                {
                    self.s.update_skip.clear();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("About EML Reader").clicked() {
                    self.about = true;
                    ui.close_menu();
                }
            });
        });
    }

    fn tabs(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            for i in 0..self.docs.len() {
                let sel = i == self.active;
                let mut title = self.docs[i].title.clone();
                if title.chars().count() > 32 {
                    title = title.chars().take(30).collect::<String>() + "…";
                }
                let text = RichText::new(&title);
                let r = ui.add(egui::SelectableLabel::new(
                    sel,
                    if sel { text.strong() } else { text },
                ));
                if r.clicked() {
                    self.active = i;
                }
                if r.middle_clicked() {
                    self.actions.push(Action::Close(i));
                }
                let full = &self.docs[i];
                r.on_hover_text(
                    full.path
                        .as_ref()
                        .map_or(full.title.clone(), |p| p.display().to_string()),
                );
                if ui
                    .add(egui::Button::new(RichText::new("✖").small()).frame(false))
                    .on_hover_text("Close (Ctrl+W)")
                    .clicked()
                {
                    self.actions.push(Action::Close(i));
                }
                ui.add_space(8.0);
            }
        });
    }

    // ------------------------------------------------------------- welcome

    fn welcome(&mut self, ui: &mut Ui) {
        ui.add_space((ui.available_height() * 0.12).min(80.0));
        header(ui, &self.logo);
        ui.add_space(18.0);
        ui.vertical_centered(|ui| {
            if ui
                .add(egui::Button::new(
                    RichText::new("  Open E-Mail …  ").size(16.0),
                ))
                .clicked()
            {
                self.actions.push(Action::OpenDialog);
            }
            ui.add_space(6.0);
            ui.label(RichText::new("or drop .eml files onto this window").weak());
            if !self.s.recent.is_empty() {
                ui.add_space(24.0);
                ui.label(RichText::new("Recent Files").strong());
                ui.add_space(4.0);
                for r in self.s.recent.clone() {
                    let name = Path::new(&r)
                        .file_name()
                        .map_or(r.clone(), |n| n.to_string_lossy().into_owned());
                    if ui.link(&name).on_hover_text(&r).clicked() {
                        self.actions.push(Action::OpenPath(PathBuf::from(&r)));
                    }
                }
            }
        });
    }

    // ------------------------------------------------------------ doc view

    fn doc_view(&mut self, ui: &mut Ui) {
        let s_prefer = self.s.prefer_html;
        let mono = self.s.monospace;
        let show_images = self.s.show_images;
        let mut decoded = self.s.header_decoded;
        let matches = self.find_matches();
        let find_cur = self.find.current;
        let mut scroll = std::mem::take(&mut self.find.scroll);
        let ctx = ui.ctx().clone();
        let Some(doc) = self.docs.get_mut(self.active) else {
            return;
        };
        let mut actions = Vec::new();

        summary(ui, doc);
        if analysis_view::rating_banner(ui, &doc.checks) {
            doc.view = View::Analysis;
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            for (v, name) in View::ALL {
                let sel = doc.view == v;
                let label = match v {
                    View::Analysis => format!(
                        "{} {name}",
                        match doc.checks.rating {
                            crate::checks::Rating::Safe => "✔",
                            crate::checks::Rating::Suspicious => "⚠",
                            crate::checks::Rating::Dangerous => "⛔",
                        }
                    ),
                    View::Message if !doc.mail.attachments.is_empty() => {
                        format!("{name} · 📎 {}", doc.mail.attachments.len())
                    }
                    _ => name.to_string(),
                };
                let text = RichText::new(label);
                if ui
                    .add(egui::SelectableLabel::new(
                        sel,
                        if sel { text.strong() } else { text },
                    ))
                    .clicked()
                    && !sel
                {
                    doc.view = v;
                    scroll = false;
                }
            }
        });
        egui::Frame::group(ui.style())
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height() - 6.0);
                match doc.view {
                    View::Message => message_view(
                        ui,
                        &ctx,
                        doc,
                        s_prefer,
                        mono,
                        show_images,
                        &matches,
                        find_cur,
                        scroll,
                        &mut actions,
                    ),
                    View::Analysis => analysis_view::analysis_view(ui, &ctx, doc, &mut actions),
                    View::Headers => headers_view(ui, doc, &mut decoded, &mut actions),
                    View::Structure => structure_view(ui, doc),
                    View::Source => {
                        let src = doc.source().to_string();
                        egui::ScrollArea::both()
                            .id_salt("source")
                            .auto_shrink(false)
                            .show(ui, |ui| {
                                text_view(ui, "src", &src, true, &matches, find_cur, scroll);
                            });
                    }
                }
            });
        self.s.header_decoded = decoded;
        self.actions.extend(actions);
    }

    // ------------------------------------------------------------- windows

    fn preview_window(&mut self, ctx: &egui::Context) {
        let Some(i) = self.preview else { return };
        let Some(doc) = self.docs.get_mut(self.active) else {
            self.preview = None;
            return;
        };
        let Some(a) = doc.mail.attachments.get(i).cloned() else {
            self.preview = None;
            return;
        };
        let tex = doc.texture(ctx, i);
        let mut open = true;
        let mut actions = Vec::new();
        egui::Window::new(format!("📎 {}", a.name))
            .id(egui::Id::new("preview"))
            .open(&mut open)
            .collapsible(false)
            .default_size([640.0, 520.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} · {}",
                            a.mime,
                            analysis::human_size(a.data.len())
                        ))
                        .weak(),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Save As …").clicked() {
                            actions.push(Action::Save(i));
                        }
                        if ui.button("Open").clicked() {
                            actions.push(Action::OpenExternal(i, false));
                        }
                        if a.is_message && ui.button("Open as Message").clicked() {
                            actions.push(Action::OpenNested(i));
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::both().auto_shrink(false).show(ui, |ui| {
                    if let Some(t) = &tex {
                        let size = t.size_vec2();
                        let scale = (ui.available_width() / size.x).min(1.0);
                        ui.add(egui::Image::new(t).fit_to_exact_size(size * scale));
                    } else if a.is_text() || a.is_message {
                        let limit = a.data.len().min(1024 * 1024);
                        let text = String::from_utf8_lossy(&a.data[..limit]).into_owned();
                        text_view(ui, "preview-text", &text, true, &[], 0, false);
                    } else {
                        ui.add_space(20.0);
                        ui.vertical_centered(|ui| {
                            ui.label("No preview for this file type.");
                            ui.label(
                                RichText::new("Open it with the default application or save it.")
                                    .weak(),
                            );
                        });
                    }
                });
            });
        if ctx.input(|i| i.key_pressed(Key::Escape)) && self.confirm.is_none() {
            open = false;
        }
        if !open {
            self.preview = None;
        }
        self.actions.extend(actions);
    }

    fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let mut keep = true;
        let mut run = None;
        egui::Window::new(&c.title)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(&c.text);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(&c.button).clicked() {
                        run = Some(c.action.clone());
                        keep = false;
                    }
                    if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                });
            });
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            keep = false;
        }
        if let Some(a) = run {
            self.actions.push(a);
        }
        if !keep {
            self.confirm = None;
        }
    }

    fn error_window(&mut self, ctx: &egui::Context) {
        let Some(e) = &self.error else { return };
        let mut keep = true;
        egui::Window::new("Error")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(RichText::new(e).color(ui.visuals().error_fg_color));
                if ui.button("OK").clicked() {
                    keep = false;
                }
            });
        if ctx.input(|i| i.key_pressed(Key::Escape) || i.key_pressed(Key::Enter)) {
            keep = false;
        }
        if !keep {
            self.error = None;
        }
    }

    // ------------------------------------------------------------- updater

    fn start_update_check(&mut self, ctx: &egui::Context, manual: bool) {
        if self.update_rx.is_some() {
            if manual {
                self.update.get_or_insert(UpdateDlg {
                    state: UpdateState::Checking,
                    manual,
                });
            }
            return;
        }
        let (tx, rx) = channel();
        let ctx2 = ctx.clone();
        update::spawn_check(self.s.update_proxy.clone(), tx, move || {
            ctx2.request_repaint()
        });
        self.update_rx = Some(rx);
        if manual {
            self.update = Some(UpdateDlg {
                state: UpdateState::Checking,
                manual,
            });
        }
    }

    fn start_update_install(&mut self, ctx: &egui::Context, rel: update::Release) {
        let Some(target) = update::running_appimage() else {
            return;
        };
        let (tx, rx) = channel();
        let ctx2 = ctx.clone();
        update::spawn_install(rel, target, self.s.update_proxy.clone(), tx, move || {
            ctx2.request_repaint()
        });
        self.update_rx = Some(rx);
        self.update = Some(UpdateDlg {
            state: UpdateState::Installing,
            manual: true,
        });
    }

    fn poll_update(&mut self) {
        let Some(rx) = &self.update_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.update_rx = None;
        let manual = self.update.as_ref().is_some_and(|u| u.manual);
        let state = match msg {
            update::Msg::Checked(Ok(Some(rel))) if manual || rel.version != self.s.update_skip => {
                Some(UpdateState::Available(rel))
            }
            update::Msg::Checked(Ok(_)) => manual.then_some(UpdateState::UpToDate),
            update::Msg::Checked(Err(e)) => manual.then_some(UpdateState::Error(e)),
            update::Msg::Installed(Ok(p)) => Some(UpdateState::Installed(p)),
            update::Msg::Installed(Err(e)) => Some(UpdateState::Error(e)),
        };
        self.update = state.map(|state| UpdateDlg { state, manual });
    }

    fn update_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.update.take() else {
            return;
        };
        let mut open = true;
        let mut keep = true;
        let mut action: Option<u8> = None; // 1 install, 2 release page, 3 skip, 4 restart
        let current = env!("CARGO_PKG_VERSION");
        egui::Window::new("Update EML Reader")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_min_width(380.0);
                match &dlg.state {
                    UpdateState::Checking => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Checking for updates …");
                        });
                    }
                    UpdateState::Installing => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Downloading and verifying the update …");
                        });
                    }
                    UpdateState::UpToDate => {
                        ui.label(format!("EML Reader {current} is up to date."));
                        if ui.button("OK").clicked() {
                            keep = false;
                        }
                    }
                    UpdateState::Available(rel) => {
                        ui.label(
                            RichText::new(format!(
                                "EML Reader {} is available (installed: {current}).",
                                rel.version
                            ))
                            .strong(),
                        );
                        if !rel.notes.trim().is_empty() {
                            egui::ScrollArea::vertical()
                                .max_height(220.0)
                                .show(ui, |ui| {
                                    ui.label(rel.notes.trim());
                                });
                        }
                        let appimage = update::running_appimage();
                        if appimage.is_none() {
                            ui.label(
                                RichText::new(
                                    "Not started from an AppImage: download the new version \
                                     from the release page.",
                                )
                                .weak(),
                            );
                        } else if rel.appimage.is_none() {
                            ui.label(
                                RichText::new("The release has no AppImage for this system.")
                                    .weak(),
                            );
                        }
                        ui.horizontal(|ui| {
                            if appimage.is_some()
                                && rel.appimage.is_some()
                                && ui.button("Update Now").clicked()
                            {
                                action = Some(1);
                            }
                            if ui.button("Open Release Page").clicked() {
                                action = Some(2);
                            }
                            if ui.button("Later").clicked() {
                                keep = false;
                            }
                            if ui.button("Skip This Version").clicked() {
                                action = Some(3);
                            }
                        });
                    }
                    UpdateState::Installed(p) => {
                        ui.label("The update has been installed. It takes effect after a restart.");
                        ui.label(RichText::new(p.display().to_string()).weak());
                        ui.horizontal(|ui| {
                            if ui.button("Restart Now").clicked() {
                                action = Some(4);
                            }
                            if ui.button("Later").clicked() {
                                keep = false;
                            }
                        });
                    }
                    UpdateState::Error(e) => {
                        ui.label(RichText::new("The update failed:").strong());
                        ui.label(e);
                        ui.horizontal(|ui| {
                            if ui.button("Open Release Page").clicked() {
                                action = Some(2);
                            }
                            if ui.button("OK").clicked() {
                                keep = false;
                            }
                        });
                    }
                }
            });
        let busy = matches!(dlg.state, UpdateState::Checking | UpdateState::Installing);
        if !busy && ctx.input(|i| i.key_pressed(Key::Escape)) {
            keep = false;
        }
        match (action, &dlg.state) {
            (Some(1), UpdateState::Available(rel)) => {
                let rel = rel.clone();
                self.start_update_install(ctx, rel);
                return;
            }
            (Some(2), UpdateState::Available(rel)) => {
                ctx.open_url(egui::OpenUrl::new_tab(&rel.page));
                keep = false;
            }
            (Some(2), _) => {
                ctx.open_url(egui::OpenUrl::new_tab(update::releases_page()));
                keep = false;
            }
            (Some(3), UpdateState::Available(rel)) => {
                self.s.update_skip = rel.version.clone();
                keep = false;
            }
            (Some(4), UpdateState::Installed(p)) => {
                self.restart_exe = Some(p.clone());
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                keep = false;
            }
            _ => {}
        }
        // A running check/download continues in the background when the window is closed.
        if open && keep {
            self.update = Some(dlg);
        }
    }

    fn proxy_window(&mut self, ctx: &egui::Context) {
        let Some(mut proxy) = self.proxy_dlg.take() else {
            return;
        };
        let mut open = true;
        let mut keep = true;
        egui::Window::new("Updater Proxy")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label("Proxy for update checks and downloads (empty = none):");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut proxy)
                        .hint_text("http://proxy.example:3128")
                        .desired_width(320.0),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() || enter {
                        self.s.update_proxy = proxy.trim().to_string();
                        keep = false;
                    }
                    if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                });
            });
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            keep = false;
        }
        if open && keep {
            self.proxy_dlg = Some(proxy);
        }
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("About EML Reader")
            .open(&mut self.about)
            .collapsible(false)
            .resizable(false)
            .max_width(520.0)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(format!("EML Reader {}", env!("CARGO_PKG_VERSION")))
                            .heading()
                            .color(crate::theme::accent(ui.visuals().dark_mode)),
                    );
                    ui.label(
                        "Viewer and analyser for e-mail files (.eml, .msg, mbox) written in Rust.",
                    );
                    ui.add_space(10.0);
                    ui.separator();
                    ui.label(RichText::new(env!("CARGO_PKG_AUTHORS")).strong());
                    ui.add_space(6.0);
                    ui.label("License: GNU General Public License v3.0 or later");
                    ui.label(
                        RichText::new(
                            "This program comes with ABSOLUTELY NO WARRANTY. It is free \
                             software: you can redistribute it and/or modify it under the \
                             terms of the GPL.",
                        )
                        .small()
                        .weak(),
                    );
                    ui.hyperlink_to(
                        "gnu.org/licenses/gpl-3.0",
                        "https://www.gnu.org/licenses/gpl-3.0.html",
                    );
                });
                ui.add_space(4.0);
                egui::CollapsingHeader::new("License Text").show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            // Wide enough for the 77 columns of the GPL text.
                            ui.set_min_width(470.0);
                            let text = RichText::new(LICENSE.replace('\r', ""))
                                .font(FontId::monospace(10.0));
                            ui.add(egui::Label::new(text).wrap());
                        });
                });
            });
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.s);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_update();
        self.poll_online();
        if ctx.input(|i| i.viewport().close_requested()) {
            if let Some(exe) = self.restart_exe.take() {
                update::restart_when_exited(&exe);
            }
        }
        // Files dropped onto the window.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        self.actions
            .extend(dropped.into_iter().map(Action::OpenPath));
        self.shortcuts(ctx);
        self.run_actions(ctx);
        if self.active >= self.docs.len() {
            self.active = self.docs.len().saturating_sub(1);
        }

        let title = match self.docs.get(self.active) {
            Some(d) => format!("{} – EML Reader", d.title),
            None => "EML Reader".into(),
        };
        if title != self.title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.title = title;
        }

        egui::TopBottomPanel::top("menu").show(ctx, |ui| self.menu(ui));
        self.mailbox_panel(ctx);
        if self.docs.len() > 1 {
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| self.tabs(ui));
        }
        if !self.docs.is_empty() {
            egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
                if self.find.open {
                    self.find_bar(ui);
                    ui.separator();
                }
                let d = &self.docs[self.active];
                ui.horizontal(|ui| {
                    let where_ = d
                        .path
                        .as_ref()
                        .map_or("(attached message)".to_string(), |p| {
                            p.display().to_string()
                        });
                    ui.label(RichText::new(where_).weak().small());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} · {} parts · {} attachments",
                                analysis::human_size(d.mail.raw.len()),
                                d.mail.parts.len(),
                                d.mail.attachments.len()
                            ))
                            .weak()
                            .small(),
                        );
                    });
                });
            });
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.docs.is_empty() {
                self.welcome(ui);
            } else {
                self.doc_view(ui);
            }
        });
        // Drag-and-drop hint.
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let rect = ctx.screen_rect();
            let p = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop"),
            ));
            p.rect_filled(rect, 0.0, Color32::from_black_alpha(150));
            p.text(
                rect.center(),
                Align2::CENTER_CENTER,
                "Drop to open",
                FontId::proportional(28.0),
                Color32::WHITE,
            );
        }
        self.preview_window(ctx);
        self.confirm_window(ctx);
        self.error_window(ctx);
        self.about_window(ctx);
        self.update_window(ctx);
        self.proxy_window(ctx);
        self.compare_window(ctx);
        // Actions from windows run in the next frame.
        if !self.actions.is_empty() {
            ctx.request_repaint();
        }
    }
}

// ------------------------------------------------------------------- views

/// Subject, sender, recipients and date above the views.
fn summary(ui: &mut Ui, doc: &Doc) {
    let m = &doc.mail;
    let subject = if m.subject.is_empty() {
        RichText::new("(no subject)").italics().weak()
    } else {
        RichText::new(&m.subject)
    };
    ui.add(egui::Label::new(subject.size(20.0).strong()).wrap());
    ui.add_space(2.0);
    let mut stripe = false;
    let mut row = |ui: &mut Ui, key: &str, f: &dyn Fn(&mut Ui)| {
        kv_row(ui, 70.0, stripe, |ui| key_label(ui, key), f);
        stripe = !stripe;
    };
    if !m.from.is_empty() {
        row(ui, "From", &|ui| addresses(ui, &m.from));
    }
    if !m.to.is_empty() {
        row(ui, "To", &|ui| addresses(ui, &m.to));
    }
    if !m.cc.is_empty() {
        row(ui, "Cc", &|ui| addresses(ui, &m.cc));
    }
    if !m.bcc.is_empty() {
        row(ui, "Bcc", &|ui| addresses(ui, &m.bcc));
    }
    if let Some(d) = m.date {
        row(ui, "Date", &|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(analysis::fmt_local(d.ts));
                ui.label(RichText::new(format!("({})", analysis::relative(d.ts, now()))).weak());
            });
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn message_view(
    ui: &mut Ui,
    ctx: &egui::Context,
    doc: &mut Doc,
    prefer_html: bool,
    mono: bool,
    show_images: bool,
    matches: &[Range<usize>],
    find_cur: usize,
    scroll: bool,
    actions: &mut Vec<Action>,
) {
    let both = doc.mail.text.is_some() && doc.mail.html.is_some();
    let html = doc.shows_html(prefer_html);
    // Body choice, HTML actions.
    if doc.mail.html.is_some() || !doc.mail.attachments.is_empty() {
        ui.horizontal(|ui| {
            if both {
                ui.spacing_mut().item_spacing.x = 2.0;
                if ui.selectable_label(!html, "Plain Text").clicked() {
                    doc.html = Some(false);
                }
                if ui.selectable_label(html, "HTML").clicked() {
                    doc.html = Some(true);
                }
                ui.spacing_mut().item_spacing.x = 8.0;
            } else if html {
                ui.label(RichText::new("HTML message (shown as text)").weak());
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if doc.mail.html.is_some()
                    && ui
                        .button("Open in Browser …")
                        .on_hover_text("Shows the HTML formatting (loads remote content)")
                        .clicked()
                {
                    actions.push(Action::OpenHtml(false));
                }
            });
        });
    }
    // Attachments.
    if !doc.mail.attachments.is_empty() {
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            for (i, a) in doc.mail.attachments.iter().enumerate() {
                let label = format!(
                    "{} {}  ·  {}",
                    attachment_icon(a),
                    a.name,
                    analysis::human_size(a.data.len())
                );
                let risky = analysis::is_risky(&a.name);
                let text = if risky {
                    RichText::new(format!("⚠ {label}")).color(ui.visuals().warn_fg_color)
                } else {
                    RichText::new(label)
                };
                let r = ui.menu_button(text, |ui| {
                    if ui.button("Preview").clicked() {
                        actions.push(Action::Preview(i));
                        ui.close_menu();
                    }
                    if a.is_message && ui.button("Open as Message").clicked() {
                        actions.push(Action::OpenNested(i));
                        ui.close_menu();
                    }
                    if ui.button("Open with Default Application").clicked() {
                        actions.push(Action::OpenExternal(i, false));
                        ui.close_menu();
                    }
                    if ui.button("Save As …").clicked() {
                        actions.push(Action::Save(i));
                        ui.close_menu();
                    }
                });
                let mut tip = a.mime.clone();
                if a.inline {
                    tip.push_str(" · inline");
                }
                r.response.on_hover_text(tip);
            }
            if doc.mail.attachments.len() > 1 && ui.button("💾 Save All …").clicked() {
                actions.push(Action::SaveAll);
            }
        });
    }
    ui.separator();

    let font_id = if mono {
        TextStyle::Monospace.resolve(ui.style())
    } else {
        TextStyle::Body.resolve(ui.style())
    };
    if html {
        // Wrap the converted HTML at the width of the view.
        let w = ui.fonts(|f| f.glyph_width(&font_id, '0')).max(4.0);
        let cols = ((ui.available_width() - 24.0) / w).clamp(30.0, 400.0) as usize;
        let cols = cols / 4 * 4;
        doc.ensure_html(cols);
    }
    let body = doc.body(prefer_html).to_string();
    let links = doc.checks.links.clone();
    let images: Vec<usize> = if show_images {
        doc.mail
            .attachments
            .iter()
            .enumerate()
            .filter(|(_, a)| a.is_image())
            .map(|(i, _)| i)
            .collect()
    } else {
        Vec::new()
    };
    egui::ScrollArea::vertical()
        .id_salt("body")
        .auto_shrink(false)
        .show(ui, |ui| {
            if body.trim().is_empty() {
                ui.label(RichText::new("(The message has no text.)").italics().weak());
            } else {
                text_view(ui, "body", &body, mono, matches, find_cur, scroll);
            }
            if html && !links.is_empty() {
                ui.add_space(8.0);
                links_section(ui, &links, actions);
            }
            if !images.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    for i in images {
                        if let Some(t) = doc.texture(ctx, i) {
                            let size = t.size_vec2();
                            let scale = (360.0 / size.x).min(240.0 / size.y).min(1.0);
                            let r = ui
                                .add(
                                    egui::Image::new(&t)
                                        .fit_to_exact_size(size * scale)
                                        .sense(Sense::click()),
                                )
                                .on_hover_text(&doc.mail.attachments[i].name);
                            if r.clicked() {
                                actions.push(Action::Preview(i));
                            }
                        }
                    }
                });
            }
        });
}

fn links_section(ui: &mut Ui, links: &[Link], actions: &mut Vec<Action>) {
    let bad = links.iter().filter(|l| !l.warning.is_empty()).count();
    let title = if bad > 0 {
        RichText::new(format!("Links ({}) – ⚠ {bad} suspicious", links.len()))
            .strong()
            .color(ui.visuals().warn_fg_color)
    } else {
        RichText::new(format!("Links ({})", links.len())).strong()
    };
    egui::CollapsingHeader::new(title)
        .id_salt("links")
        .default_open(bad > 0)
        .show(ui, |ui| {
            for (n, l) in links.iter().enumerate() {
                kv_row(
                    ui,
                    150.0,
                    n % 2 == 1,
                    |ui| {
                        let host = if l.host.is_empty() {
                            "–"
                        } else {
                            l.host.as_str()
                        };
                        let t = RichText::new(host).strong();
                        ui.add(
                            egui::Label::new(if l.warning.is_empty() {
                                t
                            } else {
                                t.color(ui.visuals().warn_fg_color)
                            })
                            .wrap(),
                        );
                    },
                    |ui| {
                        if !l.warning.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("⚠ {}", l.warning))
                                        .color(ui.visuals().warn_fg_color),
                                )
                                .wrap(),
                            );
                        }
                        if !l.text.is_empty() && l.text != l.url {
                            ui.add(egui::Label::new(format!("“{}”", l.text)).wrap());
                        }
                        let r = ui.add(
                            egui::Label::new(RichText::new(&l.url).weak().monospace())
                                .wrap()
                                .sense(Sense::click()),
                        );
                        r.context_menu(|ui| {
                            if ui.button("Copy Address").clicked() {
                                actions.push(Action::Copy(l.url.clone()));
                                ui.close_menu();
                            }
                            if ui.button("Open in Browser …").clicked() {
                                actions.push(Action::OpenUrl(l.url.clone(), false));
                                ui.close_menu();
                            }
                        });
                    },
                );
            }
            ui.label(
                RichText::new("Right-click an address to copy or open it.")
                    .small()
                    .weak(),
            );
        });
}

fn headers_view(ui: &mut Ui, doc: &mut Doc, decoded: &mut bool, actions: &mut Vec<Action>) {
    egui::ScrollArea::vertical()
        .id_salt("headers")
        .auto_shrink(false)
        .show(ui, |ui| {
            let m = &doc.mail;
            // ---- security
            section(ui, "Authentication", true, |ui| {
                if doc.checks.auth.is_empty() {
                    ui.label(
                        RichText::new(
                            "No Authentication-Results field: the message was not checked by \
                             a receiving server (e.g. a draft or a sent message).",
                        )
                        .weak(),
                    );
                } else {
                    ui.horizontal_wrapped(|ui| {
                        for r in &doc.checks.auth {
                            badge(ui, r);
                        }
                    });
                    ui.add_space(4.0);
                    for (n, r) in doc.checks.auth.iter().enumerate() {
                        kv_row(
                            ui,
                            KEY_W,
                            n % 2 == 1,
                            |ui| key_label(ui, &r.method.to_uppercase()),
                            |ui| {
                                let mut job = LayoutJob::default();
                                let body = TextStyle::Body.resolve(ui.style());
                                let (_, fg) = verdict_colors(ui, r.verdict());
                                job.append(&r.result, 0.0, TextFormat::simple(body.clone(), fg));
                                let dom = r.domain();
                                if !dom.is_empty() {
                                    job.append(
                                        &format!("  {dom}"),
                                        0.0,
                                        TextFormat::simple(
                                            body.clone(),
                                            ui.visuals().strong_text_color(),
                                        ),
                                    );
                                }
                                ui.add(egui::Label::new(job).wrap());
                                if !r.props.is_empty() {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&r.props).monospace().small(),
                                        )
                                        .wrap(),
                                    );
                                }
                                if !r.comment.is_empty() {
                                    ui.add(
                                        egui::Label::new(RichText::new(&r.comment).weak().small())
                                            .wrap(),
                                    );
                                }
                            },
                        );
                    }
                    if !doc.checks.auth_server.is_empty() {
                        ui.label(
                            RichText::new(format!("Checked by {}", doc.checks.auth_server))
                                .small()
                                .weak(),
                        );
                    }
                }
                analysis_view::dkim_arc_rows(ui, &doc.checks);
            });

            // ---- overview
            section(ui, "Overview", true, |ui| {
                let mut stripe = false;
                let mut row = |ui: &mut Ui, key: &str, f: &dyn Fn(&mut Ui)| {
                    kv_row(ui, KEY_W, stripe, |ui| key_label(ui, key), f);
                    stripe = !stripe;
                };
                let text = |v: String| {
                    move |ui: &mut Ui| {
                        ui.add(egui::Label::new(v.clone()).wrap());
                    }
                };
                if !m.from.is_empty() {
                    row(ui, "From", &|ui| addresses(ui, &m.from));
                }
                if !m.sender.is_empty() && m.sender != m.from {
                    row(ui, "Sender", &|ui| addresses(ui, &m.sender));
                }
                if !m.reply_to.is_empty() {
                    row(ui, "Reply-To", &|ui| addresses(ui, &m.reply_to));
                }
                for (k, v) in [("To", &m.to), ("Cc", &m.cc), ("Bcc", &m.bcc)] {
                    if !v.is_empty() {
                        row(ui, k, &|ui| addresses(ui, v));
                    }
                }
                if let Some(d) = m.date {
                    row(ui, "Date", &|ui| {
                        ui.add(egui::Label::new(analysis::fmt_original(d)).wrap());
                        ui.label(
                            RichText::new(format!(
                                "local: {} ({})",
                                analysis::fmt_local(d.ts),
                                analysis::relative(d.ts, now())
                            ))
                            .weak(),
                        );
                    });
                }
                if !m.subject.is_empty() {
                    row(ui, "Subject", &text(m.subject.clone()));
                }
                if !m.message_id.is_empty() {
                    row(ui, "Message-ID", &|ui| {
                        ui.add(egui::Label::new(RichText::new(&m.message_id).monospace()).wrap());
                    });
                }
                let extra = [
                    ("In-Reply-To", "In-Reply-To"),
                    ("Return-Path", "Return-Path"),
                    ("Delivered-To", "Delivered-To"),
                    ("Mail program", "User-Agent"),
                    ("Mail program", "X-Mailer"),
                    ("Priority", "X-Priority"),
                    ("Priority", "Importance"),
                    ("Organization", "Organization"),
                    ("Mailing list", "List-Id"),
                    ("Unsubscribe", "List-Unsubscribe"),
                    ("Spam status", "X-Spam-Status"),
                    ("Spam score", "X-Spam-Score"),
                    ("Spam flag", "X-Spam-Flag"),
                    ("Content-Type", "Content-Type"),
                ];
                for (label, name) in extra {
                    if let Some(v) = m.get(name) {
                        row(ui, label, &text(v.to_string()));
                    }
                }
            });

            // ---- route
            if !m.hops.is_empty() {
                let total = match (
                    m.hops.first().and_then(|h| h.date),
                    m.hops.last().and_then(|h| h.date),
                ) {
                    (Some(a), Some(b)) if m.hops.len() > 1 => {
                        format!(
                            " – {} in transit",
                            analysis::fmt_delay(b.ts - a.ts).trim_start_matches('+')
                        )
                    }
                    _ => String::new(),
                };
                section(
                    ui,
                    &format!("Delivery Route ({} hops{total})", m.hops.len()),
                    true,
                    |ui| {
                        let mut prev: Option<i64> = None;
                        let sender_hop = doc.checks.sender_ip.map(|(i, _)| i);
                        for (n, h) in m.hops.iter().enumerate() {
                            kv_row(
                                ui,
                                KEY_W,
                                n % 2 == 1,
                                |ui| {
                                    ui.label(
                                        RichText::new(format!("{}", n + 1))
                                            .strong()
                                            .color(crate::theme::accent(ui.visuals().dark_mode)),
                                    );
                                    if sender_hop == Some(n) {
                                        ui.label(
                                            RichText::new("sender IP").small().strong().color(
                                                crate::theme::accent(ui.visuals().dark_mode),
                                            ),
                                        )
                                        .on_hover_text(
                                            "First public IP address of the route: the sender's \
                                             server (or computer) as seen from outside.",
                                        );
                                    }
                                    if let Some(d) = h.date {
                                        ui.label(analysis::fmt_time_local(d.ts));
                                        if let Some(p) = prev {
                                            let delay = d.ts - p;
                                            let t =
                                                RichText::new(analysis::fmt_delay(delay)).small();
                                            ui.label(if !(0..=300).contains(&delay) {
                                                t.color(ui.visuals().warn_fg_color)
                                            } else {
                                                t.weak()
                                            });
                                        }
                                        prev = Some(d.ts);
                                    }
                                },
                                |ui| {
                                    let body = TextStyle::Body.resolve(ui.style());
                                    let strong = ui.visuals().strong_text_color();
                                    let weak = ui.visuals().weak_text_color();
                                    let mut job = LayoutJob::default();
                                    let from = if h.from.is_empty() {
                                        "?"
                                    } else {
                                        h.from.as_str()
                                    };
                                    job.append(from, 0.0, TextFormat::simple(body.clone(), strong));
                                    if !h.from_ip.is_empty() && h.from_ip != h.from {
                                        job.append(
                                            &format!(" [{}]", h.from_ip),
                                            0.0,
                                            TextFormat::simple(body.clone(), weak),
                                        );
                                    }
                                    job.append(
                                        "  →  ",
                                        0.0,
                                        TextFormat::simple(
                                            body.clone(),
                                            crate::theme::accent(ui.visuals().dark_mode),
                                        ),
                                    );
                                    let by = if h.by.is_empty() { "?" } else { h.by.as_str() };
                                    job.append(by, 0.0, TextFormat::simple(body.clone(), strong));
                                    ui.add(egui::Label::new(job).wrap());
                                    let mut details = Vec::new();
                                    if !h.with.is_empty() {
                                        details.push(h.with.clone());
                                    }
                                    if !h.tls.is_empty() {
                                        details.push(format!("🔒 {}", h.tls));
                                    }
                                    if !h.id.is_empty() {
                                        details.push(format!("id {}", h.id));
                                    }
                                    if !h.for_.is_empty() {
                                        details.push(format!("for {}", h.for_));
                                    }
                                    if !details.is_empty() {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(details.join("  ·  ")).weak().small(),
                                            )
                                            .wrap(),
                                        );
                                    }
                                    if h.by.is_empty() && h.from.is_empty() {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&h.raw).monospace().small(),
                                            )
                                            .wrap(),
                                        );
                                    }
                                },
                            );
                        }
                        ui.label(
                            RichText::new("Oldest hop first: the sending server is at the top.")
                                .small()
                                .weak(),
                        );
                        for t in &doc.checks.times {
                            ui.horizontal_top(|ui| {
                                ui.label(RichText::new("⚠").color(ui.visuals().warn_fg_color));
                                ui.add(egui::Label::new(t).wrap());
                            });
                        }
                    },
                );
            }

            // ---- spam filters
            analysis_view::spam_section(ui, &doc.checks);

            // ---- all fields
            section(
                ui,
                &format!("All Header Fields ({})", m.fields.len()),
                true,
                |ui| {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut doc.header_filter)
                                .hint_text("🔍 Filter (name or value)")
                                .desired_width(240.0),
                        );
                        ui.add_space(8.0);
                        ui.spacing_mut().item_spacing.x = 2.0;
                        if ui
                            .selectable_label(*decoded, "Decoded")
                            .on_hover_text("Encoded words (=?UTF-8?…?=) decoded")
                            .clicked()
                        {
                            *decoded = true;
                        }
                        if ui.selectable_label(!*decoded, "As Written").clicked() {
                            *decoded = false;
                        }
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button("Copy All").clicked() {
                                actions.push(Action::Copy(m.header_text.replace('\r', "")));
                            }
                        });
                    });
                    ui.add_space(4.0);
                    let decoded = *decoded;
                    let filter = doc.header_filter.to_lowercase();
                    let mut n = 0;
                    for f in &m.fields {
                        let value = if decoded { &f.value } else { &f.raw };
                        if !filter.is_empty()
                            && !f.name.to_lowercase().contains(&filter)
                            && !value.to_lowercase().contains(&filter)
                        {
                            continue;
                        }
                        kv_row(
                            ui,
                            170.0,
                            n % 2 == 1,
                            |ui| {
                                let r = ui.add(
                                    egui::Label::new(
                                        RichText::new(&f.name)
                                            .strong()
                                            .color(crate::theme::accent(ui.visuals().dark_mode)),
                                    )
                                    .wrap(),
                                );
                                if let Some(d) = crate::lexicon::describe(&f.name) {
                                    r.on_hover_text(d);
                                }
                            },
                            |ui| {
                                let r = ui
                                    .add(egui::Label::new(RichText::new(value).monospace()).wrap());
                                r.context_menu(|ui| {
                                    if ui.button("Copy Value").clicked() {
                                        actions.push(Action::Copy(value.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button("Copy Field").clicked() {
                                        actions
                                            .push(Action::Copy(format!("{}: {}", f.name, value)));
                                        ui.close_menu();
                                    }
                                });
                            },
                        );
                        n += 1;
                    }
                    if n == 0 {
                        ui.label(RichText::new("No matching fields.").weak());
                    }
                    ui.add_space(6.0);
                    ui.checkbox(&mut doc.show_raw_header, "Show header source");
                    if doc.show_raw_header {
                        let text = m.header_text.replace('\r', "");
                        text_view(ui, "raw-header", &text, true, &[], 0, false);
                    }
                },
            );
        });
}

fn structure_view(ui: &mut Ui, doc: &Doc) {
    egui::ScrollArea::vertical()
        .id_salt("structure")
        .auto_shrink(false)
        .show(ui, |ui| {
            for (n, p) in doc.mail.parts.iter().enumerate() {
                let stripe = n % 2 == 1;
                let fill = if stripe {
                    ui.visuals().faint_bg_color
                } else {
                    Color32::TRANSPARENT
                };
                egui::Frame::none()
                    .fill(fill)
                    .inner_margin(Margin::symmetric(6.0, 3.0))
                    .rounding(3.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(p.depth as f32 * 22.0);
                            let accent = crate::theme::accent(ui.visuals().dark_mode);
                            let mime = RichText::new(&p.mime).strong();
                            ui.label(
                                if p.mime.starts_with("multipart/")
                                    || p.mime.starts_with("message/")
                                {
                                    mime.color(accent)
                                } else {
                                    mime
                                },
                            );
                            if !p.name.is_empty() {
                                ui.label(format!("“{}”", p.name));
                            }
                            let mut d = vec![analysis::human_size(p.size)];
                            if !p.charset.is_empty() {
                                d.push(p.charset.clone());
                            }
                            if !p.encoding.is_empty() {
                                d.push(p.encoding.clone());
                            }
                            if !p.role.is_empty() {
                                d.push(p.role.clone());
                            }
                            ui.label(RichText::new(d.join(" · ")).weak());
                        });
                    });
            }
        });
}

// ----------------------------------------------------------------- widgets

/// Selectable text with search highlights; scrolls to the current match when asked.
fn text_view(
    ui: &mut Ui,
    id: &str,
    text: &str,
    mono: bool,
    matches: &[Range<usize>],
    current: usize,
    scroll: bool,
) {
    let font = if mono {
        TextStyle::Monospace.resolve(ui.style())
    } else {
        TextStyle::Body.resolve(ui.style())
    };
    let dark = ui.visuals().dark_mode;
    let color = ui.visuals().text_color();
    let hl_bg = tone(dark, (255, 226, 140), (110, 84, 20));
    let cur_bg = crate::theme::accent(dark);
    let cur_fg = Color32::WHITE;
    let mut layouter = |ui: &Ui, s: &str, wrap: f32| {
        let mut job = LayoutJob::default();
        let mut last = 0;
        for (i, r) in matches.iter().enumerate() {
            if r.start < last || r.end > s.len() || !s.is_char_boundary(r.start) {
                continue;
            }
            job.append(
                &s[last..r.start],
                0.0,
                TextFormat::simple(font.clone(), color),
            );
            let mut f = TextFormat::simple(font.clone(), if i == current { cur_fg } else { color });
            f.background = if i == current { cur_bg } else { hl_bg };
            job.append(&s[r.clone()], 0.0, f);
            last = r.end;
        }
        job.append(&s[last..], 0.0, TextFormat::simple(font.clone(), color));
        job.wrap.max_width = wrap;
        ui.fonts(|f| f.layout_job(job))
    };
    let mut t = text;
    let out = egui::TextEdit::multiline(&mut t)
        .id_salt(id)
        .frame(false)
        .desired_width(f32::INFINITY)
        .desired_rows(1)
        .layouter(&mut layouter)
        .show(ui);
    if scroll {
        if let Some(r) = matches.get(current) {
            let ci = text[..r.start.min(text.len())].chars().count();
            let rect = out
                .galley
                .pos_from_ccursor(CCursor::new(ci))
                .translate(out.galley_pos.to_vec2());
            ui.scroll_to_rect(rect.expand(24.0), Some(Align::Center));
        }
    }
}

/// A key/value row: fixed-width key column, wrapping value column.
fn kv_row(
    ui: &mut Ui,
    key_w: f32,
    stripe: bool,
    key: impl FnOnce(&mut Ui),
    val: impl FnOnce(&mut Ui),
) {
    let fill = if stripe {
        ui.visuals().faint_bg_color
    } else {
        Color32::TRANSPARENT
    };
    egui::Frame::none()
        .fill(fill)
        .inner_margin(Margin::symmetric(6.0, 3.0))
        .rounding(3.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(key_w, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_width(key_w);
                        key(ui);
                    },
                );
                let w = ui.available_width();
                ui.allocate_ui_with_layout(Vec2::new(w, 0.0), Layout::top_down(Align::Min), |ui| {
                    ui.set_width(w);
                    val(ui);
                });
            });
        });
}

fn key_label(ui: &mut Ui, key: &str) {
    ui.label(RichText::new(key).color(ui.visuals().weak_text_color()));
}

fn section(ui: &mut Ui, title: &str, open: bool, add: impl FnOnce(&mut Ui)) {
    egui::CollapsingHeader::new(
        RichText::new(title)
            .strong()
            .size(15.0)
            .color(crate::theme::accent(ui.visuals().dark_mode)),
    )
    .id_salt(title.split(" (").next().unwrap_or(title))
    .default_open(open)
    .show(ui, |ui| {
        add(ui);
        ui.add_space(6.0);
    });
}

/// Names strong, addresses weak, wrapping.
fn addresses(ui: &mut Ui, list: &[Mailbox]) {
    let body = TextStyle::Body.resolve(ui.style());
    let strong = ui.visuals().strong_text_color();
    let weak = ui.visuals().weak_text_color();
    let text = ui.visuals().text_color();
    let mut job = LayoutJob::default();
    for (i, m) in list.iter().enumerate() {
        if i > 0 {
            job.append(", ", 0.0, TextFormat::simple(body.clone(), weak));
        }
        if m.name.is_empty() {
            job.append(&m.addr, 0.0, TextFormat::simple(body.clone(), text));
        } else {
            job.append(&m.name, 0.0, TextFormat::simple(body.clone(), strong));
            if !m.addr.is_empty() {
                job.append(
                    &format!(" <{}>", m.addr),
                    0.0,
                    TextFormat::simple(body.clone(), weak),
                );
            }
        }
    }
    ui.add(egui::Label::new(job).wrap());
}

fn verdict_colors(ui: &Ui, v: Verdict) -> (Color32, Color32) {
    let dark = ui.visuals().dark_mode;
    match v {
        Verdict::Pass => (
            tone(dark, (220, 240, 222), (38, 82, 46)),
            tone(dark, (24, 94, 40), (196, 240, 200)),
        ),
        Verdict::Fail => (
            tone(dark, (250, 222, 218), (110, 40, 32)),
            tone(dark, (160, 30, 20), (255, 214, 206)),
        ),
        Verdict::Weak => (
            tone(dark, (250, 236, 206), (100, 72, 20)),
            tone(dark, (130, 80, 0), (255, 226, 170)),
        ),
        Verdict::Neutral => (
            ui.visuals().widgets.inactive.bg_fill,
            ui.visuals().text_color(),
        ),
    }
}

fn badge(ui: &mut Ui, r: &AuthResult) {
    let (bg, fg) = verdict_colors(ui, r.verdict());
    let icon = match r.verdict() {
        Verdict::Pass => "✔",
        Verdict::Fail => "✖",
        Verdict::Weak => "⚠",
        Verdict::Neutral => "•",
    };
    egui::Frame::none()
        .fill(bg)
        .rounding(5.0)
        .inner_margin(Margin::symmetric(9.0, 4.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{icon} {} {}", r.method.to_uppercase(), r.result))
                    .color(fg)
                    .strong(),
            );
        });
}

fn attachment_icon(a: &Attachment) -> &'static str {
    if a.is_message {
        "✉"
    } else if a.is_image() {
        "🖼"
    } else if a.mime == "application/pdf" {
        "📄"
    } else if a.is_text() {
        "🗋"
    } else if a.mime.contains("zip") || a.mime.contains("compressed") {
        "📦"
    } else {
        "📎"
    }
}

fn tone(dark: bool, light: (u8, u8, u8), dark_rgb: (u8, u8, u8)) -> Color32 {
    let (r, g, b) = if dark { dark_rgb } else { light };
    Color32::from_rgb(r, g, b)
}

/// The application icon (`packaging/make_icon.py`), shown on the start page.
fn load_logo(ctx: &egui::Context) -> egui::TextureHandle {
    let img = eframe::icon_data::from_png_bytes(include_bytes!("../packaging/eml-reader.png"))
        .expect("embedded icon");
    let ci = egui::ColorImage::from_rgba_unmultiplied(
        [img.width as usize, img.height as usize],
        &img.rgba,
    );
    ctx.load_texture("logo", ci, egui::TextureOptions::LINEAR)
}

/// Logo and subtitle.
fn header(ui: &mut Ui, logo: &egui::TextureHandle) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 86.0), Sense::hover());
    let p = ui.painter_at(rect);
    let font = FontId::proportional(40.0);
    let accent = crate::theme::accent(ui.visuals().dark_mode);
    let text = ui.visuals().text_color();
    let galley_a = p.layout_no_wrap("eml".into(), font.clone(), accent);
    let galley_b = p.layout_no_wrap("reader".into(), font, text);
    let icon = 54.0;
    let gap = 10.0;
    let w = icon + gap + galley_a.size().x + galley_b.size().x;
    let x = rect.center().x - w / 2.0;
    p.image(
        logo.id(),
        egui::Rect::from_min_size(egui::pos2(x, rect.top() + 4.0), Vec2::splat(icon)),
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
    let tx = x + icon + gap;
    let y = rect.top() + 8.0;
    p.galley(egui::pos2(tx, y), galley_a.clone(), accent);
    p.galley(egui::pos2(tx + galley_a.size().x, y), galley_b, text);
    p.text(
        egui::pos2(rect.center().x, rect.bottom() - 10.0),
        Align2::CENTER_CENTER,
        "E-Mail Viewer · Attachments · Header Analysis",
        FontId::proportional(16.0),
        ui.visuals().weak_text_color(),
    );
}

// ------------------------------------------------------------- temp files

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!("eml-reader-{}", std::process::id()))
}

/// Writes an attachment to a fresh temporary directory (for the default application).
fn write_temp(name: &str, data: &[u8]) -> Result<PathBuf, String> {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = temp_root().join(n.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(analysis::safe_file_name(name));
    std::fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Removes temporary directories of earlier runs (older than a day).
fn clean_temp() {
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("eml-reader-") {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() > 86_400);
        if old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn open_external(path: &Path) -> Result<(), String> {
    std::process::Command::new("xdg-open")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("xdg-open: {e}"))
}

/// `dir/name`, or `dir/name (2).ext` … when that exists.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (2..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let dir = std::env::temp_dir().join(format!("eml-uniq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.pdf"), dir.join("a.pdf"));
        std::fs::write(dir.join("a.pdf"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.pdf"), dir.join("a (2).pdf"));
        std::fs::write(dir.join("a (2).pdf"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.pdf"), dir.join("a (3).pdf"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn doc_body_choice() {
        let m = Mail::parse(include_bytes!("../tests/data/sample.eml").to_vec()).unwrap();
        let mut d = Doc::new(m, None, "x".into());
        assert!(d.shows_html(true) && !d.shows_html(false));
        d.ensure_html(80);
        assert!(d.body(true).contains("Entwurf"));
        assert!(d.body(false).contains("anbei der Entwurf"));
        assert!(d.source().starts_with("Return-Path:"));
    }
}
