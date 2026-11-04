# EML Reader (Rust, egui)

Viewer and analyser for e-mail files for Linux – `.eml` (RFC 5322 / MIME), Outlook `.msg` and
`mbox` mailboxes – shipped as a single AppImage. Shows the message, its attachments and a
**readable analysis of the header**, rates the message (inconspicuous / suspicious / dangerous)
and explains why – without loading anything from the internet unless asked to.

| View | Contents |
|---|---|
| **Message** | Subject, sender, recipients, date (local time, "2 hours ago"); plain-text or HTML part (HTML converted to text, switchable); attachments with preview, *Open with Default Application*, *Save As …*, *Save All …*; attached images below the text; **links** of the HTML part with their real destination |
| **Analysis** | **Rating** with all findings; **Domains** (From, Sender, Reply-To, Return-Path, DKIM, SPF envelope, Message-ID, recipients compared with the sender's domain, look-alike domains); **Attachments** (real file type from the content, disguised files, macros, password-protected archives and their contents, active PDF content, SHA-256 with VirusTotal look-up by hash); **HTML content** (hidden text, tracking pixels, remote images, forms, scripts); **Links**; **Online check** on request |
| **Headers** | **Authentication** (SPF/DKIM/DMARC/ARC badges, DKIM signatures with offline body-hash check, ARC chain), **Overview**, **Delivery Route** (hops in chronological order, delay per hop, TLS, sender IP, implausible times), **Spam Filters** (SpamAssassin, Rspamd and Microsoft 365 rules with points and explanations), **All Header Fields** (filter, decoded or as written, explanations as tooltips, copy, header source) |
| **Structure** | MIME tree with types, file names, sizes, character sets, transfer encodings and roles |
| **Source** | The raw message |

The coloured **rating** strip above the views summarises the findings; a click opens the Analysis.

## Checks

Offline (always):

- **Look-alike domains**: digits and homoglyphs (`paypa1.com`, `arnazon.de`), Latin mixed with
  Cyrillic/Greek letters, punycode (`xn--…`) shown decoded, brand names in foreign domains
  (`paypal-security.com`) or in front of the real domain (`paypal.com.login-check.net`) – checked
  against about 40 brands (banks, parcel services, shops, mail and cloud providers).
- **Domain comparison**: all domains of the message against the sender's organisational domain.
- **Authentication**: results of the receiving server, DKIM body hash recomputed (was the body
  changed after signing?), `l=` partial signatures, ARC chain of forwarding servers.
- **Sender**: reply-to elsewhere, display name with a different address, missing sender.
- **Route**: first public IP address (sender), hops in the wrong order, long delays, Date field
  later than the first server or long before it.
- **Attachments**: real type from the first bytes (EXE/ELF/scripts named `.pdf` …), program files
  and double extensions, macros in Office files (OOXML and old OLE formats), encrypted ZIPs and
  program files inside archives, JavaScript/launch actions in PDFs, SHA-256 hashes.
- **HTML**: deceptive links (text shows a different domain, `user@host` tricks), hidden text
  (display:none, white on white, font size 0 …), tracking pixels, remote images, forms, scripts.
- **Spam filters**: scores and rules of SpamAssassin, Rspamd and Microsoft 365 made readable.

Online (*Tools → Online Check (DNS) …*, asks first): SPF record and evaluation for the sender IP
(ip4/ip6/a/mx/include/redirect), DMARC policy, DKIM key and **cryptographic signature check**,
reverse DNS, network (AS) and country of the route's IP addresses. Queries go over DNS-over-HTTPS
to Cloudflare (`cloudflare-dns.com`, via `curl`, proxy from *Help → Updater Proxy*); IP networks
come from Team Cymru's IP-to-ASN DNS service. Only domain names and IP addresses are sent.

## More

- **Analysis report** (*File/Tools → Export Analysis Report …*) as HTML or text, with all
  findings, hashes, route and header fields – e.g. for the IT department.
- **Compare Headers** (*Tools*): two open messages side by side, optionally only the differences.
- **mbox** files open in a side panel with a filterable message list; **Outlook .msg** files are
  converted on opening (transport headers, recipients, text/HTML body, attachments).
- Several messages in tabs; open via *File → Open …* (Ctrl+O), *Recent Files*, drag and drop,
  the command line (`eml-reader a.eml b.msg`) or the file manager.
- Forwarded messages (`message/rfc822` attachments) open in their own tab.
- Opening risky attachments, links or the HTML part in the browser (remote content, tracking
  pixels) asks for confirmation; embedded `cid:` images are included in the browser view.
- **Find** in the message or the source (Ctrl+F, F3 / Shift+F3).
- *File → Export as Text …*, *Save Message As … (.eml)*.
- Shortcuts: Ctrl+1 … 5 views, Ctrl+H headers, Ctrl+U source, Ctrl+Tab / Ctrl+Shift+Tab tabs,
  Ctrl+W close, Ctrl+Plus/Minus zoom.
- Character sets of all common mail encodings via
  [mail-parser](https://github.com/stalwartlabs/mail-parser); system fonts as fallback for CJK
  and symbols.
- UI colour scheme "Rust" of notepad-rs, light and dark (*View → Dark Theme*).
- Settings and recent files are stored in `~/.local/share/eml-reader/`.
- **Updates** (*Help → Check for Updates*): checks the GitHub releases, downloads the new
  AppImage, verifies its SHA-256 checksum and replaces the running AppImage; checked once a day at
  start-up (*Help → Check for Updates at Start-up*, or `EML_NO_UPDATE=1`). Same updater as
  notepad-rs.

The rating is a hint, not a guarantee: a message without findings can still be fraudulent.

## Building

```bash
cargo test                          # parser, checks, DKIM, SPF, .msg, mbox, report, updater
cargo run --release -- mail.eml     # run directly
packaging/build-appimage.sh         # -> dist/EML-Reader-<version>-x86_64.AppImage (+ .sha256)
```

Needs Rust 1.98 or newer. The script downloads `appimagetool` when needed (or set
`APPIMAGETOOL=/path/to/tool`).

The binary depends only on glibc. A plain build needs the glibc of the build system; with
`ZIGBUILD=1` (needs `cargo-zigbuild` and zig) it targets glibc 2.31 (`GLIBC=2.31`, Ubuntu 20.04,
Debian 11 and newer), as the releases do.

**CI** (`.github/workflows/appimage.yml`) runs the tests, builds the AppImage with zigbuild, checks
the glibc requirement and starts it with a test message on Xvfb (screenshots as artifact) on every
push and pull request. A tag `v<version>` (matching `Cargo.toml`) publishes the pre-release with
the AppImage and its `.sha256` file for the updater.

The DKIM test messages in `tests/data/` were signed with
[dkimpy](https://launchpad.net/dkimpy) (relaxed and simple canonicalisation), the reference for
the verifier.

## Layout

- `src/mail.rs` – message model: header fields, addresses, bodies, attachments, MIME tree, hops
- `src/checks.rs` – all offline checks of a message and the rating
- `src/analysis.rs` – Authentication-Results parser, notes, links, search, formatting
- `src/domains.rs` – punycode, look-alike domains, organisational domain, domain comparison
- `src/files.rs` – real file types, ZIP contents, macros, PDF actions, hashes
- `src/htmlcheck.rs` – hidden text, tracking pixels, remote images, forms
- `src/trace.rs` – sender IP, time anomalies, ARC chain, spam filter reports
- `src/dkim.rs` – DKIM canonicalisation, body hash, RSA-SHA256 signature check
- `src/online.rs` – DNS over HTTPS, SPF evaluation, DMARC, DKIM keys, IP networks
- `src/msg.rs` – Outlook .msg → RFC 5322 conversion
- `src/report.rs` – analysis report (HTML/text)
- `src/lexicon.rs` – explanations of header fields
- `src/app.rs`, `src/app/analysis_view.rs` – user interface (eframe/egui 0.29)
- `src/fonts.rs` – system fallback fonts (CJK, symbols)
- `src/update.rs` – updater (GitHub releases, SHA-256 check, replaces the AppImage)
- `src/theme.rs` – UI colour scheme "Rust" (dark and light), shared with
  [notepad-rs](https://github.com/StofflHD/notepad-rs)
- `packaging/` – desktop file, icon (`make_icon.py`, needs pycairo), AppRun, build script

## License

GPL-3.0-or-later, see [LICENSE](LICENSE). The licence is also shown under *Help → About*.

---

© StofflHD and Claude
