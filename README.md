# EML Reader (Rust, egui)

Viewer for e-mail files (`.eml`, RFC 5322 / MIME) for Linux, shipped as a single AppImage.
Shows the message, its attachments and a **readable analysis of the header** – without loading
anything from the internet.

| View | Contents |
|---|---|
| **Message** | Subject, sender, recipients, date (local time, "2 hours ago"); plain-text or HTML part (HTML converted to text, switchable); attachments with preview, *Open with Default Application*, *Save As …*, *Save All …*; attached images shown below the text; **links** of the HTML part with their real destination |
| **Headers** | **Notes** (warnings about suspicious messages), **Authentication** (SPF/DKIM/DMARC/ARC as coloured badges, signing domain, checking server), **Overview** (sender, Reply-To, recipients, date in the original zone and local time, Message-ID, Return-Path, mail program, priority, mailing list, spam status), **Delivery Route** (Received hops in chronological order with time, delay per hop, TLS, total transit time), **All Header Fields** (filter, decoded or as written, copy per field or all, header source) |
| **Structure** | MIME tree with types, file names, sizes, character sets, transfer encodings and roles |
| **Source** | The raw message |

**Safety notes** in the Headers view point out, among others: failed or missing SPF/DKIM/DMARC
checks, replies that go to a different domain (Reply-To), a sender name that shows a different
address, links whose text shows a different domain than they lead to (or that hide their
destination behind `user@host`), program or script attachments and double file extensions.
Opening such an attachment asks for confirmation; opening links or the HTML part in the browser
(which loads remote content such as tracking pixels) asks as well. Embedded images (`cid:`) are
included when the HTML part is opened in the browser.

- Several messages in tabs; open via *File → Open …* (Ctrl+O), *Recent Files*, drag and drop,
  the command line (`eml-reader a.eml b.eml`) or the file manager (`message/rfc822`).
- Forwarded messages (`message/rfc822` attachments) open in their own tab.
- **Find** in the message or the source (Ctrl+F, F3 / Shift+F3), highlights all matches.
- *File → Export as Text …*, *Save Message As … (.eml)*, *Open HTML in Browser …*.
- Shortcuts: Ctrl+1 … 4 views, Ctrl+H headers, Ctrl+U source, Ctrl+Tab / Ctrl+Shift+Tab tabs,
  Ctrl+W close, Ctrl+Plus/Minus zoom.
- Character sets of all common mail encodings (incl. ISO-2022-JP, Big5, GB18030, UTF-7) via
  [mail-parser](https://github.com/stalwartlabs/mail-parser); system fonts are used as fallback for
  CJK and symbols.
- UI colour scheme "Rust" of notepad-rs (warm neutrals with an orange accent), light and dark
  (*View → Dark Theme*).
- Settings and recent files are stored in `~/.local/share/eml-reader/`.
- **Updates** (*Help → Check for Updates*): checks the GitHub releases, downloads the new
  AppImage, verifies its SHA-256 checksum (`.sha256` asset of the release) and replaces the running
  AppImage; *Restart Now* starts the new version. By default this is checked once a day at start-up
  (*Help → Check for Updates at Start-up*, or `EML_NO_UPDATE=1`). HTTP goes through `curl` or
  `wget`; a proxy can be set under *Help → Updater Proxy*. Same updater as notepad-rs.

## Building

```bash
cargo test                          # parser, header analysis, updater
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

## Layout

- `src/mail.rs` – message model: header fields, addresses, bodies, attachments, MIME tree,
  Received hops (with tests on `tests/data/sample.eml`)
- `src/analysis.rs` – Authentication-Results parser, safety notes, link extraction, search,
  formatting (with tests)
- `src/app.rs` – user interface (eframe/egui 0.29)
- `src/fonts.rs` – system fallback fonts (CJK, symbols)
- `src/update.rs` – updater (GitHub releases, SHA-256 check, replaces the AppImage; with tests)
- `src/theme.rs` – UI colour scheme "Rust" (dark and light), shared with
  [notepad-rs](https://github.com/StofflHD/notepad-rs)
- `packaging/` – desktop file, icon (`make_icon.py`, needs pycairo), AppRun, build script

## License

GPL-3.0-or-later, see [LICENSE](LICENSE). The licence is also shown under *Help → About*.

---

© StofflHD and Claude
