//! Attachment checks: the real file type from the first bytes, archive contents, macros,
//! active PDF content and SHA-256 hashes.

use sha2::{Digest, Sha256};

/// What the bytes of a file really are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    WindowsProgram,
    LinuxProgram,
    Script,
    Zip,
    Ole,
    Pdf,
    Rtf,
    Png,
    Jpeg,
    Gif,
    Webp,
    Rar,
    SevenZip,
    Gzip,
    Iso,
    Html,
    Text,
    Unknown,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::WindowsProgram => "Windows program (EXE/DLL)",
            Kind::LinuxProgram => "Linux program (ELF)",
            Kind::Script => "script",
            Kind::Zip => "ZIP archive (also Office documents)",
            Kind::Ole => "OLE document (old Office / Outlook)",
            Kind::Pdf => "PDF document",
            Kind::Rtf => "RTF document",
            Kind::Png => "PNG image",
            Kind::Jpeg => "JPEG image",
            Kind::Gif => "GIF image",
            Kind::Webp => "WebP image",
            Kind::Rar => "RAR archive",
            Kind::SevenZip => "7-Zip archive",
            Kind::Gzip => "gzip archive",
            Kind::Iso => "disk image (ISO)",
            Kind::Html => "HTML document",
            Kind::Text => "text",
            Kind::Unknown => "unknown",
        }
    }

    pub fn is_program(self) -> bool {
        matches!(
            self,
            Kind::WindowsProgram | Kind::LinuxProgram | Kind::Script
        )
    }
}

/// The real type of a file from its first bytes.
pub fn detect(data: &[u8]) -> Kind {
    let starts = |m: &[u8]| data.starts_with(m);
    if starts(b"MZ") && data.len() > 64 {
        Kind::WindowsProgram
    } else if starts(b"\x7fELF") {
        Kind::LinuxProgram
    } else if starts(b"#!") {
        Kind::Script
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        Kind::Zip
    } else if starts(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        Kind::Ole
    } else if data[..data.len().min(1024)]
        .windows(5)
        .any(|w| w == b"%PDF-")
    {
        Kind::Pdf
    } else if starts(b"{\\rtf") {
        Kind::Rtf
    } else if starts(b"\x89PNG") {
        Kind::Png
    } else if starts(&[0xFF, 0xD8, 0xFF]) {
        Kind::Jpeg
    } else if starts(b"GIF8") {
        Kind::Gif
    } else if starts(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        Kind::Webp
    } else if starts(b"Rar!") {
        Kind::Rar
    } else if starts(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        Kind::SevenZip
    } else if starts(&[0x1F, 0x8B]) {
        Kind::Gzip
    } else if data.get(0x8001..0x8006) == Some(b"CD001") {
        Kind::Iso
    } else {
        let head = String::from_utf8_lossy(&data[..data.len().min(512)]).to_ascii_lowercase();
        let t = head.trim_start();
        if t.starts_with("<!doctype html") || t.starts_with("<html") {
            Kind::Html
        } else if t.starts_with("@echo")
            || t.starts_with("<script")
            || t.starts_with("<job")
            || t.contains("powershell")
            || t.contains("wscript.")
            || t.contains("createobject(")
        {
            Kind::Script
        } else if data
            .iter()
            .take(4096)
            .all(|&b| b >= 0x09 && b != 0x7f || b >= 0x80)
        {
            Kind::Text
        } else {
            Kind::Unknown
        }
    }
}

/// The file types an extension promises (None = no expectation).
fn expected(ext: &str) -> Option<&'static [Kind]> {
    use Kind::*;
    Some(match ext {
        "pdf" => &[Pdf],
        "png" => &[Png],
        "jpg" | "jpeg" => &[Jpeg],
        "gif" => &[Gif],
        "webp" => &[Webp],
        "zip" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "odt" | "ods" | "odp"
        | "jar" | "apk" | "epub" | "kmz" => &[Zip],
        "doc" | "xls" | "ppt" | "msg" => &[Ole, Rtf, Zip],
        "rtf" => &[Rtf],
        "rar" => &[Rar],
        "7z" => &[SevenZip],
        "gz" | "tgz" => &[Gzip],
        "exe" | "dll" | "scr" | "com" => &[WindowsProgram],
        "txt" | "csv" | "log" | "ics" | "vcf" => &[Text, Html],
        "html" | "htm" => &[Html, Text],
        _ => return None,
    })
}

#[derive(Clone, Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub size: u64,
    pub encrypted: bool,
}

fn u16_at(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

/// The entries of a ZIP archive (from its central directory).
pub fn zip_entries(d: &[u8]) -> Option<Vec<ZipEntry>> {
    let min = d.len().saturating_sub(65_557);
    let eocd = (min..d.len().saturating_sub(21))
        .rev()
        .find(|&i| d[i..i + 4] == [0x50, 0x4B, 0x05, 0x06])?;
    let count = u16_at(d, eocd + 10)? as usize;
    let mut pos = u32_at(d, eocd + 16)? as usize;
    let mut out = Vec::new();
    for _ in 0..count.min(10_000) {
        if u32_at(d, pos)? != 0x0201_4B50 {
            break;
        }
        let flags = u16_at(d, pos + 8)?;
        let size = u32_at(d, pos + 24)? as u64;
        let name_len = u16_at(d, pos + 28)? as usize;
        let extra = u16_at(d, pos + 30)? as usize;
        let comment = u16_at(d, pos + 32)? as usize;
        let name = String::from_utf8_lossy(d.get(pos + 46..pos + 46 + name_len)?).into_owned();
        out.push(ZipEntry {
            name,
            size,
            encrypted: flags & 1 == 1,
        });
        pos += 46 + name_len + extra + comment;
    }
    Some(out)
}

/// Result of checking one attachment.
#[derive(Clone, Debug, Default)]
pub struct FileCheck {
    pub kind_name: &'static str,
    pub is_program: bool,
    pub sha256: String,
    /// The extension promises a different type.
    pub mismatch: Option<String>,
    pub macros: bool,
    pub encrypted: bool,
    pub pdf_active: Vec<&'static str>,
    pub entries: Vec<ZipEntry>,
    /// Program files inside an archive.
    pub risky_entries: Vec<String>,
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

pub fn check(name: &str, data: &[u8]) -> FileCheck {
    let kind = detect(data);
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let mut c = FileCheck {
        kind_name: kind.name(),
        is_program: kind.is_program(),
        sha256: format!("{:x}", Sha256::digest(data)),
        ..Default::default()
    };
    if let Some(exp) = expected(&ext) {
        if kind != Kind::Unknown && !exp.contains(&kind) {
            c.mismatch = Some(format!(
                "named .{ext}, but the content is a {}",
                kind.name()
            ));
        }
    } else if kind.is_program() && !crate::analysis::is_risky(name) {
        c.mismatch = Some(format!("the content is a {}", kind.name()));
    }
    match kind {
        Kind::Zip => {
            if let Some(entries) = zip_entries(data) {
                c.encrypted = entries.iter().any(|e| e.encrypted);
                c.macros = entries
                    .iter()
                    .any(|e| e.name.to_ascii_lowercase().ends_with("vbaproject.bin"));
                c.risky_entries = entries
                    .iter()
                    .filter(|e| crate::analysis::is_risky(&e.name))
                    .map(|e| e.name.clone())
                    .collect();
                c.entries = entries;
            }
        }
        Kind::Ole => {
            c.macros = contains(data, &utf16("_VBA_PROJECT")) || contains(data, &utf16("Macros"));
        }
        Kind::Pdf => {
            for (needle, what) in [
                (&b"/JavaScript"[..], "JavaScript"),
                (b"/JS ", "JavaScript"),
                (b"/Launch", "launches programs (/Launch)"),
                (b"/OpenAction", "runs an action when opened (/OpenAction)"),
                (b"/EmbeddedFile", "embedded files"),
                (b"/AA", "automatic actions (/AA)"),
                (b"/SubmitForm", "sends form data (/SubmitForm)"),
            ] {
                if contains(data, needle) && !c.pdf_active.contains(&what) {
                    c.pdf_active.push(what);
                }
            }
        }
        _ => {}
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ZIP with one stored file (local header + central directory + EOCD).
    fn zip(name: &str, data: &[u8], encrypted: bool) -> Vec<u8> {
        let flags: u16 = if encrypted { 1 } else { 0 };
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0]);
        z.extend_from_slice(&flags.to_le_bytes());
        z.extend_from_slice(&[0; 10]);
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(name.as_bytes());
        z.extend_from_slice(data);
        let cd = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0]);
        z.extend_from_slice(&flags.to_le_bytes());
        z.extend_from_slice(&[0; 10]);
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0; 12]);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(name.as_bytes());
        let cd_len = z.len() - cd;
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&(cd_len as u32).to_le_bytes());
        z.extend_from_slice(&(cd as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z
    }

    #[test]
    fn real_types() {
        let mut exe = b"MZ".to_vec();
        exe.resize(200, 0);
        let c = check("Rechnung.pdf", &exe);
        assert!(c.is_program);
        assert!(c.mismatch.unwrap().contains("Windows program"));
        assert!(
            check("bericht.pdf", b"%PDF-1.4\n/OpenAction 1 0 R /JavaScript")
                .pdf_active
                .len()
                == 2
        );
        assert!(check("a.txt", b"hello\nworld\n").mismatch.is_none());
        assert!(check("bild.jpg", b"\x89PNG\r\n\x1a\nxxxx")
            .mismatch
            .is_some());
        assert_eq!(
            check("x", b"abc").sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn archives() {
        let z = zip("Rechnung.pdf.exe", b"MZ", false);
        let c = check("rechnung.zip", &z);
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.risky_entries, ["Rechnung.pdf.exe"]);
        assert!(!c.encrypted);
        assert!(check("x.zip", &zip("a.txt", b"x", true)).encrypted);
        let docm = zip("word/vbaProject.bin", b"x", false);
        assert!(check("angebot.docm", &docm).macros);
    }
}
