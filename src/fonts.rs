//! System fallback fonts for characters the built-in egui fonts lack (CJK, many symbols),
//! as in notepad-rs – mails come in every script.

use std::path::{Path, PathBuf};

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

fn font_dirs() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/usr/share/fonts"),
        PathBuf::from("/usr/local/share/fonts"),
    ];
    if let Some(h) = std::env::var_os("HOME").map(PathBuf::from) {
        v.push(h.join(".local/share/fonts"));
        v.push(h.join(".fonts"));
    }
    v
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() && depth < 6 {
            walk(&p, depth + 1, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| matches!(x.to_lowercase().as_str(), "ttf" | "otf" | "ttc"))
        {
            out.push(p);
        }
    }
}

/// Fallback fonts for scripts missing from the built-in fonts.
fn fallbacks() -> Vec<PathBuf> {
    let wanted = [
        "DejaVuSans.ttf",
        "NotoSansCJK-Regular.ttc",
        "NotoSansCJKjp-Regular.otf",
        "wqy-microhei.ttc",
        "DroidSansFallbackFull.ttf",
        "NotoSansSymbols2-Regular.ttf",
    ];
    let mut fonts = Vec::new();
    for d in font_dirs() {
        walk(&d, 0, &mut fonts);
    }
    let mut out = Vec::new();
    let mut have_cjk = false;
    for w in wanted {
        let is_cjk = w.contains("CJK") || w.contains("wqy") || w.contains("Droid");
        if is_cjk && have_cjk {
            continue;
        }
        if let Some(p) = fonts
            .iter()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(w))
        {
            out.push(p.clone());
            have_cjk |= is_cjk;
        }
    }
    out
}

pub fn apply(ctx: &egui::Context) {
    let mut defs = FontDefinitions::default();
    for (i, p) in fallbacks().into_iter().enumerate() {
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let name = format!("fallback-{i}");
        defs.font_data
            .insert(name.clone(), FontData::from_owned(bytes));
        for fam in [FontFamily::Monospace, FontFamily::Proportional] {
            defs.families.entry(fam).or_default().push(name.clone());
        }
    }
    ctx.set_fonts(defs);
}
