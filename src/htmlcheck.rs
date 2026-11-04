//! Checks of the HTML part: hidden text, tracking pixels, remote images, forms and scripts.

use crate::analysis::{unescape_html, url_host};

#[derive(Clone, Debug, Default)]
pub struct HtmlCheck {
    /// Text the reader does not see (display:none, white on white, font-size 0 …): (why, text).
    pub hidden: Vec<(String, String)>,
    /// Remote images of at most 2×2 pixels or hidden: their URLs.
    pub pixels: Vec<String>,
    /// Hosts of remote images (with count).
    pub remote: Vec<(String, usize)>,
    /// Targets of `<form action>`.
    pub forms: Vec<String>,
    pub scripts: usize,
}

struct Tag<'a> {
    name: String,
    closing: bool,
    attrs: &'a str,
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let lower = attrs.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let at = from + i;
        from = at + name.len();
        let before_ok = at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace();
        let rest = lower[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let skip = attrs.len() - attrs[from..].trim_start().len() + 1;
        let v = attrs[skip..].trim_start();
        let val = match v.chars().next() {
            Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
            _ => v
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or(""),
        };
        return Some(unescape_html(val));
    }
    None
}

/// Why an element with these attributes is invisible.
fn hidden_reason(t: &Tag<'_>) -> Option<&'static str> {
    let style: String = attr(t.attrs, "style")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let has = |s: &str| {
        style
            .split(';')
            .any(|d| d == s || d.starts_with(&format!("{s}!")))
    };
    if attr(t.attrs, "hidden").is_some()
        || t.attrs
            .to_ascii_lowercase()
            .split_whitespace()
            .any(|w| w == "hidden")
    {
        return Some("hidden attribute");
    }
    if has("display:none") {
        return Some("display:none");
    }
    if has("visibility:hidden") {
        return Some("visibility:hidden");
    }
    if has("opacity:0") {
        return Some("opacity 0");
    }
    for s in [
        "font-size:0",
        "font-size:0px",
        "font-size:1px",
        "font-size:0pt",
        "font-size:1pt",
    ] {
        if has(s) {
            return Some("font size 0/1");
        }
    }
    if (has("max-height:0") || has("height:0") || has("height:0px") || has("max-height:0px"))
        && style.contains("overflow:hidden")
    {
        return Some("height 0");
    }
    let white = [
        "color:#fff",
        "color:#ffffff",
        "color:white",
        "color:rgb(255,255,255)",
    ];
    let white_bg = !style.contains("background")
        || style.contains("background:#fff")
        || style.contains("background-color:#fff")
        || style.contains("background-color:white")
        || style.contains("background:white");
    if white.iter().any(|w| has(w)) && white_bg {
        return Some("white text on white");
    }
    None
}

const VOID: [&str; 12] = [
    "img", "br", "hr", "meta", "link", "input", "area", "base", "col", "source", "wbr", "track",
];

pub fn check(html: &str) -> HtmlCheck {
    let mut c = HtmlCheck::default();
    let mut hosts: Vec<(String, usize)> = Vec::new();
    // Open hidden element: (tag name, depth of same-name tags, reason, collected text).
    let mut hidden: Option<(String, usize, &'static str, String)> = None;
    let mut pos = 0;
    let bytes = html.as_bytes();
    let mut in_style_or_script = false;
    while pos < html.len() {
        let Some(lt) = html[pos..].find('<').map(|i| pos + i) else {
            if let Some(h) = &mut hidden {
                h.3.push_str(&html[pos..]);
            }
            break;
        };
        if let Some(h) = &mut hidden {
            if !in_style_or_script {
                h.3.push_str(&html[pos..lt]);
                h.3.push(' ');
            }
        }
        if html[lt..].starts_with("<!--") {
            pos = html[lt..].find("-->").map_or(html.len(), |e| lt + e + 3);
            continue;
        }
        let Some(gt) = html[lt..].find('>').map(|i| lt + i) else {
            break;
        };
        pos = gt + 1;
        let inner = &html[lt + 1..gt];
        let closing = inner.starts_with('/');
        let inner = inner.trim_start_matches('/');
        let name_end = inner
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(inner.len());
        let tag = Tag {
            name: inner[..name_end].to_ascii_lowercase(),
            closing,
            attrs: &inner[name_end..],
        };
        if tag.name.is_empty() || !bytes[lt + 1].is_ascii_alphabetic() && !closing {
            continue;
        }
        if matches!(tag.name.as_str(), "style" | "script" | "head" | "title") {
            in_style_or_script = !tag.closing;
        }
        if tag.name == "script" && !tag.closing {
            c.scripts += 1;
        }
        if tag.name == "form" && !tag.closing {
            let action = attr(tag.attrs, "action").unwrap_or_default();
            c.forms.push(if action.is_empty() {
                "(no target)".into()
            } else {
                action
            });
        }
        let mut remote = |url: &str, c: &mut HtmlCheck| {
            let u = url.trim();
            if u.starts_with("http://") || u.starts_with("https://") || u.starts_with("//") {
                let host = url_host(&if u.starts_with("//") {
                    format!("https:{u}")
                } else {
                    u.to_string()
                });
                match hosts.iter_mut().find(|(h, _)| *h == host) {
                    Some((_, n)) => *n += 1,
                    None => hosts.push((host, 1)),
                }
                let _ = c;
                true
            } else {
                false
            }
        };
        if tag.name == "img" && !tag.closing {
            let src = attr(tag.attrs, "src").unwrap_or_default();
            if remote(&src, &mut c) {
                let num = |a: &str| {
                    attr(tag.attrs, a)
                        .and_then(|v| v.trim_end_matches("px").trim().parse::<f32>().ok())
                };
                let style = attr(tag.attrs, "style")
                    .unwrap_or_default()
                    .replace(' ', "")
                    .to_ascii_lowercase();
                let tiny = matches!(num("width"), Some(w) if w <= 2.0)
                    || matches!(num("height"), Some(h) if h <= 2.0)
                    || style.contains("width:1px")
                    || style.contains("height:1px")
                    || style.contains("width:0")
                    || style.contains("display:none");
                if tiny && !c.pixels.contains(&src) {
                    c.pixels.push(src);
                }
            }
        }
        if let Some(style) = attr(tag.attrs, "style").or_else(|| attr(tag.attrs, "background")) {
            let l = style.to_ascii_lowercase();
            if let Some(i) = l.find("url(") {
                let u = style[i + 4..].trim_start_matches(['\'', '"']);
                let u = u.split([')', '\'', '"']).next().unwrap_or("");
                remote(u, &mut c);
            } else if l.starts_with("http") {
                remote(&style, &mut c);
            }
        }
        // hidden text tracking
        match &mut hidden {
            Some(h) => {
                if tag.name == h.0 && !VOID.contains(&tag.name.as_str()) {
                    if tag.closing {
                        if h.1 == 0 {
                            let (_, _, why, text) = hidden.take().unwrap();
                            let t = unescape_html(&text)
                                .split_whitespace()
                                .collect::<Vec<_>>()
                                .join(" ");
                            if t.chars().count() >= 3 && c.hidden.len() < 50 {
                                let t = if t.chars().count() > 300 {
                                    t.chars().take(300).collect::<String>() + "…"
                                } else {
                                    t
                                };
                                c.hidden.push((why.to_string(), t));
                            }
                        } else {
                            h.1 -= 1;
                        }
                    } else {
                        h.1 += 1;
                    }
                }
            }
            None => {
                if !tag.closing && !VOID.contains(&tag.name.as_str()) && !in_style_or_script {
                    if let Some(why) = hidden_reason(&tag) {
                        hidden = Some((tag.name.clone(), 0, why, String::new()));
                    }
                }
            }
        }
    }
    hosts.sort_by_key(|h| std::cmp::Reverse(h.1));
    c.remote = hosts;
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_and_tracking() {
        let html = r#"<html><head><style>p{}</style></head><body>
            <p>Sichtbar</p>
            <div style="display: none">versteckter <b>Text</b> mit <div>innen</div> Ende</div>
            <span style="color:#ffffff">weiß auf weiß</span>
            <span style="font-size:0px">unsichtbar klein</span>
            <img src="https://track.example.net/o.gif?id=42" width="1" height="1">
            <img src="https://cdn.example.org/logo.png" width="200">
            <img src="cid:x@y">
            <td background="https://cdn.example.org/bg.png"></td>
            <form action="https://evil.example/login"><input name=pw></form>
            <script>alert(1)</script>
        </body></html>"#;
        let c = check(html);
        let texts: Vec<_> = c.hidden.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            texts,
            [
                "versteckter Text mit innen Ende",
                "weiß auf weiß",
                "unsichtbar klein"
            ]
        );
        assert_eq!(c.hidden[1].0, "white text on white");
        assert_eq!(c.pixels, ["https://track.example.net/o.gif?id=42"]);
        assert_eq!(c.remote[0], ("cdn.example.org".to_string(), 2));
        assert_eq!(c.forms, ["https://evil.example/login"]);
        assert_eq!(c.scripts, 1);
        assert!(check("<p>ok</p>").hidden.is_empty());
    }
}
