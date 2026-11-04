//! Domain checks: punycode (IDN) decoding, look-alike domains that imitate well-known brands,
//! the organisational domain and the comparison of all domains a message names.

/// Well-known brands with their official registrable domains.
const BRANDS: &[(&str, &[&str])] = &[
    (
        "paypal",
        &[
            "paypal.com",
            "paypal.de",
            "paypal.me",
            "paypal-community.com",
        ],
    ),
    (
        "amazon",
        &[
            "amazon.com",
            "amazon.de",
            "amazon.co.uk",
            "amazon.fr",
            "amazon.it",
            "amazon.es",
            "amazonaws.com",
            "amazonses.com",
            "amazon.at",
        ],
    ),
    ("apple", &["apple.com", "icloud.com", "me.com", "mac.com"]),
    ("icloud", &["icloud.com", "apple.com"]),
    (
        "microsoft",
        &[
            "microsoft.com",
            "office.com",
            "outlook.com",
            "live.com",
            "hotmail.com",
            "microsoftonline.com",
            "office365.com",
            "sharepoint.com",
            "onmicrosoft.com",
        ],
    ),
    (
        "office365",
        &["office365.com", "microsoft.com", "office.com"],
    ),
    ("outlook", &["outlook.com", "microsoft.com", "live.com"]),
    (
        "google",
        &[
            "google.com",
            "google.de",
            "gmail.com",
            "googlemail.com",
            "youtube.com",
            "googleusercontent.com",
        ],
    ),
    ("gmail", &["gmail.com", "google.com", "googlemail.com"]),
    (
        "facebook",
        &["facebook.com", "facebookmail.com", "fb.com", "meta.com"],
    ),
    ("instagram", &["instagram.com", "facebookmail.com"]),
    ("whatsapp", &["whatsapp.com", "whatsapp.net"]),
    ("netflix", &["netflix.com"]),
    ("spotify", &["spotify.com"]),
    (
        "ebay",
        &["ebay.com", "ebay.de", "ebay.co.uk", "ebay-kleinanzeigen.de"],
    ),
    ("linkedin", &["linkedin.com"]),
    ("dropbox", &["dropbox.com", "dropboxmail.com"]),
    ("docusign", &["docusign.com", "docusign.net"]),
    ("adobe", &["adobe.com", "adobesign.com"]),
    ("wetransfer", &["wetransfer.com"]),
    ("dhl", &["dhl.de", "dhl.com", "deutschepost.de", "dhl.net"]),
    ("deutschepost", &["deutschepost.de", "dhl.de"]),
    (
        "hermes",
        &["myhermes.de", "hermesworld.com", "hermes-europe.eu"],
    ),
    ("fedex", &["fedex.com"]),
    ("ups", &["ups.com"]),
    (
        "sparkasse",
        &["sparkasse.de", "s-f.de", "sparkassen-finanzportal.de"],
    ),
    ("volksbank", &["volksbank.de", "vr.de", "atruvia.de"]),
    ("postbank", &["postbank.de"]),
    ("commerzbank", &["commerzbank.de", "commerzbank.com"]),
    ("deutschebank", &["deutsche-bank.de", "db.com"]),
    ("comdirect", &["comdirect.de"]),
    ("consorsbank", &["consorsbank.de"]),
    ("dkb", &["dkb.de"]),
    ("n26", &["n26.com"]),
    ("telekom", &["telekom.de", "t-online.de", "telekom.com"]),
    ("vodafone", &["vodafone.de", "vodafone.com"]),
    ("gmx", &["gmx.de", "gmx.net", "gmx.at", "gmx.ch", "gmx.com"]),
    ("ionos", &["ionos.de", "ionos.com", "1und1.de"]),
    ("elster", &["elster.de"]),
    ("binance", &["binance.com"]),
    ("coinbase", &["coinbase.com"]),
    ("steam", &["steampowered.com", "steamcommunity.com"]),
];

// --------------------------------------------------------------- punycode

/// Decodes one punycode label (without the `xn--` prefix), RFC 3492.
fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    let (basic, ext) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    let mut out: Vec<char> = basic.chars().collect();
    if !basic.is_ascii() {
        return None;
    }
    let (mut n, mut bias, mut i) = (128u32, 72u32, 0u32);
    let mut it = ext.bytes().peekable();
    while it.peek().is_some() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let c = it.next()?;
            let digit = match c {
                b'a'..=b'z' => c - b'a',
                b'A'..=b'Z' => c - b'A',
                b'0'..=b'9' => c - b'0' + 26,
                _ => return None,
            } as u32;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                1
            } else if k >= bias + 26 {
                26
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len = out.len() as u32 + 1;
        // adapt
        let mut delta = if old_i == 0 {
            (i - old_i) / 700
        } else {
            (i - old_i) / 2
        };
        delta += delta / len;
        let mut kk = 0;
        while delta > ((BASE - 1) * 26) / 2 {
            delta /= BASE - 1;
            kk += BASE;
        }
        bias = kk + (BASE * delta) / (delta + 38);
        n = n.checked_add(i / len)?;
        i %= len;
        out.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(out.into_iter().collect())
}

/// The domain with `xn--` labels decoded to Unicode.
pub fn to_unicode(domain: &str) -> String {
    domain
        .split('.')
        .map(|l| {
            l.strip_prefix("xn--")
                .or_else(|| l.strip_prefix("XN--"))
                .and_then(punycode_decode)
                .unwrap_or_else(|| l.to_string())
        })
        .collect::<Vec<_>>()
        .join(".")
}

// ------------------------------------------------------------ organisation

/// The registrable ("organisational") domain: `mail.shop.example.co.uk` → `example.co.uk`.
/// A short list of second-level registries covers the common cases.
pub fn org_domain(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    let n = labels.len();
    let sld = labels[n - 2];
    let tld = labels[n - 1];
    let take = if tld.len() == 2
        && matches!(
            sld,
            "co" | "com"
                | "org"
                | "net"
                | "ac"
                | "gov"
                | "edu"
                | "or"
                | "ne"
                | "go"
                | "gv"
                | "ltd"
                | "plc"
        ) {
        3
    } else {
        2
    };
    labels[n - take.min(n)..].join(".")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Same,
    /// Same organisational domain (e.g. a subdomain).
    Related,
    Different,
}

pub fn relation(a: &str, b: &str) -> Relation {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    if a == b {
        Relation::Same
    } else if org_domain(&a) == org_domain(&b) {
        Relation::Related
    } else {
        Relation::Different
    }
}

// --------------------------------------------------------------- lookalike

/// Maps characters that look alike to one representative (Cyrillic/Greek letters, digits).
fn skeleton(label: &str) -> String {
    let mapped: String = label
        .chars()
        .map(|c| match c {
            'а' | 'α' | '@' => 'a',
            'е' | 'ε' | 'ё' | '3' => 'e',
            'о' | 'ο' | 'σ' | '0' => 'o',
            'р' | 'ρ' => 'p',
            'с' | 'ϲ' => 'c',
            'у' | 'γ' => 'y',
            'х' | 'χ' => 'x',
            'і' | 'ι' | 'ı' | 'í' | 'ì' | '!' => 'i',
            'ј' => 'j',
            'ѕ' | '5' | '$' => 's',
            'ԁ' => 'd',
            'ɡ' => 'g',
            'ӏ' | '1' | '|' | 'ł' => 'l',
            'ν' => 'v',
            'κ' | 'к' => 'k',
            'т' | 'τ' => 't',
            'п' => 'n',
            'м' => 'm',
            'в' => 'b',
            'н' => 'h',
            'ö' => 'o',
            'ä' | 'á' | 'à' | 'â' => 'a',
            'ü' | 'ú' => 'u',
            'é' | 'è' | 'ê' => 'e',
            _ => c,
        })
        .collect();
    mapped
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace('-', "")
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != cb))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

fn is_latin(c: char) -> bool {
    c.is_ascii() || ('\u{00C0}'..='\u{024F}').contains(&c)
}

fn is_cyrillic_or_greek(c: char) -> bool {
    ('\u{0370}'..='\u{03FF}').contains(&c) || ('\u{0400}'..='\u{04FF}').contains(&c)
}

/// Why a domain looks like an imitation (None = inconspicuous).
pub fn lookalike(domain: &str) -> Option<String> {
    let uni = to_unicode(&domain.to_ascii_lowercase());
    let org = org_domain(&uni);
    let main = org.split('.').next().unwrap_or("");
    if main.is_empty() {
        return None;
    }
    let official = |list: &[&str]| list.iter().any(|d| *d == org);
    let shown = if uni != domain.to_ascii_lowercase() {
        format!("{uni} (written as {domain})")
    } else {
        uni.clone()
    };
    // Latin mixed with Cyrillic/Greek in one label: a classic homograph.
    for label in uni.split('.') {
        let latin = label.chars().any(|c| c.is_ascii_alphabetic());
        let other = label.chars().any(is_cyrillic_or_greek);
        if latin && other {
            return Some(format!(
                "{shown} mixes Latin with Cyrillic/Greek letters that look the same"
            ));
        }
    }
    let sk = skeleton(main);
    for (brand, domains) in BRANDS {
        if official(domains) {
            return None;
        }
        let plain = main.replace('-', "");
        let close = if brand.len() >= 6 {
            sk == *brand || levenshtein(&sk, brand) <= 1
        } else {
            sk == *brand
        };
        if close && plain != *brand {
            return Some(format!(
                "{shown} imitates {brand} (official: {})",
                domains[0]
            ));
        }
        if plain == *brand && !official(domains) {
            return Some(format!(
                "{shown} uses the name {brand}, but is not an official domain ({})",
                domains[0]
            ));
        }
        // brand as a word of the domain: paypal-security.com, secure-amazon.net
        let words: Vec<&str> = main.split('-').collect();
        if words.len() > 1 && words.iter().any(|w| skeleton(w) == *brand) {
            return Some(format!(
                "{shown} contains the name {brand}, but is not an official domain ({})",
                domains[0]
            ));
        }
        // official name in a subdomain: paypal.com.evil.net
        if brand.len() >= 4 {
            let sub = &uni[..uni.len().saturating_sub(org.len())];
            if sub.split('.').any(|l| l == *brand) {
                return Some(format!(
                    "{shown} puts the name {brand} in front of the real domain {org}"
                ));
            }
        }
    }
    if !uni.chars().all(is_latin) && uni.chars().any(|c| c.is_alphabetic() && !is_latin(c)) {
        let plain_lookalike = skeleton(main).is_ascii();
        if plain_lookalike && main.chars().any(is_cyrillic_or_greek) {
            return Some(format!(
                "{shown} consists of letters that imitate the Latin name {}",
                skeleton(main)
            ));
        }
    }
    None
}

// ------------------------------------------------------------------ table

/// One domain a message names, with its role and its relation to the sender's domain.
#[derive(Clone, Debug)]
pub struct DomainRow {
    pub role: String,
    pub domain: String,
    pub relation: Relation,
    pub lookalike: Option<String>,
}

/// All domains of the message compared with the From domain.
pub fn domain_rows(
    mail: &crate::mail::Mail,
    auth: &[crate::analysis::AuthResult],
) -> Vec<DomainRow> {
    use crate::mail::domain_of;
    let from = mail
        .from
        .first()
        .and_then(|m| m.domain())
        .unwrap_or_default();
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut add = |role: &str, d: Option<String>| {
        if let Some(d) = d.filter(|d| !d.is_empty()) {
            if !rows.iter().any(|(r, x)| r == role && *x == d) {
                rows.push((role.to_string(), d));
            }
        }
    };
    add("From", Some(from.clone()));
    for m in &mail.sender {
        add("Sender", m.domain());
    }
    for m in &mail.reply_to {
        add("Reply-To", m.domain());
    }
    add("Return-Path", mail.get("Return-Path").and_then(domain_of));
    for f in mail.all("DKIM-Signature") {
        let d = crate::dkim::tag(&f.raw, "d");
        add("DKIM signature", d.map(|d| d.to_ascii_lowercase()));
    }
    for r in auth {
        if r.method == "spf" {
            add("SPF (envelope)", Some(r.domain()).filter(|d| !d.is_empty()));
        }
    }
    add("Message-ID", domain_of(&mail.message_id));
    for m in mail.to.iter().take(5) {
        add("To", m.domain());
    }
    rows.into_iter()
        .map(|(role, domain)| DomainRow {
            relation: if from.is_empty() {
                Relation::Different
            } else {
                relation(&domain, &from)
            },
            lookalike: lookalike(&domain),
            role,
            domain,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode() {
        assert_eq!(to_unicode("xn--mnchen-3ya.de"), "münchen.de");
        assert_eq!(to_unicode("xn--pypal-4ve.com"), "pаypal.com");
        assert_eq!(to_unicode("example.org"), "example.org");
        assert_eq!(to_unicode("xn--bcher-kva.example"), "bücher.example");
    }

    #[test]
    fn organisation() {
        assert_eq!(org_domain("mail.shop.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("a.b.example.de"), "example.de");
        assert_eq!(org_domain("example.de"), "example.de");
        assert_eq!(
            relation("mailer.example.org", "example.org"),
            Relation::Related
        );
        assert_eq!(relation("evil.net", "example.org"), Relation::Different);
    }

    #[test]
    fn lookalikes() {
        assert!(lookalike("paypa1.com").unwrap().contains("imitates paypal"));
        assert!(lookalike("paypal-security.com")
            .unwrap()
            .contains("contains the name"));
        assert!(lookalike("xn--pypal-4ve.com")
            .unwrap()
            .contains("mixes Latin"));
        assert!(lookalike("arnazon.de").unwrap().contains("amazon"));
        assert!(lookalike("paypal.com.login-check.net")
            .unwrap()
            .contains("in front of"));
        assert!(lookalike("spark4sse.de").is_some());
        assert!(lookalike("paypal.com").is_none());
        assert!(lookalike("mail.paypal.de").is_none());
        assert!(lookalike("example.org").is_none());
        assert!(
            lookalike("shopping.de").is_none(),
            "short brand inside a word"
        );
        assert!(lookalike("münchen.de").is_none());
        assert!(lookalike("upsilon.com").is_none());
    }
}
