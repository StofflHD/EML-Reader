//! Online checks on request: DNS queries over HTTPS (Cloudflare, via curl) for SPF, DMARC and
//! DKIM keys, the SPF evaluation of the sender's IP, the DKIM signature check and the
//! network/country of the IP addresses of the route (Team Cymru IP-to-ASN over DNS).

use std::net::IpAddr;
use std::process::Command;
use std::sync::mpsc::Sender;

/// What to check (collected from the message on the UI thread).
#[derive(Clone, Debug, Default)]
pub struct Job {
    pub raw: Vec<u8>,
    pub from_domain: String,
    pub mailfrom_domain: String,
    pub sender_ip: Option<IpAddr>,
    /// (index, domain, selector) of the DKIM signatures.
    pub dkim: Vec<(usize, String, String)>,
    pub ips: Vec<IpAddr>,
    pub proxy: String,
}

#[derive(Clone, Debug, Default)]
pub struct SpfCheck {
    pub domain: String,
    pub record: Option<String>,
    pub result: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct DmarcCheck {
    pub domain: String,
    pub record: Option<String>,
    pub policy: String,
    pub explain: String,
}

#[derive(Clone, Debug)]
pub struct DkimCheck {
    pub domain: String,
    pub selector: String,
    pub record: Option<String>,
    pub valid: Result<bool, String>,
}

#[derive(Clone, Debug, Default)]
pub struct IpInfo {
    pub ip: String,
    pub ptr: String,
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub org: String,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub spf: Vec<SpfCheck>,
    pub dmarc: Option<DmarcCheck>,
    pub dkim: Vec<DkimCheck>,
    pub ips: Vec<IpInfo>,
    pub errors: Vec<String>,
}

pub type Resolver<'a> = &'a dyn Fn(&str, &str) -> Result<Vec<String>, String>;

fn which(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
}

/// DNS over HTTPS (JSON API). Returns the answer data of the asked type.
pub fn doh(name: &str, typ: &str, proxy: &str) -> Result<Vec<String>, String> {
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!("invalid DNS name: {name}"));
    }
    if !which("curl") {
        return Err("The online check needs curl.".into());
    }
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type={typ}");
    let mut c = Command::new("curl");
    c.args([
        "-fsS",
        "--max-time",
        "10",
        "-A",
        concat!("EML-Reader/", env!("CARGO_PKG_VERSION")),
        "-H",
        "accept: application/dns-json",
    ]);
    if !proxy.is_empty() {
        c.args(["-x", proxy]);
    }
    let o = c.arg(&url).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
    }
    parse_doh(&String::from_utf8_lossy(&o.stdout), typ)
}

fn type_code(typ: &str) -> u64 {
    match typ {
        "A" => 1,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        _ => 0,
    }
}

pub fn parse_doh(json: &str, typ: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("DNS: {e}"))?;
    let status = v["Status"].as_u64().unwrap_or(2);
    if status == 3 {
        return Ok(Vec::new()); // NXDOMAIN
    }
    if status != 0 {
        return Err(format!("DNS error (status {status})"));
    }
    let want = type_code(typ);
    let mut out = Vec::new();
    for a in v["Answer"].as_array().into_iter().flatten() {
        if a["type"].as_u64() != Some(want) {
            continue;
        }
        let data = a["data"].as_str().unwrap_or("");
        out.push(if typ == "TXT" {
            join_txt(data)
        } else {
            data.trim_end_matches('.').to_string()
        });
    }
    Ok(out)
}

/// `"v=spf1 a" " -all"` → `v=spf1 a -all`
fn join_txt(data: &str) -> String {
    let t = data.trim();
    if !t.starts_with('"') {
        return t.to_string();
    }
    let mut out = String::new();
    let mut inside = false;
    let mut esc = false;
    for c in t.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' && inside {
            esc = true;
        } else if c == '"' {
            inside = !inside;
        } else if inside {
            out.push(c);
        }
    }
    out
}

// --------------------------------------------------------------------- SPF

fn cidr_match(ip: &IpAddr, net: &str, default_len: Option<u8>) -> bool {
    let (addr, len) = match net.split_once('/') {
        Some((a, l)) => (a, l.parse::<u8>().ok()),
        None => (net, None),
    };
    let Ok(net_ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let l = len.or(default_len).unwrap_or(32).min(32) as u32;
            let mask = if l == 0 { 0 } else { u32::MAX << (32 - l) };
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let l = len.or(default_len).unwrap_or(128).min(128) as u32;
            let mask = if l == 0 { 0 } else { u128::MAX << (128 - l) };
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

/// Dual CIDR length of `a`/`mx` (`a:host/24//64`).
fn dual_len(spec: &str, ip: &IpAddr) -> (String, Option<u8>) {
    let (host, v4, v6) = match spec.split_once("//") {
        Some((left, v6)) => {
            let (h, v4) = left
                .split_once('/')
                .map_or((left, None), |(h, l)| (h, l.parse().ok()));
            (h, v4, v6.parse().ok())
        }
        None => match spec.split_once('/') {
            Some((h, l)) => (h, l.parse().ok(), None),
            None => (spec, None, None),
        },
    };
    (host.to_string(), if ip.is_ipv4() { v4 } else { v6 })
}

/// Evaluates the SPF record of `domain` for `ip` (RFC 7208, without macros and ptr).
/// Returns (result, explanation).
pub fn spf_eval(ip: &IpAddr, domain: &str, dns: Resolver<'_>) -> (String, String, Option<String>) {
    let mut lookups = 0;
    let (r, d, rec) = spf_inner(ip, domain, dns, 0, &mut lookups);
    (r, d, rec)
}

fn spf_inner(
    ip: &IpAddr,
    domain: &str,
    dns: Resolver<'_>,
    depth: u32,
    lookups: &mut u32,
) -> (String, String, Option<String>) {
    let txt = match dns(domain, "TXT") {
        Ok(t) => t,
        Err(e) => return ("temperror".into(), e, None),
    };
    let recs: Vec<&String> = txt
        .iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    let rec = match recs.len() {
        0 => {
            return (
                "none".into(),
                format!("{domain} publishes no SPF record"),
                None,
            )
        }
        1 => recs[0].clone(),
        _ => {
            return (
                "permerror".into(),
                format!("{domain} has several SPF records"),
                None,
            )
        }
    };
    let ret = |r: &str, d: String| (r.to_string(), d, Some(rec.clone()));
    let mut redirect = None;
    for term in rec.split_whitespace().skip(1) {
        let lower = term.to_ascii_lowercase();
        if let Some(r) = lower.strip_prefix("redirect=") {
            redirect = Some(r.to_string());
            continue;
        }
        if lower.starts_with("exp=") || (lower.contains('=') && !lower.contains(':')) {
            continue;
        }
        let (q, mech) = match lower.chars().next() {
            Some(c @ ('+' | '-' | '~' | '?')) => (c, &lower[1..]),
            _ => ('+', lower.as_str()),
        };
        let result = match q {
            '-' => "fail",
            '~' => "softfail",
            '?' => "neutral",
            _ => "pass",
        };
        if mech.contains('%') {
            continue; // macros are not expanded
        }
        let (name, arg) = match mech.find([':', '/']) {
            Some(i) => (&mech[..i], mech[i..].trim_start_matches(':')),
            None => (mech, ""),
        };
        let matched = match name {
            "all" => true,
            "ip4" | "ip6" => cidr_match(ip, arg, None),
            "a" | "mx" => {
                *lookups += 1;
                let spec = if arg.is_empty() || arg.starts_with('/') {
                    format!("{domain}{arg}")
                } else {
                    arg.to_string()
                };
                let (host, len) = dual_len(&spec, ip);
                let hosts = if name == "mx" {
                    dns(&host, "MX")
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|m| {
                            m.split_whitespace()
                                .nth(1)
                                .map(|h| h.trim_end_matches('.').to_string())
                        })
                        .take(10)
                        .collect()
                } else {
                    vec![host]
                };
                let typ = if ip.is_ipv4() { "A" } else { "AAAA" };
                hosts.iter().any(|h| {
                    dns(h, typ).unwrap_or_default().iter().any(|a| {
                        cidr_match(
                            ip,
                            &match len {
                                Some(l) => format!("{a}/{l}"),
                                None => a.clone(),
                            },
                            None,
                        )
                    })
                })
            }
            "include" => {
                *lookups += 1;
                if depth > 9 {
                    return ret("permerror", "too many nested includes".into());
                }
                let (r, _, _) = spf_inner(ip, arg, dns, depth + 1, lookups);
                match r.as_str() {
                    "pass" => true,
                    "temperror" => {
                        return ret("temperror", format!("include:{arg} could not be resolved"))
                    }
                    "permerror" | "none" => {
                        return ret("permerror", format!("include:{arg} is invalid"))
                    }
                    _ => false,
                }
            }
            "exists" => {
                *lookups += 1;
                !dns(arg, "A").unwrap_or_default().is_empty()
            }
            "ptr" => false,
            _ => return ret("permerror", format!("unknown mechanism {term}")),
        };
        if *lookups > 10 {
            return ret("permerror", "more than 10 DNS lookups".into());
        }
        if matched {
            return ret(result, format!("{ip} matches \"{term}\" of {domain}"));
        }
    }
    if let Some(r) = redirect {
        *lookups += 1;
        let (res, d, _) = spf_inner(ip, &r, dns, depth + 1, lookups);
        return ret(&res, d);
    }
    ret("neutral", format!("no mechanism of {domain} matches {ip}"))
}

// ------------------------------------------------------------------- DMARC

pub fn dmarc_explain(record: &str) -> (String, String) {
    let p = crate::dkim::tag(record, "p")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let pct = crate::dkim::tag(record, "pct").unwrap_or_else(|| "100".into());
    let what = match p.as_str() {
        "reject" => "messages that fail DMARC are to be rejected",
        "quarantine" => "messages that fail DMARC are to be treated as spam",
        "none" => "monitoring only: failing messages are delivered normally",
        _ => "no valid policy",
    };
    let mut e = what.to_string();
    if pct != "100" {
        e.push_str(&format!(" (applies to {pct} % of the messages)"));
    }
    if let Some(sp) = crate::dkim::tag(record, "sp") {
        e.push_str(&format!("; subdomains: {sp}"));
    }
    if crate::dkim::tag(record, "adkim").as_deref() == Some("s")
        || crate::dkim::tag(record, "aspf").as_deref() == Some("s")
    {
        e.push_str("; strict alignment");
    }
    (p, e)
}

// --------------------------------------------------------------------- IPs

pub fn reverse_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let hex = format!("{:032x}", u128::from(*v));
            hex.chars()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
        }
    }
}

fn ip_info(ip: &IpAddr, dns: Resolver<'_>) -> IpInfo {
    let rev = reverse_name(ip);
    let arpa = if ip.is_ipv4() {
        "in-addr.arpa"
    } else {
        "ip6.arpa"
    };
    let mut info = IpInfo {
        ip: ip.to_string(),
        ptr: dns(&format!("{rev}.{arpa}"), "PTR")
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or_default(),
        ..Default::default()
    };
    let zone = if ip.is_ipv4() {
        "origin.asn.cymru.com"
    } else {
        "origin6.asn.cymru.com"
    };
    if let Some(t) = dns(&format!("{rev}.{zone}"), "TXT")
        .ok()
        .and_then(|v| v.into_iter().next())
    {
        let f: Vec<&str> = t.split('|').map(str::trim).collect();
        info.asn = f
            .first()
            .unwrap_or(&"")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        info.prefix = f.get(1).unwrap_or(&"").to_string();
        info.country = f.get(2).unwrap_or(&"").to_string();
        if !info.asn.is_empty() {
            if let Some(t) = dns(&format!("AS{}.asn.cymru.com", info.asn), "TXT")
                .ok()
                .and_then(|v| v.into_iter().next())
            {
                info.org = t.split('|').nth(4).unwrap_or("").trim().to_string();
            }
        }
    }
    info
}

// --------------------------------------------------------------------- run

pub fn run(job: &Job, dns: Resolver<'_>) -> Report {
    let mut r = Report::default();
    // SPF for the envelope domain (and the From domain if it differs)
    let mut spf_domains = vec![job.mailfrom_domain.clone()];
    if job.from_domain != job.mailfrom_domain {
        spf_domains.push(job.from_domain.clone());
    }
    for d in spf_domains.into_iter().filter(|d| !d.is_empty()) {
        let check = match &job.sender_ip {
            Some(ip) => {
                let (result, detail, record) = spf_eval(ip, &d, dns);
                SpfCheck {
                    domain: d,
                    record,
                    result,
                    detail,
                }
            }
            None => {
                let record = dns(&d, "TXT")
                    .unwrap_or_default()
                    .into_iter()
                    .find(|t| t.to_ascii_lowercase().starts_with("v=spf1"));
                SpfCheck {
                    domain: d,
                    record,
                    result: "unknown".into(),
                    detail: "no public sender IP in the route".into(),
                }
            }
        };
        r.spf.push(check);
    }
    // DMARC
    if !job.from_domain.is_empty() {
        let org = crate::domains::org_domain(&job.from_domain);
        let mut tries = vec![job.from_domain.clone()];
        if org != job.from_domain {
            tries.push(org);
        }
        let mut found = None;
        for d in tries {
            match dns(&format!("_dmarc.{d}"), "TXT") {
                Ok(t) => {
                    if let Some(rec) = t
                        .into_iter()
                        .find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"))
                    {
                        found = Some((d, rec));
                        break;
                    }
                }
                Err(e) => r.errors.push(format!("DMARC {d}: {e}")),
            }
        }
        r.dmarc = Some(match found {
            Some((domain, rec)) => {
                let (policy, explain) = dmarc_explain(&rec);
                DmarcCheck {
                    domain,
                    record: Some(rec),
                    policy,
                    explain,
                }
            }
            None => DmarcCheck {
                domain: job.from_domain.clone(),
                record: None,
                policy: String::new(),
                explain:
                    "no DMARC record: anyone can send in this domain's name without consequences"
                        .into(),
            },
        });
    }
    // DKIM
    for (index, domain, selector) in &job.dkim {
        let name = format!("{selector}._domainkey.{domain}");
        let (record, valid) = match dns(&name, "TXT") {
            Ok(t) => match t.into_iter().find(|t| t.contains("p=")) {
                Some(rec) => {
                    let v = crate::dkim::verify(&job.raw, *index, &rec);
                    (Some(rec), v)
                }
                None => (None, Err(format!("no key published at {name}"))),
            },
            Err(e) => (None, Err(e)),
        };
        r.dkim.push(DkimCheck {
            domain: domain.clone(),
            selector: selector.clone(),
            record,
            valid,
        });
    }
    for ip in job.ips.iter().take(12) {
        r.ips.push(ip_info(ip, dns));
    }
    r
}

pub fn spawn(job: Job, tx: Sender<Report>, wake: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let proxy = job.proxy.clone();
        let cache = std::sync::Mutex::new(std::collections::HashMap::<
            String,
            Result<Vec<String>, String>,
        >::new());
        let dns = move |name: &str, typ: &str| {
            let key = format!("{typ} {name}");
            if let Some(v) = cache.lock().unwrap().get(&key) {
                return v.clone();
            }
            let v = doh(name, typ, &proxy);
            cache.lock().unwrap().insert(key, v.clone());
            v
        };
        let _ = tx.send(run(&job, &dns));
        wake();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fake() -> HashMap<(&'static str, &'static str), Vec<&'static str>> {
        HashMap::from([
            (
                ("shop.example", "TXT"),
                vec![
                    "v=spf1 mx include:_spf.mailer.example ~all",
                    "google-site-verification=x",
                ],
            ),
            (("shop.example", "MX"), vec!["10 mx.shop.example."]),
            (("mx.shop.example", "A"), vec!["192.0.2.10"]),
            (
                ("_spf.mailer.example", "TXT"),
                vec!["v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 -all"],
            ),
            (
                ("other.example", "TXT"),
                vec!["v=spf1 redirect=shop.example"],
            ),
            (
                ("_dmarc.shop.example", "TXT"),
                vec!["v=DMARC1; p=quarantine; pct=50; rua=mailto:d@shop.example"],
            ),
            (
                ("10.2.0.192.origin.asn.cymru.com", "TXT"),
                vec!["64496 | 192.0.2.0/24 | DE | ripencc | 2001-01-01"],
            ),
            (
                ("AS64496.asn.cymru.com", "TXT"),
                vec!["64496 | DE | ripencc | 2001-01-01 | EXAMPLE-NET, DE"],
            ),
            (("10.2.0.192.in-addr.arpa", "PTR"), vec!["mx.shop.example"]),
        ])
    }

    fn resolver<'a>(
        map: &'a HashMap<(&'static str, &'static str), Vec<&'static str>>,
    ) -> impl Fn(&str, &str) -> Result<Vec<String>, String> + 'a {
        move |n: &str, t: &str| {
            Ok(map
                .iter()
                .find(|((k, kt), _)| *k == n && *kt == t)
                .map(|(_, v)| v.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default())
        }
    }

    #[test]
    fn spf() {
        let map = fake();
        let dns = resolver(&map);
        let ev = |ip: &str, d: &str| spf_eval(&ip.parse().unwrap(), d, &dns).0;
        assert_eq!(ev("192.0.2.10", "shop.example"), "pass"); // mx
        assert_eq!(ev("198.51.100.7", "shop.example"), "pass"); // include ip4
        assert_eq!(ev("2001:db8::5", "shop.example"), "pass"); // include ip6
        assert_eq!(ev("203.0.113.1", "shop.example"), "softfail"); // ~all
        assert_eq!(ev("203.0.113.1", "other.example"), "softfail"); // redirect
        assert_eq!(ev("203.0.113.1", "nothing.example"), "none");
        assert!(cidr_match(&"10.1.2.3".parse().unwrap(), "10.0.0.0/8", None));
        assert!(!cidr_match(
            &"11.1.2.3".parse().unwrap(),
            "10.0.0.0/8",
            None
        ));
    }

    #[test]
    fn full_run() {
        let map = fake();
        let dns = resolver(&map);
        let job = Job {
            raw: include_bytes!("../tests/data/dkim-relaxed.eml").to_vec(),
            from_domain: "shop.example".into(),
            mailfrom_domain: "shop.example".into(),
            sender_ip: Some("192.0.2.10".parse().unwrap()),
            dkim: vec![(0, "shop.example".into(), "mail2026".into())],
            ips: vec!["192.0.2.10".parse().unwrap()],
            proxy: String::new(),
        };
        let key = include_str!("../tests/data/dkim-key.txt")
            .trim()
            .to_string();
        let leaked: &'static str = Box::leak(key.into_boxed_str());
        let mut map2 = map.clone();
        map2.insert(("mail2026._domainkey.shop.example", "TXT"), vec![leaked]);
        let dns2 = resolver(&map2);
        let _ = dns;
        let r = run(&job, &dns2);
        assert_eq!(r.spf[0].result, "pass");
        let d = r.dmarc.unwrap();
        assert_eq!(d.policy, "quarantine");
        assert!(d.explain.contains("50 %"));
        assert_eq!(r.dkim[0].valid, Ok(true));
        assert_eq!(r.ips[0].country, "DE");
        assert_eq!(r.ips[0].org, "EXAMPLE-NET, DE");
        assert_eq!(r.ips[0].ptr, "mx.shop.example");
    }

    #[test]
    fn doh_json() {
        let j = r#"{"Status":0,"Answer":[{"name":"x","type":16,"TTL":1,"data":"\"v=spf1 \" \"-all\""},{"type":5,"data":"cname."}]}"#;
        assert_eq!(parse_doh(j, "TXT").unwrap(), ["v=spf1 -all"]);
        assert!(parse_doh(r#"{"Status":3}"#, "TXT").unwrap().is_empty());
        assert_eq!(reverse_name(&"192.0.2.1".parse().unwrap()), "1.2.0.192");
        assert!(reverse_name(&"2001:db8::1".parse().unwrap()).starts_with("1.0.0.0"));
    }
}
