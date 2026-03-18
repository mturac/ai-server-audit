// ================================================================
//  audit_core — Rust Core Library
//  Exposes C-compatible FFI functions for the Go CLI wrapper.
//  All heavy lifting: port scan, health, security, updates.
// ================================================================

use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

// ── Result types (JSON-serializable) ────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Status {
    Ok,
    Warning,
    Critical,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckResult {
    pub category: String,
    pub name:     String,
    pub status:   Status,
    pub message:  String,
    pub latency_ms: Option<u64>,
    pub details:  Vec<String>,
}

impl CheckResult {
    fn ok(cat: &str, name: &str, msg: &str) -> Self {
        Self { category: cat.into(), name: name.into(), status: Status::Ok,
               message: msg.into(), latency_ms: None, details: vec![] }
    }
    fn warn(cat: &str, name: &str, msg: &str) -> Self {
        Self { category: cat.into(), name: name.into(), status: Status::Warning,
               message: msg.into(), latency_ms: None, details: vec![] }
    }
    fn crit(cat: &str, name: &str, msg: &str) -> Self {
        Self { category: cat.into(), name: name.into(), status: Status::Critical,
               message: msg.into(), latency_ms: None, details: vec![] }
    }
    fn info(cat: &str, name: &str, msg: &str) -> Self {
        Self { category: cat.into(), name: name.into(), status: Status::Info,
               message: msg.into(), latency_ms: None, details: vec![] }
    }
    fn details(mut self, d: Vec<String>) -> Self { self.details = d; self }
    fn latency(mut self, ms: u64) -> Self { self.latency_ms = Some(ms); self }
}

// ── Port Scanner ─────────────────────────────────────────────────

fn service_name(port: u16) -> &'static str {
    match port {
        21    => "FTP",       22    => "SSH",
        23    => "Telnet",    25    => "SMTP",
        53    => "DNS",       80    => "HTTP",
        110   => "POP3",      143   => "IMAP",
        443   => "HTTPS",     3000  => "Dev/Node",
        3306  => "MySQL",     5432  => "PostgreSQL",
        6379  => "Redis",     8080  => "HTTP-Alt",
        8443  => "HTTPS-Alt", 9200  => "Elasticsearch",
        27017 => "MongoDB",   _     => "Unknown",
    }
}

fn risk_level(port: u16, open: bool) -> &'static str {
    if !open { return "none"; }
    match port {
        23 | 21        => "critical",
        6379 | 27017   => "critical",
        9200           => "high",
        3306 | 5432    => "medium",
        3000 | 8080    => "medium",
        80             => "low",
        22 | 443|8443  => "safe",
        _              => "unknown",
    }
}

fn tcp_connect(host: &str, port: u16, timeout_ms: u64) -> (bool, u64) {
    let addr = format!("{}:{}", host, port);
    let Ok(sa) = addr.parse::<SocketAddr>() else { return (false, 0); };
    let start = Instant::now();
    let open = std::net::TcpStream::connect_timeout(&sa, Duration::from_millis(timeout_ms)).is_ok();
    (open, start.elapsed().as_millis() as u64)
}

pub fn scan_ports(host: &str, ports: &[u16], timeout_ms: u64, threads: usize) -> Vec<CheckResult> {
    use std::sync::{Arc, Mutex};

    let results = Arc::new(Mutex::new(Vec::new()));
    let chunks: Vec<Vec<u16>> = ports.chunks(threads.max(1)).map(|c| c.to_vec()).collect();

    let mut handles = vec![];
    for chunk in chunks {
        let host = host.to_string();
        let results = Arc::clone(&results);
        let handle = std::thread::spawn(move || {
            for port in chunk {
                let (open, ms) = tcp_connect(&host, port, timeout_ms);
                let risk = risk_level(port, open);
                let svc  = service_name(port);
                let state = if open { "OPEN" } else { "closed" };

                let status = if !open {
                    Status::Info
                } else {
                    match risk {
                        "critical" | "high" => Status::Critical,
                        "medium"            => Status::Warning,
                        _                   => Status::Ok,
                    }
                };

                let r = CheckResult {
                    category: "Ports".into(),
                    name: format!(":{} {}", port, svc),
                    status,
                    message: format!("{} — risk:{} — {}ms", state, risk, ms),
                    latency_ms: if open { Some(ms) } else { None },
                    details: vec![
                        format!("service: {}", svc),
                        format!("risk: {}", risk),
                    ],
                };
                results.lock().unwrap().push(r);
            }
        });
        handles.push(handle);
    }
    for h in handles { let _ = h.join(); }

    let mut out = results.lock().unwrap().clone();
    out.sort_by_key(|r| r.name.clone());

    let open_n = out.iter().filter(|r| r.message.starts_with("OPEN")).count();
    let crit_n = out.iter().filter(|r| matches!(r.status, Status::Critical)).count();
    let summary_status = if crit_n > 0 { Status::Critical }
                         else if open_n > 6 { Status::Warning }
                         else { Status::Ok };
    let summary = CheckResult {
        category: "Ports".into(),
        name: "Summary".into(),
        status: summary_status,
        message: format!("{} scanned — {} open — {} critical", out.len(), open_n, crit_n),
        latency_ms: None,
        details: vec![
            format!("total_scanned: {}", out.len()),
            format!("open: {}", open_n),
            format!("critical: {}", crit_n),
        ],
    };
    let mut final_out = vec![summary];
    final_out.extend(out);
    final_out
}

// ── Health Checks ────────────────────────────────────────────────

pub fn check_health(host: &str, port: u16, label: &str, timeout_ms: u64) -> CheckResult {
    let (open, ms) = tcp_connect(host, port, timeout_ms);
    if open {
        CheckResult::ok("Health", label, &format!("Reachable in {}ms", ms))
            .latency(ms)
            .details(vec![
                format!("host: {}", host),
                format!("port: {}", port),
                format!("latency: {}ms", ms),
            ])
    } else {
        CheckResult::crit("Health", label, &format!("Unreachable ({}ms timeout)", timeout_ms))
            .details(vec![
                format!("host: {}", host),
                format!("port: {}", port),
                "Check network/firewall".into(),
            ])
    }
}

// ── Security Checks ──────────────────────────────────────────────

pub fn run_security_checks(host: &str, timeout_ms: u64) -> Vec<CheckResult> {
    let checks: &[(u16, &str, &str, &str, &str)] = &[
        (23,    "Telnet Exposure",          "critical",
         "Port 23 OPEN — plaintext remote access (CWE-319)",
         "Disable telnet, use SSH instead"),
        (21,    "FTP Exposure",             "critical",
         "Port 21 OPEN — unencrypted file transfer",
         "Use SFTP (port 22) or FTPS instead"),
        (6379,  "Redis Exposed",            "critical",
         "Redis port 6379 OPEN — often has NO authentication",
         "Bind to 127.0.0.1, enable requirepass in redis.conf"),
        (27017, "MongoDB Exposed",          "high",
         "MongoDB port 27017 OPEN — verify authentication enabled",
         "Enable --auth, bind to localhost, restrict with firewall"),
        (9200,  "Elasticsearch Exposed",    "high",
         "Elasticsearch port 9200 OPEN — may lack auth",
         "Enable X-Pack security or restrict with firewall"),
        (3306,  "MySQL Public Access",      "medium",
         "MySQL port 3306 exposed to network",
         "Bind to 127.0.0.1 or use SSH tunnel"),
        (5432,  "PostgreSQL Public Access", "medium",
         "PostgreSQL port 5432 exposed to network",
         "Use pg_hba.conf to restrict access, prefer VPN/tunnel"),
    ];

    let mut results = vec![];

    for (port, name, risk, open_msg, fix) in checks {
        let (open, _) = tcp_connect(host, *port, timeout_ms);
        if open {
            let r = match *risk {
                "critical" => CheckResult::crit("Security", name, open_msg),
                _          => CheckResult::warn("Security", name, open_msg),
            };
            results.push(r.details(vec![
                format!("fix: {}", fix),
                format!("port: {}", port),
            ]));
        } else {
            results.push(
                CheckResult::ok("Security", name, &format!("Port {} closed — OK", port))
            );
        }
    }

    let (http, _)  = tcp_connect(host, 80,  timeout_ms);
    let (https, _) = tcp_connect(host, 443, timeout_ms);
    match (http, https) {
        (true, false) => results.push(
            CheckResult::warn("Security", "HTTPS Missing",
                "HTTP open but HTTPS closed — unencrypted traffic")
                .details(vec!["Install TLS certificate (Let's Encrypt)".into(),
                              "Redirect all HTTP to HTTPS".into()])
        ),
        (true, true) => results.push(
            CheckResult::ok("Security", "HTTPS Present",
                "Both HTTP+HTTPS open — ensure HTTP->HTTPS redirect is set")
        ),
        (false, true) => results.push(
            CheckResult::ok("Security", "HTTPS Only", "HTTPS-only — excellent")
        ),
        _ => results.push(
            CheckResult::info("Security", "Web Ports",
                "Neither HTTP nor HTTPS open — not a web server?")
        ),
    }

    results
}

// ── Update Checks ────────────────────────────────────────────────

pub fn check_updates() -> Vec<CheckResult> {
    let mut results = vec![];

    match std::process::Command::new("apt-get").args(["-s", "upgrade"]).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let upgradable: Vec<&str> = stdout.lines()
                .filter(|l| l.starts_with("Inst ")).collect();
            let security: Vec<&str> = upgradable.iter()
                .filter(|l| l.contains("security")).copied().collect();

            if !security.is_empty() {
                results.push(CheckResult::crit("Updates", "APT Security Updates",
                    &format!("{} security update(s) pending!", security.len()))
                    .details(security.iter().take(10).map(|s| s.to_string()).collect()));
            } else {
                results.push(CheckResult::ok("Updates", "APT Security Updates",
                    "No pending security updates"));
            }

            let other = upgradable.len().saturating_sub(security.len());
            if other > 0 {
                results.push(CheckResult::warn("Updates", "APT Package Updates",
                    &format!("{} regular package(s) can be upgraded", other)));
            } else {
                results.push(CheckResult::ok("Updates", "APT Package Updates",
                    "All packages up to date"));
            }
        }
        Err(_) => {
            match std::process::Command::new("brew").arg("outdated").output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let outdated: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
                    if outdated.is_empty() {
                        results.push(CheckResult::ok("Updates", "Homebrew", "All packages up to date"));
                    } else {
                        results.push(CheckResult::warn("Updates", "Homebrew",
                            &format!("{} package(s) outdated", outdated.len()))
                            .details(outdated.iter().take(10).map(|s| s.to_string()).collect()));
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info("Updates", "Package Manager",
                        "Neither apt nor brew found — manual update check required"));
                }
            }
        }
    }

    results
}

// ── FFI Exports (called from Go via cgo) ────────────────────────

#[no_mangle]
pub extern "C" fn audit_scan_ports(
    host_ptr: *const c_char,
    ports_json_ptr: *const c_char,
    timeout_ms: u64,
    threads: u32,
) -> *mut c_char {
    let host       = unsafe { CStr::from_ptr(host_ptr) }.to_string_lossy().to_string();
    let ports_json = unsafe { CStr::from_ptr(ports_json_ptr) }.to_string_lossy().to_string();
    let ports: Vec<u16> = serde_json::from_str(&ports_json).unwrap_or_default();
    let results = scan_ports(&host, &ports, timeout_ms, threads as usize);
    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".into());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn audit_health_check(
    host_ptr: *const c_char,
    port: u16,
    label_ptr: *const c_char,
    timeout_ms: u64,
) -> *mut c_char {
    let host  = unsafe { CStr::from_ptr(host_ptr)  }.to_string_lossy().to_string();
    let label = unsafe { CStr::from_ptr(label_ptr) }.to_string_lossy().to_string();
    let result = check_health(&host, port, &label, timeout_ms);
    let json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn audit_security_checks(
    host_ptr: *const c_char,
    timeout_ms: u64,
) -> *mut c_char {
    let host = unsafe { CStr::from_ptr(host_ptr) }.to_string_lossy().to_string();
    let results = run_security_checks(&host, timeout_ms);
    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".into());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn audit_check_updates() -> *mut c_char {
    let results = check_updates();
    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".into());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn audit_free_string(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { drop(CString::from_raw(ptr)); }
}
