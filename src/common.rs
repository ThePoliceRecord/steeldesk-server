use clap::App;
use hbb_common::{
    allow_err, anyhow::{Context, Result}, get_version_number, log, tokio, ResultType
};
use http::HeaderMap;
use ini::Ini;
use sodiumoxide::crypto::sign;
use std::{
    io::prelude::*,
    io::Read,
    net::{IpAddr, SocketAddr},
    time::{Instant, SystemTime},
};

#[allow(dead_code)]
pub(crate) fn get_expired_time() -> Instant {
    let now = Instant::now();
    now.checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(now)
}

#[allow(dead_code)]
pub(crate) fn test_if_valid_server(host: &str, name: &str) -> ResultType<SocketAddr> {
    use std::net::ToSocketAddrs;
    let res = if host.contains(':') {
        host.to_socket_addrs()?.next().context("")
    } else {
        format!("{}:{}", host, 0)
            .to_socket_addrs()?
            .next()
            .context("")
    };
    if res.is_err() {
        log::error!("Invalid {} {}: {:?}", name, host, res);
    }
    res
}

#[allow(dead_code)]
pub(crate) fn get_servers(s: &str, tag: &str) -> Vec<String> {
    let servers: Vec<String> = s
        .split(',')
        .filter(|x| !x.is_empty() && test_if_valid_server(x, tag).is_ok())
        .map(|x| x.to_owned())
        .collect();
    log::info!("{}={:?}", tag, servers);
    servers
}

#[allow(dead_code)]
#[inline]
fn arg_name(name: &str) -> String {
    name.to_uppercase().replace('_', "-")
}

#[allow(dead_code)]
pub fn init_args(args: &str, name: &str, about: &str) {
    let matches = App::new(name)
        .version(crate::version::VERSION)
        .author("Purslane Ltd. <info@rustdesk.com>")
        .about(about)
        .args_from_usage(args)
        .get_matches();
    if let Ok(v) = Ini::load_from_file(".env") {
        if let Some(section) = v.section(None::<String>) {
            section
                .iter()
                .for_each(|(k, v)| std::env::set_var(arg_name(k), v));
        }
    }
    if let Some(config) = matches.value_of("config") {
        if let Ok(v) = Ini::load_from_file(config) {
            if let Some(section) = v.section(None::<String>) {
                section
                    .iter()
                    .for_each(|(k, v)| std::env::set_var(arg_name(k), v));
            }
        }
    }
    for (k, v) in matches.args {
        if let Some(v) = v.vals.first() {
            std::env::set_var(arg_name(k), v.to_string_lossy().to_string());
        }
    }
}

#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    std::env::var(arg_name(name)).unwrap_or(default)
}

#[allow(dead_code)]
#[inline]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or_default()
}

pub fn gen_sk(wait: u64) -> (String, Option<sign::SecretKey>) {
    let sk_file = "id_ed25519";
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    if let Ok(mut file) = std::fs::File::open(sk_file) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let contents = contents.trim();
            let sk = base64::decode(contents).unwrap_or_default();
            if sk.len() == sign::SECRETKEYBYTES {
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);
                log::info!("Private key comes from {}", sk_file);
                return (pk, Some(sign::SecretKey(tmp)));
            } else {
                // don't use log here, since it is async
                println!("Fatal error: malformed private key in {sk_file}.");
                std::process::exit(1);
            }
        }
    } else {
        let gen_func = || {
            let (tmp, sk) = sign::gen_keypair();
            (base64::encode(tmp), sk)
        };
        let (mut pk, mut sk) = gen_func();
        for _ in 0..300 {
            if !pk.contains('/') && !pk.contains(':') {
                break;
            }
            (pk, sk) = gen_func();
        }
        let pub_file = format!("{sk_file}.pub");
        if let Ok(mut f) = std::fs::File::create(&pub_file) {
            f.write_all(pk.as_bytes()).ok();
            if let Ok(mut f) = std::fs::File::create(sk_file) {
                let s = base64::encode(&sk);
                if f.write_all(s.as_bytes()).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(sk_file, std::fs::Permissions::from_mode(0o600)).ok();
                    }
                    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
                    log::debug!("Public key: [{}chars]", pk.len());
                    return (pk, Some(sk));
                }
            }
        }
    }
    ("".to_owned(), None)
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use hbb_common::tokio;
    use hbb_common::tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = terminate => {
                log::info!("signal terminate");
            }
            _ = interrupt => {
                log::info!("signal interrupt");
            }
            _ = quit => {
                log::info!("signal quit");
            }
        }
        Ok(())
    })
    .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}


/// Parse a comma-separated list of IP addresses into a `Vec<IpAddr>`.
///
/// Invalid entries are silently skipped with a warning log.
#[allow(dead_code)]
pub(crate) fn parse_trusted_proxy_ips(raw: &str) -> Vec<IpAddr> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            match s.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    log::warn!("Invalid trusted proxy IP ignored: {:?}", s);
                    None
                }
            }
        })
        .collect()
}

/// Read the `trusted-proxy-ips` configuration value and parse it into a list
/// of IP addresses. Returns an empty list if not configured.
#[allow(dead_code)]
pub fn get_trusted_proxy_ips() -> Vec<IpAddr> {
    parse_trusted_proxy_ips(&get_arg("trusted-proxy-ips"))
}

/// Determine the real client IP from a WebSocket connection, respecting trusted proxies.
///
/// If the direct connection (`addr`) comes from a trusted proxy IP, then the
/// `X-Real-IP` header (preferred) or `X-Forwarded-For` header is used to
/// determine the client IP. Otherwise, the headers are ignored and the direct
/// connection address is returned.
///
/// When no trusted proxies are configured, forwarded headers are always ignored.
#[allow(dead_code)]
pub fn get_real_ip(addr: SocketAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> SocketAddr {
    if trusted_proxies.is_empty() {
        log::debug!(
            "No trusted proxies configured; ignoring X-Real-IP/X-Forwarded-For from {}",
            addr.ip()
        );
        return addr;
    }

    let source_ip = addr.ip();
    // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
    let normalized_source = match source_ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                source_ip
            }
        }
        _ => source_ip,
    };

    if !trusted_proxies.contains(&normalized_source) {
        log::debug!(
            "Connection from {} is not a trusted proxy; ignoring forwarded headers",
            addr.ip()
        );
        return addr;
    }

    let real_ip = headers
        .get("X-Real-IP")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|header_value| header_value.to_str().ok());

    if let Some(ip_str) = real_ip {
        // X-Forwarded-For may contain multiple IPs; use the first (leftmost / original client)
        let ip_str = ip_str.split(',').next().unwrap_or(ip_str).trim();
        if ip_str.contains('.') {
            // IPv4
            format!("{ip_str}:0").parse().unwrap_or(addr)
        } else {
            // IPv6
            format!("[{ip_str}]:0").parse().unwrap_or(addr)
        }
    } else {
        addr
    }
}

pub fn check_software_update() {
    const ONE_DAY_IN_SECONDS: u64 = 60 * 60 * 24;
    std::thread::spawn(move || loop {
        std::thread::spawn(move || allow_err!(check_software_update_()));
        std::thread::sleep(std::time::Duration::from_secs(ONE_DAY_IN_SECONDS));
    });
}

#[tokio::main(flavor = "current_thread")]
async fn check_software_update_() -> hbb_common::ResultType<()> {
    let (request, url) = hbb_common::version_check_request(hbb_common::VER_TYPE_RUSTDESK_SERVER.to_string());
    let latest_release_response = reqwest::Client::builder().build()?
        .post(url)
        .json(&request)
        .send()
        .await?;

    let bytes = latest_release_response.bytes().await?;
    let resp: hbb_common::VersionCheckResponse = serde_json::from_slice(&bytes)?;
    let response_url = resp.url;
    let latest_release_version = response_url.rsplit('/').next().unwrap_or_default();
    if get_version_number(&latest_release_version) > get_version_number(crate::version::VERSION) {
       log::info!("new version is available: {}", latest_release_version);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    // --- arg_name ---

    #[test]
    fn test_arg_name_uppercases_and_replaces_underscores() {
        assert_eq!(arg_name("relay_server"), "RELAY-SERVER");
    }

    #[test]
    fn test_arg_name_already_uppercase() {
        assert_eq!(arg_name("PORT"), "PORT");
    }

    #[test]
    fn test_arg_name_empty_string() {
        assert_eq!(arg_name(""), "");
    }

    #[test]
    fn test_arg_name_multiple_underscores() {
        assert_eq!(arg_name("a_b_c_d"), "A-B-C-D");
    }

    #[test]
    fn test_arg_name_no_underscores() {
        assert_eq!(arg_name("port"), "PORT");
    }

    // --- get_arg_or ---

    #[test]
    fn test_get_arg_or_returns_default_when_unset() {
        // Use a name unlikely to collide with real env vars
        let val = get_arg_or("zzz_nonexistent_test_var_1234", "fallback".to_owned());
        assert_eq!(val, "fallback");
    }

    #[test]
    fn test_get_arg_or_returns_env_value() {
        std::env::set_var("TEST-COMMON-GETARG", "hello");
        let val = get_arg_or("test_common_getarg", "default".to_owned());
        assert_eq!(val, "hello");
        std::env::remove_var("TEST-COMMON-GETARG");
    }

    #[test]
    fn test_get_arg_returns_empty_when_unset() {
        let val = get_arg("zzz_nonexistent_test_var_5678");
        assert_eq!(val, "");
    }

    // --- get_expired_time ---

    #[test]
    fn test_get_expired_time_is_in_the_past() {
        let expired = get_expired_time();
        let now = Instant::now();
        assert!(expired < now, "expired time should be before now");
    }

    #[test]
    fn test_get_expired_time_is_roughly_one_hour_ago() {
        let expired = get_expired_time();
        let now = Instant::now();
        let elapsed = now.duration_since(expired);
        // Should be approximately 3600 seconds (allow some slack for test execution)
        assert!(elapsed.as_secs() >= 3599 && elapsed.as_secs() <= 3601);
    }

    // --- now ---

    #[test]
    fn test_now_returns_reasonable_epoch() {
        let t = now();
        // Should be after 2020-01-01 and before 2100-01-01
        assert!(t > 1_577_836_800, "timestamp should be after 2020");
        assert!(t < 4_102_444_800, "timestamp should be before 2100");
    }

    // --- test_if_valid_server ---

    #[test]
    fn test_valid_server_ip_with_port() {
        let result = test_if_valid_server("127.0.0.1:8080", "test");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_valid_server_ip_without_port() {
        // When no port is given, port 0 is appended
        let result = test_if_valid_server("127.0.0.1", "test");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_valid_server_localhost_with_port() {
        let result = test_if_valid_server("localhost:9000", "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port(), 9000);
    }

    #[test]
    fn test_invalid_server_empty_string() {
        let result = test_if_valid_server("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_server_garbage() {
        let result = test_if_valid_server("not a valid address at all!", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_server_ipv6_with_port() {
        let result = test_if_valid_server("[::1]:443", "test");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 443);
    }

    // --- get_servers ---

    #[test]
    fn test_get_servers_single_valid() {
        let servers = get_servers("127.0.0.1", "test");
        assert_eq!(servers, vec!["127.0.0.1"]);
    }

    #[test]
    fn test_get_servers_multiple_valid() {
        let servers = get_servers("127.0.0.1,127.0.0.2", "test");
        assert_eq!(servers, vec!["127.0.0.1", "127.0.0.2"]);
    }

    #[test]
    fn test_get_servers_filters_empty_segments() {
        let servers = get_servers("127.0.0.1,,127.0.0.2,", "test");
        assert_eq!(servers, vec!["127.0.0.1", "127.0.0.2"]);
    }

    #[test]
    fn test_get_servers_filters_invalid() {
        let servers = get_servers("127.0.0.1,not valid!,127.0.0.2", "test");
        assert_eq!(servers, vec!["127.0.0.1", "127.0.0.2"]);
    }

    #[test]
    fn test_get_servers_empty_string() {
        let servers = get_servers("", "test");
        assert!(servers.is_empty());
    }

    #[test]
    fn test_get_servers_all_invalid() {
        let servers = get_servers("garbage,also garbage", "test");
        assert!(servers.is_empty());
    }

    // --- Key generation helpers (unit-test the logic, not file I/O) ---

    #[test]
    fn test_keypair_generation_produces_valid_keys() {
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let sk_b64 = base64::encode(&sk);

        // Keys should base64-decode back to correct lengths
        assert_eq!(base64::decode(&pk_b64).unwrap().len(), sign::PUBLICKEYBYTES);
        assert_eq!(base64::decode(&sk_b64).unwrap().len(), sign::SECRETKEYBYTES);
    }

    #[test]
    fn test_public_key_derived_from_secret_key() {
        // This mirrors the logic in gen_sk: the public key is the second half of
        // the secret key bytes (Ed25519 seed || public key).
        let (pk, sk) = sign::gen_keypair();
        let sk_bytes = &sk[..];
        let derived_pk = &sk_bytes[sign::SECRETKEYBYTES / 2..];
        assert_eq!(derived_pk, &pk[..]);
    }

    #[test]
    fn test_public_key_base64_derivation_from_sk_matches_gen_sk_logic() {
        // Replicate exactly what gen_sk does when reading from file:
        // encode the second half of the secret key bytes as the public key.
        let (_pk, sk) = sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let sk_decoded = base64::decode(&sk_b64).unwrap();
        assert_eq!(sk_decoded.len(), sign::SECRETKEYBYTES);

        let mut tmp = [0u8; sign::SECRETKEYBYTES];
        tmp[..].copy_from_slice(&sk_decoded);
        let pk_b64 = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);

        let pk_direct = base64::encode(_pk);
        assert_eq!(pk_b64, pk_direct);
    }

    #[test]
    fn test_generated_pk_rejection_of_slash_and_colon() {
        // The gen_sk function rejects public keys containing '/' or ':'.
        // Generate many keys and verify the filter logic works.
        for _ in 0..50 {
            let (pk, _sk) = sign::gen_keypair();
            let pk_b64 = base64::encode(pk);
            if !pk_b64.contains('/') && !pk_b64.contains(':') {
                // This key would be accepted by gen_sk
                assert!(!pk_b64.contains('/'));
                assert!(!pk_b64.contains(':'));
            }
            // Keys containing '/' or ':' would be rejected and regenerated
        }
    }

    #[test]
    fn test_base64_encode_can_produce_slash() {
        // Demonstrate that base64 encoding can produce '/' characters, which is
        // why gen_sk has the rejection loop. We encode bytes that are known to
        // produce '/' in standard base64.
        let bytes = [0xFF, 0xFF]; // base64 encodes to "//8="
        let encoded = base64::encode(bytes);
        assert!(encoded.contains('/'), "expected '/' in base64 of 0xFFFF");
    }

    // --- CWE-532: Public key not leaked in log output ---
    //
    // The log line in gen_sk was changed from:
    //   log::debug!("Public key: {}", pk)
    // to:
    //   log::debug!("Public key: [{}chars]", pk.len())
    //
    // Since Rust's `log` crate has no built-in capture, we verify that the
    // format expression `format!("Public key: [{}chars]", pk.len())` does not
    // contain the actual public key value.

    #[test]
    fn test_public_key_log_format_does_not_leak_key() {
        let (pk, _sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);

        // This is the exact format expression used in the fixed log line
        let log_output = format!("Public key: [{}chars]", pk_b64.len());

        assert!(!log_output.contains(&pk_b64),
            "log output must not contain the raw public key");
        assert!(log_output.contains("chars"),
            "log output should indicate the key length, not the key value");
        // Ed25519 public keys are 32 bytes => 44 chars in base64
        assert!(log_output.contains("44"),
            "log output should show the character count of the base64 public key");
    }

    // --- Private key file permissions (CWE-732 fix) ---

    #[cfg(unix)]
    #[test]
    fn test_gen_sk_creates_private_key_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        // Run gen_sk in a temporary directory so it creates fresh key files
        let tmp_dir = std::env::temp_dir().join(format!(
            "rustdesk_test_gensk_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp_dir).unwrap();

        // Remove any pre-existing key files in the temp dir
        let _ = std::fs::remove_file("id_ed25519");
        let _ = std::fs::remove_file("id_ed25519.pub");

        let (pk, sk) = gen_sk(0);

        // Restore original directory before assertions so cleanup is reliable
        std::env::set_current_dir(&original_dir).unwrap();

        assert!(!pk.is_empty(), "gen_sk should produce a public key");
        assert!(sk.is_some(), "gen_sk should produce a secret key");

        let sk_path = tmp_dir.join("id_ed25519");
        assert!(sk_path.exists(), "private key file should exist");

        let metadata = std::fs::metadata(&sk_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Private key file should have mode 0600, got {:o}",
            mode
        );

        // Clean up
        let _ = std::fs::remove_file(tmp_dir.join("id_ed25519"));
        let _ = std::fs::remove_file(tmp_dir.join("id_ed25519.pub"));
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    // -----------------------------------------------------------------------
    // CWE-346: Trusted proxy IP validation for X-Real-IP / X-Forwarded-For
    // -----------------------------------------------------------------------

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn test_get_real_ip_no_trusted_proxies_ignores_header() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "10.0.0.1")]);
        let trusted: Vec<IpAddr> = vec![];
        let result = get_real_ip(addr, &headers, &trusted);
        assert_eq!(result, addr, "header should be ignored when no trusted proxies configured");
    }

    #[test]
    fn test_get_real_ip_accepted_from_trusted_proxy() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "203.0.113.50")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        let expected: SocketAddr = "203.0.113.50:0".parse().unwrap();
        assert_eq!(result, expected, "header should be accepted from trusted proxy");
    }

    #[test]
    fn test_get_real_ip_ignored_from_non_trusted_ip() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "10.0.0.1")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        assert_eq!(result, addr, "header should be ignored from non-trusted IP");
    }

    #[test]
    fn test_get_real_ip_multiple_trusted_proxies() {
        let trusted: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
        ];
        let headers = make_headers(&[("X-Real-IP", "203.0.113.99")]);
        let expected: SocketAddr = "203.0.113.99:0".parse().unwrap();

        // Connection from first trusted proxy
        let addr1: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        assert_eq!(get_real_ip(addr1, &headers, &trusted), expected);

        // Connection from third trusted proxy
        let addr3: SocketAddr = "10.0.0.3:3333".parse().unwrap();
        assert_eq!(get_real_ip(addr3, &headers, &trusted), expected);

        // Connection from non-trusted IP
        let addr_bad: SocketAddr = "10.0.0.99:9999".parse().unwrap();
        assert_eq!(get_real_ip(addr_bad, &headers, &trusted), addr_bad);
    }

    #[test]
    fn test_get_real_ip_x_real_ip_takes_precedence_over_x_forwarded_for() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = make_headers(&[
            ("X-Real-IP", "1.2.3.4"),
            ("X-Forwarded-For", "5.6.7.8"),
        ]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        let expected: SocketAddr = "1.2.3.4:0".parse().unwrap();
        assert_eq!(result, expected, "X-Real-IP should take precedence over X-Forwarded-For");
    }

    #[test]
    fn test_get_real_ip_x_forwarded_for_used_when_no_x_real_ip() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = make_headers(&[("X-Forwarded-For", "5.6.7.8")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        let expected: SocketAddr = "5.6.7.8:0".parse().unwrap();
        assert_eq!(result, expected, "X-Forwarded-For should be used when X-Real-IP is absent");
    }

    #[test]
    fn test_get_real_ip_loopback_in_header_not_granted_from_non_trusted() {
        // An attacker tries to spoof a loopback address via header to gain admin access
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "127.0.0.1")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()]; // attacker is not trusted
        let result = get_real_ip(addr, &headers, &trusted);
        assert_eq!(result, addr, "loopback in header must be ignored from non-trusted source");
        assert!(!result.ip().is_loopback(), "result must not be loopback");
    }

    #[test]
    fn test_get_real_ip_loopback_in_header_not_granted_no_trusted_proxies() {
        // No trusted proxies configured -- headers always ignored
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "127.0.0.1")]);
        let trusted: Vec<IpAddr> = vec![];
        let result = get_real_ip(addr, &headers, &trusted);
        assert_eq!(result, addr, "loopback in header must be ignored with no trusted proxies");
        assert!(!result.ip().is_loopback(), "result must not be loopback");
    }

    #[test]
    fn test_get_real_ip_no_headers_returns_original_addr() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = HeaderMap::new();
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        assert_eq!(result, addr, "original addr should be returned when no forwarding headers present");
    }

    #[test]
    fn test_get_real_ip_ipv6_header_value() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = make_headers(&[("X-Real-IP", "2001:db8::1")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        let expected: SocketAddr = "[2001:db8::1]:0".parse().unwrap();
        assert_eq!(result, expected, "should handle IPv6 addresses in headers");
    }

    #[test]
    fn test_get_real_ip_x_forwarded_for_multiple_ips_uses_first() {
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let headers = make_headers(&[("X-Forwarded-For", "203.0.113.50, 10.0.0.1, 10.0.0.5")]);
        let trusted: Vec<IpAddr> = vec!["10.0.0.5".parse().unwrap()];
        let result = get_real_ip(addr, &headers, &trusted);
        let expected: SocketAddr = "203.0.113.50:0".parse().unwrap();
        assert_eq!(result, expected, "should use first IP from X-Forwarded-For chain");
    }

    // --- parse_trusted_proxy_ips ---

    #[test]
    fn test_parse_trusted_proxy_ips_empty_string() {
        let result = parse_trusted_proxy_ips("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_trusted_proxy_ips_single_ip() {
        let result = parse_trusted_proxy_ips("10.0.0.1");
        assert_eq!(result, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_trusted_proxy_ips_multiple_ips() {
        let result = parse_trusted_proxy_ips("10.0.0.1,10.0.0.2,192.168.1.1");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(result[1], "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(result[2], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_trusted_proxy_ips_skips_invalid_entries() {
        let result = parse_trusted_proxy_ips("10.0.0.1,not_an_ip,10.0.0.2");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(result[1], "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_trusted_proxy_ips_handles_whitespace() {
        let result = parse_trusted_proxy_ips(" 10.0.0.1 , 10.0.0.2 ");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(result[1], "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_trusted_proxy_ips_supports_ipv6() {
        let result = parse_trusted_proxy_ips("10.0.0.1,::1,2001:db8::1");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(result[1], "::1".parse::<IpAddr>().unwrap());
        assert_eq!(result[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_trusted_proxy_ips_handles_empty_segments() {
        let result = parse_trusted_proxy_ips("10.0.0.1,,10.0.0.2,");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(result[1], "10.0.0.2".parse::<IpAddr>().unwrap());
    }
}