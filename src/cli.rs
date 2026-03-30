//! `rustdesk-api-cli` -- A simple CLI tool for managing the RustDesk Pro API server.
//!
//! Communicates with the Pro API via HTTP using reqwest.  Auth tokens are
//! persisted to `~/.rustdesk-api-token` so that only `login` needs credentials.

use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Token persistence
// ---------------------------------------------------------------------------

fn token_path() -> PathBuf {
    dirs_or_home().join(".rustdesk-api-token")
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn save_token(token: &str) -> Result<(), String> {
    fs::write(token_path(), token).map_err(|e| format!("failed to save token: {}", e))
}

fn load_token() -> Result<String, String> {
    fs::read_to_string(token_path())
        .map(|s| s.trim().to_string())
        .map_err(|_| "Not logged in. Run `login` first.".to_string())
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn build_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

fn auth_header() -> Result<String, String> {
    let token = load_token()?;
    Ok(format!("Bearer {}", token))
}

/// Print an HTTP error body if available, otherwise print the status.
fn handle_response(resp: reqwest::blocking::Response) -> Result<serde_json::Value, String> {
    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if status.is_success() {
        let val: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
        Ok(val)
    } else {
        // Try to extract error message from JSON body
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
                return Err(format!("Error {}: {}", status.as_u16(), err));
            }
        }
        Err(format!("Error {}: {}", status.as_u16(), body))
    }
}

// ---------------------------------------------------------------------------
// Table formatting
// ---------------------------------------------------------------------------

/// Print a list of objects as a simple text table.
fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(no results)");
        return;
    }

    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.join("  "));

    // Separator
    let sep_line: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep_line.join("  "));

    // Rows
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(cell.len());
                format!("{:<width$}", cell, width = w)
            })
            .collect();
        println!("{}", line.join("  "));
    }
}

/// Pretty-print a single JSON object.
fn print_json_object(val: &serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);
            for (k, v) in map {
                let display = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                println!("  {:<width$}  {}", k, display, width = max_key);
            }
        }
        other => println!("{}", serde_json::to_string_pretty(other).unwrap_or_default()),
    }
}

fn json_str(val: &serde_json::Value, key: &str) -> String {
    val.get(key)
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_login(server: &str, username: &str, password: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/login", server);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;

    let token = json
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or("no access_token in response")?;

    save_token(token)?;

    let user_name = json
        .get("user")
        .and_then(|u| u.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");

    println!("Logged in as: {}", user_name);
    println!("Token saved to: {}", token_path().display());
    Ok(())
}

fn cmd_user_list(server: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/users", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    let users = json.as_array().ok_or("expected array response")?;

    let rows: Vec<Vec<String>> = users
        .iter()
        .map(|u| {
            vec![
                json_str(u, "id"),
                json_str(u, "username"),
                json_str(u, "email"),
                json_str(u, "is_admin"),
            ]
        })
        .collect();

    print_table(&["ID", "USERNAME", "EMAIL", "ADMIN"], &rows);
    Ok(())
}

fn cmd_user_create(
    server: &str,
    username: &str,
    email: &str,
    password: &str,
    is_admin: bool,
) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/users", server);
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({
            "username": username,
            "email": email,
            "password": password,
            "is_admin": is_admin,
        }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("User created:");
    print_json_object(&json);
    Ok(())
}

fn cmd_user_delete(server: &str, id: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/users/{}", server, id);
    let resp = client
        .delete(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("{}", json_str(&json, "message"));
    Ok(())
}

fn cmd_group_list(server: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/user-groups", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    let groups = json.as_array().ok_or("expected array response")?;

    let rows: Vec<Vec<String>> = groups
        .iter()
        .map(|g| {
            vec![
                json_str(g, "id"),
                json_str(g, "name"),
                json_str(g, "parent_id"),
                json_str(g, "created_at"),
            ]
        })
        .collect();

    print_table(&["ID", "NAME", "PARENT", "CREATED"], &rows);
    Ok(())
}

fn cmd_group_create(server: &str, name: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/user-groups", server);
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("Group created:");
    print_json_object(&json);
    Ok(())
}

fn cmd_group_add_member(server: &str, group_id: &str, user_id: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/user-groups/{}/members", server, group_id);
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({ "id": user_id }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("{}", json_str(&json, "message"));
    Ok(())
}

fn cmd_group_members(server: &str, group_id: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/user-groups/{}/members", server, group_id);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    let members = json.as_array().ok_or("expected array response")?;

    let rows: Vec<Vec<String>> = members
        .iter()
        .map(|m| vec![json_str(m, "id"), json_str(m, "group_id")])
        .collect();

    print_table(&["USER_ID", "GROUP_ID"], &rows);
    Ok(())
}

fn cmd_strategy_list(server: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/strategies", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    let strategies = json.as_array().ok_or("expected array response")?;

    let rows: Vec<Vec<String>> = strategies
        .iter()
        .map(|s| {
            vec![
                json_str(s, "id"),
                json_str(s, "name"),
                json_str(s, "created_at"),
            ]
        })
        .collect();

    print_table(&["ID", "NAME", "CREATED"], &rows);
    Ok(())
}

fn cmd_strategy_create(server: &str, name: &str, settings_json: &str) -> Result<(), String> {
    let settings: serde_json::Value = serde_json::from_str(settings_json)
        .map_err(|e| format!("invalid JSON for settings: {}", e))?;

    let client = build_client();
    let url = format!("{}/api/strategies", server);
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({
            "name": name,
            "settings": settings,
        }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("Strategy created:");
    print_json_object(&json);
    Ok(())
}

fn cmd_strategy_assign(
    server: &str,
    strategy_id: &str,
    target_type: &str,
    target_id: &str,
) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/strategies/{}/assign", server, strategy_id);
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({
            "target_type": target_type,
            "target_id": target_id,
        }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("Strategy assigned:");
    print_json_object(&json);
    Ok(())
}

fn cmd_strategy_effective(
    server: &str,
    target_type: &str,
    target_id: &str,
) -> Result<(), String> {
    let client = build_client();
    let url = format!(
        "{}/api/strategies/effective/{}/{}",
        server, target_type, target_id
    );
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    println!("Effective strategy:");
    print_json_object(&json);
    Ok(())
}

fn cmd_audit_list(server: &str, limit: Option<usize>) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/audit/conn", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;
    let entries = json.as_array().ok_or("expected array response")?;

    let entries: Vec<&serde_json::Value> = match limit {
        Some(n) => entries.iter().take(n).collect(),
        None => entries.iter().collect(),
    };

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                json_str(e, "id"),
                json_str(e, "from_peer"),
                json_str(e, "to_peer"),
                json_str(e, "conn_type"),
                json_str(e, "timestamp"),
            ]
        })
        .collect();

    print_table(&["ID", "FROM", "TO", "TYPE", "TIMESTAMP"], &rows);
    Ok(())
}

fn cmd_ab_list(server: &str) -> Result<(), String> {
    let client = build_client();
    let url = format!("{}/api/ab", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let json = handle_response(resp)?;

    let entries = json
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                json_str(e, "id"),
                json_str(e, "peer_id"),
                json_str(e, "alias"),
                json_str(e, "tags"),
            ]
        })
        .collect();

    print_table(&["ID", "PEER_ID", "ALIAS", "TAGS"], &rows);

    let tags = json
        .get("tags")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    if !tags.is_empty() {
        let tag_strs: Vec<String> = tags
            .iter()
            .map(|t| t.as_str().unwrap_or("").to_string())
            .collect();
        println!("\nTags: {}", tag_strs.join(", "));
    }

    Ok(())
}

fn cmd_ab_add(server: &str, peer_id: &str, alias: Option<&str>) -> Result<(), String> {
    // First, get current address book
    let client = build_client();
    let url = format!("{}/api/ab", server);
    let resp = client
        .get(&url)
        .header("Authorization", auth_header()?)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let current = handle_response(resp)?;
    let mut entries = current
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let tags = current
        .get("tags")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();

    // Add new entry
    let new_entry = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "peer_id": peer_id,
        "alias": alias.unwrap_or(""),
        "tags": [],
        "hash": "",
    });
    entries.push(new_entry);

    // Post back
    let resp = client
        .post(&url)
        .header("Authorization", auth_header()?)
        .json(&serde_json::json!({
            "entries": entries,
            "tags": tags,
        }))
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    handle_response(resp)?;
    println!("Added peer '{}' to address book.", peer_id);
    Ok(())
}

fn cmd_status(server: &str) -> Result<(), String> {
    let client = build_client();

    // Health check
    let health_url = format!("{}/api/health", server);
    match client.get(&health_url).send() {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            println!("Health:    {} ({})", body.trim(), status.as_u16());
        }
        Err(e) => {
            println!("Health:    UNREACHABLE ({})", e);
            return Err("Server is not reachable.".to_string());
        }
    }

    // Heartbeat
    let heartbeat_url = format!("{}/api/heartbeat", server);
    match client.get(&heartbeat_url).send() {
        Ok(resp) => {
            let body = resp.text().unwrap_or_default();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                let is_pro = json
                    .get("is_pro")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                println!("Pro mode:  {}", if is_pro { "enabled" } else { "disabled" });
            } else {
                println!("Heartbeat: {}", body.trim());
            }
        }
        Err(e) => {
            println!("Heartbeat: ERROR ({})", e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CLI definition (clap v2)
// ---------------------------------------------------------------------------

fn build_cli() -> clap::App<'static, 'static> {
    clap::App::new("rustdesk-api-cli")
        .version("0.1.0")
        .about("CLI tool for managing the RustDesk Pro API server")
        .arg(
            clap::Arg::with_name("server")
                .long("server")
                .short("s")
                .takes_value(true)
                .default_value("http://localhost:21114")
                .help("Base URL of the API server"),
        )
        .subcommand(
            clap::SubCommand::with_name("login")
                .about("Login and save auth token")
                .arg(clap::Arg::with_name("username").required(true).index(1).help("Username"))
                .arg(clap::Arg::with_name("password").required(true).index(2).help("Password")),
        )
        .subcommand(
            clap::SubCommand::with_name("user")
                .about("User management")
                .subcommand(
                    clap::SubCommand::with_name("list").about("List all users"),
                )
                .subcommand(
                    clap::SubCommand::with_name("create")
                        .about("Create a new user")
                        .arg(clap::Arg::with_name("username").required(true).index(1).help("Username"))
                        .arg(clap::Arg::with_name("email").required(true).index(2).help("Email address"))
                        .arg(clap::Arg::with_name("password").required(true).index(3).help("Password"))
                        .arg(
                            clap::Arg::with_name("admin")
                                .long("admin")
                                .help("Grant admin privileges"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("delete")
                        .about("Delete a user")
                        .arg(clap::Arg::with_name("id").required(true).index(1).help("User ID")),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("group")
                .about("User group management")
                .subcommand(
                    clap::SubCommand::with_name("list").about("List user groups"),
                )
                .subcommand(
                    clap::SubCommand::with_name("create")
                        .about("Create a user group")
                        .arg(clap::Arg::with_name("name").required(true).index(1).help("Group name")),
                )
                .subcommand(
                    clap::SubCommand::with_name("add-member")
                        .about("Add a user to a group")
                        .arg(clap::Arg::with_name("group_id").required(true).index(1).help("Group ID"))
                        .arg(clap::Arg::with_name("user_id").required(true).index(2).help("User ID")),
                )
                .subcommand(
                    clap::SubCommand::with_name("members")
                        .about("List group members")
                        .arg(clap::Arg::with_name("group_id").required(true).index(1).help("Group ID")),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("strategy")
                .about("Strategy management")
                .subcommand(
                    clap::SubCommand::with_name("list").about("List all strategies"),
                )
                .subcommand(
                    clap::SubCommand::with_name("create")
                        .about("Create a strategy")
                        .arg(clap::Arg::with_name("name").required(true).index(1).help("Strategy name"))
                        .arg(
                            clap::Arg::with_name("settings_json")
                                .required(true)
                                .index(2)
                                .help("Settings as JSON string"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("assign")
                        .about("Assign a strategy to a target")
                        .arg(clap::Arg::with_name("strategy_id").required(true).index(1).help("Strategy ID"))
                        .arg(
                            clap::Arg::with_name("target_type")
                                .required(true)
                                .index(2)
                                .help("Target type: user, device, user_group, device_group"),
                        )
                        .arg(clap::Arg::with_name("target_id").required(true).index(3).help("Target ID")),
                )
                .subcommand(
                    clap::SubCommand::with_name("effective")
                        .about("Get effective strategy for a target")
                        .arg(
                            clap::Arg::with_name("target_type")
                                .required(true)
                                .index(1)
                                .help("Target type: user, device"),
                        )
                        .arg(clap::Arg::with_name("target_id").required(true).index(2).help("Target ID")),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("audit")
                .about("Audit log management")
                .subcommand(
                    clap::SubCommand::with_name("list")
                        .about("List audit log entries")
                        .arg(
                            clap::Arg::with_name("limit")
                                .long("limit")
                                .short("n")
                                .takes_value(true)
                                .help("Maximum number of entries to show"),
                        ),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("ab")
                .about("Address book management")
                .subcommand(
                    clap::SubCommand::with_name("list").about("List address book entries"),
                )
                .subcommand(
                    clap::SubCommand::with_name("add")
                        .about("Add a peer to the address book")
                        .arg(clap::Arg::with_name("peer_id").required(true).index(1).help("Peer ID"))
                        .arg(
                            clap::Arg::with_name("alias")
                                .long("alias")
                                .takes_value(true)
                                .help("Alias name for the peer"),
                        ),
                ),
        )
        .subcommand(clap::SubCommand::with_name("status").about("Check server health and heartbeat"))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let app = build_cli();
    let matches = app.get_matches();
    let server = matches.value_of("server").unwrap();

    let result = match matches.subcommand() {
        ("login", Some(m)) => cmd_login(
            server,
            m.value_of("username").unwrap(),
            m.value_of("password").unwrap(),
        ),
        ("user", Some(m)) => match m.subcommand() {
            ("list", _) => cmd_user_list(server),
            ("create", Some(cm)) => cmd_user_create(
                server,
                cm.value_of("username").unwrap(),
                cm.value_of("email").unwrap(),
                cm.value_of("password").unwrap(),
                cm.is_present("admin"),
            ),
            ("delete", Some(cm)) => cmd_user_delete(server, cm.value_of("id").unwrap()),
            _ => {
                eprintln!("Unknown user subcommand. Use --help for usage.");
                std::process::exit(1);
            }
        },
        ("group", Some(m)) => match m.subcommand() {
            ("list", _) => cmd_group_list(server),
            ("create", Some(cm)) => cmd_group_create(server, cm.value_of("name").unwrap()),
            ("add-member", Some(cm)) => cmd_group_add_member(
                server,
                cm.value_of("group_id").unwrap(),
                cm.value_of("user_id").unwrap(),
            ),
            ("members", Some(cm)) => cmd_group_members(server, cm.value_of("group_id").unwrap()),
            _ => {
                eprintln!("Unknown group subcommand. Use --help for usage.");
                std::process::exit(1);
            }
        },
        ("strategy", Some(m)) => match m.subcommand() {
            ("list", _) => cmd_strategy_list(server),
            ("create", Some(cm)) => cmd_strategy_create(
                server,
                cm.value_of("name").unwrap(),
                cm.value_of("settings_json").unwrap(),
            ),
            ("assign", Some(cm)) => cmd_strategy_assign(
                server,
                cm.value_of("strategy_id").unwrap(),
                cm.value_of("target_type").unwrap(),
                cm.value_of("target_id").unwrap(),
            ),
            ("effective", Some(cm)) => cmd_strategy_effective(
                server,
                cm.value_of("target_type").unwrap(),
                cm.value_of("target_id").unwrap(),
            ),
            _ => {
                eprintln!("Unknown strategy subcommand. Use --help for usage.");
                std::process::exit(1);
            }
        },
        ("audit", Some(m)) => match m.subcommand() {
            ("list", Some(cm)) => {
                let limit = cm.value_of("limit").map(|v| {
                    v.parse::<usize>().unwrap_or_else(|_| {
                        eprintln!("Invalid limit value: {}", v);
                        std::process::exit(1);
                    })
                });
                cmd_audit_list(server, limit)
            }
            ("list", None) => cmd_audit_list(server, None),
            _ => {
                eprintln!("Unknown audit subcommand. Use --help for usage.");
                std::process::exit(1);
            }
        },
        ("ab", Some(m)) => match m.subcommand() {
            ("list", _) => cmd_ab_list(server),
            ("add", Some(cm)) => {
                cmd_ab_add(server, cm.value_of("peer_id").unwrap(), cm.value_of("alias"))
            }
            _ => {
                eprintln!("Unknown ab subcommand. Use --help for usage.");
                std::process::exit(1);
            }
        },
        ("status", _) => cmd_status(server),
        _ => {
            eprintln!("No command specified. Use --help for usage.");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_login() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "login",
            "admin",
            "admin123",
        ]);
        assert_eq!(m.value_of("server").unwrap(), "http://localhost:21114");
        let (cmd, sub) = m.subcommand();
        assert_eq!(cmd, "login");
        let sub = sub.unwrap();
        assert_eq!(sub.value_of("username").unwrap(), "admin");
        assert_eq!(sub.value_of("password").unwrap(), "admin123");
    }

    #[test]
    fn test_cli_parses_custom_server() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "--server",
            "http://myhost:9000",
            "status",
        ]);
        assert_eq!(m.value_of("server").unwrap(), "http://myhost:9000");
        assert_eq!(m.subcommand_name(), Some("status"));
    }

    #[test]
    fn test_cli_parses_user_list() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "user", "list"]);
        let (cmd, sub) = m.subcommand();
        assert_eq!(cmd, "user");
        let sub = sub.unwrap();
        assert_eq!(sub.subcommand_name(), Some("list"));
    }

    #[test]
    fn test_cli_parses_user_create_with_admin() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "user",
            "create",
            "alice",
            "alice@example.com",
            "secret",
            "--admin",
        ]);
        let user_matches = m.subcommand_matches("user").unwrap();
        let create_matches = user_matches.subcommand_matches("create").unwrap();
        assert_eq!(create_matches.value_of("username").unwrap(), "alice");
        assert_eq!(create_matches.value_of("email").unwrap(), "alice@example.com");
        assert_eq!(create_matches.value_of("password").unwrap(), "secret");
        assert!(create_matches.is_present("admin"));
    }

    #[test]
    fn test_cli_parses_user_create_without_admin() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "user",
            "create",
            "bob",
            "bob@example.com",
            "pass123",
        ]);
        let user_matches = m.subcommand_matches("user").unwrap();
        let create_matches = user_matches.subcommand_matches("create").unwrap();
        assert_eq!(create_matches.value_of("username").unwrap(), "bob");
        assert!(!create_matches.is_present("admin"));
    }

    #[test]
    fn test_cli_parses_user_delete() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "user",
            "delete",
            "some-uuid-here",
        ]);
        let user_matches = m.subcommand_matches("user").unwrap();
        let delete_matches = user_matches.subcommand_matches("delete").unwrap();
        assert_eq!(delete_matches.value_of("id").unwrap(), "some-uuid-here");
    }

    #[test]
    fn test_cli_parses_group_create() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "group",
            "create",
            "Engineering",
        ]);
        let group_matches = m.subcommand_matches("group").unwrap();
        let create_matches = group_matches.subcommand_matches("create").unwrap();
        assert_eq!(create_matches.value_of("name").unwrap(), "Engineering");
    }

    #[test]
    fn test_cli_parses_group_add_member() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "group",
            "add-member",
            "group-123",
            "user-456",
        ]);
        let group_matches = m.subcommand_matches("group").unwrap();
        let add_matches = group_matches.subcommand_matches("add-member").unwrap();
        assert_eq!(add_matches.value_of("group_id").unwrap(), "group-123");
        assert_eq!(add_matches.value_of("user_id").unwrap(), "user-456");
    }

    #[test]
    fn test_cli_parses_group_members() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "group",
            "members",
            "group-789",
        ]);
        let group_matches = m.subcommand_matches("group").unwrap();
        let members_matches = group_matches.subcommand_matches("members").unwrap();
        assert_eq!(members_matches.value_of("group_id").unwrap(), "group-789");
    }

    #[test]
    fn test_cli_parses_strategy_create() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "strategy",
            "create",
            "Strict Policy",
            r#"{"clipboard":false}"#,
        ]);
        let strat_matches = m.subcommand_matches("strategy").unwrap();
        let create_matches = strat_matches.subcommand_matches("create").unwrap();
        assert_eq!(create_matches.value_of("name").unwrap(), "Strict Policy");
        assert_eq!(
            create_matches.value_of("settings_json").unwrap(),
            r#"{"clipboard":false}"#
        );
    }

    #[test]
    fn test_cli_parses_strategy_assign() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "strategy",
            "assign",
            "strat-id",
            "user",
            "user-id",
        ]);
        let strat_matches = m.subcommand_matches("strategy").unwrap();
        let assign_matches = strat_matches.subcommand_matches("assign").unwrap();
        assert_eq!(assign_matches.value_of("strategy_id").unwrap(), "strat-id");
        assert_eq!(assign_matches.value_of("target_type").unwrap(), "user");
        assert_eq!(assign_matches.value_of("target_id").unwrap(), "user-id");
    }

    #[test]
    fn test_cli_parses_strategy_effective() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "strategy",
            "effective",
            "device",
            "dev-123",
        ]);
        let strat_matches = m.subcommand_matches("strategy").unwrap();
        let eff_matches = strat_matches.subcommand_matches("effective").unwrap();
        assert_eq!(eff_matches.value_of("target_type").unwrap(), "device");
        assert_eq!(eff_matches.value_of("target_id").unwrap(), "dev-123");
    }

    #[test]
    fn test_cli_parses_audit_list_with_limit() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "audit",
            "list",
            "--limit",
            "50",
        ]);
        let audit_matches = m.subcommand_matches("audit").unwrap();
        let list_matches = audit_matches.subcommand_matches("list").unwrap();
        assert_eq!(list_matches.value_of("limit").unwrap(), "50");
    }

    #[test]
    fn test_cli_parses_audit_list_without_limit() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "audit", "list"]);
        let audit_matches = m.subcommand_matches("audit").unwrap();
        let list_matches = audit_matches.subcommand_matches("list").unwrap();
        assert!(list_matches.value_of("limit").is_none());
    }

    #[test]
    fn test_cli_parses_ab_list() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "ab", "list"]);
        let ab_matches = m.subcommand_matches("ab").unwrap();
        assert_eq!(ab_matches.subcommand_name(), Some("list"));
    }

    #[test]
    fn test_cli_parses_ab_add_with_alias() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "ab",
            "add",
            "peer-abc",
            "--alias",
            "My Laptop",
        ]);
        let ab_matches = m.subcommand_matches("ab").unwrap();
        let add_matches = ab_matches.subcommand_matches("add").unwrap();
        assert_eq!(add_matches.value_of("peer_id").unwrap(), "peer-abc");
        assert_eq!(add_matches.value_of("alias").unwrap(), "My Laptop");
    }

    #[test]
    fn test_cli_parses_ab_add_without_alias() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "ab", "add", "peer-xyz"]);
        let ab_matches = m.subcommand_matches("ab").unwrap();
        let add_matches = ab_matches.subcommand_matches("add").unwrap();
        assert_eq!(add_matches.value_of("peer_id").unwrap(), "peer-xyz");
        assert!(add_matches.value_of("alias").is_none());
    }

    #[test]
    fn test_cli_parses_status() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "status"]);
        assert_eq!(m.subcommand_name(), Some("status"));
    }

    #[test]
    fn test_cli_default_server() {
        let app = build_cli();
        let m = app.get_matches_from(vec!["rustdesk-api-cli", "status"]);
        assert_eq!(m.value_of("server").unwrap(), "http://localhost:21114");
    }

    #[test]
    fn test_cli_short_server_flag() {
        let app = build_cli();
        let m = app.get_matches_from(vec![
            "rustdesk-api-cli",
            "-s",
            "http://10.0.0.1:21114",
            "status",
        ]);
        assert_eq!(m.value_of("server").unwrap(), "http://10.0.0.1:21114");
    }

    // -----------------------------------------------------------------------
    // Unit tests for helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_str_extracts_string() {
        let val = serde_json::json!({"name": "alice", "count": 42});
        assert_eq!(json_str(&val, "name"), "alice");
        assert_eq!(json_str(&val, "count"), "42");
        assert_eq!(json_str(&val, "missing"), "");
    }

    #[test]
    fn test_print_table_no_panic_on_empty() {
        // Should just print "(no results)" without panicking
        print_table(&["A", "B"], &[]);
    }

    #[test]
    fn test_print_table_no_panic_on_data() {
        let rows = vec![
            vec!["1".to_string(), "alice".to_string()],
            vec!["2".to_string(), "bob".to_string()],
        ];
        print_table(&["ID", "NAME"], &rows);
    }

    #[test]
    fn test_token_path_is_in_home() {
        let path = token_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with(".rustdesk-api-token"),
            "token path should end with .rustdesk-api-token, got: {}",
            path_str
        );
    }
}
