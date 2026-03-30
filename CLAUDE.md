# CLAUDE.md — RustDesk Server

## Quick Start

```bash
nix develop                                    # Enter dev shell (all deps)
git submodule update --init --recursive        # Init hbb_common
cargo build                                    # Debug build
cargo build --release                          # Release build
cargo test                                     # Run tests (292 tests)
cargo run --bin hbbs                           # Run rendezvous server
cargo run --bin hbbr                           # Run relay server
cargo run --bin rustdesk-utils                 # CLI utilities
```

Without nix: `apt install build-essential pkg-config libsodium-dev libssl-dev libzstd-dev sqlite3`

## Architecture

Two binaries + one utility:

```
src/
├── main.rs                   # hbbs entry point
├── hbbr.rs                   # hbbr entry point
├── rendezvous_server.rs      # ID/rendezvous server (1,371 lines)
│                               Peer registration, NAT hole-punch, relay assignment
├── relay_server.rs           # Relay server (647 lines)
│                               Bidirectional byte forwarding, bandwidth mgmt
├── database.rs               # SQLite peer storage (181 lines)
├── peer.rs                   # In-memory peer map + DB backing (180 lines)
├── common.rs                 # Config, key gen, server validation (217 lines)
├── utils.rs                  # genkeypair, validatekeypair, doctor (170 lines)
└── lib.rs                    # Library root
```

### Port Map

| Port | Protocol | Binary | Purpose |
|---|---|---|---|
| 21115 | TCP | hbbs | NAT type detection |
| 21116 | TCP/UDP | hbbs | Peer registration, hole-punch |
| 21117 | TCP | hbbr | Relay connections |
| 21118 | TCP/WS | hbbs | WebSocket rendezvous |
| 21119 | TCP/WS | hbbr | WebSocket relay |
| 21114 | HTTP | hbbs | **Pro API server** (implemented — user mgmt, address book, audit) |

### Key Subsystems

**Rendezvous (`rendezvous_server.rs`):**
- `RegisterPeer` (UDP) — registers peer address, no auth
- `RegisterPk` (TCP) — registers public key with IP blocker rate limiting (30/min)
- `PunchHoleRequest` — coordinates NAT traversal between peers
- `RequestRelay` — assigns relay server when direct fails
- `OnlineRequest` — peer online status check (unauthenticated)
- Admin commands via loopback TCP on port-1

**Relay (`relay_server.rs`):**
- Pairs two streams by UUID, copies bytes bidirectionally
- Bandwidth limiting: 32Mbps per-connection, 128Mbps single, 1Gbps total
- Blacklist/blocklist for IP filtering
- Quality downgrade at 66% bandwidth threshold after 30min
- Admin commands via loopback TCP on port+1

**Database:** SQLite `db_v2.sqlite3`, single `peer` table:
- guid, id, uuid, pk, created_at, user (unused), status (unused), note (unused), info (JSON)

**Auth:** Ed25519 keypair (`id_ed25519`). Optional `-k` pre-shared key for relay (warns if not set).

**Pro API (`src/api/`):**
- `mod.rs` — axum router, CORS, route wiring
- `auth.rs` — JWT token generation/validation, auth middleware
- `heartbeat.rs` — returns `is_pro: true` (unlocks client Pro UI)
- `users.rs` — user CRUD with bcrypt passwords, admin roles
- `address_book.rs` — per-user address book with entries and tags
- `audit.rs` — connection + file transfer audit log receiver

## Build Profiles

```toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## Testing

**292 tests**, all passing. Run with:
```bash
nix develop --command bash -c 'unset SQLX_OFFLINE && export DATABASE_URL="sqlite:db_v2.sqlite3" && cargo test --lib'
```

Coverage: rendezvous_server (67), relay_server (67), common (47), peer (22), database (7), utils (14), API (60).

## Security Fixes Applied

- Crypto keys no longer logged (was INFO level)
- Key files created with 0o600 permissions
- Relay warns when running without `-k` auth key
- X-Forwarded-For only trusted from configured proxy IPs (`--trusted-proxy-ips`)
- Protobuf message size limited to 64KB
- See `docs/security-review.md` for full findings

## Admin Commands

**hbbs** (connect to port-1 via TCP loopback):
```
relay-servers(rs) <separated by ,>
reload-geo(rg)
ip-blocker(ib) [<ip>|<number>] [-]
ip-changes(ic) [<id>|<number>] [-]
punch-requests(pr) [<number>] [-]
always-use-relay(aur)
test-geo(tg) <ip1> <ip2>
```

**hbbr** (connect to port+1 via TCP loopback):
```
blacklist-add(ba) <ip>          blacklist-remove(br) <ip>
blocklist-add(Ba) <ip>          blocklist-remove(Br) <ip>
downgrade-threshold(dt) [val]   limit-speed(ls) [Mb/s]
total-bandwidth(tb) [Mb/s]      single-bandwidth(sb) [Mb/s]
usage(u)
```

## Ignore Patterns

- `target/` — Rust build artifacts
- `db_v2.sqlite3` — runtime database
- `id_ed25519*` — keypair files
- `libs/hbb_common/` — git submodule
