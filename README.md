# SteelDesk Server

Server infrastructure for [SteelDesk](https://github.com/ThePoliceRecord/steeldesk) remote desktop. Includes rendezvous server, relay server, Pro API with web console, and CLI management tool.

## What's Included

- **Rendezvous Server** (`steeldesk-server`) — peer discovery, NAT hole-punching, relay assignment
- **Relay Server** (`hbbr`) — traffic relay when direct P2P fails
- **Pro API** (port 21114) — 46 endpoints for enterprise management
- **Web Console** — React SPA at `/console/index.html`
- **CLI Tool** (`steeldesk-api-cli`) — 16 management commands

## Pro API (46 Endpoints)

| Feature | What |
|---|---|
| Authentication | JWT login, token validation |
| Heartbeat | `is_pro: true` — unlocks all client Pro UI |
| User Management | CRUD with bcrypt passwords |
| RBAC | Admin/Operator/Viewer roles, custom roles |
| Groups | User groups + device groups with membership |
| Strategies | Policy engine with assignment and group inheritance |
| Control Roles | 8 session-level permissions |
| Address Book | Per-user with tags |
| Audit Logs | Connection and file transfer audit |

## Security Fixes

- Crypto keys no longer logged at INFO level
- Relay warns without `-k` auth key
- Key files created with 0o600 permissions
- X-Forwarded-For only from configured trusted proxies
- Protobuf messages limited to 64KB

## Quick Start

```bash
nix develop
git submodule update --init --recursive
cargo build

# Run
cargo run --bin steeldesk-server -- -k mykey
cargo run --bin hbbr -- -k mykey

# Web console: http://localhost:21114/console/index.html
# Default login: admin / admin123

# CLI
cargo run --bin steeldesk-api-cli -- login admin admin123
cargo run --bin steeldesk-api-cli -- user list
```

## Port Map

| Port | Binary | Purpose |
|---|---|---|
| 21114 | steeldesk-server | **Pro API + Web Console** |
| 21115 | steeldesk-server | NAT type detection |
| 21116 | steeldesk-server | Peer registration |
| 21117 | hbbr | Relay |
| 21118 | steeldesk-server | WebSocket rendezvous |
| 21119 | hbbr | WebSocket relay |

## Testing

**332 tests**, all passing.

```bash
nix develop --command bash -c 'unset SQLX_OFFLINE && export DATABASE_URL="sqlite:db_v2.sqlite3" && cargo test --lib'
```

## License

AGPL-3.0 — same as upstream RustDesk.
