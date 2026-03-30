use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

/// Row type for the `users` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_admin: i32,
}

/// Row type for the `address_books` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AbRow {
    pub id: String,
    pub user_id: String,
    pub peer_id: String,
    pub alias: String,
    pub tags: String,
    pub hash: String,
}

/// Row type for the `audit_logs` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub from_peer: String,
    pub to_peer: String,
    pub conn_type: String,
    pub timestamp: String,
    pub note: String,
}

/// Row type for the `user_groups` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserGroupRow {
    pub id: String,
    pub name: String,
    pub parent_id: String,
    pub created_at: String,
}

/// Row type for the `device_groups` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceGroupRow {
    pub id: String,
    pub name: String,
    pub parent_id: String,
    pub created_at: String,
}

/// Row type for the `user_group_members` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserGroupMemberRow {
    pub user_id: String,
    pub group_id: String,
}

/// Row type for the `device_group_members` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceGroupMemberRow {
    pub device_id: String,
    pub group_id: String,
}

/// Row type for the `strategies` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StrategyRow {
    pub id: String,
    pub name: String,
    pub settings: String,
    pub created_at: String,
}

/// Row type for the `roles` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub permissions: String,
    pub created_at: String,
}

/// Row type for the `control_roles` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ControlRoleRow {
    pub id: String,
    pub name: String,
    pub keyboard_mouse: String,
    pub clipboard: String,
    pub file_transfer: String,
    pub audio: String,
    pub terminal: String,
    pub tunnel: String,
    pub recording: String,
    pub block_input: String,
    pub created_at: String,
}

/// Row type for user-role assignments.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRoleRow {
    pub user_id: String,
    pub role_id: String,
}

/// Row type for user-control_role assignments.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserControlRoleRow {
    pub user_id: String,
    pub control_role_id: String,
}

/// Row type for the `strategy_assignments` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StrategyAssignmentRow {
    pub strategy_id: String,
    pub target_type: String,
    pub target_id: String,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = std::env::var("MAX_DATABASE_CONNECTIONS")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // Pro API tables (runtime queries — no SQLX_OFFLINE needed)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS address_books (
                id TEXT PRIMARY KEY NOT NULL,
                user_id TEXT NOT NULL,
                peer_id TEXT NOT NULL DEFAULT '',
                alias TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '[]',
                hash TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ab_user ON address_books(user_id)"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_peer TEXT NOT NULL DEFAULT '',
                to_peer TEXT NOT NULL DEFAULT '',
                conn_type TEXT NOT NULL DEFAULT '',
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                note TEXT NOT NULL DEFAULT ''
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // Group management tables
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_groups (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                parent_id TEXT NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_groups (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                parent_id TEXT NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_group_members (
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                PRIMARY KEY (user_id, group_id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_group_members (
                device_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                PRIMARY KEY (device_id, group_id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // Strategy/policy tables
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS strategies (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                settings TEXT NOT NULL DEFAULT '{}',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS strategy_assignments (
                strategy_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                PRIMARY KEY (strategy_id, target_type, target_id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // RBAC roles table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL UNIQUE,
                scope TEXT NOT NULL DEFAULT 'individual',
                permissions TEXT NOT NULL DEFAULT '{}',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // User-role assignment table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // Control roles table (session-level permissions)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS control_roles (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                keyboard_mouse TEXT NOT NULL DEFAULT 'enable',
                clipboard TEXT NOT NULL DEFAULT 'enable',
                file_transfer TEXT NOT NULL DEFAULT 'enable',
                audio TEXT NOT NULL DEFAULT 'enable',
                terminal TEXT NOT NULL DEFAULT 'enable',
                tunnel TEXT NOT NULL DEFAULT 'enable',
                recording TEXT NOT NULL DEFAULT 'disable',
                block_input TEXT NOT NULL DEFAULT 'enable',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // User-control_role assignment table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_control_roles (
                user_id TEXT NOT NULL,
                control_role_id TEXT NOT NULL,
                PRIMARY KEY (user_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (control_role_id) REFERENCES control_roles(id)
            )"
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // User queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_user(
        &self,
        id: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        is_admin: bool,
    ) -> ResultType<()> {
        let admin_int: i32 = if is_admin { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(id)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(admin_int)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_user_by_id(&self, id: &str) -> ResultType<Option<UserRow>> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, password_hash, is_admin FROM users WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn get_user_by_username(&self, username: &str) -> ResultType<Option<UserRow>> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, password_hash, is_admin FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn list_users(&self) -> ResultType<Vec<UserRow>> {
        let rows = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, password_hash, is_admin FROM users ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn update_user(
        &self,
        id: &str,
        username: Option<&str>,
        email: Option<&str>,
        password_hash: Option<&str>,
        is_admin: Option<bool>,
    ) -> ResultType<bool> {
        // Build dynamic UPDATE
        let mut sets = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(u) = username {
            sets.push("username = ?");
            values.push(u.to_string());
        }
        if let Some(e) = email {
            sets.push("email = ?");
            values.push(e.to_string());
        }
        if let Some(p) = password_hash {
            sets.push("password_hash = ?");
            values.push(p.to_string());
        }
        if let Some(a) = is_admin {
            sets.push("is_admin = ?");
            values.push(if a { "1".to_string() } else { "0".to_string() });
        }

        if sets.is_empty() {
            return Ok(true); // nothing to update
        }

        let sql = format!("UPDATE users SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for v in &values {
            q = q.bind(v);
        }
        q = q.bind(id);
        let result = q.execute(self.pool.get().await?.deref_mut()).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_user(&self, id: &str) -> ResultType<bool> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Address book queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn get_address_book_entries(&self, user_id: &str) -> ResultType<Vec<AbRow>> {
        let rows = sqlx::query_as::<_, AbRow>(
            "SELECT id, user_id, peer_id, alias, tags, hash FROM address_books WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn replace_address_book(&self, user_id: &str, entries: &[AbRow]) -> ResultType<()> {
        // Delete all existing entries for this user, then insert new ones
        sqlx::query("DELETE FROM address_books WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;

        for entry in entries {
            sqlx::query(
                "INSERT INTO address_books (id, user_id, peer_id, alias, tags, hash) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(&entry.id)
            .bind(user_id)
            .bind(&entry.peer_id)
            .bind(&entry.alias)
            .bind(&entry.tags)
            .bind(&entry.hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        }

        Ok(())
    }

    pub async fn delete_address_book_entry(&self, user_id: &str, entry_id: &str) -> ResultType<bool> {
        let result = sqlx::query("DELETE FROM address_books WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(entry_id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Audit log queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_audit_log(
        &self,
        from_peer: &str,
        to_peer: &str,
        conn_type: &str,
        note: &str,
    ) -> ResultType<AuditRow> {
        sqlx::query(
            "INSERT INTO audit_logs (from_peer, to_peer, conn_type, note) VALUES (?, ?, ?, ?)"
        )
        .bind(from_peer)
        .bind(to_peer)
        .bind(conn_type)
        .bind(note)
        .execute(self.pool.get().await?.deref_mut())
        .await?;

        // Fetch the last inserted row
        let row = sqlx::query_as::<_, AuditRow>(
            "SELECT id, from_peer, to_peer, conn_type, timestamp, note FROM audit_logs WHERE rowid = last_insert_rowid()"
        )
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn list_audit_logs(&self) -> ResultType<Vec<AuditRow>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT id, from_peer, to_peer, conn_type, timestamp, note FROM audit_logs ORDER BY id ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // User group queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_user_group(&self, id: &str, name: &str, parent_id: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT INTO user_groups (id, name, parent_id) VALUES (?, ?, ?)"
        )
        .bind(id)
        .bind(name)
        .bind(parent_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn list_user_groups(&self) -> ResultType<Vec<UserGroupRow>> {
        let rows = sqlx::query_as::<_, UserGroupRow>(
            "SELECT id, name, parent_id, created_at FROM user_groups ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn get_user_group_by_id(&self, id: &str) -> ResultType<Option<UserGroupRow>> {
        let row = sqlx::query_as::<_, UserGroupRow>(
            "SELECT id, name, parent_id, created_at FROM user_groups WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn delete_user_group(&self, id: &str) -> ResultType<bool> {
        // Also clean up memberships
        sqlx::query("DELETE FROM user_group_members WHERE group_id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        let result = sqlx::query("DELETE FROM user_groups WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn add_user_to_group(&self, user_id: &str, group_id: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO user_group_members (user_id, group_id) VALUES (?, ?)"
        )
        .bind(user_id)
        .bind(group_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn remove_user_from_group(&self, user_id: &str, group_id: &str) -> ResultType<bool> {
        let result = sqlx::query(
            "DELETE FROM user_group_members WHERE user_id = ? AND group_id = ?"
        )
        .bind(user_id)
        .bind(group_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_user_group_members(&self, group_id: &str) -> ResultType<Vec<UserGroupMemberRow>> {
        let rows = sqlx::query_as::<_, UserGroupMemberRow>(
            "SELECT user_id, group_id FROM user_group_members WHERE group_id = ?"
        )
        .bind(group_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Device group queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_device_group(&self, id: &str, name: &str, parent_id: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT INTO device_groups (id, name, parent_id) VALUES (?, ?, ?)"
        )
        .bind(id)
        .bind(name)
        .bind(parent_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn list_device_groups(&self) -> ResultType<Vec<DeviceGroupRow>> {
        let rows = sqlx::query_as::<_, DeviceGroupRow>(
            "SELECT id, name, parent_id, created_at FROM device_groups ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn get_device_group_by_id(&self, id: &str) -> ResultType<Option<DeviceGroupRow>> {
        let row = sqlx::query_as::<_, DeviceGroupRow>(
            "SELECT id, name, parent_id, created_at FROM device_groups WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn delete_device_group(&self, id: &str) -> ResultType<bool> {
        // Also clean up memberships
        sqlx::query("DELETE FROM device_group_members WHERE group_id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        let result = sqlx::query("DELETE FROM device_groups WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn add_device_to_group(&self, device_id: &str, group_id: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO device_group_members (device_id, group_id) VALUES (?, ?)"
        )
        .bind(device_id)
        .bind(group_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn remove_device_from_group(&self, device_id: &str, group_id: &str) -> ResultType<bool> {
        let result = sqlx::query(
            "DELETE FROM device_group_members WHERE device_id = ? AND group_id = ?"
        )
        .bind(device_id)
        .bind(group_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_device_group_members(&self, group_id: &str) -> ResultType<Vec<DeviceGroupMemberRow>> {
        let rows = sqlx::query_as::<_, DeviceGroupMemberRow>(
            "SELECT device_id, group_id FROM device_group_members WHERE group_id = ?"
        )
        .bind(group_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Strategy queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_strategy(&self, id: &str, name: &str, settings: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT INTO strategies (id, name, settings) VALUES (?, ?, ?)"
        )
        .bind(id)
        .bind(name)
        .bind(settings)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_strategy_by_id(&self, id: &str) -> ResultType<Option<StrategyRow>> {
        let row = sqlx::query_as::<_, StrategyRow>(
            "SELECT id, name, settings, created_at FROM strategies WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn list_strategies(&self) -> ResultType<Vec<StrategyRow>> {
        let rows = sqlx::query_as::<_, StrategyRow>(
            "SELECT id, name, settings, created_at FROM strategies ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn update_strategy(
        &self,
        id: &str,
        name: Option<&str>,
        settings: Option<&str>,
    ) -> ResultType<bool> {
        let mut sets = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(n) = name {
            sets.push("name = ?");
            values.push(n.to_string());
        }
        if let Some(s) = settings {
            sets.push("settings = ?");
            values.push(s.to_string());
        }

        if sets.is_empty() {
            return Ok(true);
        }

        let sql = format!("UPDATE strategies SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for v in &values {
            q = q.bind(v);
        }
        q = q.bind(id);
        let result = q.execute(self.pool.get().await?.deref_mut()).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_strategy(&self, id: &str) -> ResultType<bool> {
        // Also clean up assignments
        sqlx::query("DELETE FROM strategy_assignments WHERE strategy_id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        let result = sqlx::query("DELETE FROM strategies WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn assign_strategy(
        &self,
        strategy_id: &str,
        target_type: &str,
        target_id: &str,
    ) -> ResultType<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO strategy_assignments (strategy_id, target_type, target_id) VALUES (?, ?, ?)"
        )
        .bind(strategy_id)
        .bind(target_type)
        .bind(target_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn list_strategy_assignments(
        &self,
        strategy_id: &str,
    ) -> ResultType<Vec<StrategyAssignmentRow>> {
        let rows = sqlx::query_as::<_, StrategyAssignmentRow>(
            "SELECT strategy_id, target_type, target_id FROM strategy_assignments WHERE strategy_id = ?"
        )
        .bind(strategy_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    /// Get the effective strategy for a target by looking up direct assignments,
    /// then group assignments. Returns the first matching strategy found.
    pub async fn get_effective_strategy(
        &self,
        target_type: &str,
        target_id: &str,
    ) -> ResultType<Option<StrategyRow>> {
        // 1. Check direct assignment
        let direct = sqlx::query_as::<_, StrategyAssignmentRow>(
            "SELECT strategy_id, target_type, target_id FROM strategy_assignments WHERE target_type = ? AND target_id = ? LIMIT 1"
        )
        .bind(target_type)
        .bind(target_id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;

        if let Some(assignment) = direct {
            return self.get_strategy_by_id(&assignment.strategy_id).await;
        }

        // 2. Check group assignments: find groups the target belongs to
        let group_type = match target_type {
            "user" => Some("user_group"),
            "device" => Some("device_group"),
            _ => None,
        };

        if let Some(gt) = group_type {
            let group_ids: Vec<String> = match target_type {
                "user" => {
                    let members = sqlx::query_as::<_, UserGroupMemberRow>(
                        "SELECT user_id, group_id FROM user_group_members WHERE user_id = ?"
                    )
                    .bind(target_id)
                    .fetch_all(self.pool.get().await?.deref_mut())
                    .await?;
                    members.into_iter().map(|m| m.group_id).collect()
                }
                "device" => {
                    let members = sqlx::query_as::<_, DeviceGroupMemberRow>(
                        "SELECT device_id, group_id FROM device_group_members WHERE device_id = ?"
                    )
                    .bind(target_id)
                    .fetch_all(self.pool.get().await?.deref_mut())
                    .await?;
                    members.into_iter().map(|m| m.group_id).collect()
                }
                _ => vec![],
            };

            for gid in group_ids {
                let group_assignment = sqlx::query_as::<_, StrategyAssignmentRow>(
                    "SELECT strategy_id, target_type, target_id FROM strategy_assignments WHERE target_type = ? AND target_id = ? LIMIT 1"
                )
                .bind(gt)
                .bind(&gid)
                .fetch_optional(self.pool.get().await?.deref_mut())
                .await?;

                if let Some(assignment) = group_assignment {
                    return self.get_strategy_by_id(&assignment.strategy_id).await;
                }
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Role queries (RBAC)
    // -----------------------------------------------------------------------

    pub async fn insert_role(
        &self,
        id: &str,
        name: &str,
        scope: &str,
        permissions: &str,
    ) -> ResultType<()> {
        sqlx::query(
            "INSERT INTO roles (id, name, scope, permissions) VALUES (?, ?, ?, ?)"
        )
        .bind(id)
        .bind(name)
        .bind(scope)
        .bind(permissions)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_role_by_id(&self, id: &str) -> ResultType<Option<RoleRow>> {
        let row = sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, scope, permissions, created_at FROM roles WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn get_role_by_name(&self, name: &str) -> ResultType<Option<RoleRow>> {
        let row = sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, scope, permissions, created_at FROM roles WHERE name = ?"
        )
        .bind(name)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn list_roles(&self) -> ResultType<Vec<RoleRow>> {
        let rows = sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, scope, permissions, created_at FROM roles ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn update_role(
        &self,
        id: &str,
        name: Option<&str>,
        scope: Option<&str>,
        permissions: Option<&str>,
    ) -> ResultType<bool> {
        let mut sets = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(n) = name {
            sets.push("name = ?");
            values.push(n.to_string());
        }
        if let Some(s) = scope {
            sets.push("scope = ?");
            values.push(s.to_string());
        }
        if let Some(p) = permissions {
            sets.push("permissions = ?");
            values.push(p.to_string());
        }

        if sets.is_empty() {
            return Ok(true);
        }

        let sql = format!("UPDATE roles SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for v in &values {
            q = q.bind(v);
        }
        q = q.bind(id);
        let result = q.execute(self.pool.get().await?.deref_mut()).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_role(&self, id: &str) -> ResultType<bool> {
        // Clean up user-role assignments
        sqlx::query("DELETE FROM user_roles WHERE role_id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        let result = sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn assign_role_to_user(&self, user_id: &str, role_id: &str) -> ResultType<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO user_roles (user_id, role_id) VALUES (?, ?)"
        )
        .bind(user_id)
        .bind(role_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn remove_role_from_user(&self, user_id: &str, role_id: &str) -> ResultType<bool> {
        let result = sqlx::query(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?"
        )
        .bind(user_id)
        .bind(role_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_user_roles(&self, user_id: &str) -> ResultType<Vec<RoleRow>> {
        let rows = sqlx::query_as::<_, RoleRow>(
            "SELECT r.id, r.name, r.scope, r.permissions, r.created_at
             FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?
             ORDER BY r.created_at ASC"
        )
        .bind(user_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Control role queries (Pro API)
    // -----------------------------------------------------------------------

    pub async fn insert_control_role(
        &self,
        id: &str,
        name: &str,
        keyboard_mouse: &str,
        clipboard: &str,
        file_transfer: &str,
        audio: &str,
        terminal: &str,
        tunnel: &str,
        recording: &str,
        block_input: &str,
    ) -> ResultType<()> {
        sqlx::query(
            "INSERT INTO control_roles (id, name, keyboard_mouse, clipboard, file_transfer, audio, terminal, tunnel, recording, block_input) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(id)
        .bind(name)
        .bind(keyboard_mouse)
        .bind(clipboard)
        .bind(file_transfer)
        .bind(audio)
        .bind(terminal)
        .bind(tunnel)
        .bind(recording)
        .bind(block_input)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_control_role_by_id(&self, id: &str) -> ResultType<Option<ControlRoleRow>> {
        let row = sqlx::query_as::<_, ControlRoleRow>(
            "SELECT id, name, keyboard_mouse, clipboard, file_transfer, audio, terminal, tunnel, recording, block_input, created_at FROM control_roles WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn list_control_roles(&self) -> ResultType<Vec<ControlRoleRow>> {
        let rows = sqlx::query_as::<_, ControlRoleRow>(
            "SELECT id, name, keyboard_mouse, clipboard, file_transfer, audio, terminal, tunnel, recording, block_input, created_at FROM control_roles ORDER BY created_at ASC"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows)
    }

    pub async fn update_control_role(
        &self,
        id: &str,
        name: Option<&str>,
        keyboard_mouse: Option<&str>,
        clipboard: Option<&str>,
        file_transfer: Option<&str>,
        audio: Option<&str>,
        terminal: Option<&str>,
        tunnel: Option<&str>,
        recording: Option<&str>,
        block_input: Option<&str>,
    ) -> ResultType<bool> {
        let mut sets = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(v) = name {
            sets.push("name = ?");
            values.push(v.to_string());
        }
        if let Some(v) = keyboard_mouse {
            sets.push("keyboard_mouse = ?");
            values.push(v.to_string());
        }
        if let Some(v) = clipboard {
            sets.push("clipboard = ?");
            values.push(v.to_string());
        }
        if let Some(v) = file_transfer {
            sets.push("file_transfer = ?");
            values.push(v.to_string());
        }
        if let Some(v) = audio {
            sets.push("audio = ?");
            values.push(v.to_string());
        }
        if let Some(v) = terminal {
            sets.push("terminal = ?");
            values.push(v.to_string());
        }
        if let Some(v) = tunnel {
            sets.push("tunnel = ?");
            values.push(v.to_string());
        }
        if let Some(v) = recording {
            sets.push("recording = ?");
            values.push(v.to_string());
        }
        if let Some(v) = block_input {
            sets.push("block_input = ?");
            values.push(v.to_string());
        }

        if sets.is_empty() {
            return Ok(true);
        }

        let sql = format!("UPDATE control_roles SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for v in &values {
            q = q.bind(v);
        }
        q = q.bind(id);
        let result = q.execute(self.pool.get().await?.deref_mut()).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_control_role(&self, id: &str) -> ResultType<bool> {
        // Clean up user-control_role assignments
        sqlx::query("DELETE FROM user_control_roles WHERE control_role_id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        let result = sqlx::query("DELETE FROM control_roles WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn assign_control_role_to_user(
        &self,
        user_id: &str,
        control_role_id: &str,
    ) -> ResultType<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO user_control_roles (user_id, control_role_id) VALUES (?, ?)"
        )
        .bind(user_id)
        .bind(control_role_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_user_control_role(
        &self,
        user_id: &str,
    ) -> ResultType<Option<ControlRoleRow>> {
        let row = sqlx::query_as::<_, ControlRoleRow>(
            "SELECT cr.id, cr.name, cr.keyboard_mouse, cr.clipboard, cr.file_transfer, cr.audio, cr.terminal, cr.tunnel, cr.recording, cr.block_input, cr.created_at
             FROM control_roles cr
             INNER JOIN user_control_roles ucr ON cr.id = ucr.control_role_id
             WHERE ucr.user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row)
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;

    /// Helper: create a unique temp database path and return it.
    fn temp_db_path() -> String {
        format!("test_{}.sqlite3", uuid::Uuid::new_v4())
    }

    /// Helper: remove a temp database file (best-effort).
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    // ---------------------------------------------------------------
    // Existing stress test
    // ---------------------------------------------------------------

    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
        cleanup(&db_path);
    }

    // ---------------------------------------------------------------
    // New unit tests
    // ---------------------------------------------------------------

    #[test]
    fn test_create_and_get_peer() {
        create_and_get_peer();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn create_and_get_peer() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let id = "peer_abc";
        let uuid = b"some-uuid-bytes!";
        let pk = b"public-key-bytes";
        let info = r#"{"os":"linux"}"#;

        let guid = db.insert_peer(id, uuid, pk, info).await.unwrap();
        assert!(!guid.is_empty(), "guid should be non-empty");

        let peer = db
            .get_peer(id)
            .await
            .unwrap()
            .expect("peer should exist after insert");

        assert_eq!(peer.guid, guid);
        assert_eq!(peer.id, id);
        assert_eq!(peer.uuid, uuid.to_vec());
        assert_eq!(peer.pk, pk.to_vec());
        assert_eq!(peer.info, info);

        cleanup(&db_path);
    }

    #[test]
    fn test_get_nonexistent_peer() {
        get_nonexistent_peer();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_nonexistent_peer() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let result = db.get_peer("no_such_id").await.unwrap();
        assert!(
            result.is_none(),
            "get_peer for unknown ID should return None"
        );

        cleanup(&db_path);
    }

    #[test]
    fn test_update_pk() {
        update_pk();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn update_pk() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let id = "peer_update";
        let uuid = b"uuid-bytes";
        let original_pk = b"original-pk";
        let info = "info-v1";

        let guid = db.insert_peer(id, uuid, original_pk, info).await.unwrap();

        // Verify original values
        let peer = db.get_peer(id).await.unwrap().unwrap();
        assert_eq!(peer.pk, original_pk.to_vec());
        assert_eq!(peer.info, info);

        // Update pk and info
        let new_pk = b"brand-new-pk";
        let new_info = "info-v2";
        db.update_pk(&guid, id, new_pk, new_info).await.unwrap();

        // Verify updated values
        let peer = db.get_peer(id).await.unwrap().unwrap();
        assert_eq!(peer.pk, new_pk.to_vec());
        assert_eq!(peer.info, new_info);
        // guid and uuid should remain unchanged
        assert_eq!(peer.guid, guid);
        assert_eq!(peer.uuid, uuid.to_vec());

        cleanup(&db_path);
    }

    #[test]
    fn test_duplicate_id_rejected() {
        duplicate_id_rejected();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn duplicate_id_rejected() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let id = "duplicate_peer";
        let uuid = b"uuid";
        let pk = b"pk";
        let info = "";

        // First insert should succeed
        db.insert_peer(id, uuid, pk, info).await.unwrap();

        // Second insert with the same id should fail (unique constraint on id)
        let result = db.insert_peer(id, uuid, pk, info).await;
        assert!(
            result.is_err(),
            "inserting a peer with a duplicate id should fail"
        );

        cleanup(&db_path);
    }

    #[test]
    fn test_empty_fields() {
        empty_fields();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn empty_fields() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let id = "empty_fields_peer";
        let uuid: &[u8] = b"";
        let pk: &[u8] = b"";
        let info = "";

        let guid = db.insert_peer(id, uuid, pk, info).await.unwrap();
        assert!(!guid.is_empty());

        let peer = db.get_peer(id).await.unwrap().unwrap();
        assert_eq!(peer.id, id);
        assert!(peer.uuid.is_empty());
        assert!(peer.pk.is_empty());
        assert_eq!(peer.info, "");

        cleanup(&db_path);
    }

    #[test]
    fn test_concurrent_reads() {
        concurrent_reads();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn concurrent_reads() {
        let db_path = temp_db_path();
        let db = super::Database::new(&db_path).await.unwrap();

        let id = "concurrent_peer";
        let uuid = b"concurrent-uuid";
        let pk = b"concurrent-pk";
        let info = "concurrent-info";

        db.insert_peer(id, uuid, pk, info).await.unwrap();

        // Spawn many concurrent reads of the same peer
        let mut jobs = vec![];
        for _ in 0..100 {
            let cloned = db.clone();
            let handle = tokio::spawn(async move {
                let peer = cloned
                    .get_peer("concurrent_peer")
                    .await
                    .unwrap()
                    .expect("peer should exist");
                assert_eq!(peer.id, "concurrent_peer");
                assert_eq!(peer.pk, b"concurrent-pk".to_vec());
                assert_eq!(peer.info, "concurrent-info");
            });
            jobs.push(handle);
        }

        let results = hbb_common::futures::future::join_all(jobs).await;
        for result in results {
            result.expect("concurrent read task should not panic");
        }

        cleanup(&db_path);
    }
}
