use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// Create a unique temp database path (same pattern as database.rs tests).
    fn temp_db_path() -> String {
        format!("test_peer_{}.sqlite3", uuid::Uuid::new_v4())
    }

    /// Best-effort cleanup of a temp database file.
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// Build a PeerMap backed by a fresh temp database, returning both.
    async fn make_peer_map() -> (PeerMap, String) {
        let path = temp_db_path();
        let db = database::Database::new(&path).await.unwrap();
        let pm = PeerMap {
            map: Default::default(),
            db,
        };
        (pm, path)
    }

    // ---------------------------------------------------------------
    // 1. PeerInfo struct — serialization / deserialization / defaults
    // ---------------------------------------------------------------

    #[test]
    fn test_peer_info_default() {
        let info = PeerInfo::default();
        assert_eq!(info.ip, "", "default ip should be empty string");
    }

    #[test]
    fn test_peer_info_serialize_roundtrip() {
        let info = PeerInfo {
            ip: "192.168.1.100".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ip, "192.168.1.100");
    }

    #[test]
    fn test_peer_info_deserialize_empty_object() {
        // `ip` has #[serde(default)] so missing field should produce "".
        let info: PeerInfo = serde_json::from_str("{}").unwrap();
        assert_eq!(info.ip, "");
    }

    #[test]
    fn test_peer_info_deserialize_with_ip() {
        let info: PeerInfo = serde_json::from_str(r#"{"ip":"10.0.0.1"}"#).unwrap();
        assert_eq!(info.ip, "10.0.0.1");
    }

    #[test]
    fn test_peer_info_deserialize_ignores_unknown_fields() {
        // serde by default ignores unknown fields (no deny_unknown_fields).
        let info: PeerInfo =
            serde_json::from_str(r#"{"ip":"10.0.0.1","extra":"value"}"#).unwrap();
        assert_eq!(info.ip, "10.0.0.1");
    }

    #[test]
    fn test_peer_info_clone() {
        let info = PeerInfo {
            ip: "1.2.3.4".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.ip, "1.2.3.4");
    }

    // ---------------------------------------------------------------
    // 2. Peer default values
    // ---------------------------------------------------------------

    #[test]
    fn test_peer_default_socket_addr() {
        let peer = Peer::default();
        assert_eq!(
            peer.socket_addr,
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_peer_default_fields_empty() {
        let peer = Peer::default();
        assert!(peer.guid.is_empty(), "default guid should be empty");
        assert!(peer.uuid.is_empty(), "default uuid should be empty");
        assert!(peer.pk.is_empty(), "default pk should be empty");
        assert_eq!(peer.info.ip, "", "default info.ip should be empty");
        assert_eq!(peer.reg_pk.0, 0, "default reg_pk count should be 0");
    }

    #[test]
    fn test_peer_default_last_reg_time_is_expired() {
        let peer = Peer::default();
        // get_expired_time() returns Instant::now() - 3600s, so last_reg_time
        // should be well in the past (at least ~3599s ago).
        assert!(
            peer.last_reg_time.elapsed().as_secs() >= 3599,
            "default last_reg_time should be ~1 hour in the past"
        );
    }

    // ---------------------------------------------------------------
    // 3. LockPeer fields — verify Arc<RwLock<Peer>> access pattern
    // ---------------------------------------------------------------

    #[test]
    fn test_lock_peer_default_fields() {
        lock_peer_default_fields();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn lock_peer_default_fields() {
        let lock_peer: LockPeer = Default::default();
        let r = lock_peer.read().await;
        assert_eq!(r.socket_addr, "0.0.0.0:0".parse::<SocketAddr>().unwrap());
        assert!(r.guid.is_empty());
        assert!(r.uuid.is_empty());
        assert!(r.pk.is_empty());
        assert_eq!(r.info.ip, "");
        assert!(r.last_reg_time.elapsed().as_secs() >= 3599);
        assert_eq!(r.reg_pk.0, 0);
    }

    #[test]
    fn test_lock_peer_write_then_read() {
        lock_peer_write_then_read();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn lock_peer_write_then_read() {
        let lock_peer: LockPeer = Default::default();

        // Write custom values.
        {
            let mut w = lock_peer.write().await;
            w.socket_addr = "127.0.0.1:5000".parse().unwrap();
            w.guid = vec![1, 2, 3];
            w.uuid = Bytes::from_static(b"test-uuid");
            w.pk = Bytes::from_static(b"test-pk");
            w.info.ip = "10.20.30.40".to_string();
            w.last_reg_time = Instant::now();
        }

        // Read them back.
        let r = lock_peer.read().await;
        assert_eq!(r.socket_addr, "127.0.0.1:5000".parse::<SocketAddr>().unwrap());
        assert_eq!(r.guid, vec![1, 2, 3]);
        assert_eq!(&r.uuid[..], b"test-uuid");
        assert_eq!(&r.pk[..], b"test-pk");
        assert_eq!(r.info.ip, "10.20.30.40");
        assert!(
            r.last_reg_time.elapsed().as_secs() < 2,
            "last_reg_time should have been set to ~now"
        );
    }

    // ---------------------------------------------------------------
    // 4. PeerMap creation — initialization
    // ---------------------------------------------------------------

    #[test]
    fn test_peer_map_creation() {
        peer_map_creation();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn peer_map_creation() {
        let (pm, path) = make_peer_map().await;
        // The in-memory map should start empty.
        assert!(!pm.is_in_memory("anything").await);
        assert!(pm.get_in_memory("anything").await.is_none());
        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 5. Peer lookup — get() and get_or() behavior
    // ---------------------------------------------------------------

    #[test]
    fn test_get_returns_none_for_unknown_peer() {
        get_returns_none_for_unknown_peer();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_returns_none_for_unknown_peer() {
        let (pm, path) = make_peer_map().await;
        let result = pm.get("nonexistent").await;
        assert!(result.is_none(), "get() for unknown peer should return None");
        cleanup(&path);
    }

    #[test]
    fn test_get_or_creates_default_peer_for_unknown_id() {
        get_or_creates_default_peer_for_unknown_id();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_or_creates_default_peer_for_unknown_id() {
        let (pm, path) = make_peer_map().await;

        // get_or should always return a LockPeer, creating a default if absent.
        let peer = pm.get_or("brand_new").await;
        let r = peer.read().await;
        assert_eq!(r.socket_addr, "0.0.0.0:0".parse::<SocketAddr>().unwrap());
        assert!(r.guid.is_empty());
        assert!(r.pk.is_empty());

        // It should now be in memory.
        assert!(pm.is_in_memory("brand_new").await);

        cleanup(&path);
    }

    #[test]
    fn test_get_or_returns_same_peer_on_second_call() {
        get_or_returns_same_peer_on_second_call();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_or_returns_same_peer_on_second_call() {
        let (pm, path) = make_peer_map().await;

        let peer1 = pm.get_or("stable_id").await;
        // Mutate through the first reference.
        {
            let mut w = peer1.write().await;
            w.info.ip = "changed".to_string();
        }

        // Second get_or should return the same Arc, not a fresh default.
        let peer2 = pm.get_or("stable_id").await;
        let r = peer2.read().await;
        assert_eq!(
            r.info.ip, "changed",
            "get_or should return the existing peer, not create a new one"
        );

        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 6. Peer insertion — adding new peers via update_pk
    // ---------------------------------------------------------------

    #[test]
    fn test_update_pk_inserts_new_peer_into_db() {
        update_pk_inserts_new_peer_into_db();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn update_pk_inserts_new_peer_into_db() {
        let (mut pm, path) = make_peer_map().await;

        // get_or creates a default (empty guid) peer in memory.
        let peer = pm.get_or("peer_insert").await;
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let uuid = Bytes::from_static(b"my-uuid");
        let pk = Bytes::from_static(b"my-pk");

        let result = pm
            .update_pk(
                "peer_insert".to_string(),
                peer.clone(),
                addr,
                uuid.clone(),
                pk.clone(),
                "192.168.1.1".to_string(),
            )
            .await;

        assert_eq!(result, register_pk_response::Result::OK);

        // The peer should now have a non-empty guid (assigned by DB insert).
        let r = peer.read().await;
        assert!(!r.guid.is_empty(), "guid should have been set by insert");
        assert_eq!(r.socket_addr, addr);
        assert_eq!(&r.pk[..], b"my-pk");
        assert_eq!(&r.uuid[..], b"my-uuid");
        assert_eq!(r.info.ip, "192.168.1.1");

        // Verify it was persisted to the DB.
        let db_peer = pm.db.get_peer("peer_insert").await.unwrap().unwrap();
        assert_eq!(db_peer.pk, b"my-pk".to_vec());
        assert_eq!(db_peer.uuid, b"my-uuid".to_vec());

        cleanup(&path);
    }

    #[test]
    fn test_update_pk_updates_existing_peer_in_db() {
        update_pk_updates_existing_peer_in_db();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn update_pk_updates_existing_peer_in_db() {
        let (mut pm, path) = make_peer_map().await;

        let peer = pm.get_or("peer_upd").await;
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();

        // First call: inserts (guid is empty).
        let result = pm
            .update_pk(
                "peer_upd".to_string(),
                peer.clone(),
                addr,
                Bytes::from_static(b"uuid1"),
                Bytes::from_static(b"pk1"),
                "10.0.0.1".to_string(),
            )
            .await;
        assert_eq!(result, register_pk_response::Result::OK);

        let guid_after_insert = peer.read().await.guid.clone();
        assert!(!guid_after_insert.is_empty());

        // Second call: updates (guid is now set).
        let new_addr: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let result = pm
            .update_pk(
                "peer_upd".to_string(),
                peer.clone(),
                new_addr,
                Bytes::from_static(b"uuid2"),
                Bytes::from_static(b"pk2"),
                "10.0.0.2".to_string(),
            )
            .await;
        assert_eq!(result, register_pk_response::Result::OK);

        // guid should be unchanged.
        let r = peer.read().await;
        assert_eq!(r.guid, guid_after_insert, "guid should not change on update");

        // DB should reflect the updated pk and info.
        let db_peer = pm.db.get_peer("peer_upd").await.unwrap().unwrap();
        assert_eq!(db_peer.pk, b"pk2".to_vec());
        let info: PeerInfo = serde_json::from_str(&db_peer.info).unwrap();
        assert_eq!(info.ip, "10.0.0.2");

        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 7. In-memory caching — get() loads from DB into memory cache
    // ---------------------------------------------------------------

    #[test]
    fn test_get_loads_from_db_into_memory_cache() {
        get_loads_from_db_into_memory_cache();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_loads_from_db_into_memory_cache() {
        let (pm, path) = make_peer_map().await;

        // Insert a peer directly into the DB (bypassing the in-memory map).
        let pk = b"cached-pk";
        let uuid = b"cached-uuid";
        let info_str = serde_json::to_string(&PeerInfo {
            ip: "5.5.5.5".to_string(),
        })
        .unwrap();
        pm.db
            .insert_peer("cached_peer", uuid, pk, &info_str)
            .await
            .unwrap();

        // Confirm it is NOT in memory yet.
        assert!(
            !pm.is_in_memory("cached_peer").await,
            "peer should not be in memory before get()"
        );

        // get() should find it in the DB and load it into the memory cache.
        let peer = pm.get("cached_peer").await;
        assert!(peer.is_some(), "get() should find DB peer");

        let peer = peer.unwrap();
        let r = peer.read().await;
        assert_eq!(&r.pk[..], pk, "pk should be loaded from DB");
        assert_eq!(&r.uuid[..], uuid, "uuid should be loaded from DB");
        assert_eq!(r.info.ip, "5.5.5.5", "info.ip should be deserialized from DB");
        assert!(!r.guid.is_empty(), "guid should be populated from DB");
        drop(r);

        // Now it should be in memory.
        assert!(
            pm.is_in_memory("cached_peer").await,
            "peer should be in memory after get()"
        );

        // get_in_memory should also find it.
        assert!(pm.get_in_memory("cached_peer").await.is_some());

        cleanup(&path);
    }

    #[test]
    fn test_get_returns_cached_peer_on_second_call() {
        get_returns_cached_peer_on_second_call();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_returns_cached_peer_on_second_call() {
        let (pm, path) = make_peer_map().await;

        // Seed DB directly.
        pm.db
            .insert_peer("repeat", b"u", b"p", r#"{"ip":"1.1.1.1"}"#)
            .await
            .unwrap();

        // First get() loads from DB.
        let peer1 = pm.get("repeat").await.unwrap();
        // Mutate the in-memory peer.
        peer1.write().await.info.ip = "mutated".to_string();

        // Second get() should return the cached (mutated) version, not re-read DB.
        let peer2 = pm.get("repeat").await.unwrap();
        let r = peer2.read().await;
        assert_eq!(
            r.info.ip, "mutated",
            "second get() should return the in-memory cached peer"
        );

        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 8. get_in_memory and is_in_memory
    // ---------------------------------------------------------------

    #[test]
    fn test_get_in_memory_returns_none_for_db_only_peer() {
        get_in_memory_returns_none_for_db_only_peer();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_in_memory_returns_none_for_db_only_peer() {
        let (pm, path) = make_peer_map().await;

        // Insert directly into DB.
        pm.db
            .insert_peer("db_only", b"u", b"p", "")
            .await
            .unwrap();

        // get_in_memory does NOT consult the DB.
        assert!(
            pm.get_in_memory("db_only").await.is_none(),
            "get_in_memory should not find a peer that is only in the DB"
        );
        assert!(!pm.is_in_memory("db_only").await);

        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 9. get_or with DB-backed peer
    // ---------------------------------------------------------------

    #[test]
    fn test_get_or_finds_db_peer_and_caches_it() {
        get_or_finds_db_peer_and_caches_it();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn get_or_finds_db_peer_and_caches_it() {
        let (pm, path) = make_peer_map().await;

        pm.db
            .insert_peer("db_peer", b"uuid-db", b"pk-db", r#"{"ip":"9.9.9.9"}"#)
            .await
            .unwrap();

        // get_or delegates to get() first, which checks DB.
        let peer = pm.get_or("db_peer").await;
        let r = peer.read().await;
        assert_eq!(&r.pk[..], b"pk-db");
        assert_eq!(r.info.ip, "9.9.9.9");
        drop(r);

        // It should now be cached.
        assert!(pm.is_in_memory("db_peer").await);

        cleanup(&path);
    }

    // ---------------------------------------------------------------
    // 10. Constants sanity checks
    // ---------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(IP_CHANGE_DUR, 180);
        assert_eq!(IP_CHANGE_DUR_X2, 360);
        assert_eq!(DAY_SECONDS, 86400);
        assert_eq!(IP_BLOCK_DUR, 60);
    }
}
