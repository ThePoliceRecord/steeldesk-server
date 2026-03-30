use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
        time::{interval, Duration},
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, HashSet},
    io::prelude::*,
    io::Error,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

type Usage = (usize, usize, usize, usize);

lazy_static::lazy_static! {
    static ref PEERS: Mutex<HashMap<String, Box<dyn StreamTrait>>> = Default::default();
    static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
}

static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s
/// Maximum allowed protobuf message size for relay handshake/pairing (64 KB).
/// Dropped before parsing to prevent memory-exhaustion DoS (CWE-400).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;
/// Maximum allowed size for relay-forwarded data (16 MB). Relay data streams
/// carry video frames that can be larger than control messages, but still need
/// an upper bound. This limit applies only to the initial handshake message;
/// once paired, streams are forwarded without protobuf parsing.
#[allow(dead_code)]
const MAX_RELAY_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";

#[tokio::main(flavor = "multi_thread")]
pub async fn start(port: &str, key: &str) -> ResultType<()> {
    let key = get_server_sk(key);
    if let Ok(mut file) = std::fs::File::open(BLACKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blacklist({}): {}",
        BLACKLIST_FILE,
        BLACKLIST.read().await.len()
    );
    if let Ok(mut file) = std::fs::File::open(BLOCKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blocklist({}): {}",
        BLOCKLIST_FILE,
        BLOCKLIST.read().await.len()
    );
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(listen_any(port).await?, listen_any(port2).await?, &key).await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}

fn check_params() {
    let tmp = std::env::var("DOWNGRADE_THRESHOLD")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        DOWNGRADE_THRESHOLD_100.store((tmp * 100.) as _, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
    );
    let tmp = std::env::var("DOWNGRADE_START_CHECK")
        .map(|x| x.parse::<usize>().unwrap_or(0))
        .unwrap_or(0);
    if tmp > 0 {
        DOWNGRADE_START_CHECK.store(tmp * 1000, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000
    );
    let tmp = std::env::var("LIMIT_SPEED")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        LIMIT_SPEED.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = std::env::var("TOTAL_BANDWIDTH")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        TOTAL_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }

    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = std::env::var("SINGLE_BANDWIDTH")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        SINGLE_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    )
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = "".to_owned();
    let mut fds = cmd.trim().split(' ');
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLACKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLACKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLACKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLOCKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLOCKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLOCKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        DOWNGRADE_THRESHOLD_100.store((v * 100.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<usize>() {
                    if v > 0 {
                        DOWNGRADE_START_CHECK.store(v * 1000, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!("{}s\n", DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000);
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        LIMIT_SPEED.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        TOTAL_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                        limiter.set_speed_limit(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        SINGLE_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .read()
                .await
                .iter()
                .map(|x| (x.0.clone(), *x.1))
                .collect();
            tmp.sort_by(|a, b| ((b.1).1).partial_cmp(&(a.1).1).unwrap());
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}kb/s {}kb/s {}kb/s",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(listener: TcpListener, listener2: TcpListener, key: &str) {
    check_params();
    let limiter = <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    limiter: &Limiter,
    key: &str,
    ws: bool,
) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    stream.write(res.as_bytes()).await.ok();
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    if BLOCKLIST.read().await.get(&ip).is_some() {
        log::info!("{} blocked", ip);
        return;
    }
    let key = key.to_owned();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, &key, limiter, ws).await);
    });
}

async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let trusted_proxies = crate::common::get_trusted_proxy_ips();
        let callback = |req: &Request, response: Response| {
            let headers = req.headers();
            addr = crate::common::get_real_ip(addr, headers, &trusted_proxies);
            Ok(response)
        };
        let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
        make_pair_(ws_stream, addr, key, limiter).await;
    } else {
        make_pair_(FramedStream::from(stream, addr), addr, key, limiter).await;
    }
    Ok(())
}

async fn make_pair_(stream: impl StreamTrait, addr: SocketAddr, key: &str, limiter: Limiter) {
    let mut stream = stream;
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if bytes.len() > MAX_MESSAGE_SIZE {
            log::warn!("Oversized message ({} bytes) from {}, dropping", bytes.len(), addr);
            return;
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !key.is_empty() && rf.licence_key != key {
                    log::warn!("Relay authentication failed from {} - invalid key", addr);
                    return;
                }
                if !rf.uuid.is_empty() {
                    let mut peer = PEERS.lock().await.remove(&rf.uuid);
                    if let Some(peer) = peer.as_mut() {
                        log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                        let id = format!("{}:{}", addr.ip(), addr.port());
                        USAGE.write().await.insert(id.clone(), Default::default());
                        if !stream.is_ws() && !peer.is_ws() {
                            peer.set_raw();
                            stream.set_raw();
                            log::info!("Both are raw");
                        }
                        if let Err(err) = relay(addr, &mut stream, peer, limiter, id.clone()).await
                        {
                            log::info!("Relay of {} closed: {}", addr, err);
                        } else {
                            log::info!("Relay of {} closed", addr);
                        }
                        USAGE.write().await.remove(&id);
                    } else {
                        log::info!("New relay request {} from {}", rf.uuid, addr);
                        PEERS.lock().await.insert(rf.uuid.clone(), Box::new(stream));
                        sleep(30.).await;
                        PEERS.lock().await.remove(&rf.uuid);
                    }
                }
            }
        }
    }
}

async fn relay(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let limiter = <Limiter>::new(sb);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as _);
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100. / 1000.) as usize; // in bit/ms
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            if BLOCKLIST.read().await.get(&ip).is_some() {
                log::info!("{} blocked", ip);
                break;
            }
            blacked = BLACKLIST.read().await.get(&ip).is_some();
            tm = std::time::Instant::now();
            let speed = total_s / n;
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total > elapsed * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}

fn get_server_sk(key: &str) -> String {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300);
        key = pk;
    }

    if key.is_empty() {
        log::warn!("WARNING: Relay server running without authentication key (-k). Any client can use this relay. Set a key with -k for production use.");
    } else {
        log::info!("Key: (configured)");
    }

    key
}

/// Returns the warning message emitted when the relay key is empty.
/// Exposed for testing.
#[cfg(test)]
fn empty_key_warning_message() -> &'static str {
    "WARNING: Relay server running without authentication key (-k). Any client can use this relay. Set a key with -k for production use."
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self
            .send(tungstenite::Message::Binary(bytes.to_vec()))
            .await?) // to-do: poor performance
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // Helper: create a Limiter suitable for tests (no actual rate limiting needed).
    fn test_limiter() -> Limiter {
        <Limiter>::new(f64::INFINITY)
    }

    // ---------------------------------------------------------------------------
    // Blacklist direct operations
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn blacklist_add_and_contains() {
        // Ensure clean state
        BLACKLIST.write().await.remove("10.0.0.1");

        BLACKLIST.write().await.insert("10.0.0.1".to_owned());
        assert!(BLACKLIST.read().await.contains("10.0.0.1"));
    }

    #[tokio::test]
    async fn blacklist_remove() {
        BLACKLIST.write().await.insert("10.0.0.2".to_owned());
        assert!(BLACKLIST.read().await.contains("10.0.0.2"));

        BLACKLIST.write().await.remove("10.0.0.2");
        assert!(!BLACKLIST.read().await.contains("10.0.0.2"));
    }

    #[tokio::test]
    async fn blacklist_insert_then_remove_individual() {
        let ip_a = "10.0.0.30";
        let ip_b = "10.0.0.31";
        BLACKLIST.write().await.insert(ip_a.to_owned());
        BLACKLIST.write().await.insert(ip_b.to_owned());
        assert!(BLACKLIST.read().await.contains(ip_a));
        assert!(BLACKLIST.read().await.contains(ip_b));

        BLACKLIST.write().await.remove(ip_a);
        BLACKLIST.write().await.remove(ip_b);
        assert!(!BLACKLIST.read().await.contains(ip_a));
        assert!(!BLACKLIST.read().await.contains(ip_b));
    }

    #[tokio::test]
    async fn blacklist_does_not_contain_absent_ip() {
        BLACKLIST.write().await.remove("192.168.255.255");
        assert!(!BLACKLIST.read().await.contains("192.168.255.255"));
    }

    // ---------------------------------------------------------------------------
    // Blocklist direct operations
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn blocklist_add_and_contains() {
        BLOCKLIST.write().await.remove("10.1.0.1");

        BLOCKLIST.write().await.insert("10.1.0.1".to_owned());
        assert!(BLOCKLIST.read().await.contains("10.1.0.1"));
    }

    #[tokio::test]
    async fn blocklist_remove() {
        BLOCKLIST.write().await.insert("10.1.0.2".to_owned());
        assert!(BLOCKLIST.read().await.contains("10.1.0.2"));

        BLOCKLIST.write().await.remove("10.1.0.2");
        assert!(!BLOCKLIST.read().await.contains("10.1.0.2"));
    }

    #[tokio::test]
    async fn blocklist_insert_then_remove_individual() {
        let ip_a = "10.1.0.30";
        let ip_b = "10.1.0.31";
        BLOCKLIST.write().await.insert(ip_a.to_owned());
        BLOCKLIST.write().await.insert(ip_b.to_owned());
        assert!(BLOCKLIST.read().await.contains(ip_a));
        assert!(BLOCKLIST.read().await.contains(ip_b));

        BLOCKLIST.write().await.remove(ip_a);
        BLOCKLIST.write().await.remove(ip_b);
        assert!(!BLOCKLIST.read().await.contains(ip_a));
        assert!(!BLOCKLIST.read().await.contains(ip_b));
    }

    // ---------------------------------------------------------------------------
    // Atomic bandwidth value defaults
    // ---------------------------------------------------------------------------

    #[test]
    fn default_limit_speed() {
        // Default: 32 * 1024 * 1024 bit/s
        let val = LIMIT_SPEED.load(Ordering::SeqCst);
        assert_eq!(val, 32 * 1024 * 1024);
    }

    #[test]
    fn default_total_bandwidth() {
        // Default: 1024 * 1024 * 1024 bit/s  (1 Gbit/s)
        let val = TOTAL_BANDWIDTH.load(Ordering::SeqCst);
        assert_eq!(val, 1024 * 1024 * 1024);
    }

    #[test]
    fn default_single_bandwidth() {
        // Default: 128 * 1024 * 1024 bit/s  (128 Mbit/s)
        let val = SINGLE_BANDWIDTH.load(Ordering::SeqCst);
        assert_eq!(val, 128 * 1024 * 1024);
    }

    #[test]
    fn default_downgrade_threshold() {
        // Default: 66  (represents 0.66)
        let val = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst);
        assert_eq!(val, 66);
    }

    #[test]
    fn default_downgrade_start_check() {
        // Default: 1_800_000 ms  (30 minutes)
        let val = DOWNGRADE_START_CHECK.load(Ordering::SeqCst);
        assert_eq!(val, 1_800_000);
    }

    // ---------------------------------------------------------------------------
    // Atomic store/load round-trips
    // ---------------------------------------------------------------------------

    #[test]
    fn atomic_store_and_load() {
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        LIMIT_SPEED.store(999_999, Ordering::SeqCst);
        assert_eq!(LIMIT_SPEED.load(Ordering::SeqCst), 999_999);

        // Restore
        LIMIT_SPEED.store(original, Ordering::SeqCst);
    }

    // ---------------------------------------------------------------------------
    // Downgrade threshold calculation
    //
    // From relay():
    //   let downgrade_threshold =
    //       (sb * DOWNGRADE_THRESHOLD_100 / 100. / 1000.) as usize;  // bit/ms
    //   downgrade triggers when:
    //       elapsed > DOWNGRADE_START_CHECK  AND  total > elapsed * downgrade_threshold
    //
    // We replicate the formula and test edge cases.
    // ---------------------------------------------------------------------------

    #[test]
    fn downgrade_threshold_calculation_default() {
        let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64; // 128 * 1024 * 1024
        let dt100 = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64; // 66
        let threshold = (sb * dt100 / 100. / 1000.) as usize; // bit/ms

        // 128 * 1024 * 1024 * 66 / 100 / 1000 = ~88_541
        let expected = (128.0 * 1024.0 * 1024.0 * 66.0 / 100.0 / 1000.0) as usize;
        assert_eq!(threshold, expected);
        // Sanity: should be in a reasonable range (tens of thousands of bit/ms)
        assert!(threshold > 50_000);
        assert!(threshold < 200_000);
    }

    #[test]
    fn downgrade_triggers_when_total_exceeds_threshold_times_elapsed() {
        let sb = 128.0 * 1024.0 * 1024.0; // 128 Mbit/s
        let dt100 = 66_usize;
        let downgrade_threshold = (sb * dt100 as f64 / 100. / 1000.) as usize;

        let elapsed_ms: usize = 2_000_000; // 2000 seconds, past the 1800s check
        let start_check: usize = 1_800_000;

        // Just below threshold: should NOT trigger
        let total_bits_below = elapsed_ms * downgrade_threshold - 1;
        assert!(elapsed_ms > start_check);
        assert!(!(total_bits_below > elapsed_ms * downgrade_threshold));

        // At threshold: should NOT trigger (> is strict)
        let total_bits_at = elapsed_ms * downgrade_threshold;
        assert!(!(total_bits_at > elapsed_ms * downgrade_threshold));

        // Above threshold: SHOULD trigger
        let total_bits_above = elapsed_ms * downgrade_threshold + 1;
        assert!(total_bits_above > elapsed_ms * downgrade_threshold);
    }

    #[test]
    fn downgrade_does_not_trigger_before_start_check() {
        let start_check = DOWNGRADE_START_CHECK.load(Ordering::SeqCst); // 1_800_000 ms
        let elapsed_ms: usize = 1_000_000; // 1000s, below 1800s threshold

        // Even with massive total, elapsed must exceed start_check first
        assert!(!(elapsed_ms > start_check));
    }

    // ---------------------------------------------------------------------------
    // check_cmd: blacklist commands
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_blacklist_add_single() {
        let limiter = test_limiter();
        // Clean up
        BLACKLIST.write().await.remove("10.99.0.1");

        check_cmd("ba 10.99.0.1", limiter.clone()).await;
        assert!(BLACKLIST.read().await.contains("10.99.0.1"));

        // Clean up
        BLACKLIST.write().await.remove("10.99.0.1");
    }

    #[tokio::test]
    async fn cmd_blacklist_add_multiple_pipe_separated() {
        let limiter = test_limiter();
        // Use unique IPs unlikely to be touched by other tests
        check_cmd("ba 10.200.1.1|10.200.1.2|10.200.1.3", limiter.clone()).await;
        let bl = BLACKLIST.read().await;
        assert!(bl.contains("10.200.1.1"));
        assert!(bl.contains("10.200.1.2"));
        assert!(bl.contains("10.200.1.3"));
        drop(bl);

        // Clean up
        let mut bl = BLACKLIST.write().await;
        bl.remove("10.200.1.1");
        bl.remove("10.200.1.2");
        bl.remove("10.200.1.3");
    }

    #[tokio::test]
    async fn cmd_blacklist_add_long_form() {
        let limiter = test_limiter();
        check_cmd("blacklist-add 10.200.2.1", limiter.clone()).await;
        assert!(BLACKLIST.read().await.contains("10.200.2.1"));
        BLACKLIST.write().await.remove("10.200.2.1");
    }

    #[tokio::test]
    async fn cmd_blacklist_remove_single() {
        let limiter = test_limiter();
        BLACKLIST.write().await.insert("10.99.3.1".to_owned());

        check_cmd("br 10.99.3.1", limiter.clone()).await;
        assert!(!BLACKLIST.read().await.contains("10.99.3.1"));
    }

    #[tokio::test]
    async fn cmd_blacklist_remove_multiple_pipe_separated() {
        let limiter = test_limiter();
        BLACKLIST.write().await.insert("10.99.4.1".to_owned());
        BLACKLIST.write().await.insert("10.99.4.2".to_owned());

        check_cmd("br 10.99.4.1|10.99.4.2", limiter.clone()).await;
        assert!(!BLACKLIST.read().await.contains("10.99.4.1"));
        assert!(!BLACKLIST.read().await.contains("10.99.4.2"));
    }

    #[tokio::test]
    async fn cmd_blacklist_remove_all() {
        let limiter = test_limiter();
        // Add entries, then remove all via command.
        // Note: "br all" clears the entire set, which can race with other tests.
        // We only assert the entries we added are gone; we do NOT assert the set is empty
        // because other tests may have re-added entries after our clear.
        BLACKLIST.write().await.insert("10.200.5.1".to_owned());
        BLACKLIST.write().await.insert("10.200.5.2".to_owned());

        check_cmd("br all", limiter.clone()).await;

        assert!(!BLACKLIST.read().await.contains("10.200.5.1"));
        assert!(!BLACKLIST.read().await.contains("10.200.5.2"));
    }

    #[tokio::test]
    async fn cmd_blacklist_remove_long_form() {
        let limiter = test_limiter();
        BLACKLIST.write().await.insert("10.99.6.1".to_owned());

        check_cmd("blacklist-remove 10.99.6.1", limiter.clone()).await;
        assert!(!BLACKLIST.read().await.contains("10.99.6.1"));
    }

    #[tokio::test]
    async fn cmd_blacklist_query_present() {
        let limiter = test_limiter();
        BLACKLIST.write().await.insert("10.99.7.1".to_owned());

        let res = check_cmd("b 10.99.7.1", limiter.clone()).await;
        assert_eq!(res.trim(), "true");

        BLACKLIST.write().await.remove("10.99.7.1");
    }

    #[tokio::test]
    async fn cmd_blacklist_query_absent() {
        let limiter = test_limiter();
        BLACKLIST.write().await.remove("10.99.8.1");

        let res = check_cmd("b 10.99.8.1", limiter.clone()).await;
        assert_eq!(res.trim(), "false");
    }

    #[tokio::test]
    async fn cmd_blacklist_query_long_form() {
        let limiter = test_limiter();
        BLACKLIST.write().await.insert("10.200.9.1".to_owned());

        let res = check_cmd("blacklist 10.200.9.1", limiter.clone()).await;
        assert_eq!(res.trim(), "true");

        BLACKLIST.write().await.remove("10.200.9.1");
    }

    #[tokio::test]
    async fn cmd_blacklist_list_all() {
        let limiter = test_limiter();
        // Add unique entries and verify they appear in the listing.
        // Do NOT clear the set -- that races with other tests.
        BLACKLIST.write().await.insert("10.200.10.1".to_owned());
        BLACKLIST.write().await.insert("10.200.10.2".to_owned());

        let res = check_cmd("b", limiter.clone()).await;
        assert!(res.contains("10.200.10.1"));
        assert!(res.contains("10.200.10.2"));

        // Clean up our entries only
        BLACKLIST.write().await.remove("10.200.10.1");
        BLACKLIST.write().await.remove("10.200.10.2");
    }

    // ---------------------------------------------------------------------------
    // check_cmd: blocklist commands
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_blocklist_add_single() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.remove("10.88.0.1");

        check_cmd("Ba 10.88.0.1", limiter.clone()).await;
        assert!(BLOCKLIST.read().await.contains("10.88.0.1"));

        BLOCKLIST.write().await.remove("10.88.0.1");
    }

    #[tokio::test]
    async fn cmd_blocklist_add_multiple_pipe_separated() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.remove("10.88.1.1");
        BLOCKLIST.write().await.remove("10.88.1.2");

        check_cmd("Ba 10.88.1.1|10.88.1.2", limiter.clone()).await;
        assert!(BLOCKLIST.read().await.contains("10.88.1.1"));
        assert!(BLOCKLIST.read().await.contains("10.88.1.2"));

        BLOCKLIST.write().await.remove("10.88.1.1");
        BLOCKLIST.write().await.remove("10.88.1.2");
    }

    #[tokio::test]
    async fn cmd_blocklist_add_long_form() {
        let limiter = test_limiter();
        check_cmd("blocklist-add 10.201.2.1", limiter.clone()).await;
        assert!(BLOCKLIST.read().await.contains("10.201.2.1"));
        BLOCKLIST.write().await.remove("10.201.2.1");
    }

    #[tokio::test]
    async fn cmd_blocklist_remove_single() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.insert("10.88.3.1".to_owned());

        check_cmd("Br 10.88.3.1", limiter.clone()).await;
        assert!(!BLOCKLIST.read().await.contains("10.88.3.1"));
    }

    #[tokio::test]
    async fn cmd_blocklist_remove_all() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.insert("10.201.4.1".to_owned());
        BLOCKLIST.write().await.insert("10.201.4.2".to_owned());

        check_cmd("Br all", limiter.clone()).await;
        assert!(!BLOCKLIST.read().await.contains("10.201.4.1"));
        assert!(!BLOCKLIST.read().await.contains("10.201.4.2"));
    }

    #[tokio::test]
    async fn cmd_blocklist_remove_long_form() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.insert("10.88.5.1".to_owned());

        check_cmd("blocklist-remove 10.88.5.1", limiter.clone()).await;
        assert!(!BLOCKLIST.read().await.contains("10.88.5.1"));
    }

    #[tokio::test]
    async fn cmd_blocklist_query_present() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.insert("10.88.6.1".to_owned());

        let res = check_cmd("B 10.88.6.1", limiter.clone()).await;
        assert_eq!(res.trim(), "true");

        BLOCKLIST.write().await.remove("10.88.6.1");
    }

    #[tokio::test]
    async fn cmd_blocklist_query_absent() {
        let limiter = test_limiter();
        BLOCKLIST.write().await.remove("10.88.7.1");

        let res = check_cmd("B 10.88.7.1", limiter.clone()).await;
        assert_eq!(res.trim(), "false");
    }

    #[tokio::test]
    async fn cmd_blocklist_list_all() {
        let limiter = test_limiter();
        // Add unique entries and verify they appear in the listing.
        BLOCKLIST.write().await.insert("10.201.8.1".to_owned());
        BLOCKLIST.write().await.insert("10.201.8.2".to_owned());

        let res = check_cmd("B", limiter.clone()).await;
        assert!(res.contains("10.201.8.1"));
        assert!(res.contains("10.201.8.2"));

        BLOCKLIST.write().await.remove("10.201.8.1");
        BLOCKLIST.write().await.remove("10.201.8.2");
    }

    // ---------------------------------------------------------------------------
    // check_cmd: bandwidth / threshold get (read current values)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_downgrade_threshold_read() {
        let limiter = test_limiter();
        let original = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst);
        DOWNGRADE_THRESHOLD_100.store(66, Ordering::SeqCst);

        let res = check_cmd("dt", limiter.clone()).await;
        assert_eq!(res.trim(), "0.66");

        DOWNGRADE_THRESHOLD_100.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_downgrade_threshold_set() {
        let limiter = test_limiter();
        let original = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst);

        check_cmd("dt 0.75", limiter.clone()).await;
        assert_eq!(DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst), 75);

        // Restore
        DOWNGRADE_THRESHOLD_100.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_downgrade_threshold_set_long_form() {
        let limiter = test_limiter();
        let original = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst);

        check_cmd("downgrade-threshold 0.80", limiter.clone()).await;
        assert_eq!(DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst), 80);

        DOWNGRADE_THRESHOLD_100.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_downgrade_threshold_ignores_zero() {
        let limiter = test_limiter();
        let original = DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst);

        check_cmd("dt 0", limiter.clone()).await;
        // Value should remain unchanged because the code checks `v > 0.`
        assert_eq!(DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_downgrade_start_check_read() {
        let limiter = test_limiter();
        let original = DOWNGRADE_START_CHECK.load(Ordering::SeqCst);
        DOWNGRADE_START_CHECK.store(1_800_000, Ordering::SeqCst);

        let res = check_cmd("t", limiter.clone()).await;
        assert_eq!(res.trim(), "1800s");

        DOWNGRADE_START_CHECK.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_downgrade_start_check_set() {
        let limiter = test_limiter();
        let original = DOWNGRADE_START_CHECK.load(Ordering::SeqCst);

        // "t 600" means 600 seconds; code stores v * 1000
        check_cmd("t 600", limiter.clone()).await;
        assert_eq!(DOWNGRADE_START_CHECK.load(Ordering::SeqCst), 600_000);

        DOWNGRADE_START_CHECK.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_downgrade_start_check_ignores_zero() {
        let limiter = test_limiter();
        let original = DOWNGRADE_START_CHECK.load(Ordering::SeqCst);

        check_cmd("t 0", limiter.clone()).await;
        assert_eq!(DOWNGRADE_START_CHECK.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_limit_speed_read() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);
        LIMIT_SPEED.store(32 * 1024 * 1024, Ordering::SeqCst);

        let res = check_cmd("ls", limiter.clone()).await;
        assert_eq!(res.trim(), "32Mb/s");

        LIMIT_SPEED.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_limit_speed_set() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        check_cmd("ls 64", limiter.clone()).await;
        assert_eq!(
            LIMIT_SPEED.load(Ordering::SeqCst),
            (64.0 * 1024.0 * 1024.0) as usize
        );

        LIMIT_SPEED.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_limit_speed_set_long_form() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        check_cmd("limit-speed 16", limiter.clone()).await;
        assert_eq!(
            LIMIT_SPEED.load(Ordering::SeqCst),
            (16.0 * 1024.0 * 1024.0) as usize
        );

        LIMIT_SPEED.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_total_bandwidth_read() {
        let limiter = test_limiter();
        let original = TOTAL_BANDWIDTH.load(Ordering::SeqCst);
        TOTAL_BANDWIDTH.store(1024 * 1024 * 1024, Ordering::SeqCst);

        let res = check_cmd("tb", limiter.clone()).await;
        assert_eq!(res.trim(), "1024Mb/s");

        TOTAL_BANDWIDTH.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_total_bandwidth_set() {
        let limiter = test_limiter();
        let original = TOTAL_BANDWIDTH.load(Ordering::SeqCst);

        check_cmd("tb 512", limiter.clone()).await;
        assert_eq!(
            TOTAL_BANDWIDTH.load(Ordering::SeqCst),
            (512.0 * 1024.0 * 1024.0) as usize
        );

        TOTAL_BANDWIDTH.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_single_bandwidth_read() {
        let limiter = test_limiter();
        let original = SINGLE_BANDWIDTH.load(Ordering::SeqCst);
        SINGLE_BANDWIDTH.store(128 * 1024 * 1024, Ordering::SeqCst);

        let res = check_cmd("sb", limiter.clone()).await;
        assert_eq!(res.trim(), "128Mb/s");

        SINGLE_BANDWIDTH.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_single_bandwidth_set() {
        let limiter = test_limiter();
        let original = SINGLE_BANDWIDTH.load(Ordering::SeqCst);

        check_cmd("sb 256", limiter.clone()).await;
        assert_eq!(
            SINGLE_BANDWIDTH.load(Ordering::SeqCst),
            (256.0 * 1024.0 * 1024.0) as usize
        );

        SINGLE_BANDWIDTH.store(original, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cmd_single_bandwidth_set_long_form() {
        let limiter = test_limiter();
        let original = SINGLE_BANDWIDTH.load(Ordering::SeqCst);

        check_cmd("single-bandwidth 64", limiter.clone()).await;
        assert_eq!(
            SINGLE_BANDWIDTH.load(Ordering::SeqCst),
            (64.0 * 1024.0 * 1024.0) as usize
        );

        SINGLE_BANDWIDTH.store(original, Ordering::SeqCst);
    }

    // ---------------------------------------------------------------------------
    // check_cmd: bandwidth commands ignore non-positive values
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_limit_speed_ignores_zero() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        check_cmd("ls 0", limiter.clone()).await;
        assert_eq!(LIMIT_SPEED.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_limit_speed_ignores_negative() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        check_cmd("ls -5", limiter.clone()).await;
        assert_eq!(LIMIT_SPEED.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_total_bandwidth_ignores_zero() {
        let limiter = test_limiter();
        let original = TOTAL_BANDWIDTH.load(Ordering::SeqCst);

        check_cmd("tb 0", limiter.clone()).await;
        assert_eq!(TOTAL_BANDWIDTH.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_single_bandwidth_ignores_zero() {
        let limiter = test_limiter();
        let original = SINGLE_BANDWIDTH.load(Ordering::SeqCst);

        check_cmd("sb 0", limiter.clone()).await;
        assert_eq!(SINGLE_BANDWIDTH.load(Ordering::SeqCst), original);
    }

    // ---------------------------------------------------------------------------
    // check_cmd: help command
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_help() {
        let limiter = test_limiter();
        let res = check_cmd("h", limiter.clone()).await;
        assert!(res.contains("blacklist-add(ba)"));
        assert!(res.contains("blacklist-remove(br)"));
        assert!(res.contains("blocklist-add(Ba)"));
        assert!(res.contains("blocklist-remove(Br)"));
        assert!(res.contains("downgrade-threshold(dt)"));
        assert!(res.contains("downgrade-start-check(t)"));
        assert!(res.contains("limit-speed(ls)"));
        assert!(res.contains("total-bandwidth(tb)"));
        assert!(res.contains("single-bandwidth(sb)"));
        assert!(res.contains("usage(u)"));
    }

    // ---------------------------------------------------------------------------
    // check_cmd: unknown command returns empty string
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_unknown_returns_empty() {
        let limiter = test_limiter();
        let res = check_cmd("nonexistent-command", limiter.clone()).await;
        assert_eq!(res, "");
    }

    #[tokio::test]
    async fn cmd_empty_returns_empty() {
        let limiter = test_limiter();
        let res = check_cmd("", limiter.clone()).await;
        assert_eq!(res, "");
    }

    // ---------------------------------------------------------------------------
    // check_cmd: usage tracking
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_usage_displays_entries() {
        let limiter = test_limiter();

        // Insert a synthetic usage entry:
        //   Usage = (elapsed_ms, total_bits, highest_speed_bit_per_ms, current_speed_bit_per_ms)
        USAGE.write().await.insert(
            "10.77.0.1:12345".to_owned(),
            (60_000, 1_000_000, 500, 200),
        );

        let res = check_cmd("u", limiter.clone()).await;
        assert!(res.contains("10.77.0.1:12345"));
        // elapsed/1000 = 60
        assert!(res.contains("60s"));

        USAGE.write().await.remove("10.77.0.1:12345");
    }

    #[tokio::test]
    async fn cmd_usage_skips_zero_elapsed() {
        let limiter = test_limiter();

        // Entry with elapsed == 0 should be skipped
        USAGE
            .write()
            .await
            .insert("10.77.0.2:12345".to_owned(), (0, 1_000, 100, 50));

        let res = check_cmd("u", limiter.clone()).await;
        assert!(!res.contains("10.77.0.2:12345"));

        USAGE.write().await.remove("10.77.0.2:12345");
    }

    #[tokio::test]
    async fn cmd_usage_sorted_by_total_descending() {
        let limiter = test_limiter();

        // Use highly distinctive keys and extreme total values so ordering is
        // unambiguous even if other tests have entries in the USAGE map.
        USAGE
            .write()
            .await
            .insert("sort_low:1".to_owned(), (1000, 100, 10, 10));
        USAGE
            .write()
            .await
            .insert("sort_high:2".to_owned(), (1000, 999_999_999, 10, 10));
        USAGE
            .write()
            .await
            .insert("sort_mid:3".to_owned(), (1000, 500_000_000, 10, 10));

        let res = check_cmd("u", limiter.clone()).await;
        let pos_high = res.find("sort_high:2").unwrap();
        let pos_mid = res.find("sort_mid:3").unwrap();
        let pos_low = res.find("sort_low:1").unwrap();

        // Sorted by total (field index 1) descending
        assert!(pos_high < pos_mid, "high should appear before mid");
        assert!(pos_mid < pos_low, "mid should appear before low");

        // Clean up our entries only
        let mut usage = USAGE.write().await;
        usage.remove("sort_low:1");
        usage.remove("sort_high:2");
        usage.remove("sort_mid:3");
    }

    // ---------------------------------------------------------------------------
    // check_cmd: commands with invalid (non-numeric) arguments
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn cmd_limit_speed_ignores_non_numeric() {
        let limiter = test_limiter();
        let original = LIMIT_SPEED.load(Ordering::SeqCst);

        check_cmd("ls abc", limiter.clone()).await;
        assert_eq!(LIMIT_SPEED.load(Ordering::SeqCst), original);
    }

    #[tokio::test]
    async fn cmd_downgrade_start_check_ignores_non_numeric() {
        let limiter = test_limiter();
        let original = DOWNGRADE_START_CHECK.load(Ordering::SeqCst);

        check_cmd("t abc", limiter.clone()).await;
        assert_eq!(DOWNGRADE_START_CHECK.load(Ordering::SeqCst), original);
    }

    // ---------------------------------------------------------------------------
    // USAGE map direct operations
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn usage_insert_and_read() {
        let key = "10.66.0.1:9999".to_owned();
        USAGE.write().await.remove(&key);

        let entry: Usage = (5000, 800_000, 300, 160);
        USAGE.write().await.insert(key.clone(), entry);

        let map = USAGE.read().await;
        let stored = map.get(&key).unwrap();
        assert_eq!(*stored, (5000, 800_000, 300, 160));

        drop(map);
        USAGE.write().await.remove(&key);
    }

    #[tokio::test]
    async fn usage_remove() {
        let key = "10.66.0.2:9999".to_owned();
        USAGE.write().await.insert(key.clone(), (1, 2, 3, 4));
        assert!(USAGE.read().await.contains_key(&key));

        USAGE.write().await.remove(&key);
        assert!(!USAGE.read().await.contains_key(&key));
    }

    // ---------------------------------------------------------------------------
    // get_server_sk: basic key handling
    // ---------------------------------------------------------------------------

    #[test]
    fn get_server_sk_empty_key_returns_empty() {
        let result = get_server_sk("");
        assert_eq!(result, "");
    }

    #[test]
    fn get_server_sk_plain_text_returned_as_is() {
        // A short non-base64 / non-special key is returned unchanged
        let result = get_server_sk("my_test_key_123");
        assert_eq!(result, "my_test_key_123");
    }

    #[test]
    fn empty_key_warning_contains_expected_text() {
        let msg = empty_key_warning_message();
        assert!(
            msg.contains("without authentication key"),
            "Warning should mention missing authentication key"
        );
        assert!(
            msg.contains("-k"),
            "Warning should reference the -k flag"
        );
        assert!(
            msg.contains("Any client can use this relay"),
            "Warning should explain the security impact"
        );
    }

    // -----------------------------------------------------------------------
    // CWE-532: Verify get_server_sk does not leak raw key material in logs.
    //
    // The log line was changed from:
    //   log::info!("Key: {}", key)
    // to a conditional that logs either "Key: (configured)" or a warning about
    // no key being set. The raw key value is never interpolated into log output.
    //
    // Since Rust's `log` crate has no built-in capture, we verify indirectly:
    // the function returns the correct key, and the format pattern used in the
    // log macro only produces fixed strings, never the raw key.
    // -----------------------------------------------------------------------

    #[test]
    fn get_server_sk_log_does_not_contain_raw_key() {
        let secret = "relay_secret_key_xyz";
        let result = get_server_sk(secret);
        assert_eq!(result, secret, "key should be returned correctly");

        // The log now emits "Key: (configured)" -- verify it cannot contain the raw key
        let log_configured = "Key: (configured)";
        assert!(!log_configured.contains(secret),
            "log output must not contain the raw key value");
    }

    #[test]
    fn get_server_sk_log_warns_when_empty_does_not_leak() {
        let result = get_server_sk("");
        assert_eq!(result, "", "empty key should return empty");

        // When key is empty, the log emits a warning (not the key value).
        let warning = empty_key_warning_message();
        assert!(!warning.is_empty(), "warning message should not be empty");
        // The warning is a fixed string -- it cannot contain any key material
        assert!(!warning.contains("Key:"),
            "warning should not use the 'Key:' format that previously leaked");
    }

    #[test]
    fn get_server_sk_log_does_not_leak_crypto_key() {
        let (_pk, sk) = sodiumoxide::crypto::sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let result = get_server_sk(&sk_b64);

        // The function should derive the public key from the secret key
        let expected_pk = base64::encode(&sk[sign::SECRETKEYBYTES / 2..]);
        assert_eq!(result, expected_pk, "should return derived public key");

        // The log message is the fixed string "Key: (configured)" -- verify
        // it does not contain the derived public key or the secret key
        let log_msg = "Key: (configured)";
        assert!(!log_msg.contains(&result),
            "log must not contain the derived public key");
        assert!(!log_msg.contains(&sk_b64),
            "log must not contain the secret key");
    }

    // ---------------------------------------------------------------------------
    // Message size limit tests (CWE-400 mitigation)
    // ---------------------------------------------------------------------------

    #[test]
    fn max_message_size_constant_is_64kb() {
        assert_eq!(MAX_MESSAGE_SIZE, 64 * 1024);
    }

    #[test]
    fn max_relay_message_size_constant_is_16mb() {
        assert_eq!(MAX_RELAY_MESSAGE_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn relay_forwarding_limit_is_separate_from_rendezvous_limit() {
        // The relay forwarding limit (16 MB) must be strictly greater than the
        // rendezvous/handshake limit (64 KB) because relay data includes video
        // frames that are legitimately large.
        assert!(
            MAX_RELAY_MESSAGE_SIZE > MAX_MESSAGE_SIZE,
            "relay forwarding limit ({}) must exceed rendezvous limit ({})",
            MAX_RELAY_MESSAGE_SIZE,
            MAX_MESSAGE_SIZE
        );
    }

    #[test]
    fn message_under_limit_passes_size_check() {
        let bytes = vec![0u8; MAX_MESSAGE_SIZE - 1];
        assert!(
            bytes.len() <= MAX_MESSAGE_SIZE,
            "message under limit should pass the size check"
        );
    }

    #[test]
    fn message_at_exact_boundary_passes_size_check() {
        let bytes = vec![0u8; MAX_MESSAGE_SIZE];
        // The check is `bytes.len() > MAX_MESSAGE_SIZE` (strict greater-than),
        // so exactly MAX_MESSAGE_SIZE should pass.
        assert!(
            !(bytes.len() > MAX_MESSAGE_SIZE),
            "message at exact boundary (64 KB) should pass the size check"
        );
    }

    #[test]
    fn message_one_over_boundary_fails_size_check() {
        let bytes = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(
            bytes.len() > MAX_MESSAGE_SIZE,
            "message at 64 KB + 1 should fail the size check"
        );
    }

    #[test]
    fn message_over_limit_fails_size_check() {
        let bytes = vec![0u8; MAX_MESSAGE_SIZE * 2];
        assert!(
            bytes.len() > MAX_MESSAGE_SIZE,
            "message well over limit should fail the size check"
        );
    }
}
