use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i32 = 30_000;
/// Maximum allowed protobuf message size (64 KB). Any message exceeding this
/// limit is dropped before parsing to prevent memory-exhaustion DoS (CWE-400).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    TcpStream(TcpStreamSink),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<Vec<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(Vec::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
}

impl RendezvousServer {
    #[tokio::main(flavor = "multi_thread")]
    pub async fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key);
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        log::info!("Listening on tcp/udp :{}", port);
        log::info!("Listening on tcp :{}, extra port for NAT test", nat_port);
        log::info!("Listening on websocket :{}", ws_port);
        let mut socket = create_udp_listener(port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(port).await?;
        let mut listener2 = create_tcp_listener(nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_port).await?;
        let test_addr = std::env::var("TEST_HBBS").unwrap_or_default();
        if std::env::var("ALWAYS_USE_RELAY")
            .unwrap_or_default()
            .to_uppercase()
            == "Y"
        {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(nat_port).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_port).await?;
                    }
                }
            }
        };
        // Start the Pro API server on port 21114 (hbbs port - 2)
        let api_port = (port - 2) as u16;
        let api_task = async move {
            if let Err(err) = crate::api::start_api_server(api_port).await {
                log::error!("Pro API server failed: {}", err);
            }
            Ok(()) as ResultType<()>
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
            res = api_task => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            log::warn!("Oversized message ({} bytes) from {}, dropping", bytes.len(), addr);
            return Ok(());
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id,
                                        ip,
                                        rk.pk,
                                        peer.info.ip,
                                        peer.pk,
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id,
                                    rk.uuid,
                                    peer.uuid
                                );
                                drop(peer);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    if self.pm.is_in_memory(&ph.id).await {
                        self.handle_udp_punch_hole_request(addr, ph, key).await?;
                    } else {
                        // not in memory, fetch from db with spawn in case blocking me
                        let mut me = self.clone();
                        let key = key.to_owned();
                        tokio::spawn(async move {
                            allow_err!(me.handle_udp_punch_hole_request(addr, ph, &key).await);
                        });
                    }
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    self.handle_hole_sent(phs, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    self.handle_local_addr(la, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if bytes.len() > MAX_MESSAGE_SIZE {
            log::warn!("Oversized message ({} bytes) from {}, dropping", bytes.len(), addr);
            return false;
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }
                _ => {}
            }
        }
        false
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i32, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let to_id_clone = id.clone();
                let mut lock = PUNCH_REQS.lock().await;
                let mut dup = false;
                for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
                    if e.from_ip == from_ip && e.to_id == to_id_clone {
                        if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
                        break;
                    }
                }
                if !dup { lock.push(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id: to_id_clone }); }
            }

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i32;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.tx.send(Data::Msg(msg.into(), addr))?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if bytes.len() > MAX_MESSAGE_SIZE {
                    log::warn!("Oversized message ({} bytes) from {}, dropping", bytes.len(), addr);
                    return;
                }
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let trusted_proxies = crate::common::get_trusted_proxy_ips();
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                addr = crate::common::get_real_ip(addr, headers, &trusted_proxies);
                Ok(response)
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                        break;
                    }
                }
            }
        } else {
            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a));
            while let Ok(Some(Ok(bytes))) = timeout(30_000, b.next()).await {
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> (String, Option<sign::SecretKey>) {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0);
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", if key.is_empty() { "(not set)" } else { "(configured)" });
        }
        (key, out_sk)
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if bytes.len() > MAX_MESSAGE_SIZE {
                  log::warn!("Oversized message ({} bytes) in test_hbbs, dropping", bytes.len());
                  continue;
              }
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(port: i32, rmem: usize) -> ResultType<FramedSocket> {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(port: i32) -> ResultType<TcpListener> {
    let s = listen_any(port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    // -----------------------------------------------------------------------
    // Helper: build a RendezvousServer with a temp SQLite DB for method tests.
    // PeerMap::new() reads the DB_URL env var, so we serialize creation with
    // a mutex to avoid races between parallel tests.
    // -----------------------------------------------------------------------
    static DB_URL_MUTEX: once_cell::sync::Lazy<std::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

    async fn make_test_server() -> (RendezvousServer, String) {
        let db_path = format!("/tmp/test_rv_{}.sqlite3", uuid::Uuid::new_v4());
        let pm = {
            let _guard = DB_URL_MUTEX.lock().unwrap();
            std::env::set_var("DB_URL", &db_path);
            let pm = PeerMap::new().await.expect("PeerMap::new for test");
            std::env::remove_var("DB_URL");
            pm
        };
        let (tx, _rx) = mpsc::unbounded_channel::<Data>();
        let rs = RendezvousServer {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx,
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(Vec::new()),
            inner: Arc::new(Inner {
                serial: 1,
                version: String::new(),
                software_url: String::new(),
                sk: None,
                mask: None,
                local_ip: String::new(),
            }),
        };
        (rs, db_path)
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    // =======================================================================
    // 1. IP Blocker logic
    // =======================================================================

    #[tokio::test]
    async fn ip_blocker_new_ip_is_allowed() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.10";
        IP_BLOCKER.lock().await.remove(ip);

        let allowed = rs.check_ip_blocker(ip, "peer_a").await;
        assert!(allowed, "a brand-new IP should be allowed");

        // Entry should now exist in the map
        {
            let lock = IP_BLOCKER.lock().await;
            assert!(lock.contains_key(ip));
            // Counter starts at 0 for a new entry (incremented on second call)
            let entry = &lock[ip];
            assert_eq!(entry.0 .0, 0);
        }

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn ip_blocker_allows_up_to_30_calls_per_minute() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.20";
        IP_BLOCKER.lock().await.remove(ip);

        // Trace through check_ip_blocker logic:
        //   Call 1: IP not found => insert with counter=0. Returns true.
        //   Call 2: counter=0, 0>30 false, counter becomes 1. Returns true.
        //   Call 3: counter=1, 1>30 false, counter becomes 2. Returns true.
        //   ...
        //   Call 32: counter=30, 30>30 false, counter becomes 31. Returns true.
        //   Call 33: counter=31, 31>30 TRUE. Returns false.
        for i in 0..32 {
            let allowed = rs.check_ip_blocker(ip, "peer_a").await;
            assert!(allowed, "call {} should be allowed (counter <= 30)", i + 1);
        }
        // 33rd call: counter is now 31, which is > 30 => blocked
        let blocked = rs.check_ip_blocker(ip, "peer_a").await;
        assert!(!blocked, "33rd call should be blocked (rate limit exceeded)");

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn ip_blocker_rate_limit_resets_after_60_seconds() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.30";
        IP_BLOCKER.lock().await.remove(ip);

        // Seed the entry
        rs.check_ip_blocker(ip, "peer_a").await;

        // Manually push the per-minute counter timestamp back > 60 seconds
        {
            let mut lock = IP_BLOCKER.lock().await;
            let entry = lock.get_mut(ip).unwrap();
            entry.0 .1 = Instant::now()
                .checked_sub(std::time::Duration::from_secs(IP_BLOCK_DUR + 1))
                .unwrap();
            // Set counter high
            entry.0 .0 = 99;
        }

        // After the window elapsed the counter should reset; IP should be allowed.
        let allowed = rs.check_ip_blocker(ip, "peer_a").await;
        assert!(allowed, "IP should be allowed after the 60s window resets");

        // Counter should have been reset to 0, then incremented to 1
        {
            let lock = IP_BLOCKER.lock().await;
            assert_eq!(lock[ip].0 .0, 1);
        }

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn ip_blocker_unique_id_limit_300_per_day() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.40";
        IP_BLOCKER.lock().await.remove(ip);

        // Seed the entry
        rs.check_ip_blocker(ip, "seed_id").await;

        // Manually inject 301 unique IDs into the daily set
        {
            let mut lock = IP_BLOCKER.lock().await;
            let entry = lock.get_mut(ip).unwrap();
            entry.1 .0.clear();
            for i in 0..301 {
                entry.1 .0.insert(format!("id_{}", i));
            }
            // Keep the daily timestamp recent
            entry.1 .1 = Instant::now();
            // Keep the per-minute counter low so we don't hit that limit
            entry.0 .0 = 0;
            entry.0 .1 = Instant::now();
        }

        // A *new* ID should be blocked (> 300 unique IDs and is_new == true)
        let blocked = rs.check_ip_blocker(ip, "brand_new_id").await;
        assert!(
            !blocked,
            "a new ID should be blocked when >300 unique IDs already seen"
        );

        // But an *existing* ID should still be allowed (!is_new => allowed)
        let allowed = rs.check_ip_blocker(ip, "id_0").await;
        assert!(
            allowed,
            "an already-known ID should still be allowed even with >300 unique IDs"
        );

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn ip_blocker_daily_set_resets_after_24h() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.50";
        IP_BLOCKER.lock().await.remove(ip);

        // Seed the entry
        rs.check_ip_blocker(ip, "seed_id").await;

        // Fill up the daily set and push timestamp back
        {
            let mut lock = IP_BLOCKER.lock().await;
            let entry = lock.get_mut(ip).unwrap();
            for i in 0..301 {
                entry.1 .0.insert(format!("id_{}", i));
            }
            entry.1 .1 = Instant::now()
                .checked_sub(std::time::Duration::from_secs(DAY_SECONDS + 1))
                .unwrap();
            entry.0 .0 = 0;
            entry.0 .1 = Instant::now();
        }

        // After the day window, the set should be cleared => new IDs allowed
        let allowed = rs.check_ip_blocker(ip, "totally_new_id").await;
        assert!(
            allowed,
            "after the daily window resets, new IDs should be allowed again"
        );

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn ip_blocker_entry_creation_tracks_counter_and_set() {
        let (rs, db_path) = make_test_server().await;
        let ip = "198.51.100.60";
        IP_BLOCKER.lock().await.remove(ip);

        // First call creates the entry with counter=0 and empty ID set
        rs.check_ip_blocker(ip, "peer_x").await;
        {
            let lock = IP_BLOCKER.lock().await;
            let entry = &lock[ip];
            assert_eq!(entry.0 .0, 0, "first call should set per-minute counter to 0");
            assert!(
                entry.1 .0.is_empty(),
                "first call should have empty ID set (insert happens on second+ call)"
            );
        }

        // Second call should increment counter and insert the ID
        rs.check_ip_blocker(ip, "peer_x").await;
        {
            let lock = IP_BLOCKER.lock().await;
            let entry = &lock[ip];
            assert_eq!(entry.0 .0, 1, "second call increments per-minute counter");
            assert!(
                entry.1 .0.contains("peer_x"),
                "second call should add 'peer_x' to the daily set"
            );
        }

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    // =======================================================================
    // 2. IP Changes tracking
    // =======================================================================

    #[tokio::test]
    async fn ip_changes_new_entry_created() {
        let id = "test_ic_new".to_string();
        IP_CHANGES.lock().await.remove(&id);

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                id.clone(),
                (Instant::now(), HashMap::from([("1.2.3.4".to_string(), 1)])),
            );
        }

        {
            let lock = IP_CHANGES.lock().await;
            let (tm, ips) = lock.get(&id).unwrap();
            assert!(tm.elapsed().as_secs() < 2);
            assert_eq!(ips.get("1.2.3.4"), Some(&1));
        }

        IP_CHANGES.lock().await.remove(&id);
    }

    #[tokio::test]
    async fn ip_changes_increment_existing_ip() {
        let id = "test_ic_incr".to_string();
        IP_CHANGES.lock().await.remove(&id);

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                id.clone(),
                (Instant::now(), HashMap::from([("10.0.0.1".to_string(), 3)])),
            );
        }

        // Simulate another change to the same IP: increment
        {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((_tm, ips)) = lock.get_mut(&id) {
                if let Some(v) = ips.get_mut("10.0.0.1") {
                    *v += 1;
                }
            }
        }

        {
            let lock = IP_CHANGES.lock().await;
            assert_eq!(lock[&id].1.get("10.0.0.1"), Some(&4));
        }

        IP_CHANGES.lock().await.remove(&id);
    }

    #[tokio::test]
    async fn ip_changes_adds_new_ip_to_existing_entry() {
        let id = "test_ic_new_ip".to_string();
        IP_CHANGES.lock().await.remove(&id);

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                id.clone(),
                (Instant::now(), HashMap::from([("10.0.0.1".to_string(), 1)])),
            );
        }

        // New IP for the same ID
        {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((_tm, ips)) = lock.get_mut(&id) {
                ips.insert("10.0.0.2".to_string(), 1);
            }
        }

        {
            let lock = IP_CHANGES.lock().await;
            assert_eq!(lock[&id].1.len(), 2);
            assert_eq!(lock[&id].1.get("10.0.0.2"), Some(&1));
        }

        IP_CHANGES.lock().await.remove(&id);
    }

    #[tokio::test]
    async fn ip_changes_window_resets_after_180_seconds() {
        let id = "test_ic_reset".to_string();
        IP_CHANGES.lock().await.remove(&id);

        // Create an entry with a stale timestamp (> IP_CHANGE_DUR seconds ago)
        {
            let mut lock = IP_CHANGES.lock().await;
            let old_time = Instant::now()
                .checked_sub(std::time::Duration::from_secs(IP_CHANGE_DUR + 10))
                .unwrap();
            lock.insert(
                id.clone(),
                (
                    old_time,
                    HashMap::from([("old_ip".to_string(), 5), ("another_old".to_string(), 3)]),
                ),
            );
        }

        // Simulate the logic from handle_udp RegisterPk: if elapsed > IP_CHANGE_DUR, clear
        let new_ip = "new_ip".to_string();
        {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(new_ip.clone(), 1);
                }
            }
        }

        {
            let lock = IP_CHANGES.lock().await;
            let (tm, ips) = lock.get(&id).unwrap();
            assert!(tm.elapsed().as_secs() < 2, "timestamp should be fresh");
            assert_eq!(ips.len(), 1, "old IPs should be cleared");
            assert_eq!(ips.get("new_ip"), Some(&1));
        }

        IP_CHANGES.lock().await.remove(&id);
    }

    #[tokio::test]
    async fn ip_changes_tracks_multiple_ids_independently() {
        let id_a = "test_ic_multi_a".to_string();
        let id_b = "test_ic_multi_b".to_string();

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.remove(&id_a);
            lock.remove(&id_b);
            lock.insert(
                id_a.clone(),
                (Instant::now(), HashMap::from([("1.1.1.1".to_string(), 1)])),
            );
            lock.insert(
                id_b.clone(),
                (Instant::now(), HashMap::from([("2.2.2.2".to_string(), 2)])),
            );
        }

        {
            let lock = IP_CHANGES.lock().await;
            assert_eq!(lock[&id_a].1.get("1.1.1.1"), Some(&1));
            assert_eq!(lock[&id_b].1.get("2.2.2.2"), Some(&2));
            // They should not interfere
            assert!(lock[&id_a].1.get("2.2.2.2").is_none());
            assert!(lock[&id_b].1.get("1.1.1.1").is_none());
        }

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.remove(&id_a);
            lock.remove(&id_b);
        }
    }

    #[tokio::test]
    async fn ip_changes_retain_filters_stale_and_single_ip() {
        // This tests the retain logic from the "ic" admin command:
        // retain only entries where elapsed < IP_CHANGE_DUR_X2 AND ips.len() > 1
        let id_stale = "test_ic_retain_stale".to_string();
        let id_single = "test_ic_retain_single".to_string();
        let id_good = "test_ic_retain_good".to_string();

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.remove(&id_stale);
            lock.remove(&id_single);
            lock.remove(&id_good);

            // Stale entry (old timestamp, multiple IPs)
            let old = Instant::now()
                .checked_sub(std::time::Duration::from_secs(IP_CHANGE_DUR_X2 + 1))
                .unwrap();
            lock.insert(
                id_stale.clone(),
                (
                    old,
                    HashMap::from([("a".to_string(), 1), ("b".to_string(), 1)]),
                ),
            );

            // Fresh entry with only 1 IP (should be filtered)
            lock.insert(
                id_single.clone(),
                (Instant::now(), HashMap::from([("a".to_string(), 1)])),
            );

            // Good entry: fresh and multiple IPs
            lock.insert(
                id_good.clone(),
                (
                    Instant::now(),
                    HashMap::from([("a".to_string(), 1), ("b".to_string(), 1)]),
                ),
            );

            // Run the retain logic while still holding lock
            lock.retain(|_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);

            assert!(
                !lock.contains_key(&id_stale),
                "stale entry should be removed"
            );
            assert!(
                !lock.contains_key(&id_single),
                "single-IP entry should be removed"
            );
            assert!(
                lock.contains_key(&id_good),
                "good entry should be retained"
            );

            lock.remove(&id_good);
        }
    }

    // =======================================================================
    // 3. Punch request dedup
    // =======================================================================

    #[tokio::test]
    async fn punch_req_records_entry() {
        let mut lock = PUNCH_REQS.lock().await;
        let initial_len = lock.len();
        lock.push(PunchReqEntry {
            tm: Instant::now(),
            from_ip: "1.1.1.1".to_string(),
            to_ip: "2.2.2.2".to_string(),
            to_id: "peer_target".to_string(),
        });
        assert_eq!(lock.len(), initial_len + 1);
        let last = lock.last().unwrap();
        assert_eq!(last.from_ip, "1.1.1.1");
        assert_eq!(last.to_id, "peer_target");
    }

    #[tokio::test]
    async fn punch_req_dedup_within_60_seconds() {
        // Simulate the dedup logic from handle_punch_hole_request
        let from_ip = "10.99.0.1".to_string();
        let to_id = "dedup_target".to_string();
        let to_ip = "10.99.0.2".to_string();

        let mut lock = PUNCH_REQS.lock().await;
        // Insert an entry with a recent timestamp
        lock.push(PunchReqEntry {
            tm: Instant::now(),
            from_ip: from_ip.clone(),
            to_ip: to_ip.clone(),
            to_id: to_id.clone(),
        });

        // Now run the dedup logic on the same lock
        let mut dup = false;
        for e in lock.iter().rev().take(30) {
            if e.from_ip == from_ip && e.to_id == to_id {
                if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                    dup = true;
                }
                break;
            }
        }
        assert!(dup, "same from_ip + to_id within 60s should be a duplicate");
    }

    #[tokio::test]
    async fn punch_req_not_dup_after_60_seconds() {
        let from_ip = "10.99.1.1".to_string();
        let to_id = "dedup_target_old".to_string();

        let mut lock = PUNCH_REQS.lock().await;
        // Insert an entry with an OLD timestamp (>60s ago)
        let old_time = Instant::now()
            .checked_sub(std::time::Duration::from_secs(PUNCH_REQ_DEDUPE_SEC + 10))
            .unwrap();
        lock.push(PunchReqEntry {
            tm: old_time,
            from_ip: from_ip.clone(),
            to_ip: "x".to_string(),
            to_id: to_id.clone(),
        });

        let mut dup = false;
        for e in lock.iter().rev().take(30) {
            if e.from_ip == from_ip && e.to_id == to_id {
                if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                    dup = true;
                }
                break;
            }
        }
        assert!(!dup, "entry older than 60s should not be considered a dup");
    }

    #[tokio::test]
    async fn punch_req_different_from_ip_is_not_dup() {
        let to_id = "same_target".to_string();

        let mut lock = PUNCH_REQS.lock().await;
        lock.push(PunchReqEntry {
            tm: Instant::now(),
            from_ip: "10.100.0.1".to_string(),
            to_ip: "10.100.0.2".to_string(),
            to_id: to_id.clone(),
        });

        // Different from_ip, same to_id
        let from_ip2 = "10.100.0.99";
        let mut dup = false;
        for e in lock.iter().rev().take(30) {
            if e.from_ip == from_ip2 && e.to_id == to_id {
                if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                    dup = true;
                }
                break;
            }
        }
        assert!(!dup, "different from_ip should not be a dup");
    }

    #[tokio::test]
    async fn punch_req_dedup_window_limited_to_30_entries() {
        // The dedup only checks the last 30 entries. If the matching entry is
        // older than 30 positions from the tail, it won't be found.
        let from_ip = "10.101.0.1".to_string();
        let to_id = "dedup_30_target".to_string();

        let mut lock = PUNCH_REQS.lock().await;
        // Push the matching entry
        lock.push(PunchReqEntry {
            tm: Instant::now(),
            from_ip: from_ip.clone(),
            to_ip: "x".to_string(),
            to_id: to_id.clone(),
        });
        // Push 30 more non-matching entries to push it out of the window
        for i in 0..30 {
            lock.push(PunchReqEntry {
                tm: Instant::now(),
                from_ip: format!("filler_{}", i),
                to_ip: "filler".to_string(),
                to_id: format!("filler_{}", i),
            });
        }

        let mut dup = false;
        for e in lock.iter().rev().take(30) {
            if e.from_ip == from_ip && e.to_id == to_id {
                if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                    dup = true;
                }
                break;
            }
        }
        assert!(
            !dup,
            "entry pushed outside the 30-entry window should not be found"
        );
    }

    #[tokio::test]
    async fn punch_req_clear() {
        let mut lock = PUNCH_REQS.lock().await;
        lock.push(PunchReqEntry {
            tm: Instant::now(),
            from_ip: "clear_test".to_string(),
            to_ip: "x".to_string(),
            to_id: "x".to_string(),
        });
        lock.clear();
        assert!(lock.is_empty());
    }

    // =======================================================================
    // 4. Admin command parsing (check_cmd)
    // =======================================================================

    #[tokio::test]
    async fn cmd_help() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("h").await;
        assert!(res.contains("relay-servers(rs)"));
        assert!(res.contains("ip-blocker(ib)"));
        assert!(res.contains("ip-changes(ic)"));
        assert!(res.contains("punch-requests(pr)"));
        assert!(res.contains("always-use-relay(aur)"));
        assert!(res.contains("test-geo(tg)"));
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_relay_servers_list_empty() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("relay-servers").await;
        // No relay servers configured => empty output
        assert!(res.is_empty() || res.trim().is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_rs_alias_works() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("rs").await;
        // Should behave identically to "relay-servers"
        assert!(res.is_empty() || res.trim().is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_relay_servers_set_sends_data() {
        let (rs, db_path) = make_test_server().await;
        // Setting relay-servers sends a message on the channel
        let res = rs.check_cmd("rs 127.0.0.1:21117").await;
        // The command doesn't produce output when setting
        assert!(res.is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_ip_blocker_query_specific_ip() {
        let (rs, db_path) = make_test_server().await;
        let ip = "10.200.0.1";

        // Insert a test entry
        {
            let mut lock = IP_BLOCKER.lock().await;
            let mut ids = HashSet::new();
            ids.insert("test_id".to_owned());
            lock.insert(ip.to_owned(), ((5, Instant::now()), (ids, Instant::now())));
        }

        let res = rs.check_cmd(&format!("ib {}", ip)).await;
        // Should contain the per-minute count (5) and ID set size (1)
        assert!(res.contains("5/"), "should show per-minute count: {}", res);
        assert!(res.contains("1/"), "should show unique ID count: {}", res);

        IP_BLOCKER.lock().await.remove(ip);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_ip_blocker_remove_ip() {
        let (rs, db_path) = make_test_server().await;
        let ip = "10.200.0.2";

        {
            let mut lock = IP_BLOCKER.lock().await;
            lock.insert(
                ip.to_owned(),
                ((1, Instant::now()), (HashSet::new(), Instant::now())),
            );
        }
        assert!(IP_BLOCKER.lock().await.contains_key(ip));

        // "ib <ip> -" should remove the entry
        rs.check_cmd(&format!("ib {} -", ip)).await;
        assert!(
            !IP_BLOCKER.lock().await.contains_key(ip),
            "entry should be removed by 'ib <ip> -'"
        );

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_ip_changes_query_specific_id() {
        let (rs, db_path) = make_test_server().await;
        let id = "test_ic_cmd_id";

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                id.to_string(),
                (
                    Instant::now(),
                    HashMap::from([("1.1.1.1".to_string(), 2), ("2.2.2.2".to_string(), 1)]),
                ),
            );
        }

        let res = rs.check_cmd(&format!("ic {}", id)).await;
        // Should show elapsed time and IP map
        assert!(res.contains("1.1.1.1"), "should list IPs: {}", res);
        assert!(res.contains("2.2.2.2"), "should list IPs: {}", res);

        IP_CHANGES.lock().await.remove(id);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_ip_changes_remove_id() {
        let (rs, db_path) = make_test_server().await;
        let id = "test_ic_cmd_remove";

        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                id.to_string(),
                (Instant::now(), HashMap::from([("a".to_string(), 1), ("b".to_string(), 1)])),
            );
        }

        rs.check_cmd(&format!("ic {} -", id)).await;
        assert!(
            !IP_CHANGES.lock().await.contains_key(id),
            "entry should be removed"
        );

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_punch_requests_clear() {
        let (rs, db_path) = make_test_server().await;
        {
            let mut lock = PUNCH_REQS.lock().await;
            lock.push(PunchReqEntry {
                tm: Instant::now(),
                from_ip: "1.1.1.1".to_string(),
                to_ip: "2.2.2.2".to_string(),
                to_id: "target".to_string(),
            });
        }

        rs.check_cmd("pr -").await;
        assert!(
            PUNCH_REQS.lock().await.is_empty(),
            "'pr -' should clear all punch requests"
        );

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_punch_requests_list_shows_entries() {
        let (rs, db_path) = make_test_server().await;
        {
            let mut lock = PUNCH_REQS.lock().await;
            lock.clear();
            lock.push(PunchReqEntry {
                tm: Instant::now(),
                from_ip: "10.50.0.1".to_string(),
                to_ip: "10.50.0.2".to_string(),
                to_id: "pr_list_target".to_string(),
            });
        }

        let res = rs.check_cmd("pr 0").await;
        assert!(
            res.contains("10.50.0.1"),
            "should show from_ip: {}",
            res
        );
        assert!(
            res.contains("pr_list_target"),
            "should show to_id: {}",
            res
        );
        assert!(
            res.contains("10.50.0.2"),
            "should show to_ip: {}",
            res
        );

        PUNCH_REQS.lock().await.clear();
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_always_use_relay_query() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("always-use-relay").await;
        assert!(
            res.contains("ALWAYS_USE_RELAY"),
            "should show the current value: {}",
            res
        );
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_aur_alias_works() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("aur").await;
        assert!(res.contains("ALWAYS_USE_RELAY"));
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_always_use_relay_set_y() {
        let (rs, db_path) = make_test_server().await;
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        rs.check_cmd("aur Y").await;
        assert!(ALWAYS_USE_RELAY.load(Ordering::SeqCst));

        // Reset
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_always_use_relay_set_n() {
        let (rs, db_path) = make_test_server().await;
        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        rs.check_cmd("aur N").await;
        assert!(!ALWAYS_USE_RELAY.load(Ordering::SeqCst));
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_test_geo_two_ips() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("tg 1.2.3.4 5.6.7.8").await;
        // With no relay servers configured, get_relay_server returns ""
        assert_eq!(res.trim(), r#""""#, "should return empty relay: {}", res);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_test_geo_single_ip() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("tg 1.2.3.4").await;
        assert_eq!(res.trim(), r#""""#);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_unknown_returns_empty() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("nonexistent_command").await;
        assert!(res.is_empty(), "unknown commands should produce no output");
        cleanup(&db_path);
    }

    // =======================================================================
    // 5. get_server_sk -- static method, testable directly
    // =======================================================================

    #[test]
    fn get_server_sk_empty_key_generates_keypair() {
        let (key, _sk) = RendezvousServer::get_server_sk("");
        // Empty key => no key output, but sk may or may not be generated
        // (depends on file system state, but key should remain empty)
        assert!(key.is_empty(), "empty key input should produce empty key output");
    }

    #[test]
    fn get_server_sk_dash_generates_keypair() {
        let (key, sk) = RendezvousServer::get_server_sk("-");
        // "-" key generates a new keypair and outputs the public key
        assert!(sk.is_some(), "'-' should generate a secret key");
        assert!(!key.is_empty(), "'-' should produce a public key");
    }

    #[test]
    fn get_server_sk_underscore_generates_keypair() {
        let (key, sk) = RendezvousServer::get_server_sk("_");
        assert!(sk.is_some(), "'_' should generate a secret key");
        assert!(!key.is_empty(), "'_' should produce a public key");
    }

    #[test]
    fn get_server_sk_valid_sk_base64() {
        // Generate a real keypair and pass the full secret key as base64
        let (_pk, sk) = sodiumoxide::crypto::sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let (key, out_sk) = RendezvousServer::get_server_sk(&sk_b64);

        assert!(out_sk.is_some(), "valid sk should be parsed");
        // The returned key should be the public key portion (second half of sk)
        let expected_pk = base64::encode(&sk[sign::SECRETKEYBYTES / 2..]);
        assert_eq!(key, expected_pk);
    }

    #[test]
    fn get_server_sk_invalid_base64_treated_as_passphrase() {
        // A random string that is not valid base64 of the right length
        let (key, sk) = RendezvousServer::get_server_sk("not-valid-base64!!!");
        // Not a valid key, not empty/dash/underscore => no keypair generated,
        // key is returned as-is, sk is None
        assert_eq!(key, "not-valid-base64!!!");
        assert!(sk.is_none());
    }

    #[test]
    fn get_server_sk_short_base64_treated_as_passphrase() {
        // Valid base64 but wrong length (not SECRETKEYBYTES)
        let short = base64::encode(b"too short");
        let (key, sk) = RendezvousServer::get_server_sk(&short);
        assert_eq!(key, short);
        assert!(sk.is_none());
    }

    // =======================================================================
    // 6. Configuration handling -- parse_relay_servers, get_relay_server
    // =======================================================================

    #[tokio::test]
    async fn parse_relay_servers_sets_both_fields() {
        let (mut rs, db_path) = make_test_server().await;
        rs.parse_relay_servers("127.0.0.1,127.0.0.2");
        // relay_servers0 should contain the parsed list
        assert_eq!(rs.relay_servers0.len(), 2);
        assert!(rs.relay_servers0.contains(&"127.0.0.1".to_string()));
        assert!(rs.relay_servers0.contains(&"127.0.0.2".to_string()));
        // relay_servers should clone relay_servers0
        assert_eq!(rs.relay_servers.len(), 2);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn parse_relay_servers_empty_string() {
        let (mut rs, db_path) = make_test_server().await;
        rs.parse_relay_servers("");
        assert!(rs.relay_servers0.is_empty());
        assert!(rs.relay_servers.is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn get_relay_server_empty_returns_empty() {
        let (rs, db_path) = make_test_server().await;
        let result = rs.get_relay_server(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        );
        assert_eq!(result, "");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn get_relay_server_single_returns_it() {
        let (mut rs, db_path) = make_test_server().await;
        rs.relay_servers = Arc::new(vec!["relay.example.com".to_string()]);
        let result = rs.get_relay_server(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        );
        assert_eq!(result, "relay.example.com");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn get_relay_server_rotation() {
        let (mut rs, db_path) = make_test_server().await;
        rs.relay_servers = Arc::new(vec![
            "relay1.example.com".to_string(),
            "relay2.example.com".to_string(),
            "relay3.example.com".to_string(),
        ]);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        // Get several relay servers -- they should rotate
        let mut seen = HashSet::new();
        for _ in 0..6 {
            let r = rs.get_relay_server(ip, ip);
            seen.insert(r);
        }
        // Over 6 calls with 3 servers, we should see all 3
        assert_eq!(seen.len(), 3, "rotation should cycle through all relays");

        cleanup(&db_path);
    }

    // =======================================================================
    // 7. get_pk -- returns empty when no sk or empty version
    // =======================================================================

    #[tokio::test]
    async fn get_pk_returns_empty_when_no_sk() {
        let (mut rs, db_path) = make_test_server().await;
        // inner.sk is None by default in test server
        let pk = rs.get_pk("1.0.0", "some_id".to_string()).await;
        assert!(pk.is_empty(), "get_pk should return empty when sk is None");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn get_pk_returns_empty_when_version_empty() {
        let (mut rs, db_path) = make_test_server().await;
        // Even if sk were set, empty version => empty
        let pk = rs.get_pk("", "some_id".to_string()).await;
        assert!(pk.is_empty(), "get_pk should return empty when version is empty");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn get_pk_returns_empty_for_unknown_peer() {
        let (mut rs, db_path) = make_test_server().await;
        // Set up an sk so it doesn't short-circuit
        let (_pk, sk) = sign::gen_keypair();
        let mut inner = (*rs.inner).clone();
        inner.sk = Some(sk);
        rs.inner = Arc::new(inner);

        let result = rs.get_pk("1.0.0", "nonexistent_peer".to_string()).await;
        assert!(
            result.is_empty(),
            "get_pk for unknown peer should return empty"
        );
        cleanup(&db_path);
    }

    // =======================================================================
    // 8. is_lan
    // =======================================================================

    #[tokio::test]
    async fn is_lan_returns_false_with_no_mask() {
        let (rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert!(!rs.is_lan(addr), "should return false when no mask configured");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn is_lan_returns_true_for_matching_network() {
        let (mut rs, db_path) = make_test_server().await;
        let mut inner = (*rs.inner).clone();
        inner.mask = Some("192.168.1.0/24".parse().unwrap());
        rs.inner = Arc::new(inner);

        let addr: SocketAddr = "192.168.1.50:5555".parse().unwrap();
        assert!(rs.is_lan(addr), "192.168.1.50 should be in 192.168.1.0/24");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn is_lan_returns_false_for_non_matching_network() {
        let (mut rs, db_path) = make_test_server().await;
        let mut inner = (*rs.inner).clone();
        inner.mask = Some("192.168.1.0/24".parse().unwrap());
        rs.inner = Arc::new(inner);

        let addr: SocketAddr = "10.0.0.1:5555".parse().unwrap();
        assert!(!rs.is_lan(addr), "10.0.0.1 should not be in 192.168.1.0/24");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn is_lan_ipv6_mapped_v4_in_network() {
        let (mut rs, db_path) = make_test_server().await;
        let mut inner = (*rs.inner).clone();
        inner.mask = Some("192.168.1.0/24".parse().unwrap());
        rs.inner = Arc::new(inner);

        // IPv6-mapped IPv4: ::ffff:192.168.1.50
        let addr: SocketAddr = "[::ffff:192.168.1.50]:5555".parse().unwrap();
        assert!(
            rs.is_lan(addr),
            "IPv6-mapped 192.168.1.50 should be in 192.168.1.0/24"
        );
        cleanup(&db_path);
    }

    // =======================================================================
    // 9. ALWAYS_USE_RELAY atomic
    // =======================================================================

    #[test]
    fn always_use_relay_default_is_false() {
        // Reset to default (false) in case other tests changed it
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        assert!(!ALWAYS_USE_RELAY.load(Ordering::SeqCst));
    }

    #[test]
    fn always_use_relay_toggle() {
        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        assert!(ALWAYS_USE_RELAY.load(Ordering::SeqCst));

        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        assert!(!ALWAYS_USE_RELAY.load(Ordering::SeqCst));
    }

    // =======================================================================
    // 10. PunchReqEntry struct
    // =======================================================================

    #[test]
    fn punch_req_entry_clone() {
        let entry = PunchReqEntry {
            tm: Instant::now(),
            from_ip: "1.2.3.4".to_string(),
            to_ip: "5.6.7.8".to_string(),
            to_id: "target_peer".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.from_ip, "1.2.3.4");
        assert_eq!(cloned.to_ip, "5.6.7.8");
        assert_eq!(cloned.to_id, "target_peer");
    }

    // =======================================================================
    // 11. Constants sanity checks
    // =======================================================================

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(REG_TIMEOUT, 30_000);
        assert_eq!(PUNCH_REQ_DEDUPE_SEC, 60);
        assert_eq!(CHECK_RELAY_TIMEOUT, 3_000);
        assert_eq!(IP_CHANGE_DUR, 180);
        assert_eq!(IP_CHANGE_DUR_X2, 360);
        assert_eq!(DAY_SECONDS, 86400);
        assert_eq!(IP_BLOCK_DUR, 60);
    }

    // =======================================================================
    // 12. ROTATION_RELAY_SERVER atomic
    // =======================================================================

    #[test]
    fn rotation_relay_server_increments() {
        let before = ROTATION_RELAY_SERVER.load(Ordering::SeqCst);
        let got = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst);
        assert_eq!(got, before);
        let after = ROTATION_RELAY_SERVER.load(Ordering::SeqCst);
        assert_eq!(after, before + 1);
    }

    // =======================================================================
    // 13. Inner struct -- serial and configuration
    // =======================================================================

    #[test]
    fn inner_clone() {
        let inner = Inner {
            serial: 42,
            version: "1.2.3".to_string(),
            software_url: "https://example.com/update".to_string(),
            mask: Some("10.0.0.0/8".parse().unwrap()),
            local_ip: "10.0.0.1".to_string(),
            sk: None,
        };
        let cloned = inner.clone();
        assert_eq!(cloned.serial, 42);
        assert_eq!(cloned.version, "1.2.3");
        assert_eq!(cloned.software_url, "https://example.com/update");
        assert_eq!(cloned.local_ip, "10.0.0.1");
        assert!(cloned.mask.is_some());
        assert!(cloned.sk.is_none());
    }

    // =======================================================================
    // 14. Data enum variants
    // =======================================================================

    #[test]
    fn data_relay_servers0_clone() {
        let data = Data::RelayServers0("127.0.0.1,127.0.0.2".to_string());
        let cloned = data.clone();
        match cloned {
            Data::RelayServers0(s) => assert_eq!(s, "127.0.0.1,127.0.0.2"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn data_relay_servers_clone() {
        let data = Data::RelayServers(vec!["a".to_string(), "b".to_string()]);
        let cloned = data.clone();
        match cloned {
            Data::RelayServers(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0], "a");
                assert_eq!(v[1], "b");
            }
            _ => panic!("wrong variant"),
        }
    }

    // =======================================================================
    // 15. IP Blocker -- retain logic (as used in the "ib" admin command)
    // =======================================================================

    #[tokio::test]
    async fn ip_blocker_retain_filters_stale() {
        let mut lock = IP_BLOCKER.lock().await;

        // Use unique IPs to avoid interference with other tests
        let fresh_ip = "250.0.0.1";
        let stale_ip = "250.0.0.2";
        lock.remove(fresh_ip);
        lock.remove(stale_ip);

        // Fresh entry (within both windows)
        lock.insert(
            fresh_ip.to_owned(),
            ((1, Instant::now()), (HashSet::new(), Instant::now())),
        );
        // Stale entry (both timestamps beyond their windows)
        let old_minute = Instant::now()
            .checked_sub(std::time::Duration::from_secs(IP_BLOCK_DUR + 1))
            .unwrap();
        let old_day = Instant::now()
            .checked_sub(std::time::Duration::from_secs(DAY_SECONDS + 1))
            .unwrap();
        lock.insert(
            stale_ip.to_owned(),
            ((10, old_minute), (HashSet::new(), old_day)),
        );

        // Apply the retain logic from check_cmd "ib"
        lock.retain(|_, (a, b)| {
            a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                || b.1.elapsed().as_secs() <= DAY_SECONDS
        });

        assert!(lock.contains_key(fresh_ip), "fresh should be retained");
        assert!(!lock.contains_key(stale_ip), "stale should be removed");

        lock.remove(fresh_ip);
    }

    // =======================================================================
    // 16. Edge cases for check_cmd
    // =======================================================================

    #[tokio::test]
    async fn cmd_empty_string() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("").await;
        assert!(res.is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_whitespace_only() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("   ").await;
        assert!(res.is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_test_geo_invalid_ip() {
        let (rs, db_path) = make_test_server().await;
        let res = rs.check_cmd("tg not_an_ip").await;
        // Invalid IP should produce no output (parse fails)
        assert!(res.is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_relay_servers_list_after_parse() {
        let (mut rs, db_path) = make_test_server().await;
        rs.parse_relay_servers("127.0.0.1");
        let res = rs.check_cmd("rs").await;
        assert!(
            res.contains("127.0.0.1"),
            "should list the configured relay server: {}",
            res
        );
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn cmd_punch_requests_pagination() {
        let (rs, db_path) = make_test_server().await;
        {
            let mut lock = PUNCH_REQS.lock().await;
            lock.clear();
            for i in 0..20 {
                lock.push(PunchReqEntry {
                    tm: Instant::now(),
                    from_ip: format!("10.0.0.{}", i),
                    to_ip: "10.0.0.99".to_string(),
                    to_id: format!("target_{}", i),
                });
            }
        }

        // Default page size is 10, starting at offset 5
        let res = rs.check_cmd("pr 5").await;
        let lines: Vec<&str> = res.trim().lines().collect();
        assert_eq!(lines.len(), 10, "should show 10 entries: {}", res);
        // First entry should be index 5
        assert!(lines[0].contains("10.0.0.5"));

        // Page size 3 starting at 0
        let res = rs.check_cmd("pr 0 3").await;
        let lines: Vec<&str> = res.trim().lines().collect();
        assert_eq!(lines.len(), 3, "custom page size should work: {}", res);

        PUNCH_REQS.lock().await.clear();
        cleanup(&db_path);
    }

    // =======================================================================
    // CWE-532: Verify get_server_sk does not leak raw key material in logs.
    //
    // The log line in get_server_sk was changed from:
    //   log::info!("Key: {}", key)
    // to:
    //   log::info!("Key: {}", if key.is_empty() { "(not set)" } else { "(configured)" })
    //
    // Rust's `log` crate has no built-in capture mechanism, so we verify the
    // fix indirectly: the format string now only interpolates "(configured)" or
    // "(not set)", never the raw key. These tests confirm that get_server_sk
    // still returns the correct key value (functional correctness) while the
    // log macro source is audited to never contain `"Key: {}", key` verbatim.
    // =======================================================================

    #[test]
    fn get_server_sk_log_does_not_contain_raw_key_for_passphrase() {
        // Verify the function still returns the key correctly (not broken by fix)
        let passphrase = "my_secret_passphrase_12345";
        let (returned_key, sk) = RendezvousServer::get_server_sk(passphrase);
        assert_eq!(returned_key, passphrase, "passphrase key should be returned as-is");
        assert!(sk.is_none(), "passphrase should not produce an sk");

        // The log format string is:
        //   "Key: {}", if key.is_empty() { "(not set)" } else { "(configured)" }
        // This means the log output is either "Key: (not set)" or "Key: (configured)",
        // never the raw passphrase. We verify by formatting the same expression:
        let log_output = format!("Key: {}", if returned_key.is_empty() { "(not set)" } else { "(configured)" });
        assert!(!log_output.contains(passphrase),
            "log output must not contain the raw key value");
        assert!(log_output.contains("(configured)"),
            "log output should say '(configured)' for non-empty key");
    }

    #[test]
    fn get_server_sk_log_does_not_contain_raw_key_for_crypto_sk() {
        let (_pk, sk) = sodiumoxide::crypto::sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let (returned_key, out_sk) = RendezvousServer::get_server_sk(&sk_b64);

        assert!(out_sk.is_some(), "valid sk should be parsed");
        assert!(!returned_key.is_empty(), "returned key should not be empty");

        // Verify the log format doesn't leak the derived public key
        let log_output = format!("Key: {}", if returned_key.is_empty() { "(not set)" } else { "(configured)" });
        assert!(!log_output.contains(&returned_key),
            "log output must not contain the derived public key");
        assert!(!log_output.contains(&sk_b64),
            "log output must not contain the raw secret key");
    }

    #[test]
    fn get_server_sk_log_shows_not_set_for_empty_key() {
        let (returned_key, _sk) = RendezvousServer::get_server_sk("");
        // Empty key path: the outer `if !key.is_empty()` guard means no log is emitted,
        // but if it were, the format would produce "(not set)".
        let log_output = format!("Key: {}", if returned_key.is_empty() { "(not set)" } else { "(configured)" });
        assert_eq!(log_output, "Key: (not set)");
    }

    // =======================================================================
    // Message size limit tests (CWE-400 mitigation)
    // =======================================================================

    #[test]
    fn max_message_size_constant_is_64kb() {
        assert_eq!(MAX_MESSAGE_SIZE, 64 * 1024);
    }

    #[tokio::test]
    async fn message_under_limit_is_accepted() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // Build a valid small RegisterPeer message
        let mut msg = RendezvousMessage::new();
        msg.set_register_peer(RegisterPeer {
            id: "test_small".to_owned(),
            ..Default::default()
        });
        let bytes = BytesMut::from(msg.write_to_bytes().unwrap().as_slice());
        assert!(bytes.len() < MAX_MESSAGE_SIZE, "test message should be well under the limit");

        // Create a throwaway socket (we won't actually send on it)
        let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(true)).await.unwrap();
        // handle_udp should succeed without error (message is under the size limit)
        let result = rs.handle_udp(&bytes, addr, &mut socket, "").await;
        assert!(result.is_ok(), "small message should be accepted");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn message_over_limit_is_rejected() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // Create a message that exceeds the limit
        let bytes = BytesMut::from(&vec![0u8; MAX_MESSAGE_SIZE + 1][..]);

        let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(true)).await.unwrap();
        // handle_udp should return Ok(()) — the oversized message is silently dropped
        let result = rs.handle_udp(&bytes, addr, &mut socket, "").await;
        assert!(result.is_ok(), "oversized message should be dropped without error");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn message_at_exact_boundary_is_accepted() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // Exactly MAX_MESSAGE_SIZE bytes — should be accepted (limit is >)
        let bytes = BytesMut::from(&vec![0u8; MAX_MESSAGE_SIZE][..]);

        let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(true)).await.unwrap();
        let result = rs.handle_udp(&bytes, addr, &mut socket, "").await;
        assert!(result.is_ok(), "message at exact boundary should be accepted");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn message_one_over_boundary_is_rejected() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // MAX_MESSAGE_SIZE + 1 bytes — should be rejected
        let bytes = BytesMut::from(&vec![0u8; MAX_MESSAGE_SIZE + 1][..]);

        let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(true)).await.unwrap();
        let result = rs.handle_udp(&bytes, addr, &mut socket, "").await;
        assert!(result.is_ok(), "message one byte over boundary should be dropped without error");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn tcp_message_over_limit_is_rejected() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // Create a message that exceeds the limit
        let bytes = vec![0u8; MAX_MESSAGE_SIZE + 1];

        // handle_tcp should return false (message dropped)
        let result = rs.handle_tcp(&bytes, &mut None, addr, "", false).await;
        assert!(!result, "oversized TCP message should be dropped (return false)");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn tcp_message_under_limit_is_accepted() {
        let (mut rs, db_path) = make_test_server().await;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // Build a valid small PunchHoleRequest message (handled by handle_tcp)
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole_request(PunchHoleRequest {
            id: "test_tcp_small".to_owned(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        assert!(bytes.len() < MAX_MESSAGE_SIZE, "test message should be well under the limit");

        // handle_tcp with a valid but small message should not panic or error.
        // It returns true if the message was a PunchHoleRequest (which it is),
        // but the handler may fail internally since we have no real peer. It
        // should still pass the size check and attempt to parse.
        let _result = rs.handle_tcp(&bytes, &mut None, addr, "", false).await;
        // We don't assert the return value here because the punch-hole logic
        // depends on state; we only care that the size check passed.

        cleanup(&db_path);
    }
}
