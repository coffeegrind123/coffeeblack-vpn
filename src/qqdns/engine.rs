//! The symmetric UDP-over-DNS duplex engine — a Tokio port of QQ-Tunnel's
//! `main.py`.
//!
//! Both ends of the tunnel run this identical engine; only the [`EngineConfig`]
//! differs. It wires together four kinds of task:
//!
//! * **`h_recv`** — reads raw UDP datagrams from the local app socket
//!   (`h_in_address`; on the server that's traffic the AmneziaWG datapath
//!   replies with), fragments each into DNS queries and fans them across the
//!   send queues.
//! * **`wan_send` workers** — one per resolver (`dns_ips`); each drains its
//!   queue and paces datagrams out to `resolver:53`, honouring
//!   `packets_send_interval` (resolver rate limits) and dropping datagrams
//!   that waited past `packets_wait_time_limit`.
//! * **`wan_recv`** — the authoritative-side listener (`receive_port`, usually
//!   53). Parses inbound queries whose QNAME ends in one of our `recv_domains`,
//!   reassembles the fragments, decodes, and emits the recovered datagram to
//!   the local app; always answers the resolver with a NOERROR/empty response.
//!
//! ## Roles
//!
//! *Client role* (`h_out_address = None`): learns the local app's address from
//! whoever first sends to `h_in_address` and returns decoded traffic there.
//!
//! *Server role* (`h_out_address = Some(addr)`): the local app is at a fixed
//! address (the AmneziaWG loopback backend); only datagrams from it are
//! accepted on the `h_recv` side, and decoded traffic is delivered to it.
//!
//! ## Single-tunnel property (important)
//!
//! The upstream wire format carries no client identifier, so one engine
//! instance is a **single point-to-point tunnel**: on the server every decoded
//! datagram is delivered from one local source socket, so AmneziaWG sees a
//! single peer endpoint. One QQ-DNS instance therefore serves one client
//! endpoint at a time — it is a blackout-survival path for a single client,
//! not a multi-peer transport. Running several clients means several instances
//! (distinct `h_in` ports + delegated domains).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::qqdns::codec::{
    b32_decode_nopad, get_base32_final_domains, get_chunk_data, get_chunk_len, SendDomain,
    DATA_OFFSET_WIDTH, TOTAL_DATA_OFFSET,
};
use crate::qqdns::dns::{
    build_dns_query, create_noerror_empty_response, encode_qname, handle_dns_request, label_domain,
    match_recv_suffix, resolve_addr,
};
use crate::qqdns::reassembly::DataHandler;

/// Max datagrams queued per resolver before new ones are dropped
/// (upstream `PACKETS_QUEUE_SIZE`).
const PACKETS_QUEUE_SIZE: usize = 1024;
/// How long a partial datagram's fragments live awaiting completion
/// (upstream `ASSEMBLE_TIME`).
const ASSEMBLE_TIME: Duration = Duration::from_secs(13);
/// Receive buffer for a single UDP datagram (upstream reads 65575).
const RECV_BUF: usize = 65_575;

/// Full engine configuration — the Rust analogue of QQ-Tunnel's `config.json`
/// plus the resolved role.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Resolver IPs queries are sent to (always on port 53), round-robined.
    pub dns_ips: Vec<String>,
    /// Source address the send sockets bind to (`send_interface_ip`).
    pub send_interface_ip: String,
    /// Address the authoritative listener binds to (`receive_interface_ip`).
    pub receive_interface_ip: String,
    /// Port the authoritative listener binds to (usually 53, or 5353 behind a
    /// PREROUTING redirect).
    pub receive_port: u16,
    /// Domains delegated to the *other* side — data-bearing queries target
    /// these. Round-robined.
    pub send_domains: Vec<String>,
    /// Our own delegated domains — inbound queries whose QNAME ends in one of
    /// these are accepted.
    pub recv_domains: Vec<String>,
    /// Local UDP app endpoint bound by the engine (`h_in_address`).
    pub h_in_address: String,
    /// Server role: fixed local app target (`h_out_address`). `None` = client
    /// role (learn it from the first sender).
    pub h_out_address: Option<String>,
    /// Max final domain length (without trailing dot), e.g. 253.
    pub max_domain_len: usize,
    /// Max length of each subdomain label (≤63).
    pub max_sub_len: usize,
    /// Extra transmissions per datagram (0 = send once). Multiplies bandwidth.
    pub retries: usize,
    /// DNS query type used for outbound queries (1=A, 28=AAAA, 16=TXT, …).
    pub send_query_type: u16,
    /// Pacing interval between packets per resolver queue.
    pub packets_send_interval: Duration,
    /// Drop a queued datagram that has waited longer than this.
    pub packets_wait_time_limit: Duration,
    /// Number of source sockets used to spread queries across ports.
    pub send_sock_numbers: usize,
}

impl EngineConfig {
    fn validate(&self) -> Result<()> {
        if self.dns_ips.is_empty() {
            return Err(anyhow!("dns_ips is empty"));
        }
        if self.send_domains.is_empty() {
            return Err(anyhow!("send_domains is empty"));
        }
        if self.recv_domains.is_empty() {
            return Err(anyhow!("recv_domains is empty"));
        }
        if self.send_sock_numbers == 0 {
            return Err(anyhow!("send_sock_numbers must be >= 1"));
        }
        let max_encoded = self.max_domain_len + 2;
        if max_encoded > 255 {
            return Err(anyhow!("max_domain_len too large (max 253)"));
        }
        if self.max_sub_len > 63 {
            return Err(anyhow!("max_sub_len cannot exceed 63"));
        }
        Ok(())
    }
}

/// One queued send: the fragments (each already a full DNS query datagram),
/// tagged with enqueue time and try index. The target resolver is fixed by
/// the worker that drains this job's queue (one queue per resolver).
struct SendJob {
    /// `(send_socket, dns_query_bytes)` per fragment.
    frags: Vec<(Arc<UdpSocket>, Vec<u8>)>,
    entry_time: Instant,
    curr_try: usize,
}

/// A running engine. Dropping this does not stop the tasks; call
/// [`EngineHandle::stop`] (the supervisor does this on reconfigure/disable).
pub struct EngineHandle {
    tasks: Vec<JoinHandle<()>>,
    listen: String,
    h_in: String,
}

impl EngineHandle {
    pub fn listen_addr(&self) -> &str {
        &self.listen
    }
    pub fn h_in_addr(&self) -> &str {
        &self.h_in
    }
    /// Abort every task. UDP relay tasks are stateless enough that abrupt
    /// cancellation is safe — the peer re-establishes on its next keepalive.
    pub fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
    /// True if every task is still alive.
    pub fn is_running(&self) -> bool {
        self.tasks.iter().all(|t| !t.is_finished())
    }
}

/// Shared last-seen local-app address (`last_h_addr`). Read by `wan_recv` to
/// know where decoded traffic goes; written by `h_recv` in client role.
type LastHAddr = Arc<Mutex<Option<SocketAddr>>>;

/// Precomputed send-domain table (QNAME + fitted chunk length).
fn build_send_domains(cfg: &EngineConfig) -> Result<Vec<SendDomain>> {
    let max_encoded = (cfg.max_domain_len + 2) as i64;
    let mut out = Vec::with_capacity(cfg.send_domains.len());
    for d in &cfg.send_domains {
        let qname = encode_qname(d.to_ascii_lowercase().as_bytes());
        let chunk_len = get_chunk_len(
            max_encoded,
            qname.len() as i64,
            cfg.max_sub_len as i64,
            DATA_OFFSET_WIDTH as i64,
        )
        .with_context(|| format!("send domain '{d}' leaves no room for data"))?;
        out.push(SendDomain {
            qname_encoded: qname,
            chunk_len,
        });
    }
    Ok(out)
}

/// Start the engine. Binds all sockets up front (so a bind failure is a hard,
/// reported error rather than a silent dead task) and spawns the task set.
pub async fn start(cfg: EngineConfig) -> Result<EngineHandle> {
    cfg.validate()?;

    let send_domains = Arc::new(build_send_domains(&cfg)?);
    let recv_domains: Arc<Vec<Vec<Vec<u8>>>> = Arc::new(
        cfg.recv_domains
            .iter()
            .map(|d| label_domain(d.to_ascii_lowercase().as_bytes()))
            .collect(),
    );

    let resolvers: Vec<SocketAddr> = cfg
        .dns_ips
        .iter()
        .map(|ip| {
            // "host:port" (e.g. an explicit `[v6]:53`, or a non-standard port
            // behind a redirect) is used verbatim; a bare host/IP defaults to
            // the standard resolver port 53 (matching upstream).
            if let Ok(sa) = ip.parse::<SocketAddr>() {
                return Ok(sa);
            }
            resolve_addr(&format!("{ip}:53"))
                .ok_or_else(|| anyhow!("cannot resolve dns_ip '{ip}'"))
        })
        .collect::<Result<_>>()?;

    // Local app socket (h_in_address): received-from in h_recv, sent-to in wan_recv.
    let h_in_sock = Arc::new(
        UdpSocket::bind(&cfg.h_in_address)
            .await
            .with_context(|| format!("bind h_in_address '{}'", cfg.h_in_address))?,
    );

    // Authoritative listener (receive_interface_ip:receive_port).
    let listen = format!("{}:{}", cfg.receive_interface_ip, cfg.receive_port);
    let wan_sock = Arc::new(
        UdpSocket::bind(&listen)
            .await
            .with_context(|| format!("bind receive address '{listen}'"))?,
    );

    // N source sockets bound to send_interface_ip:0 for port spreading.
    let mut send_socks: Vec<Arc<UdpSocket>> = Vec::with_capacity(cfg.send_sock_numbers);
    for _ in 0..cfg.send_sock_numbers {
        let bind = format!("{}:0", cfg.send_interface_ip);
        let s = UdpSocket::bind(&bind)
            .await
            .with_context(|| format!("bind send socket '{bind}'"))?;
        send_socks.push(Arc::new(s));
    }
    let send_socks = Arc::new(send_socks);

    // Fixed vs learned local-app address.
    let (last_h_addr, use_fixed): (LastHAddr, bool) = match &cfg.h_out_address {
        Some(a) => {
            let addr = resolve_addr(a).ok_or_else(|| anyhow!("cannot resolve h_out_address '{a}'"))?;
            (Arc::new(Mutex::new(Some(addr))), true)
        }
        None => (Arc::new(Mutex::new(None)), false),
    };

    // One bounded queue + worker per resolver.
    let mut senders: Vec<mpsc::Sender<SendJob>> = Vec::with_capacity(resolvers.len());
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    for resolver in &resolvers {
        let (tx, rx) = mpsc::channel::<SendJob>(PACKETS_QUEUE_SIZE);
        senders.push(tx);
        let wait_limit = cfg.packets_wait_time_limit;
        let interval = cfg.packets_send_interval;
        let resolver = *resolver;
        tasks.push(tokio::spawn(wan_send_worker(rx, wait_limit, interval, resolver)));
    }
    let senders = Arc::new(senders);
    let resolvers = Arc::new(resolvers);

    // h_recv: local app -> DNS queries.
    tasks.push(tokio::spawn(h_recv(
        Arc::clone(&h_in_sock),
        Arc::clone(&send_socks),
        Arc::clone(&senders),
        Arc::clone(&send_domains),
        Arc::clone(&resolvers),
        Arc::clone(&last_h_addr),
        use_fixed,
        cfg.clone(),
    )));

    // wan_recv: DNS queries -> local app.
    tasks.push(tokio::spawn(wan_recv(
        Arc::clone(&wan_sock),
        Arc::clone(&h_in_sock),
        Arc::clone(&recv_domains),
        Arc::clone(&last_h_addr),
    )));

    info!(
        listen = %listen,
        h_in = %cfg.h_in_address,
        role = if use_fixed { "server" } else { "client" },
        resolvers = resolvers.len(),
        send_socks = cfg.send_sock_numbers,
        "qqdns engine started"
    );

    Ok(EngineHandle {
        tasks,
        listen,
        h_in: cfg.h_in_address,
    })
}

/// Drains one resolver's queue, pacing datagrams out to `resolver:53`.
async fn wan_send_worker(
    mut rx: mpsc::Receiver<SendJob>,
    wait_limit: Duration,
    interval: Duration,
    resolver: SocketAddr,
) {
    while let Some(job) = rx.recv().await {
        if job.entry_time.elapsed() > wait_limit {
            debug!("qqdns: drop delayed packet");
            continue;
        }
        // Alternate iteration direction per try (upstream behaviour: spreads
        // which fragments go first so a truncated burst still varies).
        let n = job.frags.len();
        let reverse = job.curr_try & 1 == 1;
        for k in 0..n {
            let i = if reverse { n - 1 - k } else { k };
            let (sock, data) = &job.frags[i];
            if let Err(e) = sock.send_to(data, resolver).await {
                warn!(error = %e, %resolver, "qqdns: send error");
                break;
            }
            if !interval.is_zero() {
                tokio::time::sleep(interval).await;
            }
        }
    }
}

/// Reads local-app datagrams, encodes each into DNS queries, and fans copies
/// (one per retry) across the resolver queues.
#[allow(clippy::too_many_arguments)]
async fn h_recv(
    h_in_sock: Arc<UdpSocket>,
    send_socks: Arc<Vec<Arc<UdpSocket>>>,
    senders: Arc<Vec<mpsc::Sender<SendJob>>>,
    send_domains: Arc<Vec<SendDomain>>,
    resolvers: Arc<Vec<SocketAddr>>,
    last_h_addr: LastHAddr,
    use_fixed: bool,
    cfg: EngineConfig,
) {
    let tries = cfg.retries + 1;
    let n_socks = send_socks.len();
    let n_domains = send_domains.len();
    let n_res = resolvers.len();

    // Rolling indices/counters (single-task, no sync needed). `senders[i]`
    // drains to `resolvers[i]`, so one rolling index spreads jobs across
    // resolvers with per-resolver pacing (equivalent to upstream's separate
    // send_ip/queue counters, which stay a constant permutation apart).
    let mut send_sock_index = rr_seed(n_socks);
    let mut query_id: u16 = rr_seed(0x1_0000) as u16;
    let mut data_offset: u32 = rr_seed(TOTAL_DATA_OFFSET as usize) as u32;
    let mut res_index = rr_seed(n_res);
    let mut send_domain_index = rr_seed(n_domains);

    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, src) = match h_in_sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "qqdns: h_in recv error");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if len == 0 {
            continue;
        }

        // Learn or gate the local-app address.
        if use_fixed {
            let fixed = *last_h_addr.lock().unwrap();
            if fixed != Some(src) {
                continue; // server: only accept the configured backend
            }
        } else {
            let mut g = last_h_addr.lock().unwrap();
            if *g != Some(src) {
                *g = Some(src);
                info!(addr = %src, "qqdns: local app address learned");
            }
        }

        let final_domains = get_base32_final_domains(
            &buf[..len],
            data_offset,
            send_domain_index,
            &send_domains,
            cfg.max_sub_len,
            DATA_OFFSET_WIDTH,
            cfg.max_domain_len + 2,
        );
        if final_domains.is_empty() {
            warn!(len, "qqdns: datagram too large for max_domain_len, dropped");
            continue;
        }
        data_offset = (data_offset + 1) & (TOTAL_DATA_OFFSET - 1);
        send_domain_index = (send_domain_index + final_domains.len()) % n_domains;

        // Build per-fragment DNS query datagrams.
        let mut frags: Vec<(Arc<UdpSocket>, Vec<u8>)> = Vec::with_capacity(final_domains.len());
        for fd in &final_domains {
            let query = build_dns_query(fd, query_id, cfg.send_query_type);
            frags.push((Arc::clone(&send_socks[send_sock_index]), query));
            send_sock_index = (send_sock_index + 1) % n_socks;
            query_id = query_id.wrapping_add(1);
        }
        let frags = Arc::new(frags);

        // Enqueue `tries` copies, round-robining across the resolver queues.
        for curr_try in 0..tries {
            let job = SendJob {
                frags: (*frags).clone(),
                entry_time: Instant::now(),
                curr_try,
            };
            // Non-blocking: a full queue drops this copy (matches upstream).
            match senders[res_index].try_send(job) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => return, // shutting down
            }
            res_index = (res_index + 1) % n_res;
        }
    }
}

/// The authoritative-side listener: decode inbound queries, reassemble, emit
/// to the local app, and always answer the resolver.
async fn wan_recv(
    wan_sock: Arc<UdpSocket>,
    h_in_sock: Arc<UdpSocket>,
    recv_domains: Arc<Vec<Vec<Vec<u8>>>>,
    last_h_addr: LastHAddr,
) {
    let dh = DataHandler::new(TOTAL_DATA_OFFSET as usize, ASSEMBLE_TIME);
    let _sweeper = dh.spawn_sweeper();

    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, resolver_src) = match wan_sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "qqdns: wan recv error");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let raw = &buf[..len];

        // Parse + suffix-match; on any failure just skip (no response — an
        // unmatched query isn't ours).
        let parsed = match handle_dns_request(raw) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let suffix = match match_recv_suffix(&parsed.labels, &recv_domains) {
            Some(n) => n,
            None => continue,
        };

        // Reassemble + deliver (best-effort; a malformed fragment is dropped
        // but we still answer the resolver below).
        let data_with_header: Vec<u8> = parsed.labels[..parsed.labels.len() - suffix]
            .iter()
            .flatten()
            .copied()
            .collect();
        if !data_with_header.is_empty() {
            if let Ok(cd) = get_chunk_data(&data_with_header, DATA_OFFSET_WIDTH) {
                // Guard: the last possible fragment index must be flagged last.
                let bad = cd.fragment_part == 63 && !cd.last_fragment;
                if !bad && !cd.chunk.is_empty() {
                    if let Some(joined) = dh.new_data_event(
                        cd.data_offset,
                        cd.fragment_part,
                        cd.last_fragment,
                        cd.chunk,
                    ) {
                        match b32_decode_nopad(&joined) {
                            Ok(payload) => {
                                let dest = *last_h_addr.lock().unwrap();
                                if let Some(dest) = dest {
                                    if let Err(e) = h_in_sock.send_to(&payload, dest).await {
                                        warn!(error = %e, %dest, "qqdns: h_in send error");
                                    }
                                }
                            }
                            Err(e) => debug!(error = %e, "qqdns: base32 decode failed"),
                        }
                    }
                }
            }
        }

        // Always answer the resolver with NOERROR/empty so recursion stays healthy.
        let response =
            create_noerror_empty_response(parsed.qid, parsed.qflags, &raw[12..parsed.next_question]);
        if let Err(e) = wan_sock.send_to(&response, resolver_src).await {
            warn!(error = %e, "qqdns: wan response send error");
        }
    }
}

/// Deterministic-but-varied round-robin seed. Avoids `rand`: derives a start
/// index from a process-lifetime atomic counter mixed with the coarse clock,
/// so distinct engines/tasks don't all start at 0 (which would bias the first
/// packets onto one socket/resolver) without needing a CSPRNG for what is
/// only a load-spreading hint.
fn rr_seed(modulus: usize) -> usize {
    if modulus <= 1 {
        return 0;
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    ((c ^ t) % modulus as u64) as usize
}
