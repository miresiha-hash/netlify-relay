//! `CarrierKind::Text` — the client session.
//!
//! The byte path, one hop per line:
//!
//! ```text
//!  kernel TUN ─ reader thread ─ TextTunnel (pacer, window)
//!      ─ TextWire ─ BaleSignaling::send_text_message ─ Bale
//!      ─ inbound f=2 push ─ one process-wide text callback
//!      ─ TextTunnel::deliver (reassembly) ─ IpSink
//!      ─ writer thread ─ back into the TUN fd
//! ```
//!
//! No call, no LK room, no ReliabilitySocket, no LiveKit: the peer
//! only has to be online.
//!
//! Two deliberate departures from the Voice path:
//!
//! * **The TUN is mandatory here.** Voice treats `--client-tun` as
//!   an optional add-on to SOCKS5; Text has no SOCKS5 (that server
//!   hangs off `LkTunnel`), so the TUN *is* the transport and
//!   failing to open it fails the mode rather than degrading to
//!   nothing.
//! * **The TUN is driven by plain threads, not tokio.** `poll(2)`
//!   with a 20 ms deadline keeps the reader wake-up bounded and
//!   gives teardown a deterministic deadline: the mode-switch
//!   `select!` drops this future, [`Session::drop`] sets a stop
//!   flag and joins both threads, and only then can the next mode
//!   reopen `bale-c0` without a stale reader stealing its packets.

// Shared by both platform variants — only `run`'s signature needs
// these, which is what keeps the non-unix stub warning-free.
use bale_signaling::BaleSignaling;
use lk_signaling::PeerId;
use std::error::Error;
use std::sync::Arc;

#[cfg(unix)]
use crate::text_tunnel::{Backpressure, TextTunnel, TextWire, WireError};
#[cfg(unix)]
use async_trait::async_trait;
#[cfg(unix)]
use bale_signaling::TextMessage;
#[cfg(unix)]
use lktunnel::tun::{unwrap_from_wire, wrap_for_wire, TunFormat};
#[cfg(unix)]
use parking_lot::RwLock;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::sync::OnceLock;
#[cfg(unix)]
use std::thread::JoinHandle;
#[cfg(unix)]
use std::time::Duration;
// The stats loop is the one async task here, so its handle is
// tokio's — which is why it is aliased instead of being the
// `JoinHandle` above. Only tokio's can be `abort`ed; the reader
// and writer are OS threads and stop via the stop flag.
#[cfg(unix)]
use tokio::task::JoinHandle as TokioJoinHandle;

/// Default interface / address for the text-mode TUN, matching the
/// values the Voice path uses for `--client-tun` so the host-side
/// route recipe is identical whichever carrier is selected.
///
/// Both are overridable from the environment because two daemons on
/// one host — the testbed, or anyone testing two peers against each
/// other — would otherwise fight over a single interface name. The
/// second `TUNSETIFF` does not fail here: it attaches to the
/// *existing* device, so both processes would share one TUN and
/// quietly steal each other's packets.
#[cfg(unix)]
const DEFAULT_TUN_NAME: &str = "bale-c0";
#[cfg(unix)]
const DEFAULT_TUN_ADDR: &str = "10.8.0.2";
#[cfg(unix)]
const TUN_PREFIX: u8 = 24;
#[cfg(unix)]
const TUN_MTU: u16 = 1400;

/// TUN interface name: `BALE_TEXT_TUN_NAME`, else the default.
#[cfg(unix)]
fn tun_name() -> String {
    std::env::var("BALE_TEXT_TUN_NAME")
        .unwrap_or_else(|_| DEFAULT_TUN_NAME.to_string())
}

/// TUN address: `BALE_TEXT_TUN_ADDR`, else the default. Left to
/// `open_client_tun` to parse, so a malformed value surfaces as an
/// error naming the address rather than a silent fallback.
#[cfg(unix)]
fn tun_addr() -> String {
    std::env::var("BALE_TEXT_TUN_ADDR")
        .unwrap_or_else(|_| DEFAULT_TUN_ADDR.to_string())
}

/// How long the TUN threads wait between wake-ups. Bounds both
/// their idle cost (~50 wake-ups/s) and how long teardown can take
/// to join them. Irrelevant to latency: the transport itself paces
/// at roughly one message per second.
#[cfg(unix)]
const POLL_MS: i32 = 20;

/// One Text-mode client session. Runs until the mode-switch
/// `select!` drops it — there is no session-ended event to wait
/// for, unlike Voice where LK's `Disconnected` is the authority.
///
/// `peer` must already be a resolved Bale uid (see
/// `BaleSignaling::resolve_peer`).
#[cfg(unix)]
pub async fn run(
    signaling: Arc<BaleSignaling>,
    peer: PeerId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let peer_uid: i32 = peer
        .id_str()
        .parse()
        .map_err(|_| "text client: peer id is not a Bale uid")?;

    log::info!("text: peer {peer_uid} — no call; IP packets ride Bale text messages");
    log::info!("text: SOCKS5 is Voice-only; the byte path here is the kernel TUN");

    let tun_name = tun_name();
    let tun_addr = tun_addr();
    let dev = crate::tun::open_client_tun(&tun_name, &tun_addr, TUN_PREFIX, TUN_MTU).map_err(|e| {
        format!(
            "text: kernel TUN open failed ({tun_name} {tun_addr}: {e}) — Text mode needs CAP_NET_ADMIN"
        )
    })?;
    let iface = dev.name.clone();
    let raw: RawFd = dev.into_raw_fd();
    // SAFETY: `open_client_tun` handed us a live descriptor and we
    // just consumed the `TunDevice` guard, so nothing closes it
    // behind our back.
    let file = Arc::new(unsafe { File::from_raw_fd(raw) });
    log::info!(
        "text: TUN {iface} up ({tun_addr}/{TUN_PREFIX}, mtu={TUN_MTU}, fd={raw})"
    );

    let wire: Arc<dyn TextWire> = Arc::new(BaleTextWire {
        signaling: signaling.clone(),
        peer,
    });
    let tunnel = Arc::new(TextTunnel::open(wire, peer_uid));

    // Inbound half. `add_on_text_message` only ever pushes — the
    // signaling layer has no unregister — so registering one
    // callback per session would strand a stale closure (and its
    // `Arc<TextTunnel>`) on every reconnect. Instead the callback
    // is installed once per process and routed through a slot that
    // whichever session is live owns.
    let slot = sink_slot(&signaling);
    *slot.write() = Some(tunnel.clone());

    let stop = Arc::new(AtomicBool::new(false));

    // Outbound (TUN → tunnel). `try_send_payload` is synchronous
    // and non-blocking, so this needs no executor at all.
    let stop_r = stop.clone();
    let file_r = file.clone();
    let tunnel_r = tunnel.clone();
    let reader = std::thread::Builder::new()
        .name("text-tun-reader".into())
        .spawn(move || reader_loop(&*file_r, &*tunnel_r, &stop_r))
        .map_err(|e| format!("text: spawn TUN reader failed: {e}"))?;

    // Inbound (tunnel → TUN). The `IpSink` callback is sync and
    // can't await a write, so it hands packets to a queue the
    // writer thread drains.
    let (pkt_tx, pkt_rx) = mpsc::channel::<Vec<u8>>();
    tunnel.set_on_ip(Arc::new(move |pkt: &[u8]| {
        // Unbounded by design — the transport's own pacer caps how
        // fast this can fill, and an IP path that can't keep up
        // drops rather than grows. `send` only fails once the
        // writer is gone, i.e. we are already tearing down.
        let _ = pkt_tx.send(pkt.to_vec());
    }));

    let stop_w = stop.clone();
    let file_w = file.clone();
    let writer = std::thread::Builder::new()
        .name("text-tun-writer".into())
        .spawn(move || writer_loop(&*file_w, pkt_rx, &stop_w))
        .map_err(|e| format!("text: spawn TUN writer failed: {e}"))?;

    // Heartbeat so the log shows whether bytes are actually moving
    // — "session up" alone proves nothing about throughput.
    let stats_of = tunnel.clone();
    let stats = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let s = stats_of.stats();
            log::info!(
                "text: stats sent={} recv={} ack={} in_flight={} retransmits={} dup={} rate_limited={}",
                s.sent_data, s.recv_data, s.sent_ack, s.in_flight,
                s.retransmits, s.dup_dropped, s.rate_limited
            );
        }
    });

    // Declared last so it drops first on cancel, before `tunnel`
    // and `file`. The leading underscore is what keeps it alive —
    // `let _ = ...` would drop the guard at that statement, which
    // is the opposite of what we want.
    let _session = Session {
        slot,
        stop,
        reader: Some(reader),
        writer: Some(writer),
        stats: Some(stats),
    };

    log::info!(
        "text: session running — change mode (or Disconnect) to tear it down"
    );
    std::future::pending::<()>().await;
    Ok(())
}

// ── outbound half: Bale signaling as a TextWire ────────────────

/// [`TextWire`] over the real Bale signaling client.
///
/// `send_text_message` is inherent on `BaleSignaling` (not on the
/// `Signaling` trait) and it resolves `PeerId` to a uid itself, so
/// no extra conversion happens here.
#[cfg(unix)]
struct BaleTextWire {
    signaling: Arc<BaleSignaling>,
    peer:      PeerId,
}

#[cfg(unix)]
#[async_trait]
impl TextWire for BaleTextWire {
    async fn send(&self, text: &str) -> Result<(), WireError> {
        match self.signaling.send_text_message(&self.peer, text).await {
            Ok(_) => Ok(()),
            // The pacer has already spent this slot's budget, so
            // there is nothing to retry inline — the tunnel's 15 s
            // retransmit is what recovers it.
            Err(e) => Err(WireError::Failed(e.to_string())),
        }
    }
}

// ── inbound half: one callback for the process, not per session ─

/// The delivery point the single text-message callback writes to.
///
/// [`BaleSignaling::add_on_text_message`] only ever pushes; there
/// is no unregister. Registering one callback per session would
/// leave a stale closure — and its `Arc<TextTunnel>` — behind on
/// every reconnect, so the callback is installed exactly once and
/// routed through this slot instead.
#[cfg(unix)]
static SINK: OnceLock<Arc<RwLock<Option<Arc<TextTunnel>>>>> = OnceLock::new();

#[cfg(unix)]
fn sink_slot(signaling: &Arc<BaleSignaling>) -> Arc<RwLock<Option<Arc<TextTunnel>>>> {
    SINK.get_or_init(|| {
        let slot: Arc<RwLock<Option<Arc<TextTunnel>>>> = Arc::new(RwLock::new(None));
        let deliver_to = slot.clone();
        signaling.add_on_text_message(Arc::new(move |msg: TextMessage| {
            let guard = deliver_to.read();
            if let Some(t) = &*guard {
                // `deliver` already rejects other peers, our own
                // echo, non-base64 text and unknown frame kinds,
                // so every inbound text can be forwarded without
                // filtering again here.
                t.deliver(msg.sender_uid, &msg.text);
            }
        }));
        slot
    })
    .clone()
}

// ── the two TUN threads ────────────────────────────────────────

/// TUN → tunnel.
///
/// `try_send_payload` never blocks, so there is nothing to await;
/// a full window is backed off against rather than spun on or
/// dropped from, because the window is only 8 deep and losing
/// packets there would be our own doing rather than congestion.
#[cfg(unix)]
fn reader_loop(file: &File, tunnel: &TextTunnel, stop: &AtomicBool) {
    let fmt = crate::tun::host_tun_format();
    'outer: while !stop.load(Ordering::Relaxed) {
        let pkt = match read_packet(file, POLL_MS, fmt) {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(e) => {
                log::warn!("text: TUN read stopped: {e}");
                break;
            }
        };
        loop {
            if stop.load(Ordering::Relaxed) {
                break 'outer;
            }
            match tunnel.try_send_payload(pkt.clone()) {
                Ok(()) => break,
                Err(Backpressure::Closed) => break 'outer,
                Err(Backpressure::Oversized(n)) => {
                    log::warn!("text: {n}-byte packet exceeds a frame — dropped");
                    break;
                }
                Err(Backpressure::Full) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    log::debug!("text: TUN reader thread exiting");
}

/// tunnel → TUN. Drains the queue the `IpSink` callback fills.
///
/// The timeout is what makes teardown possible: without it this
/// would block in `recv` until the sender dropped, and the sender
/// lives inside the tunnel the guard is trying to release.
#[cfg(unix)]
fn writer_loop(file: &File, rx: mpsc::Receiver<Vec<u8>>, stop: &AtomicBool) {
    let fmt = crate::tun::host_tun_format();
    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(POLL_MS as u64)) {
            Ok(pkt) => {
                // The kernel TUN wants wire form, not raw IP:
                // macOS utun insists on its 4-byte AF prefix,
                // Linux `IFF_NO_PI` gets the packet untouched.
                let wire = wrap_for_wire(&pkt, fmt);
                let mut f: &File = file;
                if let Err(e) = f.write_all(&wire) {
                    log::warn!("text: TUN write failed: {e}");
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    log::debug!("text: TUN writer thread exiting");
}

/// Poll the TUN for one packet, in **raw IP** regardless of the
/// host's framing.
///
/// `Ok(None)` means "nothing within the deadline" — a normal wait,
/// and also this module's shutdown granularity. `Err` means the
/// device is gone and the reader should stop.
#[cfg(unix)]
fn read_packet(file: &File, timeout_ms: i32, format: TunFormat) -> Result<Option<Vec<u8>>, String> {
    let mut pfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one owned descriptor, polled only from this thread,
    // with `pfd` outliving the call.
    let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ready < 0 {
        let e = std::io::Error::last_os_error();
        return match e.kind() {
            // EINTR is not a failure — just re-arm the wait.
            std::io::ErrorKind::Interrupted => Ok(None),
            _ => Err(format!("poll failed: {e}")),
        };
    }
    if ready == 0 {
        return Ok(None);
    }
    if (pfd.revents & libc::POLLNVAL) != 0 {
        return Err("TUN file descriptor is no longer valid".into());
    }
    if (pfd.revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
        return Err(format!("TUN reported revents={:#06x}", pfd.revents));
    }
    if (pfd.revents & libc::POLLIN) == 0 {
        return Ok(None);
    }

    // 2048 comfortably covers an MTU-1400 IP packet. Filling the
    // buffer would mean truncation, which corrupts the datagram —
    // drop loudly rather than forward a broken packet.
    let mut buf = vec![0u8; 2048];
    let mut f: &File = file;
    let n = f.read(&mut buf).map_err(|e| format!("TUN read failed: {e}"))?;
    if n == 0 {
        return Err("TUN returned EOF".into());
    }
    if n == buf.len() {
        return Err(format!("{n}-byte packet filled the read buffer (mtu={TUN_MTU}?)"));
    }
    buf.truncate(n);
    // Hand the tunnel raw IP: macOS utun's 4-byte AF prefix has to
    // go, Linux `IFF_NO_PI` has nothing to remove. `unwrap` returns
    // an empty slice when the frame was header-only.
    let ip = unwrap_from_wire(&buf, format);
    if ip.is_empty() {
        return Err("TUN handed back a header-only frame".into());
    }
    Ok(Some(ip.to_vec()))
}

// ── teardown ───────────────────────────────────────────────────

/// Held by [`run`]'s future, so the mode-switch `select!` dropping
/// that future is what tears the session down.
#[cfg(unix)]
struct Session {
    slot:   Arc<RwLock<Option<Arc<TextTunnel>>>>,
    stop:   Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    stats:  Option<TokioJoinHandle<()>>,
}

#[cfg(unix)]
impl Drop for Session {
    fn drop(&mut self) {
        // Order matters. The slot goes first because it owns an
        // `Arc<TextTunnel>`, which keeps the writer's queue alive;
        // then the stop flag; then join, so the next mode never
        // finds a stale reader still stealing packets from
        // `bale-c0`. Both threads poll on a 20 ms deadline, so
        // neither join can run long.
        *self.slot.write() = None;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
        if let Some(h) = self.stats.take() {
            h.abort();
        }
        log::info!("text: session torn down");
    }
}

// ── non-unix ───────────────────────────────────────────────────

/// Windows and other non-unix targets have no kernel TUN we ship
/// (see `tun::open_client_tun`), so Text mode has no byte path
/// there. Fail loudly instead of idling.
#[cfg(not(unix))]
pub async fn run(
    _signaling: Arc<BaleSignaling>,
    _peer: PeerId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("text carrier needs a kernel TUN — unsupported on this OS".into())
}
