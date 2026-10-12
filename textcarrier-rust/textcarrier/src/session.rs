//! The `CarrierKind::Text` client session — one pairwise
//! [`TextTunnel`] between this process and one peer, fed by two
//! OS threads off an already-open kernel TUN fd.
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
//! A deliberate departure from the Voice path: **the TUN is driven
//! by plain threads, not tokio.** `poll(2)` with a 20 ms deadline
//! keeps the reader wake-up bounded and gives teardown a
//! deterministic deadline: the mode-switch `select!` drops the
//! session future, [`Session::drop`] sets a stop flag and joins
//! both threads, and only then can the next mode reopen the TUN
//! without a stale reader stealing its packets.

use bale_signaling::{BaleSignaling, TextMessage};
use lk_signaling::PeerId;
use lktunnel::tun::TunFormat;
use parking_lot::RwLock;
use std::error::Error;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;
// The stats loop is the one async task here, so its handle is
// tokio's — which is why it is aliased instead of being the
// `JoinHandle` above. Only tokio's can be `abort`ed; the reader
// and writer are OS threads and stop via the stop flag.
use tokio::task::JoinHandle as TokioJoinHandle;

use crate::io::{reader_loop, writer_loop};
use crate::wire::BaleTextWire;
use crate::{TextTunnel, TextWire};

/// One Text-mode client session. Runs until the caller drops (or
/// aborts) the future this is awaited in — there is no
/// session-ended event to wait for, unlike Voice where LK's
/// `Disconnected` is the authority.
///
/// Teardown is entirely future-drop: [`Session::drop`] clears the
/// sink slot, sets the stop flag, joins both OS threads (each
/// bounded by a 20 ms poll deadline) and aborts the stats task.
/// That is exactly how the desktop mode-switch `select!` works,
/// and it maps 1:1 onto a JNI `JoinHandle::abort()`.
///
/// Must be awaited/spawned **on a tokio runtime**: `TextTunnel`
/// calls `tokio::spawn` internally, so a bare non-runtime thread
/// would panic ("no reactor running").
///
/// `tun` is an already-open, **owned** TUN fd — the caller does
/// `File::from_raw_fd` exactly once (Android: the
/// `VpnService.Builder.establish()` fd, which is
/// [`TunFormat::RawIp`]). `format` is that fd's packet framing;
/// desktop passes `crate::tun::host_tun_format()`.
///
/// `peer` must already be a resolved Bale uid (see
/// `BaleSignaling::resolve_peer`).
pub async fn run(
    signaling: Arc<BaleSignaling>,
    peer: PeerId,
    tun: Arc<File>,
    format: TunFormat,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let peer_uid: i32 = peer
        .id_str()
        .parse()
        .map_err(|_| "text client: peer id is not a Bale uid")?;

    log::info!("text: peer {peer_uid} — no call; IP packets ride Bale text messages");
    log::info!("text: SOCKS5 is Voice-only; the byte path here is the kernel TUN");

    let file = tun;

    let wire: Arc<dyn TextWire> = Arc::new(BaleTextWire::new(signaling.clone(), peer));
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
        .spawn(move || reader_loop(&*file_r, &*tunnel_r, &stop_r, None, format))
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
        .spawn(move || writer_loop(&*file_w, pkt_rx, &stop_w, None, format))
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

// ── inbound half: one callback for the process, not per session ─

/// The delivery point the single text-message callback writes to.
///
/// [`BaleSignaling::add_on_text_message`] only ever pushes; there
/// is no unregister. Registering one callback per session would
/// leave a stale closure — and its `Arc<TextTunnel>` — behind on
/// every reconnect, so the callback is installed exactly once and
/// routed through this slot instead.
static SINK: OnceLock<Arc<RwLock<Option<Arc<TextTunnel>>>>> = OnceLock::new();

/// The process-wide sink slot: installed (with the one-way text
/// callback) on first use, then read/written by whichever session
/// is live.
///
/// `pub` because both consumers of this crate — the desktop
/// binary's shell and the Android JNI shim — drive their sessions
/// out of this one slot; there is exactly one per process.
pub fn sink_slot(signaling: &Arc<BaleSignaling>) -> Arc<RwLock<Option<Arc<TextTunnel>>>> {
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

// ── teardown ───────────────────────────────────────────────────

/// Held by [`run`]'s future, so the caller dropping (or aborting)
/// that future is what tears the session down — the mode-switch
/// `select!` on desktop, a `JoinHandle::abort()` on JNI.
struct Session {
    slot:   Arc<RwLock<Option<Arc<TextTunnel>>>>,
    stop:   Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    stats:  Option<TokioJoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        // Order matters. First: close the tunnel explicitly. Clearing
        // the slot only drops *our* `Arc<TextTunnel>` ref, but the
        // sender task holds its own `Arc<Inner>` and `Inner` owns the
        // channel's send half — so the task is structurally immortal
        // and would keep retransmitting a dead frame into the peer's
        // chat forever. `close()` is what actually stops it.
        if let Some(t) = self.slot.read().as_ref() {
            t.close();
        }
        // Then the slot goes first because it owns an
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
