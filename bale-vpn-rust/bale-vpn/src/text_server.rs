//! Server-side `CarrierKind::Text` acceptor.
//!
//! Why this module exists: the server is call-driven. A client only
//! appears in `lktunnel`'s `ServerTunnelManager` after
//! `IncomingHandler::decide` returns `Accept` and `accepted_sessions`
//! emits a session — both happen because a *call* was placed. A Text
//! client never places a call: it starts sending framed IP packets
//! addressed to our uid. This module is the sibling acceptor:
//!
//!   first frame from an unknown uid
//!     → `crate::server::decide_admission` (blacklist → capacity →
//!        allow-list → 60 s pending UI row — the exact rules the voice
//!        path applies, factored out of `AdmissionDecider`)
//!   Accept
//!     → one kernel-TUN slot + `bale<K>` interface at `10.8.<K>.1/24`
//!       (the same recipe `daemon.rs::handle_server_session` uses)
//!     → one [`TextTunnel`] + one TUN reader/writer thread pair —
//!       exactly what `text_client` runs on the other end
//!     → a registry entry `ServerState::client_infos()` merges into the
//!       UI's client list, so a text peer looks identical to an LK one.
//!
//! Per-client-uid tunnels, not one multiplexed tunnel: `TextTunnel` is
//! pairwise by construction (`Inner.peer_uid` filters inbound in
//! `text_tunnel.rs::deliver`), and its seq/cumulative-ACK/window-8
//! state is per-tunnel. Reusing it per uid means zero changes to the
//! proven client path; generalizing it to per-peer state would touch
//! `text_tunnel.rs` and double its test surface for no gain.
//!
//! Unix-only, same as `crate::tun` — a text session is kernel-TUN only
//! (Windows server mode runs userspace NAT). `main.rs` gates the
//! module; every call site is `#[cfg(unix)]`.
//!
//! All of this runs on the *process-wide* text callback
//! (`BaleSignaling::add_on_text_message` only ever pushes, never
//! unregisters — the client's `sink_slot` in `text_client.rs` makes
//! the same point). The callback is installed exactly once and routes
//! by `sender_uid` into the registry below.

use crate::daemon::AppState;
use crate::server::{ClientInfo, ServerState};
use crate::text_client::BaleTextWire;
use crate::text_tunnel::{TextTunnel, TextWire};
use bale_signaling::TextMessage;
// `whoami` / `resolve_peer` / `fetch_display_name` are `Signaling`
// trait methods (they live in the trait's impl block, not an inherent
// one) — without this import the calls simply don't resolve.
use lk_signaling::{CallDecision, PeerId, Signaling};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── process-wide state ──────────────────────────────────────────

static REGISTRY: OnceLock<Arc<RwLock<Registry>>> = OnceLock::new();
/// The text callback may only ever be registered once (no unregister
/// exists — a second registration would double-deliver every frame).
static CALLBACK_INSTALLED: OnceLock<()> = OnceLock::new();
/// Set by [`install`], cleared by [`shutdown`]. Admission tasks that
/// were parked on the UI's pending row across a mode switch re-check
/// it before installing a session.
static RUNNING: AtomicBool = AtomicBool::new(false);
/// Our own uid, for dropping our own echoed sends: Bale echoes every
/// sent text back under our own uid. The tunnels filter it
/// (`deliver` rejects `from_uid != peer_uid`), but the *admission
/// trigger* below runs before any tunnel exists, so the callback
/// needs it here. 0 = not known (never a valid uid).
static SELF_UID: AtomicI32 = AtomicI32::new(0);

struct SessionEntry {
    tunnel:      Arc<TextTunnel>,
    stop:        Arc<AtomicBool>,
    reader:      JoinHandle<()>,
    writer:      JoinHandle<()>,
    slot:        u8,
    display_name: Option<String>,
    connected_at: u64,
    tx_bytes:    Arc<AtomicU64>,
    rx_bytes:    Arc<AtomicU64>,
    /// Epoch secs of the last inbound text frame (data *or* ACK) —
    /// the reaper's clock. Stamped by the receive callback.
    last_activity: Arc<AtomicU64>,
}

struct Registry {
    /// key: client uid. One tunnel per client, pairwise by design.
    sessions: HashMap<i32, SessionEntry>,
    /// uids with an admission task in flight (up to 60 s parked on
    /// the UI). Keeps a burst of first frames from spawning one
    /// admission per frame.
    admitting: HashSet<i32>,
}

/// Borrow, don't clone. Returning the `Arc` by value made every
/// `let guard = registry().write()` bind a guard whose owner — the
/// temporary `Arc` — died at the end of the statement (E0716);
/// chaining `registry().write().x` happened to survive only because
/// the temporary outlives the whole expression.
fn registry() -> &'static RwLock<Registry> {
    REGISTRY
        .get_or_init(|| {
            Arc::new(RwLock::new(Registry {
                sessions: HashMap::new(),
                admitting: HashSet::new(),
            }))
        })
        .as_ref()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Idle limit for a text session: no inbound frame (data or ACK) for
/// this long and the session is reaped, slot and interface returned.
/// 1800 s default; `BALE_TEXT_SERVER_IDLE_SECS` overrides, 0
/// disables. There is no session-ended event on this carrier — a
/// client that dies silently would otherwise keep its slot forever.
fn idle_secs() -> u64 {
    std::env::var("BALE_TEXT_SERVER_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_800)
}

// ── lifecycle ───────────────────────────────────────────────────

/// Arm the acceptor. Called from `run_server` (async, so `whoami`
/// can be awaited) once per server-mode entry.
pub async fn install(state: Arc<AppState>) {
    RUNNING.store(true, Ordering::Relaxed);
    let reg = registry();

    // Own uid, for the self-echo filter. `cached_self` fills
    // asynchronously after the WS handshake, so a short retry: a
    // freshly restarted server may not have it yet.
    let mut me: Option<PeerId> = None;
    for _ in 0..10 {
        if let Some(p) = state.signaling.whoami().await {
            me = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    match me.map(|p| p.id_str().parse::<i32>().ok()) {
        Some(Some(u)) => SELF_UID.store(u, Ordering::Relaxed),
        _ => log::warn!(
            "text-server: own uid unavailable — self-echo filter disabled"
        ),
    }

    // Admission tasks must spawn on the daemon's runtime even though
    // the callback itself fires on the WS client's thread — a bare
    // `tokio::spawn` there would panic with "no reactor running".
    let rt = tokio::runtime::Handle::current();

    // One callback per process. It holds an Arc to the registry —
    // never to a session — so a later install (mode re-entry) must
    // not register a second one, and a teardown needs no unregister.
    let reg_for_cb = reg.clone();
    let state_for_cb = state.clone();
    let sig = state.signaling.clone();
    let _ = CALLBACK_INSTALLED.get_or_init(move || {
        let reg = reg_for_cb;
        let rt = rt;
        // Build the callback first, register second: binding `cb`
        // before the call keeps `state_for_cb` (which `cb` captures)
        // out of the receiver expression — `x.f(cb_that_moves_x)`
        // would not borrow-check.
        let cb = Arc::new(move |msg: TextMessage| {
            if msg.sender_uid == SELF_UID.load(Ordering::Relaxed) {
                return; // our own echo
            }
            let now = now_secs();
            let st = {
                let mut w = reg.write();
                if let Some(e) = w.sessions.get(&msg.sender_uid) {
                    // Known client: forward the frame exactly like
                    // the client's `sink_slot` callback does, and
                    // keep the reaper's clock fresh (deliver()
                    // covers ACKs too).
                    e.last_activity.store(now, Ordering::Relaxed);
                    e.tunnel.deliver(msg.sender_uid, &msg.text);
                    return;
                }
                // Unknown uid: either admission is already in
                // flight, or this is a client knocking. Frames are
                // NOT buffered before admission — the client's
                // retransmit (text_tunnel's 15 s stalled-packet
                // resend) recovers them, and buffering would mean
                // holding unbounded plaintext IP packets for a peer
                // nobody has approved yet.
                if !w.admitting.insert(msg.sender_uid) {
                    return; // already in flight
                }
                state_for_cb.clone()
            };
            log::info!(
                "text-server: first text frame from uid {} — starting admission",
                msg.sender_uid
            );
            let uid = msg.sender_uid;
            rt.spawn(async move { admit(st, uid).await });
        });
        sig.add_on_text_message(cb);
    });

    // Idle reaper. Exits when `RUNNING` clears (mode teardown); the
    // next `install` spawns a fresh one.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if !RUNNING.load(Ordering::Relaxed) {
                return;
            }
            let idle = idle_secs();
            if idle == 0 {
                continue;
            }
            let now = now_secs();
            let stale: Vec<i32> = registry()
                .read()
                .sessions
                .iter()
                .filter(|(_, e)| {
                    now.saturating_sub(e.last_activity.load(Ordering::Relaxed)) > idle
                })
                .map(|(uid, _)| *uid)
                .collect();
            for uid in stale {
                let entry = registry().write().sessions.remove(&uid);
                if let Some(e) = entry {
                    let slot = teardown(e);
                    state.server.release_kernel_slot(slot);
                    log::info!("text-server: uid {uid} idle >{idle}s — reaped");
                }
            }
        }
    });

    log::info!("text-server: acceptor armed (idle limit {}s)", idle_secs());
}

/// Stop every text session and free its kernel-TUN slot. Called from
/// `ServerState::clear_all`, which every teardown path already runs
/// (mode switch, UI `/disconnect`, final shutdown).
pub fn shutdown(server: &ServerState) {
    RUNNING.store(false, Ordering::Relaxed);
    let drained: Vec<(i32, SessionEntry)> = {
        let mut w = registry().write();
        w.admitting.clear();
        w.sessions.drain().collect()
    };
    for (uid, e) in drained {
        let slot = teardown(e);
        server.release_kernel_slot(slot);
        log::info!("text-server: session for uid {uid} torn down (slot {slot})");
    }
}

/// Kick one session — the UI's `/tunnel/clients/:peer_id/disconnect`
/// route reaches here via `ServerState::remove_client`. Returns
/// whether a session was actually removed.
pub fn remove_one(server: &ServerState, peer_id: &str) -> bool {
    let Ok(uid) = peer_id.parse::<i32>() else { return false };
    match registry().write().sessions.remove(&uid) {
        Some(e) => {
            let slot = teardown(e);
            server.release_kernel_slot(slot);
            log::info!("text-server: uid {uid} kicked via UI (slot {slot})");
            true
        }
        None => false,
    }
}

/// Stop one session: signal both threads, join them, then let the
/// entry drop — the threads hold the last `Arc<File>` refs, so the
/// TUN fd closes after they exit (the kernel removes the interface
/// with it), and the `Arc<TextTunnel>` drop takes the tunnel's
/// sender task with it. Returns the freed slot.
fn teardown(e: SessionEntry) -> u8 {
    let SessionEntry {
        stop,
        reader,
        writer,
        slot,
        ..
    } = e;
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
    let _ = writer.join();
    slot
}

// ── admission ───────────────────────────────────────────────────

/// One admitted client. Runs on a spawned task — it may park up to
/// 60 s on the UI's pending row.
async fn admit(state: Arc<AppState>, uid: i32) {
    let uid_str = uid.to_string();

    // Identity first: without a PeerId there is no wire to send on.
    let Some(peer) = state.signaling.resolve_peer(&uid_str).await else {
        log::warn!("text-server: cannot resolve uid {uid_str} — dropping contact");
        registry().write().admitting.remove(&uid);
        return;
    };
    let display = state.signaling.fetch_display_name(&peer).await;

    // The voice path's rules, shared by construction —
    // `crate::server::decide_admission`.
    let decision =
        crate::server::decide_admission(&state.server, &uid_str, display.clone()).await;
    if !matches!(decision, CallDecision::Accept) {
        registry().write().admitting.remove(&uid);
        return;
    }
    // A mode switch may have raced the (up to 60 s) admission park.
    if !RUNNING.load(Ordering::Relaxed) {
        registry().write().admitting.remove(&uid);
        return;
    }

    // Kernel-TUN slot + interface — the same recipe as the voice
    // path (`handle_server_session` in daemon.rs): `bale<K>`,
    // `10.8.<K>.1/24`.
    let Some(slot) = state.server.alloc_kernel_slot() else {
        log::warn!("text-server: TUN slot pool exhausted — dropping {uid_str}");
        registry().write().admitting.remove(&uid);
        return;
    };
    let name = format!("bale{slot}");
    let addr = format!("10.8.{slot}.1");
    let dev = match crate::tun::open_server_tun(&name, &addr, 24, 1400) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("text-server: open {name} ({addr}/24) failed for {uid_str}: {e}");
            state.server.release_kernel_slot(slot);
            registry().write().admitting.remove(&uid);
            return;
        }
    };
    // SAFETY: the fd is freshly owned by `dev`; `into_raw_fd`
    // hands ownership over exactly once and `from_raw_fd` takes it
    // exactly once — the idiom `text_client::run` uses.
    let raw = dev.into_raw_fd();
    let file = Arc::new(unsafe { File::from_raw_fd(raw) });

    // The pairwise tunnel: wire targets this client only, and the
    // tunnel's `deliver` accepts only frames whose `sender_uid`
    // matches — same two filters, opposite directions.
    let wire: Arc<dyn TextWire> =
        Arc::new(BaleTextWire::new(state.signaling.clone(), peer));
    // `open_shared`, not `open`: N clients = N tunnels, all spending
    // ONE Bale account's per-user bucket (see `open_shared`).
    let tunnel = Arc::new(TextTunnel::open_shared(wire, uid));

    // TUN → tunnel: the sink the IpSink fills. Unbounded like
    // `text_client::run`'s writer queue — the tunnel's own window
    // (8) and pacer are the real pacing.
    let (pkt_tx, pkt_rx) = mpsc::channel::<Vec<u8>>();
    tunnel.set_on_ip(Arc::new(move |pkt: &[u8]| {
        let _ = pkt_tx.send(pkt.to_vec());
    }));

    let stop           = Arc::new(AtomicBool::new(false));
    let tx_bytes       = Arc::new(AtomicU64::new(0));
    let rx_bytes       = Arc::new(AtomicU64::new(0));
    let last_activity  = Arc::new(AtomicU64::new(now_secs()));

    // TUN reader: blocking-fd polling on a std thread, exactly what
    // the client does. Each thread holds an `Arc<File>` so the fd
    // outlives this fn; `teardown` joins both before the last refs
    // drop.
    let stop_r   = stop.clone();
    let file_r   = file.clone();
    let tunnel_r = tunnel.clone();
    let txb      = tx_bytes.clone();
    let reader = match std::thread::Builder::new()
        .name(format!("text-tun-reader-{slot}"))
        .spawn(move || {
            crate::text_client::reader_loop(&file_r, &tunnel_r, &stop_r, Some(&*txb))
        }) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("text-server: reader spawn failed for {uid_str}: {e}");
            state.server.release_kernel_slot(slot);
            registry().write().admitting.remove(&uid);
            return;
        }
    };
    // tunnel → TUN writer (same thread pair as the client).
    let stop_w = stop.clone();
    let file_w = file.clone();
    let rxb    = rx_bytes.clone();
    let writer = match std::thread::Builder::new()
        .name(format!("text-tun-writer-{slot}"))
        .spawn(move || {
            crate::text_client::writer_loop(&file_w, pkt_rx, &stop_w, Some(&*rxb))
        }) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("text-server: writer spawn failed for {uid_str}: {e}");
            stop.store(true, Ordering::Relaxed);
            let _ = reader.join();
            state.server.release_kernel_slot(slot);
            registry().write().admitting.remove(&uid);
            return;
        }
    };

    {
        let mut reg = registry().write();
        if !RUNNING.load(Ordering::Relaxed) {
            // Shutdown raced the installation — unwind.
            reg.admitting.remove(&uid);
            drop(reg);
            stop.store(true, Ordering::Relaxed);
            let _ = reader.join();
            let _ = writer.join();
            state.server.release_kernel_slot(slot);
            return;
        }
        reg.admitting.remove(&uid);
        reg.sessions.insert(
            uid,
            SessionEntry {
                tunnel,
                stop,
                reader,
                writer,
                slot,
                display_name: display,
                connected_at: now_secs(),
                tx_bytes,
                rx_bytes,
                last_activity,
            },
        );
    }
    log::info!("text-server: session up for {uid_str} — {name} ({addr}/24)");
}

// ── UI surface ──────────────────────────────────────────────────

/// Merged into `ServerState::client_infos` — the UI's `/tunnel/clients`
/// shows text peers next to LK ones, same shape, same `fmtAge`.
pub fn client_infos() -> Vec<ClientInfo> {
    registry()
        .read()
        .sessions
        .iter()
        .map(|(uid, e)| ClientInfo {
            peer_id:         uid.to_string(),
            display_name:    e.display_name.clone(),
            rx_bytes:        e.rx_bytes.load(Ordering::Relaxed),
            tx_bytes:        e.tx_bytes.load(Ordering::Relaxed),
            connected_at_ms: e.connected_at.saturating_mul(1_000),
        })
        .collect()
}

/// Counted toward `max_clients` in `decide_admission` — a text
/// session occupies a kernel-TUN slot just like an LK one.
pub fn session_count() -> usize {
    registry().read().sessions.len()
}
