//! Daemon orchestration. Owns the [`BaleSignaling`] instance,
//! the per-mode active handle (client / server), and the shared
//! `AppState` the HTTP UI reads/writes.

use crate::client::ClientState;
use crate::config::{ConfigFile, FileTokenStore, Resolved};
use crate::server::ServerState;
use bale_signaling::auth::BaleAuth;
use bale_signaling::BaleSignaling;
use lk_signaling::{
    CallDecision, IncomingHandler, PeerId, PlaceCallError, Signaling, TokenStore,
};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, watch, RwLock};

/// State shared with the HTTP UI handlers. Wrapped in an Arc so
/// axum's State extractor can clone it onto every request task.
pub struct AppState {
    /// Bale signaling client. Lifecycle is process-scoped: one
    /// instance from daemon start to daemon exit; the WS run
    /// loop inside handles reconnects.
    pub signaling: Arc<BaleSignaling>,
    /// Auth helper (SMS OTP + signup + paste-cookie refresh).
    /// Stateless — one shared instance is fine.
    pub auth: BaleAuth,
    /// Token storage. `BaleAuth` writes through this on
    /// `Authenticated`; the signaling layer reads it on connect.
    pub token_store: Arc<dyn TokenStore>,
    /// Shared on-disk config handle. Both the [`FileTokenStore`]
    /// and the HTTP `/config` handler call `update()` so writes
    /// can't lose updates to each other.
    pub config_file: Arc<ConfigFile>,
    /// Resolved config — guarded by an `RwLock` so the UI can
    /// expose `/config` reads + writes without races.
    pub cfg: RwLock<Resolved>,
    /// Mode-change channel — `/config` publishes here when the
    /// caller flips `mode`, [`run_mode`] subscribes so it can
    /// tear down the current per-mode task and restart in the
    /// new mode without a process restart.
    pub mode_tx: watch::Sender<Option<String>>,
    /// Client-mode session state. Empty when in server mode.
    pub client: Arc<ClientState>,
    /// Server-mode admission + per-call tracking. Empty when in
    /// client mode (the structures are cheap to keep around).
    pub server: Arc<ServerState>,
    /// Long-lived activation driver shared across mode swaps.
    /// Owned here so that `ClientTunnelManager` / `ServerTunnelManager`
    /// don't drop the WS activation state when they go out of
    /// scope between modes — the next manager pushes a fresh
    /// intent and the driver dedupes if it's the same.
    pub activation: Arc<lktunnel::manager::ActivationDriver<BaleSignaling>>,
}

pub async fn run(cfg: Resolved) -> Result<(), Box<dyn Error>> {
    let (_tx, rx) = oneshot::channel::<()>();
    // No external shutdown source — the headless path relies on
    // [`wait_for_signal`] for ctrl-C / SIGTERM, so the receiver
    // never fires (the `_tx` half stays in scope and only drops
    // when this function returns).
    run_with_shutdown(cfg, rx).await
}

/// As [`run`] but accepts an external shutdown channel — used by
/// the GUI shell so closing the window can trigger a clean WS
/// close + LK room drain before the process exits.
pub async fn run_with_shutdown(
    cfg:      Resolved,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error>> {
    // Boot the lktunnel mio reactor. The CLI / Android JNI shim
    // both do this — the binary `bale-vpn` was missing it, so
    // `attach_tun` / NAT host-socket registration silently failed
    // with "dispatcher not running". Idempotent.
    lktunnel::dispatcher::init();

    // Pull a pre-fix config (token included) over from the default
    // location when this daemon runs with a custom --config-dir —
    // before the split-brain fix the file was persisted next to the
    // binary instead of the flag dir.
    crate::config::migrate_config_dir(&cfg.config_dir);
    let config_file = Arc::new(ConfigFile::new(cfg.config_dir.clone()));
    // Snapshot the persisted lists / cap so ServerState starts
    // pre-seeded — the UI handlers write through to disk on
    // mutations, so the on-disk file is the source of truth.
    let persisted = config_file.load();
    let token_store: Arc<dyn TokenStore> = FileTokenStore::new(config_file.clone()).into_arc();
    let signaling   = BaleSignaling::new(token_store.clone());
    // Load any persisted token from disk into the WS rule engine
    // so a cold start with saved credentials brings the WS up
    // automatically (no waiting for an explicit /connect call).
    signaling.auto_load_token();
    let auth        = BaleAuth::new();
    let http_port   = cfg.port;
    let (mode_tx, _) = watch::channel(cfg.mode.clone());

    // Client-mode: start idle. The persisted `peer_id` is the
    // user's last-dialed peer (kept for UI dropdown convenience
    // via the persisted file), but we don't auto-dial on startup —
    // the user explicitly presses Connect in the UI, which POSTs
    // /tunnel/config and sets peer_id back. Without this, a
    // server-side InvalidPeer error would tight-loop run_mode
    // because run_client immediately re-dials on next iteration.
    let mut cfg = cfg;
    cfg.peer_id = None;
    let activation = lktunnel::manager::ActivationDriver::new(signaling.clone());
    let state = Arc::new(AppState {
        signaling:   signaling.clone(),
        auth,
        token_store,
        config_file,
        cfg:         RwLock::new(cfg),
        mode_tx,
        client:      ClientState::new(),
        server:      ServerState::with_config(
                         persisted.admission,
                         persisted.blacklist,
                         persisted.max_clients,
                     ),
        activation,
    });

    // HTTP UI runs for the whole daemon lifetime. Bound to
    // 127.0.0.1 so off-host access requires an explicit
    // ssh-tunnel — matches the Node app's policy.
    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse()?;
    let http_state = state.clone();
    let http_task  = tokio::spawn(async move {
        if let Err(e) = crate::ui::serve(http_state, http_addr).await {
            log::error!("HTTP UI exited: {e}");
        }
    });

    // The per-mode work runs in parallel with the HTTP UI. The
    // mode task exiting is NOT a daemon-shutdown signal — it
    // exits cleanly any time the user hasn't signed in yet (or
    // briefly between mode switches), and the HTTP UI needs to
    // stay up so they can sign in. Daemon-shutdown is triggered
    // by `http_task` exit (port-bind failure, etc.), an OS
    // signal, or the GUI shell's explicit close.
    let mode_state = state.clone();
    let mode_task  = tokio::spawn(async move {
        match run_mode(mode_state).await {
            Ok(())  => log::info!("mode task exited cleanly"),
            Err(e)  => log::error!("mode task exited with error: {e}"),
        }
    });

    tokio::select! {
        _ = http_task                       => log::info!("HTTP UI task exited"),
        _ = wait_for_signal()               => log::info!("signal received, shutting down"),
        // GUI shell signals here on window close. `oneshot::Receiver`
        // resolves to either `Ok(())` (explicit send) or `Err(_)`
        // (sender dropped) — both mean "shut down", so we don't
        // care which.
        _ = shutdown                        => log::info!("shutdown channel signaled"),
    }
    // Cancel the mode task in case it's still running; ignore
    // any panic/cancel error.
    mode_task.abort();

    // Drain order: drop active per-mode sessions first so their
    // LK rooms send participant-leave / close, then disconnect
    // the signaling WS so Bale gets a clean session close. A
    // brief sleep gives outgoing frames time to flush before the
    // tokio runtime drops on return.
    state.client.clear();
    state.server.clear_all().await;
    signaling.disconnect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

/// Per-mode orchestration. Runs the client/server lifecycle in
/// a loop: starts the current mode, tears down + restarts when
/// `/config` flips `mode`.
///
/// For client mode without a configured peer or token we just
/// wait — the HTTP UI lets the user complete sign-in and pick a
/// peer.
async fn run_mode(state: Arc<AppState>) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Loop: each iteration covers one full "auth → WS → mode"
    // lifecycle. Logout drops us back to the auth-wait at the
    // top by clearing the token and pushing `None` on mode_tx
    // (the outer select wakes, the mode is unset, we fall through
    // to auth-recheck).
    let mut mode_rx = state.mode_tx.subscribe();
    'outer: loop {
        // 1. Wait for auth. The auth handler writes through
        //    `TokenStore::save`; we poll once a second so the
        //    pickup is prompt without any explicit signal.
        if !state.signaling.is_authenticated() {
            log::info!("no token yet — waiting for sign-in via HTTP UI");
            while !state.signaling.is_authenticated() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            log::info!("token acquired — bringing WS up");
        }

        // 2. Bring up the WS. Errors are non-fatal: log and
        //    iterate (the next loop reaches the auth check and
        //    if the token is still there, retries the connect).
        log::info!("connecting WS…");
        if let Err(e) = state.signaling.connect().await {
            log::warn!("ws connect: {e} — retrying in 2s");
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue 'outer;
        }
        // Poll for handshake completion. Bounded so a wedged WS
        // doesn't hold up the loop forever; we proceed anyway.
        let mut tries = 0u32;
        while !state.signaling.is_connected() && tries < 40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            tries += 1;
        }
        if state.signaling.is_connected() { log::info!("WS connected"); }
        else { log::warn!("WS handshake didn't complete after 10s — continuing anyway"); }

        // 3. Pick a mode (waiting on `mode_tx` if unset). When
        //    we have one, run it until either it ends or the
        //    mode flips or auth drops.
        let mode = match state.cfg.read().await.mode.clone() {
            Some(m) if m == "client" || m == "server" => m,
            other => {
                if let Some(m) = other.filter(|m| !m.is_empty()) {
                    log::warn!("mode {m:?} not recognised — treating as unset");
                }
                log::info!("mode not selected yet — waiting for UI choice");
                if mode_rx.changed().await.is_err() {
                    log::info!("mode channel closed — exiting run_mode");
                    teardown_mode(&state).await;
                    return Ok(());
                }
                continue 'outer;
            }
        };
        log::info!("entering mode={mode}");

        let outcome: Result<(), Box<dyn Error + Send + Sync>> = tokio::select! {
            r = run_one_mode(&state, &mode) => r,
            r = mode_rx.changed()           => {
                if r.is_err() {
                    log::info!("mode channel closed — exiting run_mode");
                    teardown_mode(&state).await;
                    return Ok(());
                }
                log::info!("mode change → tearing down {mode}");
                Ok(())
            }
        };
        if let Err(e) = outcome {
            log::warn!("mode {mode} ended with error: {e}");
            // On client error, clear the configured peer so the
            // next iteration parks instead of immediately
            // re-dialing the same bad peer (and tight-looping on
            // a deterministic Bale error like InvalidPeer). The
            // user has to press Connect again from the UI, which
            // re-POSTs /tunnel/config and gives them a chance to
            // pick a different peer.
            if mode == "client" {
                state.cfg.write().await.peer_id = None;
            }
        }
        teardown_mode(&state).await;
    }
}

async fn run_one_mode(state: &Arc<AppState>, mode: &str)
    -> Result<(), Box<dyn Error + Send + Sync>>
{
    match mode {
        "client" => run_client(state).await,
        "server" => run_server(state).await,
        other    => Err(format!("unknown mode: {other}").into()),
    }
}

/// Drop per-mode state in preparation for either exit or the
/// next mode iteration. Closes any active LkTunnels (which
/// signals participant-disconnect to peers), clears the pending
/// admission queue, and installs a SilentlyIgnore handler so a
/// stray incoming call between modes isn't accepted against
/// stale state.
async fn teardown_mode(state: &Arc<AppState>) {
    state.client.clear();
    state.server.clear_all().await;
    state.signaling.tunnel_hooks().set_incoming_handler(Box::new(NoopHandler));
    // Revert the WS rule engine to client semantics on any mode
    // exit. If a prior `run_server` flipped `server_active=true`
    // and we're switching to client (or unsetting mode), the WS
    // would otherwise stay always-on under server semantics.
    //
    // No activate/deactivate push needed — both managers' Drop
    // impls deactivate() the signaling impl on tear-down, so by
    // the time the new mode constructs its manager the WS state
    // is already in the right place.
}

/// Incoming-call handler installed between modes (and any time
/// the daemon doesn't want to accept calls). Always silently
/// ignores — no Bale-side notification to the caller, just a
/// dropped INVITE.
struct NoopHandler;
#[async_trait::async_trait]
impl IncomingHandler for NoopHandler {
    async fn decide(&self, _: PeerId, _: Option<String>) -> CallDecision {
        CallDecision::SilentlyIgnore
    }
}

/// Server-mode bring-up. Installs the admission handler and a
/// background events collector. Once running, accepts incoming
/// calls per the allow/block lists; the HTTP UI exposes the
/// pending queue.
///
/// `--nat-mode kernel`: each accepted session gets its own
/// `bale<K>` TUN at `10.8.<K>.1/24` (server side, peer is
/// `10.8.<K>.2`). The kernel forwards via MASQUERADE / pf —
/// best throughput; needs `CAP_NET_ADMIN` (Linux) or root
/// (macOS) plus the broader iptables rule (see CLAUDE.md).
/// `K` runs 0..[`KERNEL_TUN_SLOT_LIMIT`); when exhausted the
/// session falls back to userspace NAT.
///
/// `--nat-mode userspace`: each accepted session runs an
/// in-process userspace NAT (`LkTunnel::start_server`). No
/// privilege needed; portable.
async fn run_server(state: &Arc<AppState>) -> Result<(), Box<dyn Error + Send + Sync>> {
    log::info!("server: installing admission handler");
    // server_active=true is auto-pushed by ServerTunnelManager::new
    // below (and =false in its Drop), so no explicit push here.

    let nat_mode = state.cfg.read().await.nat_mode.clone();
    if nat_mode == "kernel" {
        // Kernel TUN is Unix-only; Windows has no device we ship.
        #[cfg(not(unix))]
        return Err("server: kernel NAT mode is Unix-only — re-run with --nat-mode userspace".into());
        #[cfg(unix)]
        {
            // Pre-flight: open + drop a TUN once so privilege failures
            // surface at daemon-start, not at first-call time.
            // `bale_pf<K>` uses an out-of-pool slot index so the
            // probe can't race a real session's slot allocation.
            let probe_name = format!("bale_pf{KERNEL_TUN_SLOT_LIMIT}");
            let probe_addr = format!("10.8.{}.1", KERNEL_TUN_SLOT_LIMIT);
            match crate::tun::open_server_tun(&probe_name, &probe_addr, 24, 1400) {
                Ok(_) => log::info!("server: kernel TUN privilege check OK"),
                Err(e) => return Err(format!(
                    "server: kernel TUN open failed ({e}) — re-run with --nat-mode userspace, \
                     or `setcap cap_net_admin+eip $(which bale-vpn)` (Linux) / run as root (macOS) first"
                ).into()),
            }
        }
    } else if nat_mode != "userspace" {
        return Err(format!("unknown --nat-mode: {nat_mode}").into());
    }

    // Bring up the server-side tunnel manager. It installs its
    // own IncomingHandler on signaling (which delegates to our
    // AdmissionHandler), drains accepted_sessions to build
    // LkTunnels, and surfaces per-peer Connected / Disconnected
    // on its `events()` stream.
    let mgr = lktunnel::manager::ServerTunnelManager::new(
        state.signaling.clone(),
        state.activation.clone(),
    );
    mgr.set_admission(std::sync::Arc::new(AdmissionDecider {
        server: state.server.clone(),
    }));
    let mut events = mgr.events();
    let state_for_loop   = state.clone();
    let nat_mode_for_loop = nat_mode.clone();
    tokio::spawn(async move {
        use lktunnel::manager::SessionEvent;
        use tokio::sync::oneshot;
        let mut done: std::collections::HashMap<lk_signaling::PeerId, oneshot::Sender<()>> =
            std::collections::HashMap::new();
        while let Some(ev) = events.recv().await {
            match ev {
                SessionEvent::Connected { peer_id, tunnel } => {
                    let (tx, rx) = oneshot::channel();
                    done.insert(peer_id.clone(), tx);
                    let st       = state_for_loop.clone();
                    let nat_mode = nat_mode_for_loop.clone();
                    tokio::spawn(handle_server_session(st, nat_mode, peer_id, tunnel, rx));
                }
                SessionEvent::Disconnected { peer_id } => {
                    if let Some(tx) = done.remove(&peer_id) { let _ = tx.send(()); }
                }
                SessionEvent::Failed { peer_id } => {
                    // Two paths to Failed here:
                    //   1. Tunnel reached LkTunnel but never
                    //      hit Connected (handshake error,
                    //      peer never joined SFU).
                    //   2. WS CallEnded cancelled a pending
                    //      admission (the manager's CallEnded
                    //      handler drops the cancel sender and
                    //      emits Failed). The UI's pending row
                    //      needs clearing in this case so it
                    //      doesn't stay stuck on the user's
                    //      screen until they resolve it.
                    log::info!("server: session for {peer_id} failed to connect");
                    let peer_str = peer_id.id_str().to_string();
                    let st       = state_for_loop.clone();
                    tokio::spawn(async move {
                        st.server.pending_resolve(
                            &peer_str,
                            lk_signaling::CallDecision::SilentlyIgnore,
                        ).await;
                    });
                }
            }
        }
        log::info!("server: manager events stream ended");
    });

    // No WS CallEnded teardown path. LK is the sole authority
    // for "this session is over" — the per-session handler
    // observes engine Disconnected directly on the tunnel's
    // events stream. WS-side CallEnded pushes are intentionally
    // ignored so a transient WS hiccup (cardinality re-subscribes,
    // brief WS reconnect) can't drop a live LK session.

    log::info!("server: ready — parking until shutdown");
    std::future::pending::<()>().await;
    Ok(())
}

/// Drive one library-provided session. By the time we're spawned
/// the tunnel has already reached Connected (the library only
/// emits `SessionEvent::Connected` after the engine transitions
/// there). We set up NAT, install in the UI map, then park on
/// the `done` oneshot — the main events loop fires it when it
/// sees the matching `SessionEvent::Disconnected`.
async fn handle_server_session(
    st: Arc<AppState>,
    nat_mode: String,
    peer: lk_signaling::PeerId,
    tunnel: Arc<lktunnel::LkTunnel>,
    done: tokio::sync::oneshot::Receiver<()>,
) {
    let peer_id = peer.id_str().to_string();
    log::info!("server: session up for {peer_id}");
    let display = st.signaling.fetch_display_name(&peer).await;

    // Allocate a kernel-TUN slot if in kernel mode; on
    // exhaustion fall back to userspace NAT for this session
    // (other sessions can still use kernel TUN once a slot frees).
    let slots = st.server.clone();
    let mut slot_used: Option<u8> = None;
    let nat_ok = if nat_mode == "kernel" {
        // Kernel TUN is Unix-only. On non-Unix this arm is
        // unreachable (config preflight rejects kernel mode), but
        // it must still compile — fall back to userspace NAT.
        #[cfg(not(unix))]
        { let _ = &slots; tunnel.start_server().is_ok() }
        #[cfg(unix)]
        {
        match slots.alloc_kernel_slot() {
            Some(k) => {
                let name = format!("bale{k}");
                let addr = format!("10.8.{k}.1");
                match crate::tun::open_server_tun(&name, &addr, 24, 1400) {
                    Ok(dev) => {
                        let fd  = dev.into_raw_fd();
                        let fmt = crate::tun::host_tun_format();
                        match tunnel.attach_tun_with_format(fd, fmt) {
                            Ok(()) => {
                                log::info!("server: kernel TUN bale{k} ({addr}/24) attached for {peer_id} (fmt={fmt:?})");
                                slot_used = Some(k);
                                true
                            }
                            Err(e) => {
                                log::warn!("server: attach_tun bale{k} failed for {peer_id}: {e} — \
                                            fallback userspace NAT");
                                slots.release_kernel_slot(k);
                                unsafe { libc::close(fd); }
                                tunnel.start_server().is_ok()
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("server: open bale{k} failed for {peer_id}: {e} — \
                                    fallback userspace NAT");
                        slots.release_kernel_slot(k);
                        tunnel.start_server().is_ok()
                    }
                }
            }
            None => {
                log::warn!("server: kernel TUN pool exhausted — \
                            fallback userspace NAT for {peer_id}");
                tunnel.start_server().is_ok()
            }
        }
        }
    } else {
        match tunnel.start_server() {
            Ok(()) => { log::info!("server: userspace NAT up for {peer_id}"); true }
            Err(e) => { log::warn!("server: start_server failed for {peer_id}: {e}"); false }
        }
    };
    if !nat_ok {
        if let Some(k) = slot_used { slots.release_kernel_slot(k); }
        tunnel.disconnect();
        return;
    }
    st.server.install_client(peer_id.clone(), tunnel, display, slot_used).await;

    // Park until the main events loop signals Disconnected for
    // this peer. Either an `Err` (sender dropped) or `Ok(())`
    // means the session is over — clean up either way.
    let _ = done.await;
    log::info!("server: {peer_id} disconnected");
    st.server.remove_client(&peer_id).await;
}

/// Cap on simultaneous kernel-TUN sessions. Each slot consumes a
/// `10.8.<K>.0/24` subnet and a `bale<K>` interface; the iptables
/// MASQUERADE rule needs to be widened to `-s 10.8.0.0/16` to
/// cover the whole pool. 254 leaves room for a single probe slot
/// at `KERNEL_TUN_SLOT_LIMIT` so daemon-start privilege checks
/// can't collide with a real session.
pub(crate) const KERNEL_TUN_SLOT_LIMIT: u8 = 254;

/// IncomingHandler impl. Defers to [`ServerState`] for the
/// allow/block lookup and parks pending decisions on a
/// oneshot the UI completes.
struct AdmissionDecider {
    server: Arc<ServerState>,
}

#[async_trait::async_trait]
impl lk_signaling::IncomingHandler for AdmissionDecider {
    async fn decide(&self, peer: PeerId, display_name: Option<String>) -> CallDecision {
        let peer_str = peer.id_str().to_string();

        // Blocked callers: explicit reject so they see the call
        // terminate immediately, not after a timeout.
        if self.server.blacklist_list().await.iter().any(|p| p == &peer_str) {
            log::info!("server: rejecting blacklisted {peer_str}");
            return CallDecision::Reject;
        }
        // Capacity rejection stays silent — caller is free to
        // re-dial once a slot frees up.
        if self.server.client_count().await >= self.server.max_clients() as usize {
            log::info!("server: at capacity — silently ignoring {peer_str}");
            return CallDecision::SilentlyIgnore;
        }
        if self.server.admission_list().await.iter().any(|p| p == &peer_str) {
            return CallDecision::Accept;
        }

        // Park for user decision. The UI calls
        // `/server/pending/<peer>/accept|reject` to resolve.
        // 60 s default timeout matches the Android UX.
        let (tx, rx) = oneshot::channel();
        self.server.pending_park(peer_str.clone(), display_name, tx).await;
        let decision = tokio::time::timeout(Duration::from_secs(60), rx).await;
        match decision {
            Ok(Ok(d))  => d,
            Ok(Err(_)) => CallDecision::SilentlyIgnore,    // sender dropped
            Err(_)     => {
                log::info!("server: pending decision timeout for {peer_str}");
                // Best-effort: clear the pending entry so the
                // UI doesn't show a stale row.
                self.server.pending_resolve(&peer_str, CallDecision::SilentlyIgnore).await;
                CallDecision::SilentlyIgnore
            }
        }
    }
}

async fn run_client(state: &Arc<AppState>) -> Result<(), Box<dyn Error + Send + Sync>> {
    // No server-active push needed — the previous mode's manager
    // Drop already deactivated. The ClientTunnelManager
    // constructed below activates with client semantics.

    let (peer_id_str, socks5_port, client_tun) = {
        let cfg = state.cfg.read().await;
        (cfg.peer_id.clone(), cfg.socks5_port, cfg.client_tun)
    };
    let Some(peer_id_str) = peer_id_str else {
        log::info!("client: no peer_id configured — waiting for selection via HTTP UI");
        std::future::pending::<()>().await;
        return Ok(());
    };
    log::info!("client: placing call to peer {peer_id_str}");

    let peer = state.signaling.resolve_peer(&peer_id_str).await
        .ok_or("client: unknown peer (resolve_peer returned None)")?;

    // Tunnel lifecycle → notify the parked run_client via a
    // oneshot. LK is the sole authority: a `Disconnected` from
    // the manager's events stream means the session ended.
    // We do NOT subscribe to WS CallEnded — the manager itself
    // applies the "WS callEnded for our peer pre-LK → tear
    // down the dial; post-LK → ignore" rule centrally, so a
    // WS hiccup during a live session can't drop us. Pre-LK
    // WS rejections still surface here as `SessionEvent::
    // Failed` from the manager (the manager's CallEnded
    // handler disconnects the in-flight tunnel and the
    // watcher emits Failed since `entered=false`).
    let (lk_done_tx, lk_done_rx) = tokio::sync::oneshot::channel::<()>();
    let lk_done_tx = Arc::new(std::sync::Mutex::new(Some(lk_done_tx)));
    let lk_done_for_lk = Arc::clone(&lk_done_tx);

    // Bring up the client tunnel manager + subscribe to its
    // events stream BEFORE placing the call so the Connected
    // event can't be missed (sender installs on the first
    // `events()` call; the manager's internal watcher emits
    // Connected as soon as the engine reaches it, which is
    // potentially within the same task tick on a fast path).
    let mgr = lktunnel::manager::ClientTunnelManager::new(
        state.signaling.clone(),
        state.activation.clone(),
    );
    let mut mgr_events = mgr.events();

    match mgr.place_call(peer.clone()).await {
        Ok(())                                 => {}
        Err(PlaceCallError::Rejected)          => return Err("call rejected by peer".into()),
        Err(PlaceCallError::NoPeer)            => return Err("peer never joined (timeout)".into()),
        Err(PlaceCallError::NotAuthenticated)  => return Err("not authenticated".into()),
        Err(PlaceCallError::Transport(s))      => return Err(format!("transport: {s}").into()),
    }
    log::info!("client: call placed, joining LK room");

    // Wait for Connected matching our peer. `Failed` for our peer
    // means the dial never landed (pure-LK failure OR pre-LK WS
    // CallEnded — the manager funnels both through `Failed`).
    use lktunnel::manager::SessionEvent;
    let tunnel = loop {
        match mgr_events.recv().await {
            Some(SessionEvent::Connected { peer_id, tunnel }) if peer_id == peer => break tunnel,
            Some(SessionEvent::Failed { peer_id }) if peer_id == peer =>
                return Err("LK failed to connect".into()),
            Some(SessionEvent::Disconnected { peer_id }) if peer_id == peer =>
                return Err("LK disconnected before connect".into()),
            Some(_) => continue,
            None    => return Err("manager events stream closed".into()),
        }
    };
    log::info!("client: LK tunnel up");

    // Hold the manager alive past this scope — it's the only
    // thing keeping the watcher / sender side of `events()`
    // running. Dropped when the outer client task is cancelled
    // (which is what we want — it tears the session down).
    let _mgr_keepalive = mgr;

    // Spawn a watcher that fires lk_done when Disconnected for
    // our peer arrives on the unified stream.
    tokio::spawn(async move {
        while let Some(ev) = mgr_events.recv().await {
            if let SessionEvent::Disconnected { peer_id } = &ev {
                if peer_id == &peer {
                    if let Some(tx) = lk_done_for_lk.lock().expect("lk_done lock").take() {
                        log::info!("client: LK tunnel disconnected — tearing down session");
                        let _ = tx.send(());
                    }
                    break;
                }
            }
        }
    });

    let bound = tunnel.enable_socks5_server(socks5_port).await
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.to_string().into() })?;
    log::info!("client: SOCKS5 listening on {bound}");

    // Optional TUN attach. Lets the host route traffic through
    // the tunnel directly (full system VPN). The caller is
    // expected to set up routing (`ip route add default dev
    // bale-c0`) — we don't touch the routing table from here.
    // Kernel-TUN client attach is Unix-only; on Windows the host VPN
    // path isn't available (userspace NAT / SOCKS5 only).
    #[cfg(unix)]
    if client_tun {
        match crate::tun::open_client_tun("bale-c0", "10.8.0.2", 24, 1400) {
            Ok(dev) => {
                let iface = dev.name.clone();
                let fd    = dev.into_raw_fd();
                let fmt   = crate::tun::host_tun_format();
                log::info!("client: opened TUN {iface} (10.8.0.2/24, fd={fd}, fmt={fmt:?}) — \
                            install your default route via that interface");
                if let Err(e) = tunnel.attach_tun_with_format(fd, fmt) {
                    log::warn!("client: attach_tun failed: {e}");
                }
            }
            Err(e) => log::warn!(
                "client: --client-tun set but TUN open failed ({e}); SOCKS5 still up"
            ),
        }
    }
    #[cfg(not(unix))]
    if client_tun {
        log::warn!("client: --client-tun is Unix-only; ignoring on this OS (SOCKS5 still up)");
    }

    // Publish to ClientState so the HTTP UI can show status +
    // future runtime toggles (SOCKS5 on/off, port change) can
    // reach the tunnel.
    state.client.set_tunnel(tunnel.clone(), bound.port());

    // Park until either the LK side disconnects (server left
    // the room) or the outer select! catches a shutdown
    // signal. Either way, clear ClientState on exit so the UI
    // flips back to the activate prompt.
    let _ = lk_done_rx.await;
    state.client.clear();
    Ok(())
}

/// Block until SIGTERM / SIGINT (or Ctrl-C on Windows).
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint  = signal(SignalKind::interrupt()).expect("sigint");
        let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
        tokio::select! {
            _ = sigint.recv()  => log::info!("SIGINT received"),
            _ = sigterm.recv() => log::info!("SIGTERM received"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Ctrl-C received");
    }
}
