//! `BaleSignaling` — the [`lk_signaling::Signaling`] impl for
//! Bale. Wraps [`crate::ws::WsClient`] (signal channel) and uses
//! [`crate::auth::BaleAuth`] for sign-in via the `BaleAuth`
//! surface exposed alongside (not through) the trait.

use crate::contacts::{self, UserEntity};
use crate::grpc_web;
use crate::peer::BalePeer;
use crate::ws::{CallEntity, TextMessageCb, WsClient};

use async_trait::async_trait;
use lk_signaling::{
    CallDecision, ContactPage, EndReason, EventsSink, IncomingHandler,
    PeerId, PlaceCallError, Signaling, SignalingError, SignalingEvent,
    TokenStore, TransportSession, TunnelHooks,
};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc;

// Internal incoming-handler Arc alias — the trait surface takes
// `Box<dyn IncomingHandler>` and we convert to `Arc` on receipt
// so the WS listener can clone into spawned tasks.
type ArcIncoming = Arc<dyn IncomingHandler>;

pub struct BaleSignaling {
    ws:           Arc<WsClient>,
    token_store:  Arc<dyn TokenStore>,

    /// Shared HTTP client for gRPC-web calls (contacts only — WS
    /// has its own connection). Cheap to clone; reqwest pools
    /// connections internally.
    http:         reqwest::Client,

    /// Cached unfiltered contact list. Populated on the first
    /// `list_contacts(query=None)` call and invalidated on a
    /// `ContactsChanged` event (TODO once WS surfaces
    /// contact-update pushes). Hand-rolled pagination cursors
    /// index into this Vec.
    contact_cache: Mutex<Option<Vec<UserEntity>>>,

    /// Peer cache enforcing the [`PeerId`] ptr-eq identity
    /// invariant.
    peer_cache:   Mutex<HashMap<i32, PeerId>>,

    /// Multi-consumer, lossless fan-out for the unified [`SignalingEvent`]
    /// stream; [`Self::events`] hands out independent receivers. Lives from
    /// construction so consumers wired up before the lifecycle catch every
    /// event. WS callbacks push `AuthExpired` / `ProtocolObsolete` /
    /// `CallEnded` / `ContactsChanged` here — app *and* each manager get
    /// their own copy.
    events:           EventsSink<SignalingEvent>,
    incoming_handler: Mutex<Option<ArcIncoming>>,

    /// `call_id → PeerId` for every call this instance is
    /// tracking, regardless of direction. Populated by
    /// `place_call` (outgoing) and the IncomingHandler::Accept
    /// path (incoming); drained when the WS-level callEnded
    /// event arrives and emits `SignalingEvent::CallEnded`.
    active_peers:         Mutex<HashMap<i64, PeerId>>,

    /// `call_id`s currently being processed in
    /// [`Self::on_incoming_call`]. Bale's WS push pipeline can
    /// re-deliver the same `callReceived` (subscribe-stream
    /// rotation, server retransmits) — without dedup we'd run
    /// `decide()` + `accept_call()` twice for one call and end
    /// up with two LkTunnels dialing different LK SFUs. Entries
    /// are removed when the per-call task returns (any path —
    /// accept / reject / silent ignore / failure).
    in_flight_calls:      Mutex<HashSet<i64>>,

    /// Sender for the [`TransportSession`] stream consumed by
    /// the lktunnel-side manager. `None` until
    /// [`Self::accepted_sessions`] is called.
    accepted_tx:    Mutex<Option<mpsc::UnboundedSender<(PeerId, TransportSession)>>>,
    /// Monotonic teardown counter surfaced via
    /// [`TunnelHooks::subscribe_teardown`]. Incremented by both
    /// `sign_out` and `disconnect` so the server manager kills
    /// active sessions in lock-step with either user-initiated
    /// teardown.
    teardown_count: tokio::sync::watch::Sender<u64>,
}

/// RAII guard that removes a call_id from `in_flight_calls` on
/// drop. Used inside [`BaleSignaling::on_incoming_call`] so any
/// return path (success, reject, silent-ignore, error early-return)
/// releases the dedup entry without scattered manual removals.
struct InFlightGuard {
    me:      Arc<BaleSignaling>,
    call_id: i64,
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.me.in_flight_calls.lock().remove(&self.call_id);
    }
}

impl BaleSignaling {
    pub fn new(token_store: Arc<dyn TokenStore>) -> Arc<Self> {
        let me = Arc::new(Self {
            ws:                   WsClient::new(),
            token_store,
            http:                 grpc_web::build_client(),
            contact_cache:    Mutex::new(None),
            peer_cache:       Mutex::new(HashMap::new()),
            events:           EventsSink::new(),
            incoming_handler: Mutex::new(None),
            active_peers:     Mutex::new(HashMap::new()),
            in_flight_calls:  Mutex::new(HashSet::new()),
            accepted_tx:      Mutex::new(None),
            teardown_count:   tokio::sync::watch::channel(0u64).0,
        });
        me.setup_ws_listeners();
        me.setup_auth_callbacks();
        me
    }

    /// Load any persisted token from the [`TokenStore`] and push
    /// it into the WS rule engine. Idempotent. Caller-driven so
    /// platforms whose `TokenStore` impl isn't safe to invoke
    /// during construction (Android JNI: `nativeCreate` runs on
    /// a thread state where calling back into Java crashes) can
    /// defer it. The Rust binary calls it from `daemon::run`;
    /// Android relies on its existing explicit `connect()` path
    /// to load the token on demand.
    pub fn auto_load_token(self: &Arc<Self>) {
        if let Some(bytes) = self.token_store.load() {
            if let Ok(s) = String::from_utf8(bytes) {
                self.ws.set_token(Some(s));
            }
        }
    }

    /// API-level connect intent. True iff there's a token AND
    /// the user hasn't explicitly disconnected. Different from
    /// [`Signaling::is_connected`] (wire-level handshake-done):
    /// stays true through the run loop's reconnect-backoff
    /// window, so UIs can render "Connecting…" between
    /// Disconnected and Connected.
    ///
    /// Derived — no separate flag. The truth table:
    ///   - init:         token=None      → false
    ///   - connect():    token=Some, ud=false → true
    ///   - disconnect(): ud=true         → false
    ///   - sign_out():   token=None      → false
    pub fn is_connect_requested(&self) -> bool {
        self.ws.has_token() && !self.ws.is_user_disconnected()
    }

    /// True while the WS run loop is actively trying to
    /// connect / reconnect. UI's "Connecting…" indicator —
    /// distinct from [`Self::is_connect_requested`] (user
    /// intent) which can stay true while the rule engine
    /// intentionally hasn't spawned the loop.
    pub fn ws_is_attempting_connect(&self) -> bool { self.ws.is_attempting_connect() }


    /// Cache-hit-or-mint. The only sanctioned way to obtain a
    /// `PeerId` inside this impl — direct `PeerId::new(BalePeer
    /// { … })` elsewhere would violate the ptr-eq identity
    /// invariant.
    pub fn intern_peer(&self, uid: i32, access_hash: i64, display_name: Option<String>) -> PeerId {
        // Mirror the name into the WS name cache so a subsequent
        // `peer_display_name(uid)` returns it. Without this, self
        // (interned via `whoami` → `intern_peer(uid, 0, name)`)
        // would render as `(no name)` in the UI because
        // `peer_display_name` only checks `ws.cached_name`, not
        // the PeerId's internal display_name field.
        if let Some(name) = display_name.as_ref().filter(|n| !n.is_empty()) {
            self.ws.populate_names(std::iter::once((uid, Some(name.clone()))));
        }
        let mut cache = self.peer_cache.lock();
        if let Some(existing) = cache.get(&uid) {
            return existing.clone();
        }
        let id = PeerId::new(BalePeer::new(uid, access_hash, display_name));
        cache.insert(uid, id.clone());
        id
    }

    /// Bridge: WS auth-expired / version-mismatch → trait
    /// callbacks. Held via Weak so the closure doesn't keep the
    /// signaling alive past consumer drop.
    fn setup_auth_callbacks(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.ws.set_on_token_expired(Arc::new(move || {
            let Some(me) = weak.upgrade() else { return; };
            // Clear both the persisted store and the in-memory
            // WS token. Without the latter, the WS rule engine
            // still sees `has_token()=true` and a subsequent
            // re-auth's `set_token(Some(new))` wouldn't trigger
            // an evaluate (no change in the desired_up output if
            // user_disconnect is unchanged).
            me.token_store.clear();
            me.ws.set_token(None);
            me.emit_event(SignalingEvent::AuthExpired);
        }));
        let weak = Arc::downgrade(self);
        self.ws.set_on_version_mismatch(Arc::new(move || {
            let Some(me) = weak.upgrade() else { return; };
            me.emit_event(SignalingEvent::ProtocolObsolete);
        }));
    }

    /// Push an event onto the unified [`Signaling::events`]
    /// stream. Silent no-op when no consumer is subscribed.
    fn emit_event(&self, ev: SignalingEvent) {
        // Fan out to every subscriber (app + managers); no-op if none yet.
        self.events.emit(ev);
    }

    fn setup_ws_listeners(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        // callReceived / callStarted → incoming handler →
        // accept / reject / silently ignore.
        self.ws.add_on_call_received(Arc::new(move |call_id, call| {
            let Some(me) = weak.upgrade() else { return; };
            tokio::spawn(async move { me.on_incoming_call(call_id, call).await });
        }));

        let weak = Arc::downgrade(self);
        // callEnded → route to the right side based on which
        // active-call map the call_id sits in.
        self.ws.add_on_call_ended(Arc::new(move |call_id, discard_reason| {
            let Some(me) = weak.upgrade() else { return; };
            me.on_call_ended_internal(call_id, discard_reason);
        }));
    }

    /// Async incoming-call handler. Implements the Bale paired-
    /// update workaround (when `caller_id == 0`, the field
    /// arrives on a later update — silently defer) and the
    /// Accept/Reject/SilentlyIgnore dispatch.
    // RAII guard for the in_flight_calls dedup set — removes the
    // call_id on drop so all return paths in on_incoming_call
    // (success, reject, silent-ignore, every error early-return)
    // cleanly release the entry. Cheaper than scattering manual
    // removes across the many return points.
    async fn on_incoming_call(self: Arc<Self>, call_id: i64, call: Option<CallEntity>) {
        let caller_id = call.as_ref().map(|c| c.caller_id).unwrap_or(0);
        // Paired-update workaround.
        if caller_id == 0 { return; }
        if caller_id > i32::MAX as i64 || caller_id < 0 {
            log::warn!("incoming call_id={call_id} has out-of-range caller_id={caller_id}");
            return;
        }

        // Dedup: Bale's WS push pipeline can re-deliver the same
        // callReceived (we saw this when the server's WS went
        // zombie + reconnected — flushed-queue + subscribe-
        // rotation both re-delivered). Two concurrent
        // on_incoming_call calls would each accept_call + fire
        // on_session_ready → two LkTunnels for one call dialing
        // different SFUs, peer joins only one, other times out.
        if !self.in_flight_calls.lock().insert(call_id) {
            log::info!("duplicate callReceived for call_id={call_id} — ignoring");
            return;
        }
        let _guard = InFlightGuard { me: self.clone(), call_id };

        let peer = self.intern_peer(caller_id as i32, 0, None);

        let handler = self.incoming_handler.lock().clone();
        let Some(handler) = handler else {
            // No handler installed yet — silently ignore. Caller
            // times out. Matches the "no server admission UI
            // configured" case.
            return;
        };

        let decision = handler.decide(peer.clone(), self.peer_display_name(&peer)).await;

        match decision {
            CallDecision::Accept => {
                let Some(accepted) = self.ws.accept_call(call_id).await else {
                    log::warn!("acceptCall returned no entity for {call_id}");
                    return;
                };
                // Bale's AcceptCall reply doesn't always re-state
                // `is_livekit`; fall back to the incoming-event
                // entity (callStarted always carries it). Matches
                // the Kotlin BaleServerService.handleCall check.
                let is_livekit = call.as_ref().map(|c| c.is_livekit).unwrap_or(false)
                                 || accepted.is_livekit;
                if !is_livekit || accepted.token.is_empty() {
                    log::warn!(
                        "acceptCall for {call_id} missing LK creds: \
                         is_livekit={} (incoming={}, accept={}) token_len={} url_len={}",
                        is_livekit,
                        call.as_ref().map(|c| c.is_livekit).unwrap_or(false),
                        accepted.is_livekit, accepted.token.len(), accepted.url.len(),
                    );
                    return;
                }
                // Track so a later callEnded fires on_call_ended.
                self.active_peers.lock().insert(call_id, peer.clone());

                let transport = TransportSession {
                    url:     accepted.url,
                    token:   accepted.token,
                    peer_id: peer.clone(),
                };
                // Surface the transport to whichever consumer (the
                // lktunnel manager, typically) has subscribed to
                // `accepted_sessions`. If nobody's subscribed yet,
                // the session is dropped silently — there's no
                // backlog by design.
                if let Some(tx) = self.accepted_tx.lock().as_ref() {
                    let _ = tx.send((peer, transport));
                } else {
                    log::warn!("incoming call accepted but no accepted_sessions consumer; dropping");
                }
            }
            CallDecision::Reject => {
                self.ws.discard_call(call_id).await;
            }
            CallDecision::SilentlyIgnore => {
                // No-op. Caller's UI eventually times out without
                // an explicit reject — matches the blacklist /
                // pending-call-timeout flow.
            }
        }
    }

    /// Sync callEnded dispatcher. Looks up the peer for this
    /// call_id in [`Self::active_peers`], fans the event out to
    /// the manager-internal [`TunnelHooks::subscribe_call_ended`]
    /// subscribers (so the managers can enforce the
    /// "LK-authoritative" rule centrally), and emits
    /// [`SignalingEvent::CallEnded`] on the unified events
    /// stream for app consumers.
    fn on_call_ended_internal(&self, call_id: i64, discard_reason: i32) {
        let Some(peer) = self.active_peers.lock().remove(&call_id) else {
            log::debug!("callEnded for unknown call_id={call_id} (discard_reason={discard_reason})");
            return;
        };
        let reason = map_discard_reason(discard_reason);
        // One stream now: app + managers all consume `events()` (broadcast)
        // and match `CallEnded`. No separate manager fan-out.
        self.emit_event(SignalingEvent::CallEnded { peer_id: peer, reason });
    }
}

impl BaleSignaling {
    /// Read the persisted access token as a UTF-8 string. Used
    /// by the contact RPCs which go over gRPC-web (the WS
    /// already has its own copy).
    fn access_token_str(&self) -> Result<String, SignalingError> {
        self.token_store.load()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or(SignalingError::NotAuthenticated)
    }

    /// Fetch + cache the full unfiltered contact list. Subsequent
    /// `list_contacts(query=None)` calls slice into the cache
    /// without hitting the wire until [`Self::add_contact_by_phone`]
    /// / [`Self::remove_contact`] (or a future contacts-changed
    /// push) clears it.
    async fn load_full_contact_list(&self, token: &str) -> Result<Vec<UserEntity>, SignalingError> {
        if let Some(cached) = self.contact_cache.lock().clone() {
            return Ok(cached);
        }
        let peers_or_inline = contacts::get_contact_peers(&self.http, token).await
            .map_err(grpc_to_signaling)?;
        let users = if !peers_or_inline.peers.is_empty() {
            contacts::load_users_batch(&self.http, token, &peers_or_inline.peers).await
                .map_err(grpc_to_signaling)?
        } else {
            peers_or_inline.inline_users
        };
        // Pre-populate the WS name cache so per-row UI lookups
        // (`peer_display_name`) hit sync instead of firing an
        // RPC per row.
        self.ws.populate_names(users.iter().map(|u| {
            let dn = u.display_name();
            (u.id, if dn.is_empty() { None } else { Some(dn) })
        }));
        *self.contact_cache.lock() = Some(users.clone());
        Ok(users)
    }

    /// Outbound half of the text transport — see
    /// [`WsClient::send_text_message`]. Returns the `rid` the
    /// message was filed under (the inbound `newMessage` push
    /// echoes it back, so a caller can recognize its own echo).
    ///
    /// `access_hash` is passed as `0`: `SendMessage` accepts it
    /// for private peers (probed live against Bale), and
    /// [`PeerId`] is an identity token here — it deliberately
    /// doesn't carry the hash.
    pub async fn send_text_message(
        &self,
        p:    &PeerId,
        text: &str,
    ) -> Result<i64, SignalingError> {
        if !self.is_authenticated() {
            return Err(SignalingError::NotAuthenticated);
        }
        let uid = p.id_str().parse::<i32>()
            .map_err(|_| SignalingError::Transport("peer id is not a Bale uid".into()))?;
        self.ws.send_text_message(uid, 0, text).await
            .map_err(|e| SignalingError::Transport(format!("SendMessage failed: {e}")))
    }

    /// Inbound half of the text transport: register a listener for
    /// text messages arriving on the `f=2` push path (xC member
    /// 55). Forwards to [`WsClient::add_on_text_message`]; wiring
    /// done directly on the WS client keeps working alongside it.
    pub fn add_on_text_message(&self, cb: TextMessageCb) {
        self.ws.add_on_text_message(cb);
    }
}

fn grpc_to_signaling(e: crate::grpc_web::GrpcError) -> SignalingError {
    SignalingError::Transport(e.to_string())
}

/// Map Bale's `discardReason` enum to the trait's [`EndReason`].
/// We don't yet have a confirmed mapping from numeric codes to
/// the named variants, so this stays conservative: known well-
/// behaved exits map to specific variants; everything else
/// passes through as `Other(code)` so callers can interpret.
fn map_discard_reason(code: i32) -> EndReason {
    EndReason::Other(code)
}

#[async_trait]
impl Signaling for BaleSignaling {
    /// Reflects the WS handshake-completed state, not just
    /// "connect was called". Matches the trait's documented
    /// "is the control channel currently up" semantics.
    fn is_connected(&self) -> bool { self.ws.is_ready() }

    async fn connect(&self) -> Result<(), SignalingError> {
        // Push inputs into the WS rule engine; it decides whether
        // to spawn the run loop. Connect intent = clear user
        // disconnect + install token; the engine evaluates and
        // brings the WS up if all other gates allow.
        let token = self.token_store.load()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or(SignalingError::NotAuthenticated)?;
        self.ws.set_user_disconnect(false);
        self.ws.set_token(Some(token));
        Ok(())
    }

    async fn disconnect(&self) {
        // Notify subscribers first — server manager
        // `disconnect_all()`s its sessions so peers see clean
        // LK drops before the WS comes down.
        self.teardown_count.send_modify(|c| *c = c.wrapping_add(1));
        // Sticky "user disconnected" — rule engine flips WS down
        // regardless of foreground / mode. Token is preserved so
        // a subsequent `connect()` doesn't need re-auth.
        self.ws.set_user_disconnect(true);
    }

    async fn sign_out(&self) {
        // Same teardown signal as `disconnect` — server manager
        // tears its sessions down before we clear auth.
        self.teardown_count.send_modify(|c| *c = c.wrapping_add(1));
        // Token cleared → rule engine sees no auth → WS goes down.
        self.ws.set_token(None);
        self.token_store.clear();
    }

    fn events(&self) -> mpsc::UnboundedReceiver<SignalingEvent> {
        self.events.subscribe()
    }

    fn is_authenticated(&self) -> bool { self.token_store.load().is_some() }

    async fn whoami(&self) -> Option<PeerId> {
        let info = self.ws.cached_self()?;
        Some(self.intern_peer(info.uid, 0, info.name))
    }

    fn set_foreground(&self, fg: bool) { self.ws.set_foreground(fg); }

    fn tunnel_hooks(&self) -> &dyn TunnelHooks { self }
    async fn list_contacts(
        &self,
        query:  Option<&str>,
        cursor: Option<&str>,
        limit:  usize,
    ) -> Result<ContactPage, SignalingError> {
        let token = self.access_token_str()?;

        // Searches always hit the wire. The unfiltered list goes
        // through the cache so subsequent page-flips don't re-
        // fetch.
        let users = if let Some(q) = query.filter(|q| !q.is_empty()) {
            contacts::search_contacts_by_name(&self.http, &token, q).await
                .map_err(grpc_to_signaling)?
        } else {
            self.load_full_contact_list(&token).await?
        };

        // Cursor is an opaque string — we encode the next offset
        // as a decimal number. `None` cursor starts at 0.
        let start = cursor.and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let end   = start.saturating_add(limit).min(users.len());
        let slice = &users[start.min(users.len())..end];

        let peers: Vec<PeerId> = slice.iter()
            .map(|u| self.intern_peer(u.id, u.access_hash, Some(u.display_name())))
            .collect();
        let next = if end < users.len() { Some(end.to_string()) } else { None };
        Ok(ContactPage { peers, next_cursor: next })
    }
    async fn search_contact_by_phone(&self, phone: &str) -> Result<Vec<PeerId>, SignalingError> {
        let token = self.access_token_str()?;
        let users = contacts::import_contact_by_phone(&self.http, &token, phone).await
            .map_err(grpc_to_signaling)?;
        // Bale's `ImportContacts` adds matches as a side effect
        // of looking them up — there's no non-mutating phone
        // lookup RPC. Invalidate the cached list so the next
        // list_contacts picks up the new entry.
        *self.contact_cache.lock() = None;
        Ok(users.into_iter()
            .map(|u| self.intern_peer(u.id, u.access_hash, Some(u.display_name())))
            .collect())
    }

    async fn add_to_contacts(&self, _peer: &PeerId) -> Result<(), SignalingError> {
        // Bale's `ImportContacts` already added the peer during
        // [`Self::search_contact_by_phone`] — no further server
        // call is needed. Documented as part of the trait
        // contract; impls without the conflated lookup+add
        // would do the actual work here.
        Ok(())
    }
    async fn remove_contact(&self, p: &PeerId) -> Result<(), SignalingError> {
        let token = self.access_token_str()?;
        let uid   = p.id_str().parse::<i32>()
            .map_err(|_| SignalingError::Transport("peer id is not a Bale uid".into()))?;
        // Look up access_hash from our cache — RemoveContact
        // rejects stale hashes, so a fresh value is essential.
        let access_hash = self.contact_cache.lock().as_ref()
            .and_then(|users| users.iter().find(|u| u.id == uid).map(|u| u.access_hash))
            .unwrap_or(0);
        contacts::remove_contact(&self.http, &token, uid, access_hash).await
            .map_err(grpc_to_signaling)?;
        *self.contact_cache.lock() = None;
        Ok(())
    }

    fn peer_display_name(&self, p: &PeerId) -> Option<String> {
        let uid = p.id_str().parse::<i32>().ok()?;
        self.ws.cached_name(uid)
    }

    async fn fetch_display_name(&self, p: &PeerId) -> Option<String> {
        if let Some(n) = self.peer_display_name(p) { return Some(n); }
        let uid = p.id_str().parse::<i32>().ok()?;
        self.ws.load_user_name(uid).await
    }

    async fn resolve_peer(&self, s: &str) -> Option<PeerId> {
        let uid = s.parse::<i32>().ok()?;
        Some(self.intern_peer(uid, 0, None))
    }
}

#[async_trait]
impl TunnelHooks for BaleSignaling {
    async fn place_call(&self, peer: PeerId) -> Result<TransportSession, PlaceCallError> {
        let uid = peer.id_str().parse::<i32>().map_err(|_| PlaceCallError::NoPeer)?;
        let peer_type = 1i32;   // PEERTYPE_PRIVATE

        let call = self.ws.start_call(uid, peer_type).await
            .ok_or_else(|| PlaceCallError::Transport("startCall returned no entity".into()))?;
        if !call.is_livekit || call.token.is_empty() {
            return Err(PlaceCallError::Transport(
                "startCall reply had no LiveKit credentials".into()));
        }

        // Track for callEnded bookkeeping. The PeerId we hand
        // out via TransportSession is the SAME Arc the caller
        // passed in, satisfying the ptr-eq invariant.
        self.active_peers.lock().insert(call.call_id, peer.clone());

        Ok(TransportSession {
            url:     call.url,
            token:   call.token,
            peer_id: peer,
        })
    }

    fn set_incoming_handler(&self, h: Box<dyn IncomingHandler>) {
        *self.incoming_handler.lock() = Some(Arc::from(h));
    }

    fn accepted_sessions(&self) -> mpsc::UnboundedReceiver<(PeerId, TransportSession)> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.accepted_tx.lock() = Some(tx);
        rx
    }

    fn activate  (&self) { self.ws.set_manager_active(true); }
    fn deactivate(&self) { self.ws.set_manager_active(false); }

    fn subscribe_foreground(&self) -> tokio::sync::watch::Receiver<bool> {
        self.ws.subscribe_foreground()
    }

    fn subscribe_teardown(&self) -> tokio::sync::watch::Receiver<u64> {
        self.teardown_count.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_signaling::IncomingHandler;

    struct MemStore { inner: Mutex<Option<Vec<u8>>> }
    impl TokenStore for MemStore {
        fn load (&self) -> Option<Vec<u8>> { self.inner.lock().clone() }
        fn save (&self, b: &[u8])           { *self.inner.lock() = Some(b.to_vec()); }
        fn clear(&self)                     { *self.inner.lock() = None; }
    }
    fn store_empty() -> Arc<dyn TokenStore> { Arc::new(MemStore { inner: Mutex::new(None) }) }
    fn store_with(token: &str) -> Arc<dyn TokenStore> {
        Arc::new(MemStore { inner: Mutex::new(Some(token.as_bytes().to_vec())) })
    }

    #[tokio::test]
    async fn resolve_peer_round_trips_and_is_idempotent() {
        let s = BaleSignaling::new(store_empty());
        let a = s.resolve_peer("42").await.unwrap();
        let b = s.resolve_peer("42").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(a.id_str(), "42");
    }

    #[tokio::test]
    async fn resolve_peer_distinct_uids_distinct_handles() {
        let s = BaleSignaling::new(store_empty());
        let a = s.resolve_peer("1").await.unwrap();
        let b = s.resolve_peer("2").await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn resolve_peer_garbage_returns_none() {
        let s = BaleSignaling::new(store_empty());
        assert!(s.resolve_peer("not-a-number").await.is_none());
    }

    #[tokio::test]
    async fn is_authenticated_reflects_token_store() {
        assert!(!BaleSignaling::new(store_empty()).is_authenticated());
        assert!( BaleSignaling::new(store_with("tok")).is_authenticated());
    }

    #[tokio::test]
    async fn sign_out_clears_token() {
        let store = store_with("tok");
        let s = BaleSignaling::new(store.clone());
        assert!(s.is_authenticated());
        s.sign_out().await;
        assert!(!s.is_authenticated());
        assert!(store.load().is_none());
    }

    #[tokio::test]
    async fn connect_without_token_errors() {
        let s = BaleSignaling::new(store_empty());
        assert!(matches!(s.connect().await, Err(SignalingError::NotAuthenticated)));
    }

    // ── on_call_ended routing ─────────────────────────────────

    #[tokio::test]
    async fn call_ended_emits_event_for_tracked_peer() {
        let s = BaleSignaling::new(store_empty());

        let mut events = s.events();

        // Pre-record an active call (we'd normally do this via
        // place_call or the IncomingHandler::Accept path, but the
        // RPC layer needs a real WS — we're testing the
        // dispatcher in isolation).
        let peer = s.resolve_peer("777").await.unwrap();
        s.active_peers.lock().insert(123, peer.clone());

        s.on_call_ended_internal(123, 5);

        let ev = events.recv().await.expect("events stream should emit");
        match ev {
            SignalingEvent::CallEnded { peer_id, reason } => {
                assert_eq!(peer_id, peer);
                assert!(matches!(reason, EndReason::Other(5)));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(s.active_peers.lock().is_empty());
    }

    #[tokio::test]
    async fn call_ended_unknown_id_drops_silently() {
        let s = BaleSignaling::new(store_empty());
        // No callbacks installed. Should not panic.
        s.on_call_ended_internal(424242, 0);
    }

    // ── Incoming-call dispatch ────────────────────────────────

    struct AlwaysAccept;
    #[async_trait]
    impl IncomingHandler for AlwaysAccept {
        async fn decide(&self, _peer: PeerId, _name: Option<String>) -> CallDecision { CallDecision::Accept }
    }

    struct AlwaysReject;
    #[async_trait]
    impl IncomingHandler for AlwaysReject {
        async fn decide(&self, _peer: PeerId, _name: Option<String>) -> CallDecision { CallDecision::Reject }
    }

    struct AlwaysIgnore;
    #[async_trait]
    impl IncomingHandler for AlwaysIgnore {
        async fn decide(&self, _peer: PeerId, _name: Option<String>) -> CallDecision { CallDecision::SilentlyIgnore }
    }

    #[tokio::test]
    async fn incoming_call_with_caller_id_zero_is_deferred() {
        // Paired-update workaround: an incoming with caller_id=0
        // shouldn't trigger the handler at all. We verify by
        // installing a handler that panics if called.
        struct PanicHandler;
        #[async_trait]
        impl IncomingHandler for PanicHandler {
            async fn decide(&self, _peer: PeerId, _name: Option<String>) -> CallDecision {
                panic!("decide should not be called for caller_id=0");
            }
        }
        let s = BaleSignaling::new(store_empty());
        s.set_incoming_handler(Box::new(PanicHandler));

        // call.caller_id = 0 (or call=None) → defer.
        s.clone().on_incoming_call(123, None).await;
        s.clone().on_incoming_call(123, Some(CallEntity {
            call_id:   123,
            caller_id: 0,
            ..Default::default()
        })).await;
    }

    #[tokio::test]
    async fn incoming_call_silently_ignored_when_no_handler() {
        // No handler installed → silently ignore. No panic.
        let s = BaleSignaling::new(store_empty());
        s.clone().on_incoming_call(7, Some(CallEntity {
            call_id:   7,
            caller_id: 42,
            ..Default::default()
        })).await;
        // Also: caller wasn't added to accepted, no session fired.
        assert!(s.active_peers.lock().is_empty());
    }

    #[tokio::test]
    async fn incoming_call_silently_ignored_when_handler_says_silent() {
        let s = BaleSignaling::new(store_empty());
        s.set_incoming_handler(Box::new(AlwaysIgnore));

        s.clone().on_incoming_call(7, Some(CallEntity {
            call_id:   7,
            caller_id: 42,
            ..Default::default()
        })).await;
        assert!(s.active_peers.lock().is_empty());
    }

    // ── text transport ────────────────────────────────────────

    #[tokio::test]
    async fn send_text_message_requires_auth() {
        let s = BaleSignaling::new(store_empty());
        let p = s.resolve_peer("42").await.unwrap();
        assert!(matches!(
            s.send_text_message(&p, "hi").await,
            Err(SignalingError::NotAuthenticated)
        ));
    }

    #[tokio::test]
    async fn send_text_message_without_ws_reports_transport_error() {
        let s = BaleSignaling::new(store_with("tok"));
        let p = s.resolve_peer("42").await.unwrap();
        // Authenticated but never connected — no sender on the WS,
        // so the RPC layer reports NotConnected and the impl wraps
        // it as a Transport error rather than pretending to send.
        assert!(matches!(
            s.send_text_message(&p, "hi").await,
            Err(SignalingError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn text_message_push_reaches_public_listener() {
        let s   = BaleSignaling::new(store_empty());
        let got = Arc::new(Mutex::new(None::<crate::ws::TextMessage>));
        let got_cb = got.clone();
        s.add_on_text_message(Arc::new(move |m| *got_cb.lock() = Some(m)));

        // Same hand-assembled `f=2` container as the ws-level
        // byte-exact test — public entry point, same bytes.
        let frame = [
            0x0A, 0x1F, 0x0A, 0x1D, 0xBA, 0x03, 0x1A, 0x08,
            0x63, 0x10, 0xFB, 0xD0, 0x95, 0xFF, 0xBC, 0x31,
            0x18, 0xC8, 0xD3, 0x95, 0xFF, 0xBC, 0x31, 0x22,
            0x08, 0x7A, 0x06, 0x0A, 0x04, 0x70, 0x69, 0x6E,
            0x67,
        ];
        crate::ws::handle_push_container(&s.ws, &frame).unwrap();

        let m = got.lock().clone();
        let m = m.expect("listener should have fired");
        assert_eq!(m.sender_uid, 99);
        assert_eq!(m.rid, 1_700_000_000_123);
        assert_eq!(m.text, "ping");
    }
}
