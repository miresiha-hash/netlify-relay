//! Byte transport carried over Bale text messages.
//!
//! Measured ceilings this module is tuned for (probe 07,
//! `/root/balevpn-research/07-throughput.md`, live between two Bale
//! accounts on 2026-10-10):
//!
//! * sustained ≈ **1 message/second**; the server's limiter is a
//!   per-**user** token bucket of ~16 capacity refilling at ~1/s —
//!   per-message, not per-byte, so a 3 KB payload costs the same one
//!   token as a 1-byte payload. Filling the chunk is the only way to
//!   buy bandwidth.
//! * short bursts tolerate ~51 msg/s with `in-flight=16`, but
//!   `in-flight=64` collapses (59× `user_rate_limited`).
//! * inbound delivery is **100%** and in order; every message also
//!   emits a 34-byte counter push, which we ignore.
//! * the binary side of the `Content` union is unusable (member 3 is
//!   a message field, not bytes → `invalid wire-format`), so base64
//!   over the text path is the only option. That is a fixed 33%
//!   overhead and is why [`MAX_CONTENT_CHARS`] of text carries
//!   [`MAX_PAYLOAD_BYTES`] of bytes.
//!
//! Two consequences shape the design below:
//!
//! 1. **The pacer is shared between data and ACKs.** The limiter is
//!    per user, so a side that both sends data and acknowledges the
//!    peer's data spends from one bucket. Giving ACKs their own
//!    budget would exceed the ceiling and trip `user_rate_limited`.
//! 2. **ACKs are cumulative and batched**, not per frame — an ACK per
//!    frame would double the message count and halve the data rate.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Notify};

// ── Limits ───────────────────────────────────────────────────────
/// Bale accepts at most 4096 characters of content per message.
pub const MAX_CONTENT_CHARS: usize = 4096;
/// `kind(1) + seq(4) + len(2)`.
const HEADER_LEN: usize = 7;
/// Largest payload that still base64-encodes under
/// [`MAX_CONTENT_CHARS`]: `4096 * 3/4 == 3072` bytes of base64, minus
/// the header. IP packets are MTU-bounded well below this (the TUN
/// path uses 1400), so the limit is never reached in practice — it
/// exists to make an accidental oversized frame a loud error instead
/// of a server-side rejection.
pub const MAX_PAYLOAD_BYTES: usize = 3060;

/// Token-bucket capacity. The server's bucket measures ~16–20; stay
/// under it so our own burst never trips its limiter.
pub const BURST_CAPACITY: f64 = 16.0;
/// Sustained messages per second, counting data **and** ACKs. The
/// server refills ~1/s, so 0.9 leaves headroom for the retry traffic
/// and clock skew between the two sides.
pub const SUSTAINED_RATE: f64 = 0.9;

/// Retain at most this many unacknowledged frames. 64 collapses the
/// server limiter; 16 is the measured burst ceiling but leaves no
/// room for ACKs sharing the same bucket.
pub const MAX_IN_FLIGHT: usize = 8;

/// Flush a pending ACK once this many frames have arrived, or after
/// [`ACK_MAX_INTERVAL`] regardless — whichever comes first. Cumulative
/// ACKs keep the ACK message rate near 0.25/s so data keeps most of
/// the budget.
pub const ACK_EVERY_N: usize = 4;
/// Hard upper bound on ACK latency, so an idle receiver still releases
/// the sender's window instead of letting it stall into retransmits.
pub const ACK_MAX_INTERVAL_MS: u64 = 2000;

/// A frame still unacknowledged after this long is retransmitted.
/// Retransmits are safe: the receiver de-duplicates by `seq`.
pub const STALL_TIMEOUT_MS: u64 = 15_000;
/// How long to back off after the server says `user_rate_limited`.
pub const RATE_LIMIT_BACKOFF_MS: u64 = 2_000;
/// The sender task wakes at this cadence to flush due ACKs even when
/// no data is queued.
const TICK_MS: u64 = 250;
/// Give up on a frame after this many consecutive send failures — a
/// permanently failing wire must not spin forever.
const MAX_SEND_RETRIES: u32 = 50;

const KIND_DATA: u8 = 0x01;
const KIND_ACK: u8 = 0x02;

// ── Framing ──────────────────────────────────────────────────────

/// A single unit on the wire. Encoded to bytes, then base64, then
/// sent as one Bale text message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data { seq: u32, payload: Vec<u8> },
    /// Cumulative: every frame up to and including `cum` is delivered.
    Ack { cum: u32 },
}

/// Serialize a frame. [`Data`] frames are exactly
/// `HEADER_LEN + payload.len()` bytes.
///
/// [`Data`]: Frame::Data
pub fn encode_frame(f: &Frame) -> Vec<u8> {
    match f {
        Frame::Data { seq, payload } => {
            let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
            v.push(KIND_DATA);
            v.extend_from_slice(&seq.to_be_bytes());
            v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            v.extend_from_slice(payload);
            v
        }
        Frame::Ack { cum } => {
            let mut v = Vec::with_capacity(5);
            v.push(KIND_ACK);
            v.extend_from_slice(&cum.to_be_bytes());
            v
        }
    }
}

/// Parse a frame, rejecting anything short, truncated, or unknown.
/// Returns `None` rather than panicking: inbound text is attacker- and
/// glitch-controlled, so a malformed message must never kill the
/// tunnel task.
pub fn decode_frame(b: &[u8]) -> Option<Frame> {
    let (&kind, rest) = b.split_first()?;
    match kind {
        KIND_DATA => {
            if rest.len() < 6 {
                return None;
            }
            let seq = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let len = u16::from_be_bytes([rest[4], rest[5]]) as usize;
            let payload = &rest[6..];
            if payload.len() != len {
                return None;
            }
            Some(Frame::Data { seq, payload: payload.to_vec() })
        }
        KIND_ACK => {
            if rest.len() != 4 {
                return None;
            }
            Some(Frame::Ack {
                cum: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
            })
        }
        _ => None,
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// ── Pacing ───────────────────────────────────────────────────────

/// Token bucket, matching the shape of Bale's per-user limiter.
///
/// Pure and clock-injected so tests can drive it deterministically
/// without sleeping. `rate` is tokens/second; `cap` the bucket size.
pub struct Pacer {
    tokens: f64,
    cap: f64,
    rate: f64,
    last_ms: u64,
}

impl Pacer {
    /// Start full — the same burst the server allows at session start.
    pub fn new(cap: f64, rate: f64, start_ms: u64) -> Self {
        Self { tokens: cap, cap, rate, last_ms: start_ms }
    }

    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_ms {
            return;
        }
        let dt = (now_ms - self.last_ms) as f64 / 1000.0;
        self.tokens = (self.tokens + dt * self.rate).min(self.cap);
        self.last_ms = now_ms;
    }

    /// Spend one token if available.
    pub fn try_acquire(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Milliseconds until the next token, `0` if one is ready now.
    /// Clamped so a pathological `rate` can't spin the caller.
    pub fn ms_until_next(&mut self, now_ms: u64) -> u64 {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            return 0;
        }
        let need = 1.0 - self.tokens;
        ((need / self.rate) * 1000.0).ceil().max(1.0) as u64
    }
}

// ── Wire abstraction ─────────────────────────────────────────────

/// Why a send failed.
#[derive(Debug, Clone)]
pub enum WireError {
    /// The server said `user_rate_limited`. Back off, then retry the
    /// same frame — it was never accepted.
    RateLimited,
    Failed(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited => f.write_str("user_rate_limited"),
            Self::Failed(s) => write!(f, "wire: {s}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Why a payload was not accepted for transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backpressure {
    /// The local outbound queue is saturated. Back off and retry.
    Full,
    /// The payload exceeds [`MAX_PAYLOAD_BYTES`]; it can never be
    /// framed into one Bale message.
    Oversized(usize),
    /// The transport is shutting down.
    Closed,
}

impl std::fmt::Display for Backpressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => f.write_str("outbound queue full"),
            Self::Oversized(n) => write!(f, "payload of {n} bytes exceeds the {MAX_PAYLOAD_BYTES}-byte frame limit"),
            Self::Closed => f.write_str("tunnel closed"),
        }
    }
}

/// The outbound half of the transport: put one text message on the
/// wire. Inbound text arrives separately via [`TextTunnel::deliver`].
///
/// Production implements this over the real Bale signaling client
/// (`send_text_message`); tests use an in-memory channel.
#[async_trait]
pub trait TextWire: Send + Sync + 'static {
    async fn send(&self, text: &str) -> Result<(), WireError>;
}

/// Sink for reassembled payload bytes, mirroring `LkTunnel::set_on_ip`
/// so whatever sits above the transport can be swapped unchanged.
pub type IpSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// A queued outbound message. Data and ACKs share one queue on
/// purpose — one pacer, one FIFO, one budget.
enum Outbound {
    Data(Vec<u8>),
    Ack(u32),
}

/// Receiver-side reassembly state.
struct RxState {
    /// Next `seq` that can be handed up. Everything below is delivered.
    next_contig: u32,
    /// Out-of-order frames held until the gap fills.
    buf: BTreeMap<u32, Vec<u8>>,
    ack_pending: bool,
    frames_since_ack: usize,
    last_ack_at: Option<Instant>,
}

struct Inner {
    wire: Arc<dyn TextWire>,
    /// Only frames from this peer are accepted — the tunnel is
    /// pairwise, and Bale echoes our own sent message back under our
    /// own uid, which this also filters out.
    peer_uid: i32,
    on_ip: Mutex<Option<IpSink>>,
    out_tx: mpsc::Sender<Outbound>,
    rx_state: Mutex<RxState>,
    /// Cumulative ACK from the peer: everything `<= this` is delivered
    /// there and can be dropped here.
    acked_cum: AtomicU32,
    ack_notify: Notify,
    in_flight_count: AtomicU32,
    sent_data: AtomicU32,
    sent_ack: AtomicU32,
    recv_data: AtomicU32,
    dup_dropped: AtomicU32,
    retransmits: AtomicU32,
    rate_limited: AtomicU32,
}

/// A one-message-per-second byte tunnel over Bale text messages.
///
/// Clone cheaply; both halves share state. The transport does not
/// know about TUN or SOCKS5 — it hands reassembled payload bytes to
/// the [`IpSink`] installed with [`set_on_ip`](Self::set_on_ip), the
/// same seam `LkTunnel` exposes.
#[derive(Clone)]
pub struct TextTunnel {
    inner: Arc<Inner>,
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

impl TextTunnel {
    /// Start the transport. Spawns the sender task on the current
    /// tokio runtime, so it must be called from inside one.
    pub fn open(wire: Arc<dyn TextWire>, peer_uid: i32) -> Self {
        let (out_tx, out_rx) = mpsc::channel::<Outbound>(256);
        let inner = Arc::new(Inner {
            wire,
            peer_uid,
            on_ip: Mutex::new(None),
            out_tx,
            rx_state: Mutex::new(RxState {
                next_contig: 1,
                buf: BTreeMap::new(),
                ack_pending: false,
                frames_since_ack: 0,
                last_ack_at: None,
            }),
            acked_cum: AtomicU32::new(0),
            ack_notify: Notify::new(),
            in_flight_count: AtomicU32::new(0),
            sent_data: AtomicU32::new(0),
            sent_ack: AtomicU32::new(0),
            recv_data: AtomicU32::new(0),
            dup_dropped: AtomicU32::new(0),
            retransmits: AtomicU32::new(0),
            rate_limited: AtomicU32::new(0),
        });

        // `run_sender` owns its handle (the spawned future must be
        // 'static), so hand it a clone — both share the same inner Arc.
        let this = Self { inner: Arc::clone(&inner) };
        tokio::spawn(this.clone().run_sender(out_rx));
        this
    }

    /// Install the payload sink. Call once, before traffic flows.
    pub fn set_on_ip(&self, cb: IpSink) {
        *self.inner.on_ip.lock() = Some(cb);
    }

    /// Queue a payload for transmission without blocking.
    ///
    /// Mirrors `LkTunnel::SendError::Backpressure`: a saturated queue
    /// is a signal to the caller to slow down, not an error to retry.
    pub fn try_send_payload(&self, payload: Vec<u8>) -> Result<(), Backpressure> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Backpressure::Oversized(payload.len()));
        }
        self.inner.out_tx.try_send(Outbound::Data(payload)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Backpressure::Full,
            mpsc::error::TrySendError::Closed(_) => Backpressure::Closed,
        })
    }

    /// Queue a payload, waiting for queue space. Use this from the TUN
    /// read task; use [`try_send_payload`](Self::try_send_payload) where
    /// the caller can react to backpressure instead of stalling.
    pub async fn send_payload(&self, payload: Vec<u8>) -> Result<(), Backpressure> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Backpressure::Oversized(payload.len()));
        }
        self.inner.out_tx.send(Outbound::Data(payload))
            .await
            .map_err(|_| Backpressure::Closed)
    }

    /// Inbound entry point. Wire this to `add_on_text_message`; the
    /// callback is sync, as `deliver` is.
    ///
    /// Silently ignores: other peers, our own echo, non-base64 text,
    /// and unknown frame kinds. None of those are fatal — inbound text
    /// is shared with the human conversation on the same peer.
    pub fn deliver(&self, from_uid: i32, text: &str) {
        if from_uid != self.inner.peer_uid {
            return;
        }
        let Some(bytes) = unb64(text) else { return };
        match decode_frame(&bytes) {
            Some(Frame::Data { seq, payload }) => self.on_data(seq, payload),
            Some(Frame::Ack { cum }) => self.on_ack(cum),
            None => {}
        }
    }

    fn on_ack(&self, cum: u32) {
        let prev = self.inner.acked_cum.fetch_max(cum, Ordering::AcqRel);
        if cum > prev {
            self.inner.ack_notify.notify_one();
        }
    }

    fn on_data(&self, seq: u32, payload: Vec<u8>) {
        let deliver = {
            let mut st = self.inner.rx_state.lock();
            if seq < st.next_contig {
                // Already handed up. Re-ack so a lost ACK doesn't
                // wedge the sender's window.
                let cum = st.next_contig - 1;
                drop(st);
                self.inner.dup_dropped.fetch_add(1, Ordering::Relaxed);
                self.queue_ack(cum);
                return;
            }
            st.buf.insert(seq, payload);
            st.frames_since_ack += 1;
            // Mark only — the ACK itself is flushed by
            // `maybe_flush_ack` in the sender loop, batched by count
            // or elapsed time. Acking every frame here would double
            // the message rate and halve the data budget, since ACKs
            // and data share one per-user limiter.
            st.ack_pending = true;

            // Drain everything now contiguous. `next` is a local so
            // the mutable borrow of the map and the read of the cursor
            // never overlap through the guard.
            let mut deliver = Vec::new();
            let mut next = st.next_contig;
            while let Some(p) = st.buf.remove(&next) {
                deliver.push(p);
                next += 1;
            }
            st.next_contig = next;
            deliver
        };

        self.inner.recv_data.fetch_add(deliver.len() as u32, Ordering::Relaxed);
        if !deliver.is_empty() {
            let sink = self.inner.on_ip.lock();
            if let Some(cb) = sink.as_ref() {
                for p in &deliver {
                    cb(p);
                }
            }
        }
    }

    /// Queue a cumulative ACK. `try_send` on purpose: this runs from a
    /// sync callback, so it must never block. A dropped ACK costs one
    /// retransmit 15 s later, which the receiver de-duplicates.
    fn queue_ack(&self, cum: u32) {
        let _ = self.inner.out_tx.try_send(Outbound::Ack(cum));
    }

    /// Called each sender tick: flush a queued ACK once it is due by
    /// count or by elapsed time.
    fn maybe_flush_ack(&self) {
        let cum = {
            let mut st = self.inner.rx_state.lock();
            if !st.ack_pending {
                return;
            }
            let by_count = st.frames_since_ack >= ACK_EVERY_N;
            let by_time = st
                .last_ack_at
                .map_or(true, |t| t.elapsed() >= Duration::from_millis(ACK_MAX_INTERVAL_MS));
            if !by_count && !by_time {
                return;
            }
            st.ack_pending = false;
            st.frames_since_ack = 0;
            st.last_ack_at = Some(Instant::now());
            st.next_contig - 1
        };
        self.queue_ack(cum);
    }

    /// Snapshot of the transport's counters, for the UI and tests.
    pub fn stats(&self) -> TunnelStats {
        TunnelStats {
            sent_data: self.inner.sent_data.load(Ordering::Relaxed),
            sent_ack: self.inner.sent_ack.load(Ordering::Relaxed),
            recv_data: self.inner.recv_data.load(Ordering::Relaxed),
            dup_dropped: self.inner.dup_dropped.load(Ordering::Relaxed),
            retransmits: self.inner.retransmits.load(Ordering::Relaxed),
            rate_limited: self.inner.rate_limited.load(Ordering::Relaxed),
            in_flight: self.inner.in_flight_count.load(Ordering::Relaxed) as usize,
        }
    }

    /// Frames per second currently leaving this side. Diagnostic.
    pub fn sent_data(&self) -> u32 {
        self.inner.sent_data.load(Ordering::Relaxed)
    }

    /// The sender loop. Owns the pacer and the in-flight window — the
    /// only task that touches the wire.
    async fn run_sender(self, mut out_rx: mpsc::Receiver<Outbound>) {
        let mut pacer = Pacer::new(BURST_CAPACITY, SUSTAINED_RATE, 0);
        let start = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(TICK_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // (seq, payload, when it was last sent) — payload retained so
        // a stalled frame can be retransmitted.
        let mut in_flight: VecDeque<(u32, Vec<u8>, Instant)> = VecDeque::new();
        // Work received while waiting for a token, so nothing is lost.
        let mut buf: VecDeque<Outbound> = VecDeque::new();
        let mut next_seq: u32 = 0; // first frame uses seq 1
        let mut rate_limit_streak: u32 = 0;

        loop {
            self.maybe_flush_ack();

            // Release everything the peer has confirmed.
            let cum = self.inner.acked_cum.load(Ordering::Acquire);
            while in_flight.front().map_or(false, |(s, _, _)| *s <= cum) {
                in_flight.pop_front();
            }
            self.inner
                .in_flight_count
                .store(in_flight.len() as u32, Ordering::Relaxed);

            // Window full: wait for an ACK, or wake periodically to
            // notice a stall.
            if in_flight.len() >= MAX_IN_FLIGHT {
                tokio::select! {
                    _ = self.inner.ack_notify.notified() => continue,
                    _ = tokio::time::sleep(Duration::from_millis(TICK_MS)) => {
                        self.retransmit_stalled(&mut in_flight).await;
                        continue;
                    }
                }
            }

            let now = elapsed_ms(start);

            // No token yet: wait for one, but keep draining the queue
            // so bursts aren't lost while we cool down.
            let wait_ms = pacer.ms_until_next(now);
            if wait_ms > 0 {
                tokio::select! {
                    item = out_rx.recv() => {
                        match item {
                            Some(i) => buf.push_back(i),
                            None if buf.is_empty() => break,
                            None => {}
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(wait_ms.min(TICK_MS))) => {}
                }
                continue;
            }

            // Token ready — pull the oldest queued work. Idle, we must
            // still wake on the tick: `maybe_flush_ack` runs at the top
            // of the loop, and a receiver with nothing to send would
            // otherwise sleep here forever and never release the peer's
            // window with an ACK.
            let item = match buf.pop_front() {
                Some(i) => i,
                None => {
                    tokio::select! {
                        item = out_rx.recv() => match item {
                            Some(i) => i,
                            None => break,
                        },
                        _ = tick.tick() => continue,
                    }
                }
            };
            if !pacer.try_acquire(elapsed_ms(start)) {
                // Raced with another waiter; put it back and re-check.
                buf.push_front(item);
                continue;
            }

            // Compute the seq this frame *would* use, but only commit
            // it once the send is accepted. Advancing early would leave
            // a hole the receiver's cumulative ACK waits on forever.
            let (text, data_payload, candidate_seq) = match &item {
                Outbound::Data(p) => {
                    let seq = next_seq.wrapping_add(1);
                    (
                        b64(&encode_frame(&Frame::Data { seq, payload: p.clone() })),
                        Some(p.clone()),
                        seq,
                    )
                }
                Outbound::Ack(cum) => (
                    b64(&encode_frame(&Frame::Ack { cum: *cum })),
                    None,
                    next_seq,
                ),
            };

            match self.inner.wire.send(&text).await {
                Ok(()) => {
                    rate_limit_streak = 0;
                    if let Some(p) = data_payload {
                        next_seq = candidate_seq;
                        in_flight.push_back((candidate_seq, p, Instant::now()));
                        self.inner.in_flight_count
                            .store(in_flight.len() as u32, Ordering::Relaxed);
                        self.inner.sent_data.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.inner.sent_ack.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(WireError::RateLimited) => {
                    rate_limit_streak += 1;
                    self.inner.rate_limited.fetch_add(1, Ordering::Relaxed);
                    if rate_limit_streak > MAX_SEND_RETRIES {
                        log::error!(
                            "text_tunnel: giving up after {rate_limit_streak} rate-limit retries"
                        );
                        rate_limit_streak = 0;
                        continue;
                    }
                    // The frame was never accepted, so retry it after
                    // backing off. ACKs are dropped instead — the
                    // receiver will generate a fresh cumulative one.
                    if let Some(p) = data_payload {
                        buf.push_front(Outbound::Data(p));
                    }
                    tokio::time::sleep(Duration::from_millis(RATE_LIMIT_BACKOFF_MS)).await;
                }
                Err(WireError::Failed(e)) => {
                    rate_limit_streak += 1;
                    log::error!("text_tunnel: send failed: {e}");
                    if let Some(p) = data_payload {
                        if rate_limit_streak <= MAX_SEND_RETRIES {
                            buf.push_front(Outbound::Data(p));
                            tokio::time::sleep(Duration::from_millis(RATE_LIMIT_BACKOFF_MS)).await;
                        }
                    }
                }
            }
        }
    }

    /// Resend the oldest unacknowledged frame. Safe because the
    /// receiver drops duplicates by `seq`.
    async fn retransmit_stalled(&self, in_flight: &mut VecDeque<(u32, Vec<u8>, Instant)>) {
        // `Vec` in the tuple means this needs `cloned()`, not `copied()`.
        let Some((seq, payload, sent_at)) = in_flight.front().cloned() else { return };
        if sent_at.elapsed() < Duration::from_millis(STALL_TIMEOUT_MS) {
            return;
        }
        let text = b64(&encode_frame(&Frame::Data { seq, payload }));
        match self.inner.wire.send(&text).await {
            Ok(()) => {
                self.inner.retransmits.fetch_add(1, Ordering::Relaxed);
                log::warn!("text_tunnel: retransmitting stalled frame seq={seq}");
            }
            Err(WireError::RateLimited) => {
                self.inner.rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            Err(WireError::Failed(e)) => {
                log::error!("text_tunnel: retransmit failed: {e}");
            }
        }
        if let Some(entry) = in_flight.front_mut() {
            entry.2 = Instant::now();
        }
    }
}

/// Counters exposed by [`TextTunnel::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelStats {
    pub sent_data: u32,
    pub sent_ack: u32,
    pub recv_data: u32,
    pub dup_dropped: u32,
    pub retransmits: u32,
    pub rate_limited: u32,
    pub in_flight: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID_A: i32 = 100;
    const UID_B: i32 = 200;

    /// In-memory stand-in for the Bale wire: hands the text straight
    /// to the peer tunnel under the sender's own uid, which is what
    /// the real `newMessage` push does.
    struct ChanWire {
        tx: mpsc::Sender<String>,
    }

    #[async_trait]
    impl TextWire for ChanWire {
        async fn send(&self, text: &str) -> Result<(), WireError> {
            self.tx.send(text.to_string())
                .await
                .map_err(|_| WireError::Failed("peer closed".into()))
        }
    }

    /// Two tunnels wired to each other, exercising the real sender
    /// task, pacer, window, and reassembly — only the network is fake.
    fn loopback() -> (TextTunnel, TextTunnel) {
        let (a_tx, mut a_rx) = mpsc::channel::<String>(512);
        let (b_tx, mut b_rx) = mpsc::channel::<String>(512);

        // A's peer is B and vice versa, so each accepts only the
        // other's frames.
        let ta = TextTunnel::open(Arc::new(ChanWire { tx: a_tx }), UID_B);
        let tb = TextTunnel::open(Arc::new(ChanWire { tx: b_tx }), UID_A);

        let tb_fwd = tb.clone();
        tokio::spawn(async move {
            while let Some(t) = a_rx.recv().await {
                tb_fwd.deliver(UID_A, &t);
            }
        });
        let ta_fwd = ta.clone();
        tokio::spawn(async move {
            while let Some(t) = b_rx.recv().await {
                ta_fwd.deliver(UID_B, &t);
            }
        });
        (ta, tb)
    }

    fn collector() -> (Arc<Mutex<Vec<Vec<u8>>>>, IpSink) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let clone = Arc::clone(&got);
        (got, Arc::new(move |p: &[u8]| clone.lock().push(p.to_vec())))
    }

    // ── Framing ──────────────────────────────────────────────────

    #[test]
    fn data_frame_roundtrips() {
        let f = Frame::Data { seq: 0xDEAD_BEEF, payload: b"hello tunnel".to_vec() };
        assert_eq!(decode_frame(&encode_frame(&f)), Some(f));
    }

    #[test]
    fn ack_frame_roundtrips() {
        let f = Frame::Ack { cum: 4242 };
        assert_eq!(decode_frame(&encode_frame(&f)), Some(f));
    }

    #[test]
    fn seq_zero_and_max_roundtrip() {
        for seq in [0u32, 1, u32::MAX] {
            let f = Frame::Data { seq, payload: vec![7u8; 3] };
            assert_eq!(decode_frame(&encode_frame(&f)), Some(f));
        }
        // An ACK of seq 0 must not collide with the sender's initial
        // "nothing acked" sentinel.
        assert_eq!(decode_frame(&encode_frame(&Frame::Ack { cum: 0 })), Some(Frame::Ack { cum: 0 }));
    }

    #[test]
    fn decode_rejects_truncated_and_unknown_input() {
        // Empty.
        assert_eq!(decode_frame(&[]), None);
        // Unknown kind byte.
        assert_eq!(decode_frame(&[0x7F, 1, 2, 3, 4, 5, 6, 7]), None);
        // Header claims 10 bytes, carries 3.
        let mut short = vec![KIND_DATA, 0, 0, 0, 1, 0, 10];
        short.extend_from_slice(b"abc");
        assert_eq!(decode_frame(&short), None);
        // Data header cut short.
        assert_eq!(decode_frame(&[KIND_DATA, 0, 0, 0, 1]), None);
        // ACK with a stray trailing byte instead of exactly 4.
        let bad_ack = vec![KIND_ACK, 0, 0, 0, 1, 9];
        assert_eq!(decode_frame(&bad_ack), None);
    }

    #[test]
    fn largest_payload_stays_inside_the_content_limit() {
        let enc = encode_frame(&Frame::Data { seq: 1, payload: vec![0u8; MAX_PAYLOAD_BYTES] });
        assert_eq!(enc.len(), HEADER_LEN + MAX_PAYLOAD_BYTES);
        let chars = b64(&enc).chars().count();
        assert!(
            chars <= MAX_CONTENT_CHARS,
            "base64 of a max frame is {chars} chars, over Bale's {MAX_CONTENT_CHARS} limit"
        );
    }

    // ── Pacing ───────────────────────────────────────────────────

    #[test]
    fn pacer_allows_one_burst_then_refills_at_rate() {
        let mut p = Pacer::new(16.0, 1.0, 0);
        let mut ok = 0;
        for _ in 0..20 {
            if p.try_acquire(0) {
                ok += 1;
            }
        }
        assert_eq!(ok, 16, "bucket should start full at exactly its capacity");
        // One second later exactly one token has refilled.
        assert!(p.try_acquire(1000));
        assert!(!p.try_acquire(1000));
        // A further second gives exactly one more.
        assert!(p.try_acquire(2000));
        assert!(!p.try_acquire(2000));
    }

    #[test]
    fn pacer_reports_the_wait_for_the_next_token() {
        let mut p = Pacer::new(16.0, 1.0, 0);
        for _ in 0..16 {
            assert!(p.try_acquire(0));
        }
        assert_eq!(p.ms_until_next(0), 1000);
        // Half a refill later the wait halves.
        assert_eq!(p.ms_until_next(500), 500);
        // Nothing waits once a token is present.
        assert_eq!(p.ms_until_next(1000), 0);
        // A pathological rate must still not report a zero wait.
        let mut q = Pacer::new(1.0, 0.0001, 0);
        assert!(q.try_acquire(0));
        assert!(q.ms_until_next(0) > 0);
    }

    #[test]
    fn pacer_never_exceeds_capacity_no_matter_how_long_it_idles() {
        let mut p = Pacer::new(16.0, 1.0, 0);
        for _ in 0..16 {
            assert!(p.try_acquire(0));
        }
        // Ten minutes idle: the bucket refills, but only up to its
        // capacity — it does not accumulate 600 tokens.
        assert!(p.try_acquire(600_000));
        let mut gained = 0;
        for _ in 0..1000 {
            if p.try_acquire(600_000) {
                gained += 1;
            }
        }
        assert_eq!(gained, 15, "idle refills must be capped at capacity, got {gained} extra");
    }

    // ── Wire-level behaviour ─────────────────────────────────────

    #[tokio::test]
    async fn oversized_payloads_are_refused_before_reaching_the_wire() {
        let (ta, _tb) = loopback();
        match ta.try_send_payload(vec![0u8; MAX_PAYLOAD_BYTES + 1]) {
            Err(Backpressure::Oversized(n)) => assert_eq!(n, MAX_PAYLOAD_BYTES + 1),
            other => panic!("expected Oversized, got {other:?}"),
        }
        // Exactly at the limit is accepted.
        assert!(ta.try_send_payload(vec![0u8; MAX_PAYLOAD_BYTES]).is_ok());
    }

    #[tokio::test]
    async fn frames_from_other_peers_are_ignored() {
        let (_ta, tb) = loopback();
        let (got, sink) = collector();
        tb.set_on_ip(sink);

        let text = b64(&encode_frame(&Frame::Data { seq: 1, payload: b"nope".to_vec() }));
        tb.deliver(999, &text);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(got.lock().is_empty());
        assert_eq!(tb.stats().recv_data, 0);
    }

    #[tokio::test]
    async fn human_text_and_bad_base64_are_ignored_not_fatal() {
        let (_ta, tb) = loopback();
        let (got, sink) = collector();
        tb.set_on_ip(sink);

        // A plain Persian chat message — the tunnel shares the peer
        // with a human conversation, so this must be a no-op.
        tb.deliver(UID_A, "سلام دنیا، این یک پیام معمولی است");
        tb.deliver(UID_A, "!!!not base64!!!");
        tb.deliver(UID_A, "");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(got.lock().is_empty());
    }

    #[tokio::test]
    async fn out_of_order_frames_reassemble_in_sequence() {
        let (_ta, tb) = loopback();
        let (got, sink) = collector();
        tb.set_on_ip(sink);

        // Deliver 3 before 2 before 1; only contiguous data is handed
        // up, and in the right order.
        for (seq, byte) in [(3u32, b'd'), (2, b'c')] {
            let t = b64(&encode_frame(&Frame::Data { seq, payload: vec![byte] }));
            tb.deliver(UID_A, &t);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(got.lock().is_empty(), "nothing contiguous yet");

        let t = b64(&encode_frame(&Frame::Data { seq: 1, payload: vec![b'b'] }));
        tb.deliver(UID_A, &t);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(*got.lock(), vec![vec![b'b'], vec![b'c'], vec![b'd']]);
    }

    #[tokio::test]
    async fn duplicate_frames_are_dropped_and_counted() {
        let (_ta, tb) = loopback();
        let (got, sink) = collector();
        tb.set_on_ip(sink);

        let text = b64(&encode_frame(&Frame::Data { seq: 1, payload: b"once".to_vec() }));
        tb.deliver(UID_A, &text);
        tb.deliver(UID_A, &text);
        tb.deliver(UID_A, &text);
        tokio::time::sleep(Duration::from_millis(30)).await;

        assert_eq!(*got.lock(), vec![b"once".to_vec()]);
        assert_eq!(tb.stats().dup_dropped, 2);
        assert_eq!(tb.stats().recv_data, 1);
    }

    // ── End-to-end ───────────────────────────────────────────────

    #[tokio::test]
    async fn payloads_cross_the_tunnel_intact_and_in_order() {
        let (ta, tb) = loopback();
        let (got, sink) = collector();
        tb.set_on_ip(sink);

        // Distinct, non-trivial payloads so a dropped or reordered
        // frame cannot accidentally match.
        let payloads: Vec<Vec<u8>> = (0..12u32)
            .map(|i| (0..96u8).map(|j| (i as u8).wrapping_mul(31).wrapping_add(j)).collect())
            .collect();
        for p in &payloads {
            ta.send_payload(p.clone()).await.expect("send_payload");
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if got.lock().len() >= payloads.len() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out with {}/{} payloads delivered",
                got.lock().len(),
                payloads.len()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(*got.lock(), payloads);
        assert_eq!(tb.stats().recv_data, payloads.len() as u32);
    }

    #[tokio::test]
    async fn in_flight_window_never_exceeds_the_limit() {
        let (ta, tb) = loopback();
        tb.set_on_ip(Arc::new(|_| {}));

        for i in 0..20u8 {
            ta.send_payload(vec![i; 32]).await.expect("send_payload");
        }

        let mut peak = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let st = ta.stats();
            peak = peak.max(st.in_flight);
            if tokio::time::Instant::now() > deadline {
                break;
            }
            if st.in_flight == 0 && st.sent_data >= 20 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(peak <= MAX_IN_FLIGHT, "peak in-flight {peak} exceeded window of {MAX_IN_FLIGHT}");
        assert!(peak > 0, "no frame ever entered the window");
        assert_eq!(ta.stats().sent_data, 20);
    }

    #[tokio::test]
    async fn acks_are_generated_so_the_window_drains() {
        let (ta, tb) = loopback();
        tb.set_on_ip(Arc::new(|_| {}));

        // Send more frames than the window holds. If cumulative ACKs
        // were not flowing, the sender would stall at MAX_IN_FLIGHT and
        // never reach this count.
        for i in 0..16u8 {
            ta.send_payload(vec![i; 16]).await.expect("send_payload");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while ta.stats().sent_data < 16 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "stalled at {}/16 frames — ACKs are not releasing the window",
                ta.stats().sent_data
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The last frame is still in flight at this point; wait for the
        // peer's cumulative ACK to release the whole window.
        while ta.stats().in_flight > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "frames were sent but the window never drained (sent={}, in_flight={})",
                ta.stats().sent_data,
                ta.stats().in_flight,
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            tb.stats().sent_ack > 0,
            "the receiving side never emitted an ACK"
        );
        assert_eq!(ta.stats().sent_data, 16);
    }
}
