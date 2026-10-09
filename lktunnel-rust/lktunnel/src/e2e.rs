//! End-to-end encryption layer for tunnel payload frames.
//!
//! Threat model: the Bale messenger (and therefore the SFU it
//! relays through) is an **untrusted relay** — a hostile / compelled
//! operator could log, modify or drop every frame. Everything that
//! reaches the carrier (`'I'` / `'Q'` frames) is sealed here with a
//! key the relay never learns, so the operator sees only AEAD
//! ciphertext.
//!
//! The relay IS on the content path, so we build a real E2E layer —
//! nothing is trusted from signaling:
//!
//! ```text
//!   Hello    : initiator  → responder : X25519 ephemeral public key
//!   Response : responder  → initiator : X25519 ephemeral public key || sealed auth
//!   Finish   : initiator  → responder : sealed auth
//! ```
//!
//! * Key agreement: X25519, one ephemeral keypair per handshake.
//! * KDF: HKDF-SHA256 with `SHA256(Hello)` as salt over
//!   `DH || PSK` — no PSK configured by default; supply one to
//!   require it (PSK + DH = MITM-proof even if X25519 were broken).
//! * Cipher: ChaCha20-Poly1305, separate keys per direction plus a
//!   shared auth key, nonces = 4 zero bytes || 64-bit sequence.
//! * Replay: per-direction 64-bit sequence + 1024-bit sliding window.
//! * Identity check: a 6-hex-char short authentication string (SAS)
//!   derived from the full transcript, shown on both peers. Whoever
//!   sees the same SAS knows nobody is in the middle. (Trust-on-first-use
//!   unless a PSK is configured.)
//!
//! The frame tags are chosen so they can never collide with the
//! legacy plaintext tags (`'I'`/`'Q'`), and **fail-closed** is the
//! only accepted policy: until the handshake completes, or after it
//! fails, no data frame is sealed or accepted — plaintext frames
//! arriving on the wire are dropped and counted as a security event.

use ring::agreement::{self, UnparsedPublicKey};
use ring::aead::{self, Aad, LessSafeKey, Nonce};
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

/// Sealed (encrypted) data frame. Inner plaintext is the original
/// tagged frame (`'I'` / `'Q'`), so the relay can't even see which
/// plane a packet belongs to.
pub const FRAME_TYPE_E2E: u8 = 0x45; // 'E'
/// Handshake message (plaintext; public keys only, no secrets).
pub const FRAME_TYPE_KEY: u8 = 0x4B; // 'K'

pub const E2E_VERSION: u8 = 0x01;

/// Header of a sealed frame: tag + version + key id + sequence.
const HEADER_LEN: usize = 11;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PUB_LEN: usize = 32;
/// Auth token = AEAD tag + sealed transcript hash.
const AUTH_BODY_LEN: usize = KEY_LEN + TAG_LEN;

/// On-wire overhead added to every data frame by the E2E layer:
/// `'E'` + version + key id + 8-byte sequence + 16-byte AEAD tag.
/// Must stay in sync with `rtp::MAX_FRAME_BYTES` headroom.
pub const E2E_OVERHEAD: usize = HEADER_LEN + TAG_LEN; // 27 bytes

const MSG_HELLO: u8 = 1;
const MSG_RESP: u8 = 2;
const MSG_FINISH: u8 = 3;

/// Key id of the current generation. Carried in the header so a
/// rekey can be rolled out later without a wire change (receivers
/// would keep the previous key alongside).
const KEY_ID: u8 = 0;

const INFO_TX: &[u8] = b"balevpn-e2e-v1 tx";
const INFO_RX: &[u8] = b"balevpn-e2e-v1 rx";
const INFO_AUTH: &[u8] = b"balevpn-e2e-v1 auth";
const AUTH_AAD: &[u8] = b"balevpn-e2e-auth";

/// Sliding replay window, in bits (packets).
const WINDOW_BITS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eError {
    /// Handshake not finished (or already failed) — fail-closed.
    NotReady,
    /// Malformed or unexpected handshake message.
    Protocol,
    /// Peer failed to prove knowledge of the derived key.
    Auth,
    /// AEAD open failed (tampered, corrupted, or wrong key).
    Open,
    /// Sequence already accepted (replay).
    Replay,
    /// Underlying crypto primitive failed (entropy, key gen).
    Crypto,
}

impl std::fmt::Display for E2eError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E2eError::NotReady => write!(f, "handshake not established"),
            E2eError::Protocol => write!(f, "handshake protocol violation"),
            E2eError::Auth => write!(f, "peer authentication failed"),
            E2eError::Open => write!(f, "aead open failed"),
            E2eError::Replay => write!(f, "replayed sequence"),
            E2eError::Crypto => write!(f, "crypto primitive failed"),
        }
    }
}

impl std::error::Error for E2eError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Drives the handshake (the side that calls [`E2eSession::start`]).
    Initiator,
    /// Waits for the initiator's Hello.
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    SentHello,
    SentResponse,
    Established,
    Failed,
}

struct Keys {
    tx: LessSafeKey,
    rx: LessSafeKey,
    auth: LessSafeKey,
}

/// Directional replay window: bit 0 of `bits[0]` is the newest
/// accepted sequence (`highest - 1`); a set bit means "already
/// accepted". Gaps beyond `WINDOW_BITS` simply age out.
#[derive(Default)]
struct RxWindow {
    highest: u64,
    bits: [u64; WINDOW_BITS / 64],
}

impl RxWindow {
    fn too_old(&self, seq: u64) -> bool {
        self.highest > 0 && seq < self.highest.saturating_sub(WINDOW_BITS as u64)
    }

    /// Cheap pre-decrypt check so replayed traffic doesn't burn
    /// CPU. Only a hint — the authoritative accept happens after
    /// the AEAD open succeeds, so forged packets can't poison the
    /// window.
    fn already_seen(&self, seq: u64) -> bool {
        if seq >= self.highest {
            return false;
        }
        let pos = self.highest - 1 - seq;
        if pos >= WINDOW_BITS as u64 {
            return true; // aged out of the window
        }
        self.bits[(pos / 64) as usize] & (1u64 << (pos % 64)) != 0
    }

    fn accept(&mut self, seq: u64) {
        if seq >= self.highest {
            let shift = (seq - self.highest + 1) as u32;
            self.advance(shift);
            self.highest = seq + 1;
            self.bits[0] |= 1;
        } else {
            let pos = self.highest - 1 - seq;
            if pos < WINDOW_BITS as u64 {
                self.bits[(pos / 64) as usize] |= 1u64 << (pos % 64);
            }
        }
    }

    /// Shift every tracked bit toward older positions by `shift`
    /// bits (word-wise; `>= WINDOW_BITS` means everything aged out).
    fn advance(&mut self, shift: u32) {
        const WORDS: usize = WINDOW_BITS / 64;
        if shift == 0 {
            return;
        }
        if shift as usize >= WINDOW_BITS {
            self.bits = [0; WORDS];
            return;
        }
        let w = (shift / 64) as usize;
        let b = shift % 64;
        let mut out = [0u64; WORDS];
        for i in (w..WORDS).rev() {
            let src = self.bits[i - w] << b;
            let carry = if b > 0 && i - w > 0 {
                self.bits[i - w - 1] >> (64 - b)
            } else {
                0
            };
            out[i] = src | carry;
        }
        self.bits = out;
    }
}

fn nonce_for(seq: u64) -> Result<Nonce, E2eError> {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::try_assume_unique_for_key(&n).map_err(|_| E2eError::Crypto)
}

fn seal_vec(key: &LessSafeKey, seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, E2eError> {
    let nonce = nonce_for(seq)?;
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| E2eError::Crypto)?;
    Ok(buf)
}

fn open_vec(key: &LessSafeKey, seq: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<Vec<u8>, E2eError> {
    if buf.len() < TAG_LEN {
        return Err(E2eError::Open);
    }
    let plain_len = buf.len() - TAG_LEN;
    let nonce = nonce_for(seq)?;
    key.open_in_place(nonce, Aad::from(aad), buf)
        .map_err(|_| E2eError::Open)?;
    let out = buf[..plain_len].to_vec();
    buf.truncate(plain_len);
    Ok(out)
}

/// Short authentication string: 6 hex chars (3-3) from the full
/// transcript. Voice-comparable in a few seconds, ~2^24 states.
fn sas(t1: &[u8], t2: &[u8]) -> String {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(t1);
    input.extend_from_slice(t2);
    let d = digest(&SHA256, &input);
    let hex: String = d.as_ref()[..3].iter().map(|b| format!("{b:02X}")).collect();
    format!("{}-{}", &hex[..3], &hex[3..])
}

/// One E2E session per tunnel peer. Not internally synchronised —
/// the owner (an `LkTunnel`) wraps it in a `Mutex`.
pub struct E2eSession {
    role: Role,
    psk: Option<[u8; KEY_LEN]>,
    rng: SystemRandom,
    priv_key: Option<agreement::EphemeralPrivateKey>,
    local_pub: Vec<u8>,
    peer_pub: Vec<u8>,
    state: State,
    /// Initiator's Hello frame bytes (the exact wire bytes) — the
    /// transcript both sides hash into the KDF.
    transcript_init: Vec<u8>,
    /// Responder's Response frame bytes (stored so the responder can
    /// recompute the second transcript hash at Finish time).
    transcript_resp: Vec<u8>,
    /// SHA256(transcript_init) — the KDF salt for both sides.
    t1: Vec<u8>,
    keys: Option<Keys>,
    sas: Option<String>,
    tx_seq: u64,
    rx: RxWindow,
    seals: u64,
    opens: u64,
    rejects: u64,
}

impl E2eSession {
    pub fn new(role: Role, psk: Option<[u8; KEY_LEN]>) -> Self {
        Self {
            role,
            psk,
            rng: SystemRandom::new(),
            priv_key: None,
            local_pub: Vec::new(),
            peer_pub: Vec::new(),
            state: State::Idle,
            transcript_init: Vec::new(),
            transcript_resp: Vec::new(),
            t1: Vec::new(),
            keys: None,
            sas: None,
            tx_seq: 0,
            rx: RxWindow::default(),
            seals: 0,
            opens: 0,
            rejects: 0,
        }
    }

    pub fn established(&self) -> bool {
        self.state == State::Established
    }

    pub fn failed(&self) -> bool {
        self.state == State::Failed
    }

    /// 6-hex-char SAS once the handshake completes.
    pub fn sas(&self) -> Option<String> {
        self.sas.clone()
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.seals, self.opens, self.rejects)
    }

    fn gen_keypair(&self) -> Result<(agreement::EphemeralPrivateKey, Vec<u8>), E2eError> {
        let priv_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)
                .map_err(|_| E2eError::Crypto)?;
        let pub_bytes = priv_key.compute_public_key().map_err(|_| E2eError::Crypto)?;
        Ok((priv_key, pub_bytes.as_ref().to_vec()))
    }

    fn derive(&self, initiator: bool, shared: &[u8]) -> Result<Keys, E2eError> {
        let mut ikm = Vec::with_capacity(KEY_LEN * 2);
        ikm.extend_from_slice(shared);
        if let Some(psk) = self.psk {
            ikm.extend_from_slice(&psk);
        }
        let prk = hkdf::Salt::new(hkdf::SHA256, &self.t1).extract(&ikm);
        let mut tx = [0u8; KEY_LEN];
        let mut rx = [0u8; KEY_LEN];
        let mut auth = [0u8; KEY_LEN];
        prk.expand(&[INFO_TX], hkdf::HKDF_SHA256)
            .map_err(|_| E2eError::Crypto)?
            .fill(&mut tx)
            .map_err(|_| E2eError::Crypto)?;
        prk.expand(&[INFO_RX], hkdf::HKDF_SHA256)
            .map_err(|_| E2eError::Crypto)?
            .fill(&mut rx)
            .map_err(|_| E2eError::Crypto)?;
        prk.expand(&[INFO_AUTH], hkdf::HKDF_SHA256)
            .map_err(|_| E2eError::Crypto)?
            .fill(&mut auth)
            .map_err(|_| E2eError::Crypto)?;
        // Initiator transmits on tx; the responder mirrors.
        let (tx, rx) = if initiator { (tx, rx) } else { (rx, tx) };
        let unbound = |k: &[u8; KEY_LEN]| {
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, k).map_err(|_| E2eError::Crypto)
        };
        Ok(Keys {
            tx: LessSafeKey::new(unbound(&tx)?),
            rx: LessSafeKey::new(unbound(&rx)?),
            auth: LessSafeKey::new(unbound(&auth)?),
        })
    }

    fn dh(&mut self, peer_pub: Vec<u8>) -> Result<Vec<u8>, E2eError> {
        let priv_key = self.priv_key.take().ok_or(E2eError::Protocol)?;
        let peer = UnparsedPublicKey::new(&agreement::X25519, &peer_pub);
        let mut out = Vec::with_capacity(KEY_LEN);
        agreement::agree_ephemeral(priv_key, &peer, |secret| {
            out.extend_from_slice(secret);
        })
        .map_err(|_| E2eError::Crypto)?;
        self.peer_pub = peer_pub;
        Ok(out)
    }

    fn reject(&mut self) {
        self.rejects += 1;
    }

    fn fail(&mut self) {
        self.state = State::Failed;
        self.rejects += 1;
    }

    /// Initiator: build the Hello frame. The returned bytes are a
    /// complete `'K'` frame ready for `send_raw_frame`.
    pub fn start(&mut self) -> Result<Vec<u8>, E2eError> {
        if self.role != Role::Initiator || self.state != State::Idle {
            return Err(E2eError::Protocol);
        }
        let (priv_key, pub_bytes) = self.gen_keypair()?;
        self.priv_key = Some(priv_key);
        self.local_pub = pub_bytes.clone();
        let mut frame = Vec::with_capacity(3 + PUB_LEN);
        frame.extend_from_slice(&[FRAME_TYPE_KEY, E2E_VERSION, MSG_HELLO]);
        frame.extend_from_slice(&pub_bytes);
        // KDF salt on BOTH sides = SHA256(Hello). The responder sets
        // it in `on_hello`; the initiator must set it here or it would
        // derive with an empty salt and the auth tokens would never
        // match.
        self.t1 = digest(&SHA256, &frame).as_ref().to_vec();
        self.transcript_init = frame.clone();
        self.state = State::SentHello;
        Ok(frame)
    }

    /// Feed one inbound `'K'` frame. Returns the reply frame to send
    /// back, if any. Errors mean the message was rejected — the
    /// tunnel keeps the old (fail-closed) state and drops data.
    pub fn on_handshake(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, E2eError> {
        if frame.len() < 3 || frame[0] != FRAME_TYPE_KEY || frame[1] != E2E_VERSION {
            self.reject();
            return Err(E2eError::Protocol);
        }
        match frame[2] {
            MSG_HELLO => self.on_hello(frame),
            MSG_RESP => self.on_resp(frame),
            MSG_FINISH => self.on_finish(frame),
            _ => {
                self.reject();
                Err(E2eError::Protocol)
            }
        }
    }

    fn on_hello(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, E2eError> {
        if frame.len() != 3 + PUB_LEN {
            self.reject();
            return Err(E2eError::Protocol);
        }
        match self.state {
            // Duplicate / late Hello — nothing to say.
            State::Established | State::SentResponse => return Ok(None),
            State::Failed => return Err(E2eError::Protocol),
            State::Idle => {}
            State::SentHello => {
                // Simultaneous start: the larger public key wins the
                // initiator slot (deterministic, no extra message).
                // If the peer's key is smaller, it takes responder.
                if &frame[3..] <= self.local_pub.as_slice() {
                    return Ok(None);
                }
            }
        }
        let t1 = digest(&SHA256, frame);
        self.t1 = t1.as_ref().to_vec();
        self.transcript_init = frame.to_vec();
        let (priv_key, pub_bytes) = self.gen_keypair()?;
        self.priv_key = Some(priv_key);
        self.local_pub = pub_bytes.clone();
        let shared = self.dh(frame[3..].to_vec())?;
        let keys = self.derive(false, &shared)?;
        let auth_tok = seal_vec(&keys.auth, 0, AUTH_AAD, &self.t1)?;
        let mut resp = Vec::with_capacity(3 + PUB_LEN + AUTH_BODY_LEN);
        resp.extend_from_slice(&[FRAME_TYPE_KEY, E2E_VERSION, MSG_RESP]);
        resp.extend_from_slice(&pub_bytes);
        resp.extend_from_slice(&auth_tok);
        self.transcript_resp = resp.clone();
        self.keys = Some(keys);
        self.state = State::SentResponse;
        Ok(Some(resp))
    }

    fn on_resp(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, E2eError> {
        if self.state == State::Established {
            return Ok(None);
        }
        if self.state != State::SentHello {
            self.reject();
            return Err(E2eError::Protocol);
        }
        if frame.len() != 3 + PUB_LEN + AUTH_BODY_LEN {
            self.reject();
            return Err(E2eError::Protocol);
        }
        let shared = self.dh(frame[3..3 + PUB_LEN].to_vec())?;
        let keys = self.derive(true, &shared)?;
        let mut tok = frame[3 + PUB_LEN..].to_vec();
        // A token that won't open means the responder didn't prove
        // knowledge of the right key (wrong PSK / MITM) — report Auth
        // and hard-fail the session.
        let opened = match open_vec(&keys.auth, 0, AUTH_AAD, &mut tok) {
            Ok(o) => o,
            Err(_) => {
                self.fail();
                return Err(E2eError::Auth);
            }
        };
        if opened.as_slice() != self.t1.as_slice() {
            self.fail();
            return Err(E2eError::Auth);
        }
        let mut t2_input = Vec::with_capacity(self.transcript_init.len() + frame.len());
        t2_input.extend_from_slice(&self.transcript_init);
        t2_input.extend_from_slice(frame);
        let t2 = digest(&SHA256, &t2_input);
        let auth_tok = seal_vec(&keys.auth, 1, AUTH_AAD, t2.as_ref())?;
        let mut fin = Vec::with_capacity(3 + AUTH_BODY_LEN);
        fin.extend_from_slice(&[FRAME_TYPE_KEY, E2E_VERSION, MSG_FINISH]);
        fin.extend_from_slice(&auth_tok);
        self.sas = Some(sas(&self.t1, t2.as_ref()));
        self.keys = Some(keys);
        self.state = State::Established;
        Ok(Some(fin))
    }

    fn on_finish(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, E2eError> {
        if self.state == State::Established {
            return Ok(None);
        }
        if self.state != State::SentResponse {
            self.reject();
            return Err(E2eError::Protocol);
        }
        if frame.len() != 3 + AUTH_BODY_LEN {
            self.reject();
            return Err(E2eError::Protocol);
        }
        let mut t2_input = Vec::with_capacity(self.transcript_init.len() + self.transcript_resp.len());
        t2_input.extend_from_slice(&self.transcript_init);
        t2_input.extend_from_slice(&self.transcript_resp);
        let t2 = digest(&SHA256, &t2_input);
        let mut tok = frame[3..].to_vec();
        let opened = {
            let keys = self.keys.as_ref().ok_or(E2eError::Protocol)?;
            open_vec(&keys.auth, 1, AUTH_AAD, &mut tok)
        }?;
        if opened.as_slice() != t2.as_ref() {
            self.fail();
            return Err(E2eError::Auth);
        }
        self.sas = Some(sas(&self.t1, t2.as_ref()));
        self.state = State::Established;
        Ok(None)
    }

    /// Seal one tagged data frame (`'I'` / `'Q'`) into an `'E'`
    /// envelope. Fails (fail-closed) until the handshake completes.
    pub fn seal(&mut self, inner: &[u8]) -> Result<Vec<u8>, E2eError> {
        if self.state != State::Established {
            return Err(E2eError::NotReady);
        }
        let seq = self.tx_seq;
        self.tx_seq = seq.wrapping_add(1);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&[FRAME_TYPE_E2E, E2E_VERSION, KEY_ID]);
        header.extend_from_slice(&seq.to_be_bytes());
        let keys = self.keys.as_ref().ok_or(E2eError::Protocol)?;
        let nonce = nonce_for(seq)?;
        let mut body = inner.to_vec();
        keys.tx
            .seal_in_place_append_tag(nonce, Aad::from(&header[..]), &mut body)
            .map_err(|_| E2eError::Crypto)?;
        let mut out = header;
        out.append(&mut body);
        self.seals += 1;
        Ok(out)
    }

    /// Open one `'E'` envelope back into its tagged data frame.
    /// Rejects replays, tampered frames and unknown key ids.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, E2eError> {
        if self.state != State::Established {
            self.reject();
            return Err(E2eError::NotReady);
        }
        if frame.len() < HEADER_LEN + TAG_LEN
            || frame[0] != FRAME_TYPE_E2E
            || frame[1] != E2E_VERSION
            || frame[2] != KEY_ID
        {
            self.reject();
            return Err(E2eError::Open);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&frame[3..HEADER_LEN]);
        let seq = u64::from_be_bytes(seq_bytes);
        if self.rx.too_old(seq) || self.rx.already_seen(seq) {
            self.reject();
            return Err(E2eError::Replay);
        }
        let mut body = frame[HEADER_LEN..].to_vec();
        let plain_len = body.len() - TAG_LEN;
        let opened = {
            let keys = self.keys.as_ref().ok_or(E2eError::Protocol)?;
            let nonce = nonce_for(seq)?;
            keys.rx
                .open_in_place(nonce, Aad::from(&frame[..HEADER_LEN]), &mut body)
                .map(|_| ())
        };
        if opened.is_err() {
            self.reject();
            return Err(E2eError::Open);
        }
        body.truncate(plain_len);
        self.rx.accept(seq);
        self.opens += 1;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake() -> (E2eSession, E2eSession) {
        let mut a = E2eSession::new(Role::Initiator, None);
        let mut b = E2eSession::new(Role::Responder, None);
        let hello = a.start().expect("start");
        let resp = b.on_handshake(&hello).expect("hello").expect("resp");
        let fin = a.on_handshake(&resp).expect("resp").expect("finish");
        b.on_handshake(&fin).expect("finish");
        assert!(a.established() && b.established());
        (a, b)
    }

    #[test]
    fn handshake_establishes_and_matches_sas() {
        let (a, b) = handshake();
        assert_eq!(a.sas(), b.sas());
        assert!(a.sas().expect("sas").len() >= 6);
    }

    #[test]
    fn seal_open_roundtrip_both_directions() {
        let (mut a, mut b) = handshake();
        for len in [1usize, 20, 1275] {
            let inner: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = a.seal(&inner).expect("seal");
            assert_eq!(sealed.len(), inner.len() + E2E_OVERHEAD);
            assert_eq!(sealed[0], FRAME_TYPE_E2E);
            let opened = b.open(&sealed).expect("open");
            assert_eq!(opened, inner);
        }
        let sealed = b.seal(b"reverse").expect("b seal");
        assert_eq!(a.open(&sealed).expect("a open"), b"reverse".to_vec());
    }

    #[test]
    fn plaintext_frames_never_allowed_pre_handshake() {
        let mut a = E2eSession::new(Role::Initiator, None);
        assert_eq!(a.seal(b"ip packet"), Err(E2eError::NotReady));
        let mut b = E2eSession::new(Role::Responder, None);
        assert_eq!(b.open(b"whatever"), Err(E2eError::NotReady));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = handshake();
        let mut sealed = a.seal(b"secret payload").expect("seal");
        let n = sealed.len();
        sealed[n - 1] ^= 0x01; // flip a tag bit
        assert_eq!(b.open(&sealed), Err(E2eError::Open));
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let (mut a, mut b) = handshake();
        let sealed = a.seal(b"one shot").expect("seal");
        b.open(&sealed).expect("first");
        assert_eq!(b.open(&sealed), Err(E2eError::Replay));
    }

    #[test]
    fn reordered_frames_within_window_are_accepted_once() {
        let (mut a, mut b) = handshake();
        let f0 = a.seal(b"zero").expect("seal");
        let f1 = a.seal(b"one").expect("seal");
        b.open(&f1).expect("one first");
        b.open(&f0).expect("zero second");
        assert_eq!(b.open(&f1), Err(E2eError::Replay));
    }

    #[test]
    fn far_future_sequence_clears_window() {
        let (mut a, mut b) = handshake();
        let f0 = a.seal(b"zero").expect("seal");
        let f_far = {
            // Simulate a huge gap by sealing many frames (cheap).
            let mut last = Vec::new();
            for _ in 0..WINDOW_BITS as u64 + 64 {
                last = a.seal(b"gap").expect("seal");
            }
            last
        };
        b.open(&f_far).expect("far frame");
        // 'zero' is now far outside the window → replay-or-ancient.
        assert_eq!(b.open(&f0), Err(E2eError::Replay));
    }

    #[test]
    fn psk_mismatch_breaks_handshake() {
        let mut psk = [0u8; KEY_LEN];
        psk[0] = 7;
        let mut psk2 = psk;
        psk2[0] = 8;
        let mut a = E2eSession::new(Role::Initiator, Some(psk));
        let mut b = E2eSession::new(Role::Responder, Some(psk2));
        let hello = a.start().expect("start");
        let resp = b.on_handshake(&hello).expect("hello").expect("resp");
        // Initiator can't authenticate the responder → MITM alarm.
        assert_eq!(a.on_handshake(&resp), Err(E2eError::Auth));
        assert!(a.failed());
    }

    #[test]
    fn simultaneous_start_tiebreaks_to_one_initiator() {
        let mut a = E2eSession::new(Role::Initiator, None);
        let mut b = E2eSession::new(Role::Initiator, None);
        let ha = a.start().expect("start a");
        let hb = b.start().expect("start b");
        // Both sides receive the other's Hello before any Response.
        let ra = a.on_handshake(&hb).expect("a on b hello");
        let a_responded = ra.is_some();
        let rb = b.on_handshake(&ha).expect("b on a hello");
        // Exactly one side answers with a Response.
        let answered = [ra.is_some(), rb.is_some()].iter().filter(|s| **s).count();
        assert_eq!(answered, 1);
        if let Some(resp) = ra.or(rb) {
            // Deliver to whoever stayed the initiator.
            let (initiator, responder) = if a_responded { (&mut b, &mut a) } else { (&mut a, &mut b) };
            let fin = initiator.on_handshake(&resp).expect("resp").expect("finish");
            responder.on_handshake(&fin).expect("finish");
            assert!(initiator.established() && responder.established());
            assert_eq!(initiator.sas(), responder.sas());
        }
    }
}
