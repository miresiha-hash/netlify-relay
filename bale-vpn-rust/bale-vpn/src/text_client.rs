//! `CarrierKind::Text` — the client session shell.
//!
//! The portable session core (framing, pacer, the two TUN threads,
//! the process-wide text callback) now lives in the `textcarrier`
//! crate — `textcarrier::session` / `::io` / `::wire` — so the
//! Android JNI shim links the same code and cannot depend on this
//! binary crate. What stays here is the desktop-specific half: the
//! TUN recipe — env overrides, `crate::tun::open_client_tun`, and
//! the one-time fd ownership transfer — handed to
//! `textcarrier::session::run` as an owned `Arc<File>`.
//!
//! One deliberate departure from the Voice path, kept here because
//! it is this shell that opens the device: **the TUN is mandatory
//! here.** Voice treats `--client-tun` as an optional add-on to
//! SOCKS5; Text has no SOCKS5 (that server hangs off `LkTunnel`),
//! so the TUN *is* the transport and failing to open it fails the
//! mode rather than degrading to nothing.

// Shared by both platform variants — only `run`'s signature needs
// these, which is what keeps the non-unix stub warning-free.
use bale_signaling::BaleSignaling;
use lk_signaling::PeerId;
use std::error::Error;
use std::sync::Arc;

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

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

/// Open the kernel TUN and hand the owned fd to
/// `textcarrier::session::run`, which owns the fd (and the
/// session) until its future is dropped.
#[cfg(unix)]
pub async fn run(
    signaling: Arc<BaleSignaling>,
    peer: PeerId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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

    textcarrier::session::run(signaling, peer, file, crate::tun::host_tun_format()).await
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
