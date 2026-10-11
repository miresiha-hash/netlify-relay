//! The two TUN threads (`reader_loop` / `writer_loop`) and the
//! `poll(2)`-bounded [`read_packet`] they share. Unix-only because
//! `lktunnel::tun` is (lktunnel/src/lib.rs) — gated at the module
//! declaration in `lib.rs`.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use lktunnel::tun::{unwrap_from_wire, wrap_for_wire, TunFormat};

use crate::{Backpressure, TextTunnel};

/// MTU the 2048-byte read buffer is sized against. Mirrors the
/// `TUN_MTU` the desktop shell passes to `open_client_tun`
/// (bale-vpn's `text_client`); the loops never open a device, so
/// here it is only the diagnostic hint in the buffer-full error.
const TUN_MTU: u16 = 1400;

/// How long the TUN threads wait between wake-ups. Bounds both
/// their idle cost (~50 wake-ups/s) and how long teardown can take
/// to join them. Irrelevant to latency: the transport itself paces
/// at roughly one message per second.
const POLL_MS: i32 = 20;

// ── the two TUN threads ────────────────────────────────────────

/// TUN → tunnel.
///
/// `try_send_payload` never blocks, so there is nothing to await;
/// a full window is backed off against rather than spun on or
/// dropped from, because the window is only 8 deep and losing
/// packets there would be our own doing rather than congestion.
///
/// `format` is the fd's packet framing (`crate::tun::host_tun_format()`
/// on desktop; `TunFormat::RawIp` for an Android
/// `VpnService.Builder.establish()` fd).
pub fn reader_loop(
    file:     &File,
    tunnel:   &TextTunnel,
    stop:     &AtomicBool,
    tx_bytes: Option<&AtomicU64>,
    format:   TunFormat,
) {
    'outer: while !stop.load(Ordering::Relaxed) {
        let pkt = match read_packet(file, POLL_MS, format) {
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
                Ok(()) => {
                    if let Some(c) = tx_bytes {
                        c.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    }
                    break;
                }
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
pub fn writer_loop(
    file:     &File,
    rx:       mpsc::Receiver<Vec<u8>>,
    stop:     &AtomicBool,
    rx_bytes: Option<&AtomicU64>,
    format:   TunFormat,
) {
    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(POLL_MS as u64)) {
            Ok(pkt) => {
                // The kernel TUN wants wire form, not raw IP:
                // macOS utun insists on its 4-byte AF prefix,
                // Linux `IFF_NO_PI` gets the packet untouched.
                let wire = wrap_for_wire(&pkt, format);
                let mut f: &File = file;
                if let Err(e) = f.write_all(&wire) {
                    log::warn!("text: TUN write failed: {e}");
                    break;
                }
                if let Some(c) = rx_bytes {
                    c.fetch_add(pkt.len() as u64, Ordering::Relaxed);
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
