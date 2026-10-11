//! TEXT carrier — JNI surface for `ai.bale.proxy.TextTunnelNative`.
//!
//! The text carrier carries raw IP packets as Bale *text* messages: no
//! LiveKit call, no QUIC, no media path — just the one WebSocket that
//! already authenticates the app. It is the strip-mined transport for
//! when the LK / QUIC path is unreachable (blocked UDP/DTLS).
//!
//! Threading model mirrors `tunnel.rs`: every handle lives in a
//! process-wide `HandleRegistry`, all calls land on plain JNI threads,
//! and the async work runs on the single shared tokio runtime built by
//! `jni_shared::runtime()`. Nothing here allocates JVM memory, so — unlike
//! the signaling classes — this module registers no `GlobalRef` and needs
//! no `init_class_refs`.

use std::fs::File;
use std::os::raw::c_int;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jobject, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use jni_shared::jstr;
use jni_shared::runtime;
use lk_signaling::Signaling;
use lktunnel::tun::TunFormat;
use textcarrier::session;

/// A live text session: one spawned future running
/// `textcarrier::session::run`, which owns the reader thread, the writer
/// task, and the `sink_slot` entry for its `TextTunnel`.
pub(crate) struct TextSession {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TextSession {
    /// Registry removal *is* our disconnect: dropping the last handle
    /// aborts the session future, whose own destructor closes the TUN
    /// `File`, joins the reader thread, and releases the sink slot.
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) static REG: jni_shared::RegistryHandle<TextSession> =
    jni_shared::once_cell::sync::Lazy::new(jni_shared::HandleRegistry::new);

/// Open a text session on the shared Bale WebSocket.
///
/// `tun_fd` ownership transfers to native here: Kotlin must have called
/// `ParcelFileDescriptor.detachFd()` first, and must NOT close it again
/// on any path. When this returns 0, native refused *before* taking
/// ownership, so the caller still owns the fd and has to close it.
#[no_mangle]
pub extern "system" fn Java_ai_bale_proxy_TextTunnelNative_nativeTextOpen<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    signaling_handle: jlong,
    peer_id: JString<'l>,
    tun_fd: jint,
) -> jlong {
    let Some(sig) = crate::signaling::REG.lookup(signaling_handle as u64) else {
        log::warn!("nativeTextOpen: unknown signaling handle {signaling_handle}");
        return 0;
    };
    let peer = jstr(&mut env, &peer_id);
    if peer.trim().is_empty() {
        log::warn!("nativeTextOpen: empty peer id");
        return 0;
    }
    if tun_fd <= 0 {
        log::warn!("nativeTextOpen: bad tun fd {tun_fd}");
        return 0;
    }

    // SAFETY: the caller detached this fd, so Java no longer closes it;
    // we become the single owner and `Arc<File>`'s Drop closes it.
    let tun = unsafe { Arc::new(File::from_raw_fd(tun_fd as c_int)) };

    // The session future may be launched from a plain JNI thread with no
    // reactor attached; entering the shared runtime first makes the
    // `tokio::spawn` inside `session::run` land on the shared reactor.
    let _guard = runtime().enter();
    let peer_name = peer.clone();
    let task = tokio::spawn(async move {
        let Some(peer) = sig.resolve_peer(&peer).await else {
            // resolve_peer only fails for a uid the account has never
            // seen — nothing to leak or retry. The Arc<File> drop below
            // closes the TUN we were handed.
            log::error!("text: unknown peer {peer_name} (resolve_peer returned None)");
            return;
        };
        match session::run(sig, peer, tun, TunFormat::RawIp).await {
            Ok(()) => log::info!("text: session ended"),
            Err(e) => log::error!("text: session failed: {e}"),
        }
    });

    REG.insert_value(TextSession { task }) as jlong
}

/// Drop the session from the registry. Dropping the last reference aborts
/// the future, which tears down reader, writer, sink slot and TUN fd.
#[no_mangle]
pub extern "system" fn Java_ai_bale_proxy_TextTunnelNative_nativeTextDisconnect(
    _env: JNIEnv<'_>,
    _cls: JClass<'_>,
    handle: jlong,
) {
    REG.remove(handle as u64);
}

/// Session liveness. Also sweeps a finished handle out of the registry so
/// a completed session can't be handed out again.
#[no_mangle]
pub extern "system" fn Java_ai_bale_proxy_TextTunnelNative_nativeTextIsConnected(
    _env: JNIEnv<'_>,
    _cls: JClass<'_>,
    handle: jlong,
) -> jboolean {
    let Some(session) = REG.lookup(handle as u64) else {
        return JNI_FALSE;
    };
    if session.task.is_finished() {
        REG.remove(handle as u64);
        JNI_FALSE
    } else {
        JNI_TRUE
    }
}

/// No stats in v1: `textcarrier::session::run` keeps its counters inside
/// the session and `TunnelStats` has no byte totals, so there is nothing
/// honest to report. NULL is the Kotlin contract's "no data" — the service
/// poller then keeps its previous values instead of rendering zeros that
/// are indistinguishable from "no traffic".
#[no_mangle]
pub extern "system" fn Java_ai_bale_proxy_TextTunnelNative_nativeTextStats<'l>(
    _env: JNIEnv<'l>,
    _cls: JClass<'l>,
    _handle: jlong,
) -> jobject {
    std::ptr::null_mut()
}
