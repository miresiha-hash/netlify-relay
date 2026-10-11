//! Merged JNI shim — see `Cargo.toml` for the rationale.
//!
//! The actual JNI symbols live in the sibling modules:
//!   * [`tunnel`]     — `LkTunnelNative` / `NativeJni`
//!   * [`signaling`]  — `BaleSignalingNative` / `BaleAuthNative`
//!   * [`text`]       — `TextTunnelNative` (text carrier)
//!
//! This file owns only the unified `JNI_OnLoad` (one per `.so`)
//! and the two `pub(crate)` init helpers that wire up
//! module-local statics (logger, JavaVM cache, class GlobalRefs).

use jni::sys::{jint, JNI_VERSION_1_6};
use jni::JavaVM;
use std::os::raw::c_void;

pub mod tunnel;
pub mod manager;
pub mod signaling;
pub mod text;

/// Android linker entry point. Fires once when the app calls
/// `System.loadLibrary("lktunnel_jni")`. Idempotent across reloads
/// is unnecessary on Android (a fresh process always re-loads).
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
    // Single logger init — both modules just `log::*` to this.
    // BaleProxy is the umbrella tag; per-module call sites set
    // their own log targets when they want finer granularity.
    let _ = android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("BaleProxy"),
    );
    log::info!("JNI_OnLoad: lktunnel-jni native init");

    // Cache the JavaVM pointer in `jni_shared` so off-thread
    // callbacks can attach back to the JVM without re-discovering
    // it. Must happen before any module init that may spawn a
    // tokio task that calls back into Java.
    jni_shared::set_vm(vm);

    // Boot the lktunnel reactor / dispatcher thread now so the
    // first TUN attach doesn't have to spin it up on the hot
    // path. Idempotent.
    lktunnel::dispatcher::init();

    // Force tokio runtime creation now so the first signaling
    // RPC isn't delayed by tokio init.
    let _ = jni_shared::runtime();

    // Cache per-module class GlobalRefs. Must run from
    // `System.loadLibrary` context (the app classloader is the
    // current loader); doing it later from a tokio worker thread
    // fails because the worker's classloader is the system one,
    // which can't see app classes.
    if let Ok(env) = jni_shared::vm().get_env() {
        tunnel::init_class_refs(env);
    }
    if let Ok(env) = jni_shared::vm().get_env() {
        manager::init_class_refs(env);
    }
    if let Ok(env) = jni_shared::vm().get_env() {
        signaling::init_class_refs(env);
    }

    JNI_VERSION_1_6 as jint
}
