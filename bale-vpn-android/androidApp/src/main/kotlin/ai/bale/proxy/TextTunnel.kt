package ai.bale.proxy

/**
 * Text-carrier tunnel: IP packets ride as Bale *text* messages over the
 * already-open WebSocket instead of a LiveKit call.
 *
 * Lifecycle contract is identical to [LkTunnel]: the long-lived JNI
 * handle owns the native session, `disconnect()` (or a JVM finalizer
 * race against it) releases it, and there is deliberately **no fallback**
 * path. If the handle disappears the session is gone — same as the
 * desktop client, where a dead text session ends the connection rather
 * than silently switching carrier.
 *
 * The handle is process-global on the Rust side (`HandleRegistry`), so a
 * double-close is idempotent: the second `remove()` finds nothing.
 *
 * No Java-side listeners exist for the same reason as [LkTunnel]: the
 * text session has no periodic keep-alive to drive a ping, and nothing
 * meaningful pushes back while it is alive. Session end is observed by
 * the service through [isConnected].
 */
class TextTunnel private constructor(private val handle: Long) : AutoCloseable {

    init {
        require(handle != 0L) { "TextTunnel: handle == 0" }
    }

    /** Native-side session liveness: the spawned session future is still
     *  running (it only exits on a hard error — hello timeout, sink
     *  conflict, or reader/writer failure). */
    val isConnected: Boolean
        get() = TextTunnelNative.nativeTextIsConnected(handle)

    override fun close() {
        if (closed) return
        closed = true
        TextTunnelNative.nativeTextDisconnect(handle)
    }

    fun disconnect() = close()

    @Volatile
    private var closed = false

    companion object {
        /**
         * Open a text session. `tunFd` ownership transfers to native on
         * success — Kotlin must not close it again after this call.
         *
         * @return the session, or null when native refused before taking
         *   the fd (bad signaling handle / empty peer / invalid fd), in
         *   which case the caller still owns `tunFd` and must close it.
         */
        fun open(signalingHandle: Long, peerId: String, tunFd: Int): TextTunnel? {
            val h = TextTunnelNative.nativeTextOpen(signalingHandle, peerId, tunFd)
            return if (h != 0L) TextTunnel(h) else null
        }
    }
}

/**
 * JNI surface for [TextTunnel]. Merged into the same `liblktunnel_jni.so`
 * as [LkTunnelNative]; see the Rust `text` module in `lktunnel-jni`.
 */
internal object TextTunnelNative {
    init {
        System.loadLibrary("lktunnel_jni")
    }

    /**
     * Open a text session over the shared Bale WebSocket.
     *
     * @param signalingHandle registry id of the `BaleSignaling` instance
     * @param peerId target uid as a decimal string (already resolved)
     * @param tunFd raw TUN fd whose ownership transfers to native
     * @return a non-zero session handle, or 0 when native refused
     */
    @JvmStatic external fun nativeTextOpen(signalingHandle: Long, peerId: String, tunFd: Int): Long

    @JvmStatic external fun nativeTextDisconnect(handle: Long)
    @JvmStatic external fun nativeTextIsConnected(handle: Long): Boolean

    /** Always null in v1 — the session keeps its counters internally. */
    @JvmStatic external fun nativeTextStats(handle: Long): LongArray?
}
