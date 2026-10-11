package ai.bale.proxy

import ai.bale.proxy.tunnel.LiveKitStats
import ai.bale.proxy.tunnel.PacketStats
import android.app.*
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onSubscription
import java.util.concurrent.ConcurrentHashMap

private const val TAG                = "BaleProxy"
// Auto-reject a pending caller after this — caller has likely given up and the notification is stale.
private const val PENDING_TIMEOUT_MS = 60 * 1000L
// How often the pending sweep loop runs.
private const val PENDING_CHECK_MS   = 15_000L
// How often the UI snapshot loop refreshes per-client stats.
private const val STATS_REFRESH_MS   = 500L

class BaleServerService : Service() {

    data class ClientInfo(
        val callId:       Long,
        val callerId:     Long,
        val connectedAt:  Long,
        val rxPkts: Long, val rxBytes: Long,
        val txPkts: Long, val txBytes: Long,
        // Latest WebRTC transport stats from this client's LiveKit room. Null when
        // the SDK hasn't reported a nominated candidate-pair yet (usually the first
        // ~1 s after connect).
        val lkStats:      LiveKitStats? = null,
        // Aggregated TCP/UDP flow stats from the native NAT layer (NatDispatcher).
        // Null when the session has no flows yet or has been torn down.
        val packetStats:  PacketStats? = null,
    )

    /** UI-visible pending-call record. The real "pending" state
     *  lives in the in-flight [BaleIncomingHandler.decide]
     *  coroutines via [PendingDecision.deferred]; this is just
     *  the snapshot the UI iterates. */
    data class PendingCall(
        val callId:     Long,
        val callerId:   Long,
        val callerName: String? = null,
        val receivedAt: Long    = System.currentTimeMillis(),
    )

    /** In-flight admission decision. Held in [pendingDecisions]
     *  keyed by callerId. Action handlers (Allow / Reject /
     *  timeout) complete the `deferred` and the
     *  [BaleIncomingHandler] coroutine resumes with the result. */
    private data class PendingDecision(
        val callerId: Long,
        val deferred: CompletableDeferred<CallDecision>,
        val receivedAt: Long = System.currentTimeMillis(),
    )

    // Recreated whenever the service is (re)started — once cancelled, a CoroutineScope
    // is dead. Without this, an Android low-memory restart or a rapid stop→start
    // toggle would leave us with a cancelled scope; scope.launch would silently no-op
    // and incoming-call updates would be received but never dispatched.
    private var scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    // Tracks whether we've launched our background loops on the current scope. Reset
    // whenever the scope is rebuilt so a restarted service relaunches them, but stays
    // true across redundant onStartCommand calls (which Android may issue when the
    // activity calls startService more than once).
    private var loopsStarted = false

    private class Client(
        val callId:      Long,
        val callerId:    Long = 0L,
        val transport:   LkTunnel,
        val connectedAt: Long = System.currentTimeMillis(),
        // Display name resolved at connect time; reused on disconnect so the
        // notification reads the same name even if the WS is being torn down
        // by the time disconnect fires.
        @Volatile var resolvedName: String? = null,
    )

    private val clients           = ConcurrentHashMap<Long, Client>()
    /** UI-visible snapshot keyed by callerId. */
    private val pendingMap        = ConcurrentHashMap<Long, PendingCall>()
    /** In-flight admission deferreds keyed by callerId. */
    private val pendingDecisions  = ConcurrentHashMap<Long, PendingDecision>()

    companion object {
        const val ACTION_STOP = "ai.bale.proxy.SERVER_STOP"
        private const val NOTIF_ID         = 2
        private const val PENDING_NOTIF_ID = 3
        // LOW-importance channel for the silent informational notifications:
        // foreground service status + per-client connect/disconnect events.
        private const val CHANNEL          = "bale_server"
        // HIGH-importance channel — only the pending-admission notification
        // posts here, since it requires the user to allow/reject before the
        // call can proceed. Heads-up + sound is appropriate.
        private const val ALERT_CHANNEL    = "bale_server_alerts"
        // Per-callerId connect/disconnect events sit on a separate id range so they
        // don't collide with the foreground / pending notifications. Each caller
        // gets a stable id derived from their callerId, so a "disconnected" alert
        // replaces an older "connected" alert from the same caller.
        private const val CLIENT_EVENT_NOTIF_BASE = 1_000
        // Cap on simultaneously-connected clients. Hard limit matches the Node side's
        // SNAT pool size (10.8.0.2–10.8.0.254 = 253 slots) so the two platforms behave
        // identically when paired with the same kind of peer. The user-facing default
        // is 5 — most people have 2-3 devices, the extra headroom covers occasional
        // family/guest peers.
        const val MAX_CLIENTS_DEFAULT: Int = 5
        const val MAX_CLIENTS_LIMIT:   Int = 253

        fun getMaxClients(prefs: android.content.SharedPreferences): Int =
            prefs.getInt("maxClients", MAX_CLIENTS_DEFAULT).coerceIn(1, MAX_CLIENTS_LIMIT)
        fun setMaxClients(prefs: android.content.SharedPreferences, n: Int) {
            prefs.edit().putInt("maxClients", n.coerceIn(1, MAX_CLIENTS_LIMIT)).apply()
        }

        @Volatile var isRunning   = false
        @Volatile var clientCount = 0
        // User-facing verbose-logging toggle. Propagates to the native NAT
        // layer (per-flow TCP/UDP sessions + dispatcher) so retransmits,
        // cwnd-limited stalls, fragment activity, etc. surface to logcat.
        @Volatile var debug: Boolean = false
            set(value) {
                field = value
                LkTunnel.setDebug(value)
                instance?.getSharedPreferences("config", MODE_PRIVATE)
                    ?.edit()?.putBoolean("packet_debug", value)?.apply()
            }
        @Volatile private var instance:        BaleServerService? = null
        @Volatile private var clientSnapshot:  List<ClientInfo>   = emptyList()
        @Volatile private var pendingSnapshot: List<PendingCall>  = emptyList()

        fun getClientInfos():  List<ClientInfo>  = clientSnapshot
        fun getPendingCalls(): List<PendingCall> = pendingSnapshot

        fun disconnectClient(callId: Long) {
            instance?.scope?.launch { instance?.doDisconnect(callId) }
        }

        // Tear down every active client and pending request. Suspends until each
        // client has had its discardCall sent and its LiveKit room closed, so the
        // caller can safely tear down the WS afterwards without the per-client
        // discardCall RPCs racing the WS shutdown.
        suspend fun disconnectAllClients() {
            val inst = instance ?: return
            val ids = inst.clients.keys.toList()
            Log.d(TAG, "Server: disconnecting all ${ids.size} clients (user request)")
            // Send discardCall + close transports concurrently — each one waits on
            // its own RPC, but they don't need to block each other.
            coroutineScope {
                ids.forEach { id -> launch { inst.doDisconnect(id) } }
            }
            if (inst.pendingMap.isNotEmpty()) {
                val pendingIds = inst.pendingMap.keys.toList()
                Log.d(TAG, "Server: rejecting ${pendingIds.size} pending requests")
                coroutineScope {
                    pendingIds.forEach { id -> launch { inst.doRejectPending(id) } }
                }
            }
        }

        fun blockClient(callId: Long, callerId: Long) {
            if (callerId != 0L) AdmissionStore.remove(callerId)
            instance?.scope?.launch { instance?.doDisconnect(callId) }
        }

        fun acceptPending(callId: Long, addToList: Boolean) {
            instance?.scope?.launch { instance?.doAcceptPending(callId, addToList) }
        }

        fun rejectPending(callId: Long) {
            // UI-driven rejection: also blacklist so the caller can't keep
            // re-sending the same incoming call. Internal paths (sweep
            // timeout, bulk WS-teardown) call doRejectPending directly with
            // addToBlacklist=false.
            instance?.scope?.launch { instance?.doRejectPending(callId, addToBlacklist = true) }
        }

    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopServer(); return START_NOT_STICKY }

        Log.d(TAG, "BaleServerService: starting")
        // Replace a cancelled scope from a previous stopServer()/onDestroy() so the
        // new lifecycle gets a working CoroutineScope. When that happens we also need
        // to re-launch the sweep loops on the new scope.
        if (!scope.isActive) {
            scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            loopsStarted = false
            Log.d(TAG, "BaleServerService: rebuilt cancelled scope")
        }
        instance  = this
        isRunning = true
        startForeground(NOTIF_ID, buildNotification())

        val prefs = getSharedPreferences("config", MODE_PRIVATE)
        AdmissionStore.init(prefs)
        BlacklistStore.init(prefs)
        debug           = prefs.getBoolean("packet_debug",     false)

        // Construct the server tunnel manager. Its constructor:
        //   1. installs an IncomingHandler on the signaling impl
        //      that delegates to our [AdmissionDecider];
        //   2. activates the signaling impl (pinned active for
        //      the manager's lifetime — server mode ignores
        //      foreground);
        //   3. subscribes to sign-out so a UI sign-out auto-
        //      disconnects every live session.
        // Close on `stopServer` deactivates.
        // Swap BaleConnection to server-mode — closes the
        // ClientTunnelManager and constructs the ServerTunnelManager
        // we'll use. The server manager pins activation so the WS
        // stays up regardless of foreground state.
        BaleConnection.setMode(Mode.SERVER)
        val mgr = BaleConnection.serverMgr
        if (mgr == null) {
            Log.e(TAG, "Server: BaleSignaling not initialised — incoming calls disabled")
        }

        // All scope.launch{} below are subscription-creating and
        // MUST be guarded by `loopsStarted` — Android can fire
        // onStartCommand repeatedly under START_STICKY (sticky
        // restart, redundant startService calls, …) and each
        // unguarded launch piles on another collector on the same
        // SharedFlow. Symptoms when ungated: a single Rust
        // Connected delivers N times into handleSession, racing
        // multiple startServer() calls for one tunnel.
        if (!loopsStarted && mgr != null) {
            loopsStarted = true
            val subscribed = CompletableDeferred<Unit>()
            scope.launch {
                mgr.events
                    .onSubscription {
                        Log.i(TAG, "Server: collector subscribed")
                        subscribed.complete(Unit)
                    }
                    .collect { ev ->
                        Log.i(TAG, "Server: collector received $ev")
                        when (ev) {
                            is SessionEvent.Connected    -> handleSession(ev.peerId, ev.tunnelHandle)
                            is SessionEvent.Disconnected -> handleSessionEnded(ev.peerId.toLongOrNull() ?: 0L)
                            is SessionEvent.Failed       -> {
                                Log.w(TAG, "Server: session for ${ev.peerId} failed to connect")
                                handleSessionEnded(ev.peerId.toLongOrNull() ?: 0L)
                            }
                        }
                    }
            }
            scope.launch {
                subscribed.await()
                mgr.setAdmission(AdmissionDecider { peerIdStr, displayName ->
                    val live = instance
                    if (live == null || !live.scope.isActive) {
                        Log.w(TAG, "Server: incoming from $peerIdStr but service scope is gone")
                        return@AdmissionDecider CallDecision.SilentlyIgnore
                    }
                    val callerId = peerIdStr.toLongOrNull()
                        ?: return@AdmissionDecider CallDecision.SilentlyIgnore
                    live.decideIncoming(callerId, displayName)
                })
            }
            // No WS-CallEnded subscriber here either: the
            // `ServerTunnelManager` enforces the "LK is the
            // sole authority once joined" rule centrally.
            // Active-session peers' CallEnded is silently
            // ignored; pending-admission peers' CallEnded
            // cancels the in-flight `decide()` and surfaces
            // as `SessionEvent.Failed` on the manager stream,
            // which `handleSessionEnded` already drops the
            // pending entry for.
            scope.launch { pendingSweepLoop() }
            scope.launch { statsLoop() }
        }

        // Bring up the WS. sig.connect() clears the user_disconnect
        // sticky and installs the token; Rust rule engine evaluates
        // (server mode → WS up modulo user_disconnect, which we just
        // cleared). Idempotent if already connected.
        BaleConnection.signaling?.let { sig -> scope.launch { sig.connect() } }

        return START_STICKY
    }

    /** Suspend admission decision for a fresh incoming call.
     *  Mirrors the pre-migration `checkAndHandleCall` policy
     *  but returns a [CallDecision] for [BaleIncomingHandler]
     *  to consume. Pending decisions block on a
     *  [CompletableDeferred] completed by the notification's
     *  Allow/Reject buttons (or the sweep loop timeout). */
    private suspend fun decideIncoming(callerId: Long, displayName: String?): CallDecision {
        Log.d(TAG, "Server: incoming callerId=$callerId allowed=${AdmissionStore.isAllowed(callerId)}")

        // Blocked callers: explicit reject so the caller's UI
        // sees the call terminate immediately rather than
        // waiting for a timeout. The discardCall message
        // surfaces on the caller side as `EndReason::Rejected`
        // (mapped from Bale's discardReason) and they can act
        // on it right away.
        if (BlacklistStore.isBlocked(callerId)) {
            Log.d(TAG, "Server: rejecting blacklisted callerId=$callerId")
            return CallDecision.Reject
        }

        // Capacity gate. Applies to allowed and not-yet-allowed
        // alike — a pending decision queued past the cap would
        // just stall. Rejection is silent so the caller is free
        // to re-call once a slot frees up.
        val maxClients = getMaxClients(getSharedPreferences("config", MODE_PRIVATE))
        if (clients.size >= maxClients) {
            Log.d(TAG, "Server: rejecting callerId=$callerId — at capacity ${clients.size}/$maxClients")
            return CallDecision.SilentlyIgnore
        }

        if (AdmissionStore.isAllowed(callerId)) return CallDecision.Accept

        // Otherwise: enter the pending state. A duplicate from
        // the same caller cancels the previous deferred.
        pendingDecisions.remove(callerId)?.deferred?.complete(CallDecision.SilentlyIgnore)
        val deferred = CompletableDeferred<CallDecision>()
        pendingDecisions[callerId] = PendingDecision(callerId, deferred)
        // UI-visible mirror — callId field gets the callerId for
        // notification action routing (one-to-one in the new model).
        pendingMap[callerId] = PendingCall(callerId, callerId, displayName)
        pendingSnapshot = pendingMap.values.toList()
        updateNotification()
        showPendingNotification(callerId, callerName = displayName)
        return deferred.await()
    }

    /** Consumer of [ServerTunnelManager.events]'s `Connected`
     *  arm. The library has already built + registered the
     *  [LkTunnel] for this call; we wrap the handle, install
     *  the Client entry, and drive `startServer()` to bring up
     *  the userspace NAT. No `onDisconnected` wiring here — the
     *  manager's `Disconnected` event drives the matching
     *  cleanup via [onCallEndedRemote]. */
    private fun handleSession(peerIdStr: String, tunnelHandle: Long) {
        val callerId = peerIdStr.toLongOrNull() ?: run {
            Log.w(TAG, "Server: handleSession: non-numeric peerId=$peerIdStr")
            return
        }
        val callId = callerId   // peer-uid doubles as the local call key
        Log.d(TAG, "Server: new session for callerId=$callerId handle=$tunnelHandle")

        pendingMap.remove(callerId)?.let {
            pendingSnapshot = pendingMap.values.toList()
            cancelPendingNotificationIfEmpty()
        }
        pendingDecisions.remove(callerId)

        scope.launch {
            val callerName = BaleConnection.signaling?.fetchDisplayName(callerId.toString())
            val transport  = LkTunnel(tunnelHandle)
            val client     = Client(callId, callerId, transport, resolvedName = callerName)

            clients[callId] = client
            clientCount = clients.size
            rebuildSnapshot()
            updateNotification()
            postClientEvent(callerId, "connected", callerName)

            try {
                transport.startServer()
            } catch (e: Exception) {
                Log.w(TAG, "Server: startServer failed for $callId: ${e::class.simpleName}: ${e.message}")
                clients.remove(callId, client)
                clientCount = clients.size
                rebuildSnapshot()
                updateNotification()
                postClientEvent(callerId, "disconnected", callerName)
            }
        }
    }

    private fun doAcceptPending(callId: Long, addToList: Boolean) {
        // In the new model the `callId` notification arg is the
        // callerId — they're 1:1.
        val callerId = callId
        val pending = pendingDecisions.remove(callerId) ?: return
        pendingMap.remove(callerId)
        pendingSnapshot = pendingMap.values.toList()
        cancelPendingNotificationIfEmpty()
        updateNotification()
        // Capacity re-check at accept time.
        val maxClients = getMaxClients(getSharedPreferences("config", MODE_PRIVATE))
        val decision = if (clients.size >= maxClients) {
            Log.d(TAG, "Server: cannot accept pending $callerId — at capacity")
            CallDecision.SilentlyIgnore
        } else {
            if (addToList && callerId != 0L) AdmissionStore.add(callerId)
            CallDecision.Accept
        }
        pending.deferred.complete(decision)
    }

    private fun doRejectPending(callId: Long, addToBlacklist: Boolean = false) {
        val callerId = callId
        val pending = pendingDecisions.remove(callerId) ?: return
        pendingMap.remove(callerId)
        pendingSnapshot = pendingMap.values.toList()
        cancelPendingNotificationIfEmpty()
        updateNotification()
        Log.d(TAG, "Server: rejecting callerId=$callerId block=$addToBlacklist")
        pending.deferred.complete(
            if (addToBlacklist) CallDecision.Reject else CallDecision.SilentlyIgnore
        )
        if (addToBlacklist && callerId != 0L) BlacklistStore.add(callerId)
    }

    // Auto-reject pending calls that have been waiting too long — the caller has likely
    // hung up by now and the notification is just clutter.
    private suspend fun pendingSweepLoop() {
        while (true) {
            delay(PENDING_CHECK_MS)
            val now    = System.currentTimeMillis()
            // Iterate the in-flight decisions (the deferreds are
            // the source of truth). Auto-complete with
            // SilentlyIgnore for any that have been waiting past
            // PENDING_TIMEOUT_MS — caller has likely given up.
            val expired = pendingDecisions.values.filter { now - it.receivedAt > PENDING_TIMEOUT_MS }
            for (p in expired) {
                Log.d(TAG, "Server: pending callerId=${p.callerId} timed out — auto-rejecting")
                pendingDecisions.remove(p.callerId)
                pendingMap.remove(p.callerId)
                p.deferred.complete(CallDecision.SilentlyIgnore)
            }
            if (expired.isNotEmpty()) {
                pendingSnapshot = pendingMap.values.toList()
                cancelPendingNotificationIfEmpty()
                updateNotification()
            }
        }
    }

    /** LK-driven session end (manager `Disconnected` / `Failed`).
     *  Tears down the matching active client and clears any
     *  pending entry. This is the authoritative path — LK is
     *  the sole source of truth for "session over" once both
     *  parties have joined the room. */
    private fun handleSessionEnded(callId: Long) {
        if (callId == 0L) return
        if (clients.containsKey(callId)) {
            Log.d(TAG, "Server: LK session ended for $callId — tearing down active client")
            scope.launch { doDisconnect(callId) }
        }
        dropPendingEntry(callId)
    }

    /** Shared "pending caller went away" cleanup. Called from
     *  [handleSessionEnded] when the manager surfaces a
     *  `SessionEvent.Failed` for a peer that hadn't reached
     *  active state — typically because the caller hung up
     *  during the admission decision (the manager's
     *  CallEnded handler cancels the in-flight `decide()`
     *  and emits Failed). */
    private fun dropPendingEntry(callId: Long) {
        pendingDecisions.remove(callId)?.let { p ->
            Log.d(TAG, "Server: dropping pending entry for $callId (caller hung up)")
            p.deferred.complete(CallDecision.SilentlyIgnore)
            pendingMap.remove(callId)
            pendingSnapshot = pendingMap.values.toList()
            cancelPendingNotificationIfEmpty()
            updateNotification()
        }
    }

    private suspend fun statsLoop() {
        while (true) {
            delay(STATS_REFRESH_MS)
            if (clients.isNotEmpty()) rebuildSnapshot()
        }
    }


    private fun rebuildSnapshot() {
        clientSnapshot = clients.values.map { c ->
            // [rxPkts, rxBytes, txPkts, txBytes] — atomics on the
            // native side, lock-free read. May be null in the brief
            // window between connect attempt and startServer; fall
            // back to zeros so the UI doesn't blank.
            val s = c.transport.stats() ?: longArrayOf(0, 0, 0, 0)
            ClientInfo(
                callId       = c.callId,
                callerId     = c.callerId,
                connectedAt  = c.connectedAt,
                rxPkts       = s[0],
                rxBytes      = s[1],
                txPkts       = s[2],
                txBytes      = s[3],
                lkStats      = c.transport.lastStats,
                packetStats  = c.transport.flowStats()?.let(PacketStats::fromLongs),
            )
        }.sortedBy { it.connectedAt }
    }

    private suspend fun doDisconnect(callId: Long) {
        clients.remove(callId)?.also {
            Log.d(TAG, "Server: forcibly disconnecting $callId")
            // Closing the LkTunnel signals participant-disconnect
            // to the peer; Bale then fires callEnded, which the
            // events collector picks up. We don't issue an
            // explicit discardCall — the trait surface doesn't
            // expose it and the LK-side teardown is enough.
            it.transport.disconnect()
            clientCount = clients.size
            rebuildSnapshot()
            updateNotification()
            postClientEvent(it.callerId, "disconnected", it.resolvedName)
        }
    }

    /** Drop the local Client entry + close its transport. Used
     *  by [onCallEndedRemote]; the manager's per-peer registry
     *  already disconnected the underlying tunnel by this point,
     *  so the transport.disconnect() here is idempotent. */
    private fun cleanupClientLocal(callId: Long) {
        clients.remove(callId)?.also {
            Log.d(TAG, "Server: local cleanup of $callId")
            runCatching { it.transport.disconnect() }
            clientCount = clients.size
            rebuildSnapshot()
            updateNotification()
        }
    }

    private fun stopServer() {
        Log.d(TAG, "BaleServerService: stopping")
        // Hand BaleConnection back to client mode — closes the
        // ServerTunnelManager (deactivates) and constructs a
        // ClientTunnelManager whose foreground subscriber takes
        // over the WS gating.
        BaleConnection.setMode(Mode.CLIENT)
        isRunning       = false
        if (!BaleVpnService.isRunning &&
            !ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            BaleConnection.signaling?.setForeground(false)
        }
        clientCount     = 0
        clientSnapshot  = emptyList()
        pendingSnapshot = emptyList()
        loopsStarted    = false
        if (instance === this) {
            instance = null
            // No global callback to clear in the new model — the
            // IncomingHandler installed on BaleSignaling stays
            // tied to the dropped service instance. A successor
            // onStartCommand will reinstall its own.
        }
        // Complete all in-flight admission decisions as SilentlyIgnore
        // so the signaling layer drops the calls. Closing LkTunnels
        // signals participant-disconnect on accepted sessions; Bale
        // fires the matching callEnded events to peer clients.
        pendingDecisions.values.forEach { it.deferred.complete(CallDecision.SilentlyIgnore) }
        pendingDecisions.clear()
        clients.values.forEach { it.transport.disconnect() }
        clients.clear()
        pendingMap.clear()
        cancelPendingNotification()
        scope.cancel()
        stopSelf()
    }

    override fun onDestroy() { Log.d(TAG, "BaleServerService: onDestroy"); stopServer(); super.onDestroy() }
    override fun onBind(intent: Intent?) = null

    // ── Notifications ─────────────────────────────────────────────────────────

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            if (mgr.getNotificationChannel(CHANNEL) == null) {
                val ch = NotificationChannel(CHANNEL, "VPN Server", NotificationManager.IMPORTANCE_LOW)
                ch.setShowBadge(false)
                mgr.createNotificationChannel(ch)
            }
            if (mgr.getNotificationChannel(ALERT_CHANNEL) == null) {
                val ch = NotificationChannel(ALERT_CHANNEL, "Connection Requests", NotificationManager.IMPORTANCE_HIGH)
                mgr.createNotificationChannel(ch)
            }
        }
    }

    private fun buildNotification(): Notification {
        ensureChannel()
        // The WS is the only way incoming-call updates reach the server. If it's
        // down, surface that — otherwise the body just shows the live state when
        // there's something interesting to report (clients connected or pending).
        val wsAttached = BaleConnection.isConnectRequested || BaleConnection.isReady
        val wsReady    = BaleConnection.isReady
        val text = when {
            !wsAttached -> "WebSocket disconnected — no incoming calls"
            !wsReady    -> "Reconnecting WebSocket… (no incoming calls)"
            clientCount > 0 || pendingMap.isNotEmpty() -> buildList {
                if (clientCount > 0)         add("$clientCount connected")
                if (pendingMap.isNotEmpty()) add("${pendingMap.size} pending")
            }.joinToString(" • ")
            else -> ""  // idle — no body text, just the title
        }
        val b = Notification.Builder(this, CHANNEL)
            .setContentTitle("Bale VPN — Server")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
        if (text.isNotEmpty()) b.setContentText(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            b.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return b.build()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
    }

    private fun showPendingNotification(callerId: Long, callerName: String?) {
        ensureChannel()
        val callerLabel = when {
            callerName != null  -> callerName
            callerId   != 0L    -> "ID $callerId"
            else                -> "unknown caller"
        }
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = PendingIntent.getActivity(this, PENDING_NOTIF_ID, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(this, ALERT_CHANNEL)
            .setContentTitle("Bale VPN — Connection Request")
            .setContentText("$callerLabel wants to connect")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(PENDING_NOTIF_ID, n)
    }

    private fun cancelPendingNotificationIfEmpty() {
        if (pendingMap.isEmpty()) cancelPendingNotification()
    }

    private fun cancelPendingNotification() {
        getSystemService(NotificationManager::class.java).cancel(PENDING_NOTIF_ID)
    }

    // Transient connect/disconnect alert. Caller passes the pre-resolved name
    // when available (handleCall does the lookup once at connect time, then
    // disconnect callbacks use the cached value on Client.resolvedName). Falls
    // back to a fresh lookup, then to "ID $callerId" if everything fails.
    private fun postClientEvent(callerId: Long, event: String, knownName: String? = null) {
        scope.launch {
            val name = knownName ?: if (callerId != 0L) {
                try { BaleConnection.signaling?.fetchDisplayName(callerId.toString()) } catch (_: Exception) { null }
            } else null
            val label = name?.takeIf { it.isNotBlank() }
                ?: if (callerId != 0L) "ID $callerId" else "unknown caller"
            Log.d(TAG, "Server: postClientEvent callerId=$callerId resolved='$label' event=$event")
            showClientEventNotification(callerId, label, event)
        }
    }

    private fun showClientEventNotification(callerId: Long, label: String, event: String) {
        val n = Notification.Builder(this, CHANNEL)
            .setContentTitle("Bale VPN — Server")
            .setContentText("$label $event")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setAutoCancel(true)
            .build()
        // Stable per-caller id so a "disconnected" alert replaces an earlier
        // "connected" alert from the same caller — the user sees the latest
        // state, not a stack of stale events.
        val id = CLIENT_EVENT_NOTIF_BASE + (callerId.rem(10_000).toInt().let { if (it < 0) it + 10_000 else it })
        getSystemService(NotificationManager::class.java).notify(id, n)
    }
}
