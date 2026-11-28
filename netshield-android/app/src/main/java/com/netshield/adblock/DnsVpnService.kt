package com.netshield.adblock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URL
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

data class DnsLogItem(
    val domain: String,
    val blocked: Boolean,
    val reason: String,
    val time: String
)

private data class RawDnsLog(
    val domain: String,
    val blocked: Boolean,
    val reason: String,
    val timestampMs: Long
)

data class CachedDns(
    val response: ByteArray,
    val expiresAtMs: Long
)

object VpnState {
    val isRunning = AtomicBoolean(false)
    val isHomeLanStandby = AtomicBoolean(false)
    val totalQueries = AtomicInteger(0)
    val blockedQueries = AtomicInteger(0)

    private val logLock = Any()
    private val logs = ArrayDeque<RawDnsLog>(260)
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    private const val CACHE_TTL_MS = 600_000L // 10 phút -> giảm mạnh số lần đánh thức sóng 4G/Wi-Fi
    private const val NXDOMAIN_TTL_MS = 120_000L // Cache NXDOMAIN 2 phút để tránh app retry liên tục
    private const val CACHE_MAX_SIZE = 3000
    private val cacheLock = Any()
    private val dnsCache = object : LinkedHashMap<String, CachedDns>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedDns>?): Boolean {
            return size > CACHE_MAX_SIZE
        }
    }

    fun addListener(cb: () -> Unit) {
        listeners.add(cb)
    }

    fun removeListener(cb: () -> Unit) {
        listeners.remove(cb)
    }

    fun notifyChanged() {
        if (listeners.isEmpty()) return
        for (l in listeners) {
            try {
                l()
            } catch (_: Exception) {}
        }
    }

    fun getLogsSnapshot(): List<DnsLogItem> = synchronized(logLock) {
        val date = Date()
        logs.map { raw ->
            date.time = raw.timestampMs
            DnsLogItem(raw.domain, raw.blocked, raw.reason, timeFmt.format(date))
        }
    }

    fun record(domain: String, blocked: Boolean, reason: String) {
        totalQueries.incrementAndGet()
        if (blocked) blockedQueries.incrementAndGet()
        val now = System.currentTimeMillis()
        synchronized(logLock) {
            logs.addFirst(RawDnsLog(domain, blocked, reason, now))
            while (logs.size > 250) {
                logs.removeLast()
            }
        }
        notifyChanged()
    }

    fun getCachedDns(key: String, queryTxId0: Byte, queryTxId1: Byte): ByteArray? {
        val entry = synchronized(cacheLock) {
            val e = dnsCache[key] ?: return null
            if (System.currentTimeMillis() > e.expiresAtMs) {
                dnsCache.remove(key)
                return null
            }
            e
        }
        val copy = entry.response.copyOf()
        if (copy.size >= 2) {
            copy[0] = queryTxId0
            copy[1] = queryTxId1
        }
        return copy
    }

    fun putCachedDns(key: String, response: ByteArray) {
        if (response.size < 12) return
        // Cache NOERROR (0) trong 10 phút và NXDOMAIN (3) trong 2 phút
        val rcode = response[3].toInt() and 0x0F
        val ttlMs = when (rcode) {
            0 -> CACHE_TTL_MS
            3 -> NXDOMAIN_TTL_MS
            else -> return
        }
        val entry = CachedDns(response.copyOf(), System.currentTimeMillis() + ttlMs)
        synchronized(cacheLock) {
            dnsCache[key] = entry
        }
    }

    fun clearDnsCache() {
        synchronized(cacheLock) {
            dnsCache.clear()
        }
    }
}

class DnsVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.netshield.adblock.START"
        const val ACTION_STOP = "com.netshield.adblock.STOP"
        const val ACTION_REEVALUATE = "com.netshield.adblock.REEVALUATE"
        private const val CHANNEL_ID = "netshield_vpn_channel"
        private const val NOTIF_ID = 1001
        private const val VIRTUAL_DNS_V4 = "10.10.0.2"
        private const val VIRTUAL_DNS_V6 = "fd00:10:10::2"

        private val PUBLIC_UPSTREAMS: List<InetAddress> = listOfNotNull(
            runCatching { InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)) }.getOrNull(),
            runCatching { InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)) }.getOrNull(),
            runCatching {
                InetAddress.getByAddress(
                    byteArrayOf(
                        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
                    )
                )
            }.getOrNull()
        )

        private val DOH_URLS = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        )
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private var executor: ThreadPoolExecutor? = null
    private val writeLock = Any()
    private val tunLock = Any()

    @Volatile
    private var activeUnderlyingNetwork: Network? = null

    @Volatile
    private var systemDnsServers: List<InetAddress> = emptyList()

    @Volatile
    private var preferredUpstream: InetAddress? = null

    @Volatile
    private var hasIpv6Connectivity: Boolean = false

    @Volatile
    private var dohBackoffUntilMs: Long = 0L

    @Volatile
    private var lastNotifiedStandby: Boolean? = null

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_REEVALUATE -> {
                if (VpnState.isRunning.get()) {
                    evaluateHomeLanState()
                }
                return START_STICKY
            }
            else -> {
                startVpn()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn() {
        BlocklistManager.init(this)
        if (VpnState.isRunning.get()) {
            evaluateHomeLanState()
            return
        }

        createNotificationChannel()
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(), fgsType)

        VpnState.isRunning.set(true)
        refreshUnderlyingNetwork()
        registerNetworkMonitor()
        evaluateHomeLanState()
    }

    private fun isOnHomeLan(): Boolean {
        if (!BlocklistManager.isAutoPauseHomeLan()) return false
        val homeIp = BlocklistManager.getHomeDnsIp()
        if (homeIp.isEmpty()) return false

        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue

            val lp = cm.getLinkProperties(net) ?: continue
            val hasHomeDns = lp.dnsServers.any { it.hostAddress == homeIp }
            if (hasHomeDns) return true
        }
        return false
    }

    private fun evaluateHomeLanState() {
        synchronized(tunLock) {
            if (!VpnState.isRunning.get()) return
            if (isOnHomeLan()) {
                val changed = !VpnState.isHomeLanStandby.getAndSet(true)
                closeTunOnly()
                if (changed || vpnInterface == null) {
                    updateNotification()
                    VpnState.notifyChanged()
                }
            } else {
                VpnState.isHomeLanStandby.set(false)
                if (vpnInterface == null) {
                    val ok = openTun()
                    if (!ok) {
                        stopVpn()
                        return
                    }
                }
                updateNotification()
                VpnState.notifyChanged()
            }
        }
    }

    private fun openTun(): Boolean {
        refreshUnderlyingNetwork()

        val builder = Builder()
            .setSession("NetShield DNS")
            .setMtu(1500)
            .addAddress("10.10.0.1", 32)
            .addDnsServer(VIRTUAL_DNS_V4)
            .addRoute(VIRTUAL_DNS_V4, 32)
            .allowBypass()

        // Bắt luôn DNS IPv6 trên mạng 4G/5G (tránh quảng cáo Admicro lọt qua IPv6)
        try {
            builder.addAddress("fd00:10:10::1", 128)
            builder.addDnsServer(VIRTUAL_DNS_V6)
            builder.addRoute(VIRTUAL_DNS_V6, 128)
        } catch (_: Exception) {}

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        for (pkg in BlocklistManager.getBypassApps()) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: Exception) {}
        }

        val pfd = try {
            builder.establish()
        } catch (_: Exception) {
            null
        } ?: return false

        val underlying = activeUnderlyingNetwork
        try {
            setUnderlyingNetworks(if (underlying != null) arrayOf(underlying) else null)
        } catch (_: Exception) {}

        vpnInterface = pfd
        val pool = ThreadPoolExecutor(
            1,
            16,
            10L,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(128),
            ThreadPoolExecutor.DiscardOldestPolicy()
        ).apply { allowCoreThreadTimeOut(true) }
        executor = pool
        VpnState.clearDnsCache()

        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)

        readerThread = Thread({
            val buf = ByteArray(2048)
            var consecutiveErrors = 0
            try {
                while (VpnState.isRunning.get() && !VpnState.isHomeLanStandby.get() && !Thread.currentThread().isInterrupted) {
                    val len = try {
                        val n = input.read(buf)
                        consecutiveErrors = 0
                        n
                    } catch (_: Exception) {
                        if (!VpnState.isRunning.get() || VpnState.isHomeLanStandby.get() || Thread.currentThread().isInterrupted) break
                        consecutiveErrors++
                        if (consecutiveErrors >= 5) break
                        try {
                            Thread.sleep(50)
                        } catch (_: InterruptedException) {
                            break
                        }
                        continue
                    }
                    if (len <= 0) continue

                    // Parse & xử lý trực tiếp gói chặn / trúng cache ngay trên readerThread
                    // -> loại bỏ ~80% context-switch và cấp phát task cho ThreadPool
                    val parsed = DnsPacketHelper.parseUdpDns(buf, len) ?: continue
                    val (blocked, reason) = BlocklistManager.shouldBlock(parsed.domain)
                    if (blocked) {
                        val dnsResp = DnsPacketHelper.buildBlockedResponse(parsed.dnsPayload, parsed.qType)
                        writeToTun(output, DnsPacketHelper.wrapUdpResponse(parsed, dnsResp))
                        VpnState.record(parsed.domain, true, reason)
                        continue
                    }

                    val cacheKey = "${parsed.domain}:${parsed.qType}"
                    val cached = if (parsed.dnsPayload.size >= 2) {
                        VpnState.getCachedDns(cacheKey, parsed.dnsPayload[0], parsed.dnsPayload[1])
                    } else {
                        null
                    }
                    if (cached != null) {
                        writeToTun(output, DnsPacketHelper.wrapUdpResponse(parsed, cached))
                        VpnState.record(parsed.domain, false, "Cho phép (Cache)")
                        continue
                    }

                    // Chỉ đẩy truy vấn cần ra mạng (cache miss) vào ThreadPool
                    try {
                        pool.execute {
                            try {
                                handleUpstreamQuery(parsed, cacheKey, reason, output)
                            } catch (_: Exception) {}
                        }
                    } catch (_: RejectedExecutionException) {
                        break
                    }
                }
            } finally {
                // Chỉ dừng dịch vụ nếu TUN chết ngoài ý muốn (không phải do tự nghỉ mạng nội bộ)
                if (VpnState.isRunning.get() && !VpnState.isHomeLanStandby.get() && vpnInterface === pfd) {
                    stopVpn()
                }
            }
        }, "NetShield-TUN-Reader").apply { start() }
        return true
    }

    private fun closeTunOnly() {
        readerThread?.interrupt()
        readerThread = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        try {
            executor?.shutdownNow()
        } catch (_: Exception) {}
        executor = null
        VpnState.clearDnsCache()
    }

    private fun writeToTun(output: FileOutputStream, packet: ByteArray) {
        synchronized(writeLock) {
            try {
                output.write(packet)
            } catch (_: Exception) {}
        }
    }

    private fun handleUpstreamQuery(
        parsed: DnsPacketHelper.ParsedUdpDns,
        cacheKey: String,
        defaultReason: String,
        output: FileOutputStream
    ) {
        val upstreamResp = forwardToUpstream(parsed.dnsPayload)
        val dnsResp: ByteArray
        val finalReason: String
        if (upstreamResp != null) {
            VpnState.putCachedDns(cacheKey, upstreamResp)
            dnsResp = upstreamResp
            finalReason = defaultReason
        } else {
            // Trả SERVFAIL ngay thay vì nuốt gói -> ứng dụng không bị treo vô hạn
            dnsResp = DnsPacketHelper.buildServFailResponse(parsed.dnsPayload)
            finalReason = "Lỗi kết nối DNS"
        }

        writeToTun(output, DnsPacketHelper.wrapUdpResponse(parsed, dnsResp))
        VpnState.record(parsed.domain, false, finalReason)
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        val net = activeUnderlyingNetwork ?: return null
        val candidates = ArrayList<Pair<InetAddress, Int>>(3)
        val seen = HashSet<String>(4)

        fun addCandidate(addr: InetAddress, timeoutMs: Int) {
            if (candidates.size >= 3) return
            if (addr is Inet6Address && !hasIpv6Connectivity) return
            val host = addr.hostAddress ?: return
            if (host == VIRTUAL_DNS_V4 || host == VIRTUAL_DNS_V6 || host == "127.0.0.1" || host == "::1") return
            if (seen.add(host)) {
                candidates.add(addr to timeoutMs)
            }
        }

        // 1. Ưu tiên upstream phản hồi nhanh nhất gần đây (sticky)
        preferredUpstream?.let { addCandidate(it, 750) }

        // 2. DNS của chính mạng Wi-Fi / 4G đang dùng (hỗ trợ cả NAT64/DNS64)
        for (addr in systemDnsServers) {
            addCandidate(addr, 800)
        }

        // 3. Fallback sang 1.1.1.1 / 8.8.8.8 (tối đa tổng 3 ứng viên để không giữ sóng 4G/5G lâu)
        for (addr in PUBLIC_UPSTREAMS) {
            addCandidate(addr, 900)
        }

        for ((addr, timeoutMs) in candidates) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) {
                    socket.close()
                    continue
                }
                try {
                    net.bindSocket(socket)
                } catch (_: Exception) {}
                socket.soTimeout = timeoutMs

                val outPacket = DatagramPacket(query, query.size, addr, 53)
                socket.send(outPacket)

                val recvBuf = ByteArray(2048)
                val inPacket = DatagramPacket(recvBuf, recvBuf.size)
                socket.receive(inPacket)
                if (inPacket.length >= 12) {
                    preferredUpstream = addr
                    return recvBuf.copyOf(inPacket.length)
                }
            } catch (_: Exception) {
                if (preferredUpstream == addr) {
                    preferredUpstream = null
                }
            } finally {
                socket?.close()
            }
        }

        // 4. Fallback cuối cùng: DNS-over-HTTPS (có backoff 30s nếu đang mất sóng để không đốt pin)
        if (System.currentTimeMillis() < dohBackoffUntilMs) return null
        val dohResp = forwardViaDoh(query, net)
        if (dohResp == null) {
            dohBackoffUntilMs = System.currentTimeMillis() + 30_000L
        }
        return dohResp
    }

    private fun forwardViaDoh(query: ByteArray, net: Network): ByteArray? {
        val dohUrl = DOH_URLS.firstOrNull() ?: return null
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(dohUrl)
            conn = net.openConnection(url) as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 1500
            conn.readTimeout = 2000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.outputStream.use { it.write(query) }
            if (conn.responseCode == 200) {
                val bytes = conn.inputStream.use { it.readBytes() }
                if (bytes.size >= 12) bytes else null
            } else {
                null
            }
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun refreshUnderlyingNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val networks = cm.allNetworks
        var best: Network? = null
        var bestValidated = false

        for (net in networks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            if (best == null || (validated && !bestValidated)) {
                best = net
                bestValidated = validated
            }
        }

        activeUnderlyingNetwork = best
        if (best != null) {
            updateDnsFromLinkProperties(cm.getLinkProperties(best))
        }
    }

    private fun updateDnsFromLinkProperties(lp: LinkProperties?): Boolean {
        if (lp == null) return false
        hasIpv6Connectivity = lp.linkAddresses.any {
            val addr = it.address
            addr is Inet6Address && !addr.isLinkLocalAddress && !addr.isLoopbackAddress
        }
        val filtered = lp.dnsServers.filter { addr ->
            val host = addr.hostAddress ?: ""
            host.isNotEmpty() && host != VIRTUAL_DNS_V4 && host != VIRTUAL_DNS_V6 &&
                host != "127.0.0.1" && host != "::1"
        }
        if (filtered.isNotEmpty() && filtered != systemDnsServers) {
            systemDnsServers = filtered
            return true
        }
        return false
    }

    private fun registerNetworkMonitor() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        unregisterNetworkMonitor()

        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = activeUnderlyingNetwork
                activeUnderlyingNetwork = network
                try {
                    updateDnsFromLinkProperties(cm.getLinkProperties(network))
                    if (vpnInterface != null) setUnderlyingNetworks(arrayOf(network))
                } catch (_: Exception) {}
                if (prev != network) {
                    preferredUpstream = null
                    dohBackoffUntilMs = 0L
                    VpnState.clearDnsCache()
                }
                evaluateHomeLanState()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                var dnsChanged = false
                if (activeUnderlyingNetwork == null || activeUnderlyingNetwork == network) {
                    activeUnderlyingNetwork = network
                    dnsChanged = updateDnsFromLinkProperties(linkProperties)
                }
                if (dnsChanged) {
                    evaluateHomeLanState()
                }
            }

            override fun onLost(network: Network) {
                if (activeUnderlyingNetwork == network) {
                    refreshUnderlyingNetwork()
                    preferredUpstream = null
                    dohBackoffUntilMs = 0L
                    val next = activeUnderlyingNetwork
                    try {
                        if (vpnInterface != null) {
                            setUnderlyingNetworks(if (next != null) arrayOf(next) else null)
                        }
                    } catch (_: Exception) {}
                    VpnState.clearDnsCache()
                }
                evaluateHomeLanState()
            }
        }
        networkCallback = cb
        try {
            cm.registerNetworkCallback(req, cb)
        } catch (_: Exception) {}
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {}
    }

    private fun stopVpn() {
        val wasRunning = VpnState.isRunning.getAndSet(false)
        VpnState.isHomeLanStandby.set(false)
        lastNotifiedStandby = null
        preferredUpstream = null
        dohBackoffUntilMs = 0L
        unregisterNetworkMonitor()
        synchronized(tunLock) {
            closeTunOnly()
        }
        if (wasRunning) {
            VpnState.notifyChanged()
        }
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {}
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NetShield Chặn Quảng Cáo",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Hiển thị trạng thái bảo vệ DNS cục bộ"
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun updateNotification() {
        val standby = VpnState.isHomeLanStandby.get()
        if (lastNotifiedStandby == standby) return
        lastNotifiedStandby = standby
        try {
            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, buildNotification())
        } catch (_: Exception) {}
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val standby = VpnState.isHomeLanStandby.get()
        val title = if (standby) "NetShield • Mạng nội bộ" else "NetShield đang bảo vệ"
        val text = if (standby) {
            "Đang dùng DNS nội bộ (${BlocklistManager.getHomeDnsIp()}) • Chế độ tiết kiệm pin"
        } else {
            "Đang lọc DNS cục bộ (4G / Wi-Fi ngoài)"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_notif)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }
}
