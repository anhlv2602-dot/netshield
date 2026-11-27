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
import java.net.InetAddress
import java.net.URL
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
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

data class CachedDns(
    val response: ByteArray,
    val expiresAtMs: Long
)

object VpnState {
    val isRunning = AtomicBoolean(false)
    val totalQueries = AtomicInteger(0)
    val blockedQueries = AtomicInteger(0)

    private val logLock = Any()
    private val logs = ArrayDeque<DnsLogItem>(260)
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    private const val CACHE_TTL_MS = 60_000L
    private const val CACHE_MAX_SIZE = 1000
    private val dnsCache = ConcurrentHashMap<String, CachedDns>()

    fun addListener(cb: () -> Unit) {
        listeners.add(cb)
    }

    fun removeListener(cb: () -> Unit) {
        listeners.remove(cb)
    }

    fun notifyChanged() {
        for (l in listeners) {
            try {
                l()
            } catch (_: Exception) {}
        }
    }

    fun getLogsSnapshot(): List<DnsLogItem> = synchronized(logLock) {
        logs.toList()
    }

    fun record(domain: String, blocked: Boolean, reason: String) {
        totalQueries.incrementAndGet()
        if (blocked) blockedQueries.incrementAndGet()
        synchronized(logLock) {
            val nowStr = timeFmt.format(Date())
            logs.addFirst(DnsLogItem(domain, blocked, reason, nowStr))
            while (logs.size > 250) {
                logs.removeLast()
            }
        }
        notifyChanged()
    }

    fun getCachedDns(key: String, queryTxId0: Byte, queryTxId1: Byte): ByteArray? {
        val entry = dnsCache[key] ?: return null
        if (System.currentTimeMillis() > entry.expiresAtMs) {
            dnsCache.remove(key)
            return null
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
        // Chỉ cache phản hồi NOERROR (RCODE == 0)
        val rcode = response[3].toInt() and 0x0F
        if (rcode != 0) return
        if (dnsCache.size >= CACHE_MAX_SIZE) {
            dnsCache.clear()
        }
        dnsCache[key] = CachedDns(response.copyOf(), System.currentTimeMillis() + CACHE_TTL_MS)
    }

    fun clearDnsCache() {
        dnsCache.clear()
    }
}

class DnsVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.netshield.adblock.START"
        const val ACTION_STOP = "com.netshield.adblock.STOP"
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

    @Volatile
    private var activeUnderlyingNetwork: Network? = null

    @Volatile
    private var systemDnsServers: List<InetAddress> = emptyList()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn() {
        BlocklistManager.init(this)
        if (VpnState.isRunning.get() && vpnInterface != null) return

        createNotificationChannel()
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(), fgsType)

        // Quét mạng vật lý & DNS hệ thống (4G/Wi-Fi) TRƯỚC khi dựng TUN
        refreshUnderlyingNetwork()
        registerNetworkMonitor()

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

        // Luôn loại trừ chính app NetShield để không tự lặp (cả UDP và DoH fallback)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        // Loại trừ các ứng dụng người dùng chọn Bypass
        for (pkg in BlocklistManager.getBypassApps()) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: Exception) {}
        }

        val pfd = try {
            builder.establish()
        } catch (_: Exception) {
            null
        } ?: run {
            unregisterNetworkMonitor()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val underlying = activeUnderlyingNetwork
        try {
            setUnderlyingNetworks(if (underlying != null) arrayOf(underlying) else null)
        } catch (_: Exception) {}

        vpnInterface = pfd
        val pool = ThreadPoolExecutor(
            8,
            64,
            30L,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(256),
            ThreadPoolExecutor.DiscardOldestPolicy()
        )
        executor = pool
        VpnState.clearDnsCache()
        VpnState.isRunning.set(true)
        VpnState.notifyChanged()

        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)

        readerThread = Thread({
            val buf = ByteArray(32767)
            var consecutiveErrors = 0
            try {
                while (VpnState.isRunning.get() && !Thread.currentThread().isInterrupted) {
                    val len = try {
                        val n = input.read(buf)
                        consecutiveErrors = 0
                        n
                    } catch (_: Exception) {
                        if (!VpnState.isRunning.get() || Thread.currentThread().isInterrupted) break
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

                    val packetCopy = buf.copyOf(len)
                    try {
                        pool.execute {
                            try {
                                handlePacket(packetCopy, len, output)
                            } catch (_: Exception) {}
                        }
                    } catch (_: RejectedExecutionException) {
                        // Service đang dừng
                        break
                    }
                }
            } finally {
                // Nếu luồng đọc TUN dừng ngoài ý muốn, đóng VPN sạch để không làm kẹt mạng máy
                if (VpnState.isRunning.get()) {
                    stopVpn()
                }
            }
        }, "NetShield-TUN-Reader").apply { start() }
    }

    private fun handlePacket(packet: ByteArray, length: Int, output: FileOutputStream) {
        val parsed = DnsPacketHelper.parseUdpDns(packet, length) ?: return
        val (blocked, reason) = BlocklistManager.shouldBlock(parsed.domain)

        val dnsResp: ByteArray
        var finalReason = reason

        if (blocked) {
            dnsResp = DnsPacketHelper.buildNxDomainResponse(parsed.dnsPayload)
        } else {
            val cacheKey = "${parsed.domain}:${parsed.qType}"
            val cached = if (parsed.dnsPayload.size >= 2) {
                VpnState.getCachedDns(cacheKey, parsed.dnsPayload[0], parsed.dnsPayload[1])
            } else {
                null
            }

            if (cached != null) {
                dnsResp = cached
                finalReason = "Cho phép (Cache)"
            } else {
                val upstreamResp = forwardToUpstream(parsed.dnsPayload)
                if (upstreamResp != null) {
                    VpnState.putCachedDns(cacheKey, upstreamResp)
                    dnsResp = upstreamResp
                } else {
                    // Trả SERVFAIL ngay thay vì nuốt gói -> ứng dụng không bị treo vô hạn
                    dnsResp = DnsPacketHelper.buildServFailResponse(parsed.dnsPayload)
                    finalReason = "Lỗi kết nối DNS"
                }
            }
        }

        VpnState.record(parsed.domain, blocked, finalReason)

        val wrapped = DnsPacketHelper.wrapUdpResponse(parsed, dnsResp)
        synchronized(writeLock) {
            try {
                output.write(wrapped)
            } catch (_: Exception) {}
        }
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        val candidates = ArrayList<Pair<InetAddress, Int>>(6)
        val seen = HashSet<String>()

        // 1. Ưu tiên DNS của chính mạng Wi-Fi / 4G đang dùng (nhanh nhất, hỗ trợ cả NAT64/DNS64)
        for (addr in systemDnsServers) {
            val host = addr.hostAddress ?: continue
            if (host == VIRTUAL_DNS_V4 || host == VIRTUAL_DNS_V6 || host == "127.0.0.1" || host == "::1") continue
            if (seen.add(host)) {
                candidates.add(addr to 900)
            }
        }

        // 2. Fallback sang 1.1.1.1, 8.8.8.8 và 2606:4700:4700::1111
        for (addr in PUBLIC_UPSTREAMS) {
            val host = addr.hostAddress ?: continue
            if (seen.add(host)) {
                candidates.add(addr to 1200)
            }
        }

        val net = activeUnderlyingNetwork
        for ((addr, timeoutMs) in candidates) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) {
                    socket.close()
                    continue
                }
                if (net != null) {
                    try {
                        net.bindSocket(socket)
                    } catch (_: Exception) {}
                }
                socket.soTimeout = timeoutMs

                val outPacket = DatagramPacket(query, query.size, addr, 53)
                socket.send(outPacket)

                val recvBuf = ByteArray(4096)
                val inPacket = DatagramPacket(recvBuf, recvBuf.size)
                socket.receive(inPacket)
                if (inPacket.length >= 12) {
                    return recvBuf.copyOf(inPacket.length)
                }
            } catch (_: Exception) {
                // Thử upstream tiếp theo
            } finally {
                socket?.close()
            }
        }

        // 3. Fallback cuối cùng: DNS-over-HTTPS (nếu nhà mạng 4G chặn cổng UDP 53)
        return forwardViaDoh(query)
    }

    private fun forwardViaDoh(query: ByteArray): ByteArray? {
        for (dohUrl in DOH_URLS) {
            var conn: HttpURLConnection? = null
            try {
                val url = URL(dohUrl)
                val net = activeUnderlyingNetwork
                conn = (if (net != null) net.openConnection(url) else url.openConnection()) as HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 2000
                conn.readTimeout = 2500
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/dns-message")
                conn.setRequestProperty("Accept", "application/dns-message")
                conn.outputStream.use { it.write(query) }
                if (conn.responseCode == 200) {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    if (bytes.size >= 12) return bytes
                }
            } catch (_: Exception) {
                // Thử DoH tiếp theo
            } finally {
                conn?.disconnect()
            }
        }
        return null
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

    private fun updateDnsFromLinkProperties(lp: LinkProperties?) {
        if (lp == null) return
        val filtered = lp.dnsServers.filter { addr ->
            val host = addr.hostAddress ?: ""
            host.isNotEmpty() && host != VIRTUAL_DNS_V4 && host != VIRTUAL_DNS_V6 &&
                host != "127.0.0.1" && host != "::1"
        }
        if (filtered.isNotEmpty()) {
            systemDnsServers = filtered
        }
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
                activeUnderlyingNetwork = network
                try {
                    updateDnsFromLinkProperties(cm.getLinkProperties(network))
                    setUnderlyingNetworks(arrayOf(network))
                } catch (_: Exception) {}
                VpnState.clearDnsCache()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (activeUnderlyingNetwork == null || activeUnderlyingNetwork == network) {
                    activeUnderlyingNetwork = network
                    updateDnsFromLinkProperties(linkProperties)
                }
            }

            override fun onLost(network: Network) {
                if (activeUnderlyingNetwork == network) {
                    refreshUnderlyingNetwork()
                    val next = activeUnderlyingNetwork
                    try {
                        setUnderlyingNetworks(if (next != null) arrayOf(next) else null)
                    } catch (_: Exception) {}
                    VpnState.clearDnsCache()
                }
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
        unregisterNetworkMonitor()
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

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_notif)
            .setContentTitle("NetShield đang bảo vệ")
            .setContentText("Lọc quảng cáo DNS cục bộ (IPv4 & IPv6 • Wi-Fi/4G)")
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }
}
