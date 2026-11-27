package com.netshield.adblock

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

data class FilterSource(
    val id: String,
    val name: String,
    val url: String,
    val defaultEnabled: Boolean
)

object BlocklistManager {
    private const val PREFS = "netshield_prefs"
    private const val KEY_WHITELIST = "whitelist"
    private const val KEY_BLACKLIST = "blacklist"
    private const val KEY_BYPASS_APPS = "bypass_apps"
    private const val KEY_ENABLED_SOURCES = "enabled_sources"
    private const val KEY_AUTO_PAUSE_HOME = "auto_pause_home"
    private const val KEY_HOME_DNS_IP = "home_dns_ip"
    private const val DEFAULT_HOME_DNS_IP = "192.168.1.210"
    private const val BLOCKLIST_FILE = "blocklist.txt"

    val ALL_SOURCES: List<FilterSource> = listOf(
        FilterSource(
            id = "abpvn",
            name = "ABPVN Hosts (Quảng cáo Việt Nam)",
            url = "https://abpvn.com/android/abpvn.txt",
            defaultEnabled = true
        ),
        FilterSource(
            id = "oisd_small",
            name = "OISD Small (Quảng cáo & Tracker)",
            url = "https://small.oisd.nl/domainswild2",
            defaultEnabled = true
        ),
        FilterSource(
            id = "adguard_dns",
            name = "AdGuard DNS Filter (QC & Tracker mạnh)",
            url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            defaultEnabled = true
        ),
        FilterSource(
            id = "urlhaus",
            name = "URLHaus Malware (Mã độc / Virus)",
            url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
            defaultEnabled = true
        ),
        FilterSource(
            id = "phishing_army",
            name = "Phishing Army (Web lừa đảo / Giả mạo)",
            url = "https://phishing.army/download/phishing_army_blocklist.txt",
            defaultEnabled = true
        )
    )

    private val DEFAULT_ENABLED_SOURCE_IDS: Set<String> =
        ALL_SOURCES.filter { it.defaultEnabled }.map { it.id }.toSet()

    // Vùng bảo vệ tuyệt đối — KHÔNG BAO GIỜ bị chặn (Thuế/GDT, HĐĐT, Chữ ký số, Ngân hàng, Thanh toán)
    private val PROTECTED_WHITELIST = setOf(
        // Cơ quan Nhà nước, Thuế (GDT), BHXH, Hải quan, ĐKDN, VNeID
        "gov.vn", "gdt.gov.vn", "thuedientu.gdt.gov.vn", "hoadondientu.gdt.gov.vn",
        "tracuuhoadon.gdt.gov.vn", "vneid.gov.vn", "rootca.gov.vn", "neac.gov.vn",

        // Hóa đơn điện tử (HĐĐT) & Phần mềm Kế toán
        "misa.vn", "misa.com.vn", "meinvoice.vn", "amis.vn",
        "sinvoice.vn", "viettel.vn", "viettel.com.vn",
        "vnpt-invoice.com.vn", "vnpt.vn", "vnpt.com.vn",
        "ehoadon.vn", "bkav.com.vn", "bkav.vn", "ivan.vn",
        "easyinvoice.vn", "easyinvoice.com.vn", "softdreams.vn",
        "minvoice.vn", "minvoice.com.vn", "cyberbill.vn", "cybers.vn", "cyberlotus.com",
        "fast.com.vn", "einvoice.vn", "thaison.vn", "thaison.com.vn",
        "efy.com.vn", "efy.vn", "ihoadon.vn", "fpt.com.vn",
        "mobifoneinvoice.vn", "hilo.com.vn", "matbao.in", "matbao.net",
        "vietinvoice.vn", "newinvoice.vn", "smartvas.vn", "vnpayinvoice.vn",
        "wininvoice.vn", "hoadonviet.vn", "xcyber.vn", "tax24.com.vn",
        "ts24.com.vn", "ts24.vn", "nhantokhai.vn", "tvan.vn", "esoc.vn",
        "kiotviet.vn", "sapo.vn", "haravan.com", "nhanh.vn",

        // Chữ ký số (CA), OCSP/CRL & Timestamp (TSA)
        "viettel-ca.vn", "vnpt-ca.vn", "bkavca.vn", "bkav-ca.vn",
        "fpt-ca.vn", "newca.vn", "fastca.vn", "vinca.vn", "efyca.vn", "easyca.vn",
        "nacencomm.vn", "ca2.vn", "smartsign.com.vn", "vina-ca.vn", "intrustca.vn",
        "safe-ca.com", "trustca.vn", "hilo-ca.vn", "ica.com.vn", "oneca.vn",
        "nca.vn", "mobifoneca.vn", "digicert.com", "sectigo.com", "globalsign.com",
        "entrust.net", "letsencrypt.org",

        // Ngân hàng Việt Nam & Cổng thanh toán (NAPAS / VNPAY / VietQR)
        "vietcombank.com.vn", "techcombank.com.vn", "techcombank.com",
        "mbbank.com.vn", "mb.com.vn", "bidv.com.vn", "vietinbank.vn",
        "agribank.com.vn", "acb.com.vn", "vpbank.com.vn", "tpb.vn", "tpbank.vn",
        "sacombank.com.vn", "sacombank.vn", "hdbank.com.vn", "vib.com.vn",
        "shb.com.vn", "seabank.com.vn", "ocb.com.vn", "msb.com.vn",
        "eximbank.com.vn", "lpbank.com.vn", "lienvietpostbank.com.vn",
        "namabank.com.vn", "abbank.vn", "bacabank.com.vn",
        "vietcapitalbank.com.vn", "bvbank.net.vn", "ncb-bank.vn",
        "pvcombank.com.vn", "scb.com.vn", "vietabank.com.vn", "kienlongbank.com",
        "pgbank.com.vn", "saigonbank.com.vn", "baovietbank.vn", "co-opbank.com.vn",
        "shinhan.com.vn", "woori.com.vn", "hsbc.com.vn", "sc.com", "uob.com.vn",
        "publicbank.com.vn", "cimb.com.vn", "timo.vn", "cake.vn", "tnex.com.vn",
        "napas.com.vn", "vnpay.vn", "vnpayment.vn", "vietqr.io", "vietqr.net",
        "momo.vn", "zalopay.vn", "onepay.vn",

        // Kết nối hệ thống Google an toàn
        "remotedesktop.google.com", "chromoting-host.talkgadget.google.com",
        "accounts.google.com", "connectivitycheck.gstatic.com",
        "clients3.google.com", "mtalk.google.com"
    )

    private val DEFAULT_WHITELIST = PROTECTED_WHITELIST

    // Danh sách hạt nhân có sẵn để chặn ngay khi vừa cài app (đặc biệt Admicro/Kenh14/VN)
    private val SEED_ADS = setOf(
        "admicro.vn", "amcdn.vn", "admicro.vcmedia.com", "admicro1.vcmedia.vn",
        "adi.vcmedia.vn", "ads.hosting.vcmedia.vn", "logg4u.cnnd.vn", "v20.cnnd.vn",
        "eclick.vn", "adtimaserver.vn", "ad.zing.vn", "adnetwork.vn",
        "ambientdsp.com", "urekamedia.com", "ants.vn", "novanet.vn",
        "adx.vn", "adtrue.com", "yomedia.vn", "use-application-dns.net",
        "quangcao.24h.com.vn", "ad-hn.24hstatic.com", "ad-hcm.24hstatic.com",
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "google-analytics.com", "googletagmanager.com", "adservice.google.com",
        "ads.facebook.com", "an.facebook.com", "ads.tiktok.com",
        "taboola.com", "outbrain.com", "criteo.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "adnxs.com", "mgid.com",
        "popads.net", "propellerads.com", "vdo.ai", "omnitagjs.com"
    )

    private val DOMAIN_REGEX = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

    @Volatile
    private var remoteDomains: Set<String> = SEED_ADS

    @Volatile
    private var whitelist: Set<String> = DEFAULT_WHITELIST

    @Volatile
    private var blacklist: Set<String> = emptySet()

    @Volatile
    private var bypassApps: Set<String> = emptySet()

    @Volatile
    private var enabledSources: Set<String> = DEFAULT_ENABLED_SOURCE_IDS

    @Volatile
    private var autoPauseHomeLan: Boolean = true

    @Volatile
    private var homeDnsIp: String = DEFAULT_HOME_DNS_IP

    @Volatile
    private var initialized = false

    fun init(context: Context) {
        if (initialized) return
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        whitelist = prefs.getStringSet(KEY_WHITELIST, null)?.toSet() ?: DEFAULT_WHITELIST
        blacklist = prefs.getStringSet(KEY_BLACKLIST, null)?.toSet() ?: emptySet()
        bypassApps = prefs.getStringSet(KEY_BYPASS_APPS, null)?.toSet() ?: emptySet()
        enabledSources = prefs.getStringSet(KEY_ENABLED_SOURCES, null)?.toSet() ?: DEFAULT_ENABLED_SOURCE_IDS
        autoPauseHomeLan = prefs.getBoolean(KEY_AUTO_PAUSE_HOME, true)
        homeDnsIp = prefs.getString(KEY_HOME_DNS_IP, DEFAULT_HOME_DNS_IP)?.trim().orEmpty()
            .ifEmpty { DEFAULT_HOME_DNS_IP }

        val file = File(context.filesDir, BLOCKLIST_FILE)
        if (file.exists()) {
            val loaded = HashSet<String>(250000)
            loaded.addAll(SEED_ADS)
            file.forEachLine { line ->
                val d = line.trim()
                if (d.isNotEmpty()) loaded.add(d)
            }
            if (loaded.isNotEmpty()) {
                remoteDomains = loaded
            }
        }
        initialized = true
    }

    fun totalRuleCount(): Int = remoteDomains.size + blacklist.size

    fun getWhitelist(): Set<String> = whitelist
    fun getBlacklist(): Set<String> = blacklist
    fun getBypassApps(): Set<String> = bypassApps
    fun getEnabledSources(): Set<String> = enabledSources
    fun isAutoPauseHomeLan(): Boolean = autoPauseHomeLan
    fun getHomeDnsIp(): String = homeDnsIp

    fun setHomeLanConfig(context: Context, enabled: Boolean, ip: String) {
        autoPauseHomeLan = enabled
        homeDnsIp = ip.trim().ifEmpty { DEFAULT_HOME_DNS_IP }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_AUTO_PAUSE_HOME, autoPauseHomeLan)
            .putString(KEY_HOME_DNS_IP, homeDnsIp)
            .apply()
    }

    fun setEnabledSources(context: Context, ids: Set<String>) {
        enabledSources = ids
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_ENABLED_SOURCES, enabledSources)
            .apply()
    }

    fun addWhitelist(context: Context, raw: String) {
        val d = normalize(raw)
        if (d.isEmpty()) return
        whitelist = whitelist + d
        blacklist = blacklist - d
        saveSets(context)
    }

    fun removeWhitelist(context: Context, raw: String) {
        whitelist = whitelist - normalize(raw)
        saveSets(context)
    }

    fun addBlacklist(context: Context, raw: String) {
        val d = normalize(raw)
        if (d.isEmpty()) return
        blacklist = blacklist + d
        whitelist = whitelist - d
        saveSets(context)
    }

    fun removeBlacklist(context: Context, raw: String) {
        blacklist = blacklist - normalize(raw)
        saveSets(context)
    }

    fun setBypassApps(context: Context, pkgs: Set<String>) {
        bypassApps = pkgs
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_BYPASS_APPS, bypassApps)
            .apply()
    }

    private fun saveSets(context: Context) {
        VpnState.clearDnsCache()
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_WHITELIST, whitelist)
            .putStringSet(KEY_BLACKLIST, blacklist)
            .apply()
    }

    fun normalize(input: String): String {
        return input.trim()
            .lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .trim('.')
    }

    /**
     * Kiểm tra domain theo thứ tự ưu tiên: Whitelist -> Blacklist tùy chỉnh -> Blocklist tự động
     */
    fun shouldBlock(rawDomain: String): Pair<Boolean, String> {
        val domain = normalize(rawDomain)
        if (domain.isEmpty()) return false to "invalid"

        val parts = domain.split('.')
        if (parts.size < 2) return false to "local"

        val suffixes = ArrayList<String>(parts.size - 1)
        for (i in 0 until parts.size - 1) {
            suffixes.add(parts.subList(i, parts.size).joinToString("."))
        }

        for (s in suffixes) {
            if (PROTECTED_WHITELIST.contains(s)) return false to "Bảo vệ hệ thống"
        }
        for (s in suffixes) {
            if (whitelist.contains(s)) return false to "Whitelist"
        }
        for (s in suffixes) {
            if (blacklist.contains(s)) return true to "Chặn tay"
        }
        for (s in suffixes) {
            if (remoteDomains.contains(s)) return true to "Bộ lọc QC"
        }
        return false to "Cho phép"
    }

    fun updateRemoteLists(context: Context): Int {
        val activeSources = ALL_SOURCES.filter { enabledSources.contains(it.id) }
        val merged = HashSet<String>(350000)
        val exceptions = HashSet<String>(512)
        merged.addAll(SEED_ADS)

        var anySucceeded = false
        for (source in activeSources) {
            try {
                val conn = URL(source.url).openConnection() as HttpURLConnection
                conn.connectTimeout = 15000
                conn.readTimeout = 25000
                conn.setRequestProperty("User-Agent", "NetShield-Android/1.0.5")
                if (conn.responseCode == 200) {
                    BufferedReader(InputStreamReader(conn.inputStream)).use { reader ->
                        var line = reader.readLine()
                        while (line != null) {
                            parseLine(line, merged, exceptions)
                            line = reader.readLine()
                        }
                    }
                    anySucceeded = true
                }
                conn.disconnect()
            } catch (_: Exception) {
                // Giữ các nguồn tải thành công
            }
        }

        // Áp dụng ngoại lệ (@@||domain^) từ bộ lọc (ví dụ AdGuard) để giảm chặn nhầm
        if (exceptions.isNotEmpty()) {
            merged.removeAll(exceptions)
            merged.addAll(SEED_ADS)
        }

        // Cập nhật nếu người dùng tắt hết nguồn remote HOẶC tải thành công ít nhất 1 nguồn
        if (activeSources.isEmpty() || anySucceeded) {
            val tmpFile = File(context.filesDir, "$BLOCKLIST_FILE.tmp")
            val destFile = File(context.filesDir, BLOCKLIST_FILE)
            tmpFile.bufferedWriter().use { out ->
                for (d in merged) {
                    out.write(d)
                    out.newLine()
                }
            }
            tmpFile.renameTo(destFile)
            remoteDomains = merged
            VpnState.clearDnsCache()
        }
        return totalRuleCount()
    }

    private fun parseLine(raw: String, out: MutableSet<String>, exceptions: MutableSet<String>) {
        var line = raw.trim()
        if (line.isEmpty() || line.startsWith("#") || line.startsWith("!") || line.startsWith("[")) return
        val hash = line.indexOf('#')
        if (hash >= 0) line = line.substring(0, hash).trim()
        if (line.isEmpty()) return

        if (line.startsWith("@@||")) {
            val d = line.substring(4).substringBefore("^").substringBefore("/").trim().lowercase()
            if (d.isNotEmpty() && DOMAIN_REGEX.matches(d)) exceptions.add(d)
            return
        }
        if (line.startsWith("@@")) return

        if (line.startsWith("||")) {
            if (line.contains('$') && !line.endsWith("\$important")) return
            val d = line.substring(2).substringBefore("^").substringBefore("/").trim().lowercase()
            if (d.isNotEmpty() && DOMAIN_REGEX.matches(d)) out.add(d)
            return
        }

        val tokens = line.split(Regex("\\s+"))
        if (tokens.size >= 2 && (tokens[0] == "0.0.0.0" || tokens[0] == "127.0.0.1")) {
            val d = normalize(tokens[1])
            if (d != "localhost" && DOMAIN_REGEX.matches(d)) out.add(d)
        } else if (tokens.size == 1) {
            val d = normalize(tokens[0])
            if (d != "localhost" && DOMAIN_REGEX.matches(d)) out.add(d)
        }
    }
}
