package com.netshield.adblock

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private lateinit var statusPill: LinearLayout
    private lateinit var viewStatusDot: View
    private lateinit var tvStatus: TextView
    private lateinit var tvTotal: TextView
    private lateinit var tvBlocked: TextView
    private lateinit var tvRuleCount: TextView
    private lateinit var tvEmptyLogs: TextView
    private lateinit var btnToggleVpn: MaterialButton
    private lateinit var btnUpdateLists: MaterialButton
    private lateinit var btnManageLists: MaterialButton
    private lateinit var btnBypassApps: MaterialButton
    private lateinit var cardBatteryOpt: View
    private lateinit var btnBatteryOpt: TextView
    private lateinit var rvLogs: RecyclerView
    private lateinit var logAdapter: LogAdapter

    private val uiHandler = Handler(Looper.getMainLooper())
    private var refreshScheduled = false
    private val refreshRunnable = Runnable {
        refreshScheduled = false
        if (!isFinishing && !isDestroyed) {
            refreshUi()
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "Cần cấp quyền VPN cục bộ để bật lọc DNS", Toast.LENGTH_LONG).show()
        }
    }

    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Tiếp tục bình thường */ }

    private val stateListener: () -> Unit = {
        uiHandler.post {
            if (!refreshScheduled) {
                refreshScheduled = true
                uiHandler.postDelayed(refreshRunnable, 250L)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        BlocklistManager.init(this)
        setContentView(R.layout.activity_main)

        val isNightMode =
            (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = !isNightMode
            isAppearanceLightNavigationBars = !isNightMode
        }

        val rootContainer: View = findViewById(R.id.rootContainer)
        val basePaddingLeft = rootContainer.paddingLeft
        val basePaddingTop = rootContainer.paddingTop
        val basePaddingRight = rootContainer.paddingRight
        val basePaddingBottom = rootContainer.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(rootContainer) { view, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(
                basePaddingLeft + insets.left,
                basePaddingTop + insets.top,
                basePaddingRight + insets.right,
                basePaddingBottom + insets.bottom
            )
            windowInsets
        }
        ViewCompat.requestApplyInsets(rootContainer)

        statusPill = findViewById(R.id.statusPill)
        viewStatusDot = findViewById(R.id.viewStatusDot)
        tvStatus = findViewById(R.id.tvStatus)
        tvTotal = findViewById(R.id.tvTotal)
        tvBlocked = findViewById(R.id.tvBlocked)
        tvRuleCount = findViewById(R.id.tvRuleCount)
        tvEmptyLogs = findViewById(R.id.tvEmptyLogs)
        btnToggleVpn = findViewById(R.id.btnToggleVpn)
        btnUpdateLists = findViewById(R.id.btnUpdateLists)
        btnManageLists = findViewById(R.id.btnManageLists)
        btnBypassApps = findViewById(R.id.btnBypassApps)
        cardBatteryOpt = findViewById(R.id.cardBatteryOpt)
        btnBatteryOpt = findViewById(R.id.btnBatteryOpt)
        rvLogs = findViewById(R.id.rvLogs)

        logAdapter = LogAdapter { item -> showQuickDomainAction(item) }
        rvLogs.layoutManager = LinearLayoutManager(this)
        rvLogs.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))
        rvLogs.adapter = logAdapter

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        btnToggleVpn.setOnClickListener {
            if (VpnState.isRunning.get()) {
                val stopIntent = Intent(this, DnsVpnService::class.java).apply {
                    action = DnsVpnService.ACTION_STOP
                }
                startService(stopIntent)
            } else {
                val prep = VpnService.prepare(this)
                if (prep != null) {
                    vpnPermissionLauncher.launch(prep)
                } else {
                    startVpnService()
                }
            }
        }

        btnUpdateLists.setOnClickListener { showFilterSourcesDialog() }
        btnManageLists.setOnClickListener { showManageListsDialog() }
        btnBypassApps.setOnClickListener { showBypassAppsDialog() }
        btnBatteryOpt.setOnClickListener { requestBatteryOptimizationExemption() }
        statusPill.setOnClickListener { showHomeLanDialog() }

        VpnState.addListener(stateListener)
        refreshUi()
        updateBatteryButtonVisibility()

        if (BlocklistManager.totalRuleCount() < 1000) {
            updateBlocklists()
        }
    }

    override fun onResume() {
        super.onResume()
        updateBatteryButtonVisibility()
        refreshUi()
    }

    override fun onDestroy() {
        VpnState.removeListener(stateListener)
        uiHandler.removeCallbacks(refreshRunnable)
        scope.cancel()
        super.onDestroy()
    }

    private fun updateBatteryButtonVisibility() {
        val pm = getSystemService(PowerManager::class.java)
        val ignoring = pm?.isIgnoringBatteryOptimizations(packageName) == true
        cardBatteryOpt.visibility = if (ignoring) View.GONE else View.VISIBLE
    }

    @SuppressLint("BatteryLife")
    private fun requestBatteryOptimizationExemption() {
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (_: Exception) {
                Toast.makeText(
                    this,
                    "Hãy vào Cài đặt -> Pin -> NetShield -> Không giới hạn",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun refreshUi() {
        val running = VpnState.isRunning.get()
        val standby = VpnState.isHomeLanStandby.get()
        if (running) {
            if (standby) {
                statusPill.setBackgroundResource(R.drawable.bg_status_inactive)
                val inactiveFg = ContextCompat.getColor(this, R.color.ns_status_inactive_fg)
                tvStatus.text = "Mạng nội bộ (tự nghỉ)"
                tvStatus.setTextColor(inactiveFg)
                viewStatusDot.backgroundTintList = ColorStateList.valueOf(inactiveFg)
            } else {
                statusPill.setBackgroundResource(R.drawable.bg_status_active)
                val activeFg = ContextCompat.getColor(this, R.color.ns_status_active_fg)
                tvStatus.text = "Đang bảo vệ"
                tvStatus.setTextColor(activeFg)
                viewStatusDot.backgroundTintList = ColorStateList.valueOf(activeFg)
            }

            btnToggleVpn.text = "Tạm dừng bảo vệ"
            btnToggleVpn.backgroundTintList =
                ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ns_btn_stop_bg))
            btnToggleVpn.setTextColor(ContextCompat.getColor(this, R.color.ns_btn_stop_fg))
            btnToggleVpn.strokeWidth = (resources.displayMetrics.density).toInt().coerceAtLeast(1)
            btnToggleVpn.strokeColor =
                ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ns_btn_stop_stroke))
        } else {
            statusPill.setBackgroundResource(R.drawable.bg_status_inactive)
            val inactiveFg = ContextCompat.getColor(this, R.color.ns_status_inactive_fg)
            tvStatus.text = "Đang tắt"
            tvStatus.setTextColor(inactiveFg)
            viewStatusDot.backgroundTintList = ColorStateList.valueOf(inactiveFg)

            btnToggleVpn.text = "Bật bảo vệ"
            btnToggleVpn.backgroundTintList =
                ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ns_btn_primary_bg))
            btnToggleVpn.setTextColor(ContextCompat.getColor(this, R.color.ns_btn_primary_fg))
            btnToggleVpn.strokeWidth = 0
        }

        tvTotal.text = String.format("%,d", VpnState.totalQueries.get())
        tvBlocked.text = String.format("%,d", VpnState.blockedQueries.get())
        tvRuleCount.text = String.format("%,d", BlocklistManager.totalRuleCount())

        val snapshot = VpnState.getLogsSnapshot()
        logAdapter.submit(snapshot)
        tvEmptyLogs.visibility = if (snapshot.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun showFilterSourcesDialog() {
        NetShieldSheets.showFilterSources(this) {
            updateBlocklists()
        }
    }

    private fun updateBlocklists() {
        btnUpdateLists.isEnabled = false
        btnUpdateLists.text = "Đang tải..."
        scope.launch {
            val count = withContext(Dispatchers.IO) {
                BlocklistManager.updateRemoteLists(this@MainActivity)
            }
            btnUpdateLists.isEnabled = true
            btnUpdateLists.text = "Bộ lọc"
            refreshUi()
            Toast.makeText(
                this@MainActivity,
                "Đã cập nhật %,d tên miền (%d nguồn bật)".format(count, BlocklistManager.getEnabledSources().size),
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun showQuickDomainAction(item: DnsLogItem) {
        NetShieldSheets.showQuickDomainAction(this, item) {
            refreshUi()
        }
    }

    private fun showManageListsDialog() {
        NetShieldSheets.showManageLists(this) {
            refreshUi()
        }
    }

    private fun showBypassAppsDialog() {
        NetShieldSheets.showBypassApps(this, scope, packageName)
    }

    private fun showHomeLanDialog() {
        val input = android.widget.EditText(this).apply {
            hint = "IP máy chủ DNS nội bộ (VD: 192.168.1.210)"
            setText(BlocklistManager.getHomeDnsIp())
        }
        val currentlyEnabled = BlocklistManager.isAutoPauseHomeLan()
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Tự nhận dạng mạng nội bộ")
            .setMessage(
                "Khi điện thoại kết nối Wi-Fi có DNS nội bộ dưới đây, NetShield sẽ tự tạm nghỉ VPN để tiết kiệm pin và tự bật lại ngay khi ra ngoài dùng 4G hoặc Wi-Fi khác."
            )
            .setView(input)
            .setPositiveButton("Bật & Lưu") { _, _ ->
                BlocklistManager.setHomeLanConfig(this, true, input.text.toString())
                triggerReevaluateIfRunning()
                Toast.makeText(this, "Đã bật tự nghỉ cho DNS ${BlocklistManager.getHomeDnsIp()}", Toast.LENGTH_SHORT).show()
            }
            .setNeutralButton(if (currentlyEnabled) "Tắt tính năng" else "Đóng") { _, _ ->
                if (currentlyEnabled) {
                    BlocklistManager.setHomeLanConfig(this, false, input.text.toString())
                    triggerReevaluateIfRunning()
                    Toast.makeText(this, "Đã tắt chế độ tự nghỉ mạng nội bộ", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun triggerReevaluateIfRunning() {
        if (VpnState.isRunning.get()) {
            val intent = Intent(this, DnsVpnService::class.java).apply {
                action = DnsVpnService.ACTION_REEVALUATE
            }
            startService(intent)
        }
    }
}

class LogAdapter(
    private val onClick: (DnsLogItem) -> Unit
) : RecyclerView.Adapter<LogAdapter.VH>() {

    private var items: List<DnsLogItem> = emptyList()

    fun submit(newItems: List<DnsLogItem>) {
        items = newItems
        notifyDataSetChanged()
    }

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvDomain: TextView = view.findViewById(R.id.tvDomain)
        val tvMeta: TextView = view.findViewById(R.id.tvMeta)
        val tvBadge: TextView = view.findViewById(R.id.tvBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        val ctx = holder.itemView.context
        holder.tvDomain.text = item.domain
        holder.tvMeta.text = "${item.time} • ${item.reason}"
        if (item.blocked) {
            holder.tvBadge.text = "CHẶN"
            holder.tvBadge.setBackgroundResource(R.drawable.bg_badge_blocked)
            holder.tvBadge.setTextColor(ContextCompat.getColor(ctx, R.color.ns_badge_blocked_fg))
        } else {
            holder.tvBadge.text = "CHO PHÉP"
            holder.tvBadge.setBackgroundResource(R.drawable.bg_badge_allowed)
            holder.tvBadge.setTextColor(ContextCompat.getColor(ctx, R.color.ns_badge_allowed_fg))
        }
        holder.itemView.setOnClickListener { onClick(item) }
    }

    override fun getItemCount(): Int = items.size
}
