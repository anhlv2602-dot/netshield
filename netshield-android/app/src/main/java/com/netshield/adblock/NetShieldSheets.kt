package com.netshield.adblock

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.drawable.Drawable
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object NetShieldSheets {

    private fun createSheet(context: Context, layoutRes: Int): Pair<BottomSheetDialog, View> {
        val dialog = BottomSheetDialog(context, R.style.Theme_NetShield_BottomSheet)
        val view = LayoutInflater.from(context).inflate(layoutRes, null)
        dialog.setContentView(view)
        dialog.setOnShowListener {
            val bottomSheet = dialog.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            if (bottomSheet != null) {
                bottomSheet.setBackgroundResource(android.R.color.transparent)
                val behavior = BottomSheetBehavior.from(bottomSheet)
                behavior.state = BottomSheetBehavior.STATE_EXPANDED
                behavior.skipCollapsed = true
            }
        }
        return dialog to view
    }

    internal fun applySwitchStyle(ctx: Context, sw: SwitchMaterial) {
        val states = arrayOf(
            intArrayOf(android.R.attr.state_checked),
            intArrayOf(-android.R.attr.state_checked)
        )
        val thumbColors = intArrayOf(
            ContextCompat.getColor(ctx, R.color.ns_accent),
            ContextCompat.getColor(ctx, R.color.ns_switch_thumb)
        )
        val trackColors = intArrayOf(
            ContextCompat.getColor(ctx, R.color.ns_accent_track),
            ContextCompat.getColor(ctx, R.color.ns_switch_track_off)
        )
        sw.thumbTintList = ColorStateList(states, thumbColors)
        sw.trackTintList = ColorStateList(states, trackColors)
    }

    fun showFilterSources(
        context: Context,
        onSaved: () -> Unit
    ) {
        val (dialog, view) = createSheet(context, R.layout.sheet_filter_sources)
        val sources = BlocklistManager.ALL_SOURCES
        val selected = BlocklistManager.getEnabledSources().toMutableSet()

        val tvBadge: TextView = view.findViewById(R.id.tvFilterCountBadge)
        val rv: RecyclerView = view.findViewById(R.id.rvFilterSources)
        val btnClose: MaterialButton = view.findViewById(R.id.btnFilterClose)
        val btnSave: MaterialButton = view.findViewById(R.id.btnFilterSave)

        fun updateBadge() {
            val count = selected.size
            tvBadge.text = "$count/${sources.size} bật"
            if (count > 0) {
                tvBadge.setBackgroundResource(R.drawable.bg_status_active)
                tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_status_active_fg))
            } else {
                tvBadge.setBackgroundResource(R.drawable.bg_status_inactive)
                tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_status_inactive_fg))
            }
        }

        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = FilterSourceAdapter(sources, selected) {
            updateBadge()
        }
        updateBadge()

        btnClose.setOnClickListener { dialog.dismiss() }
        btnSave.setOnClickListener {
            BlocklistManager.setEnabledSources(context, selected)
            dialog.dismiss()
            onSaved()
        }

        dialog.show()
    }

    fun showManageLists(
        context: Context,
        onChanged: () -> Unit
    ) {
        val (dialog, view) = createSheet(context, R.layout.sheet_manage_lists)

        val btnClose: ImageButton = view.findViewById(R.id.btnCloseLists)
        val tabWhitelist: TextView = view.findViewById(R.id.tabWhitelist)
        val tabBlacklist: TextView = view.findViewById(R.id.tabBlacklist)
        val etAddDomain: EditText = view.findViewById(R.id.etAddDomain)
        val btnAddDomain: MaterialButton = view.findViewById(R.id.btnAddDomain)
        val etSearchDomain: EditText = view.findViewById(R.id.etSearchDomain)
        val rvDomains: RecyclerView = view.findViewById(R.id.rvDomains)
        val tvEmpty: TextView = view.findViewById(R.id.tvEmptyDomains)

        var showingWhitelist = true
        var query = ""

        lateinit var adapter: DomainListAdapter

        fun updateTabsAndList() {
            val wl = BlocklistManager.getWhitelist().sorted()
            val bl = BlocklistManager.getBlacklist().sorted()

            tabWhitelist.text = "Whitelist (${wl.size})"
            tabBlacklist.text = "Blacklist (${bl.size})"

            val activeText = ContextCompat.getColor(context, R.color.ns_text_primary)
            val inactiveText = ContextCompat.getColor(context, R.color.ns_text_secondary)

            if (showingWhitelist) {
                tabWhitelist.setBackgroundResource(R.drawable.bg_segment_active)
                tabWhitelist.setTextColor(activeText)
                tabBlacklist.background = null
                tabBlacklist.setTextColor(inactiveText)
                etAddDomain.hint = "Thêm vào Whitelist (vd: gdt.gov.vn)"
            } else {
                tabBlacklist.setBackgroundResource(R.drawable.bg_segment_active)
                tabBlacklist.setTextColor(activeText)
                tabWhitelist.background = null
                tabWhitelist.setTextColor(inactiveText)
                etAddDomain.hint = "Thêm vào Blacklist (vd: ads.example.com)"
            }

            val base = if (showingWhitelist) wl else bl
            val filtered = if (query.isBlank()) base else base.filter { it.contains(query, ignoreCase = true) }
            adapter.submit(filtered)

            if (filtered.isEmpty()) {
                tvEmpty.visibility = View.VISIBLE
                tvEmpty.text = if (query.isNotBlank()) {
                    "Không tìm thấy \"$query\""
                } else if (showingWhitelist) {
                    "Whitelist đang trống"
                } else {
                    "Chưa có tên miền nào bị chặn thủ công"
                }
            } else {
                tvEmpty.visibility = View.GONE
            }
        }

        adapter = DomainListAdapter { domain ->
            if (showingWhitelist) {
                BlocklistManager.removeWhitelist(context, domain)
            } else {
                BlocklistManager.removeBlacklist(context, domain)
            }
            Toast.makeText(context, "Đã xóa $domain", Toast.LENGTH_SHORT).show()
            updateTabsAndList()
            onChanged()
        }

        rvDomains.layoutManager = LinearLayoutManager(context)
        rvDomains.addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        rvDomains.adapter = adapter

        fun submitNewDomain() {
            val cleaned = etAddDomain.text.toString()
                .trim()
                .lowercase()
                .removePrefix("https://")
                .removePrefix("http://")
                .substringBefore("/")
                .trim('.')
            if (cleaned.isEmpty() || !cleaned.contains('.')) {
                Toast.makeText(context, "Vui lòng nhập tên miền hợp lệ (vd: gdt.gov.vn)", Toast.LENGTH_SHORT).show()
                return
            }
            if (showingWhitelist) {
                BlocklistManager.addWhitelist(context, cleaned)
            } else {
                BlocklistManager.addBlacklist(context, cleaned)
            }
            etAddDomain.setText("")
            Toast.makeText(context, "Đã thêm $cleaned", Toast.LENGTH_SHORT).show()
            updateTabsAndList()
            onChanged()
        }

        tabWhitelist.setOnClickListener {
            if (!showingWhitelist) {
                showingWhitelist = true
                updateTabsAndList()
            }
        }
        tabBlacklist.setOnClickListener {
            if (showingWhitelist) {
                showingWhitelist = false
                updateTabsAndList()
            }
        }
        btnAddDomain.setOnClickListener { submitNewDomain() }
        etAddDomain.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                submitNewDomain()
                true
            } else false
        }
        etSearchDomain.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString()?.trim().orEmpty()
                updateTabsAndList()
            }
        })
        btnClose.setOnClickListener { dialog.dismiss() }

        updateTabsAndList()
        dialog.show()
    }

    fun showBypassApps(
        context: Context,
        scope: CoroutineScope,
        selfPackage: String
    ) {
        val (dialog, view) = createSheet(context, R.layout.sheet_bypass_apps)

        val tvBadge: TextView = view.findViewById(R.id.tvBypassCountBadge)
        val etSearch: EditText = view.findViewById(R.id.etSearchApps)
        val tabAll: TextView = view.findViewById(R.id.tabAllApps)
        val tabSelected: TextView = view.findViewById(R.id.tabSelectedApps)
        val rv: RecyclerView = view.findViewById(R.id.rvBypassApps)
        val pbLoading: ProgressBar = view.findViewById(R.id.pbLoadingApps)
        val tvEmpty: TextView = view.findViewById(R.id.tvEmptyApps)
        val btnCancel: MaterialButton = view.findViewById(R.id.btnBypassCancel)
        val btnSave: MaterialButton = view.findViewById(R.id.btnBypassSave)

        val selected = BlocklistManager.getBypassApps().toMutableSet()
        var allApps: List<AppEntry> = emptyList()
        var onlySelected = false
        var query = ""

        lateinit var adapter: BypassAppAdapter

        fun updateCounters() {
            val count = selected.size
            tvBadge.text = "$count đã chọn"
            tabSelected.text = "Đã chọn ($count)"
            btnSave.text = if (count > 0) "Lưu ($count)" else "Lưu thay đổi"
            if (count > 0) {
                tvBadge.setBackgroundResource(R.drawable.bg_status_active)
                tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_status_active_fg))
            } else {
                tvBadge.setBackgroundResource(R.drawable.bg_status_inactive)
                tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_status_inactive_fg))
            }
        }

        fun applyFilter() {
            val activeText = ContextCompat.getColor(context, R.color.ns_text_primary)
            val inactiveText = ContextCompat.getColor(context, R.color.ns_text_secondary)
            if (!onlySelected) {
                tabAll.setBackgroundResource(R.drawable.bg_segment_active)
                tabAll.setTextColor(activeText)
                tabSelected.background = null
                tabSelected.setTextColor(inactiveText)
            } else {
                tabSelected.setBackgroundResource(R.drawable.bg_segment_active)
                tabSelected.setTextColor(activeText)
                tabAll.background = null
                tabAll.setTextColor(inactiveText)
            }

            val filtered = allApps.filter { app ->
                val matchesTab = !onlySelected || selected.contains(app.packageName)
                val matchesQuery = query.isBlank() ||
                    app.label.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
                matchesTab && matchesQuery
            }
            adapter.submit(filtered)
            tvEmpty.visibility = if (pbLoading.visibility == View.GONE && filtered.isEmpty()) View.VISIBLE else View.GONE
        }

        adapter = BypassAppAdapter(selected) {
            updateCounters()
            if (onlySelected) applyFilter()
        }

        rv.layoutManager = LinearLayoutManager(context)
        rv.addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        rv.adapter = adapter

        tabAll.setOnClickListener {
            if (onlySelected) {
                onlySelected = false
                applyFilter()
            }
        }
        tabSelected.setOnClickListener {
            if (!onlySelected) {
                onlySelected = true
                applyFilter()
            }
        }
        etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString()?.trim().orEmpty()
                applyFilter()
            }
        })

        btnCancel.setOnClickListener { dialog.dismiss() }
        btnSave.setOnClickListener {
            BlocklistManager.setBypassApps(context, selected)
            dialog.dismiss()
            Toast.makeText(
                context,
                "Đã lưu ${selected.size} ứng dụng loại trừ. Tắt và bật lại bảo vệ để áp dụng.",
                Toast.LENGTH_LONG
            ).show()
        }

        updateCounters()
        dialog.show()

        scope.launch {
            val loaded = withContext(Dispatchers.IO) {
                val pm = context.packageManager
                pm.getInstalledApplications(0)
                    .asSequence()
                    .filter { pm.getLaunchIntentForPackage(it.packageName) != null && it.packageName != selfPackage }
                    .map { appInfo ->
                        AppEntry(
                            label = pm.getApplicationLabel(appInfo).toString(),
                            packageName = appInfo.packageName,
                            icon = runCatching { pm.getApplicationIcon(appInfo) }.getOrNull()
                        )
                    }
                    .sortedWith(
                        compareByDescending<AppEntry> { selected.contains(it.packageName) }
                            .thenBy { it.label.lowercase() }
                    )
                    .toList()
            }
            if (dialog.isShowing) {
                allApps = loaded
                pbLoading.visibility = View.GONE
                tabAll.text = "Tất cả (${loaded.size})"
                applyFilter()
            }
        }
    }

    fun showQuickDomainAction(
        context: Context,
        item: DnsLogItem,
        onActionDone: () -> Unit
    ) {
        val (dialog, view) = createSheet(context, R.layout.sheet_quick_domain)

        val tvBadge: TextView = view.findViewById(R.id.tvQuickBadge)
        val tvMeta: TextView = view.findViewById(R.id.tvQuickMeta)
        val tvDomain: TextView = view.findViewById(R.id.tvQuickDomain)
        val tvMessage: TextView = view.findViewById(R.id.tvQuickMessage)
        val btnClose: MaterialButton = view.findViewById(R.id.btnQuickClose)
        val btnAction: MaterialButton = view.findViewById(R.id.btnQuickAction)

        tvDomain.text = item.domain
        tvMeta.text = "${item.time} • ${item.reason}"

        if (item.blocked) {
            tvBadge.text = "ĐANG CHẶN"
            tvBadge.setBackgroundResource(R.drawable.bg_badge_blocked)
            tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_badge_blocked_fg))
            tvMessage.text = "Tên miền này đang bị chặn bởi bộ lọc (${item.reason}). Thêm vào Whitelist nếu bạn muốn luôn cho phép."
            btnAction.text = "Bỏ chặn (Whitelist)"
        } else {
            tvBadge.text = "CHO PHÉP"
            tvBadge.setBackgroundResource(R.drawable.bg_badge_allowed)
            tvBadge.setTextColor(ContextCompat.getColor(context, R.color.ns_badge_allowed_fg))
            tvMessage.text = "Tên miền này đang được cho phép đi qua. Thêm vào Blacklist để chặn thủ công."
            btnAction.text = "Chặn ngay (Blacklist)"
        }

        btnClose.setOnClickListener { dialog.dismiss() }
        btnAction.setOnClickListener {
            if (item.blocked) {
                BlocklistManager.addWhitelist(context, item.domain)
                Toast.makeText(context, "Đã bỏ chặn ${item.domain}", Toast.LENGTH_SHORT).show()
            } else {
                BlocklistManager.addBlacklist(context, item.domain)
                Toast.makeText(context, "Đã chặn ${item.domain}", Toast.LENGTH_SHORT).show()
            }
            dialog.dismiss()
            onActionDone()
        }

        dialog.show()
    }
}

private data class AppEntry(
    val label: String,
    val packageName: String,
    val icon: Drawable?
)

private class FilterSourceAdapter(
    private val sources: List<FilterSource>,
    private val selected: MutableSet<String>,
    private val onToggle: () -> Unit
) : RecyclerView.Adapter<FilterSourceAdapter.VH>() {

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvTitle: TextView = view.findViewById(R.id.tvSourceTitle)
        val tvDesc: TextView = view.findViewById(R.id.tvSourceDesc)
        val sw: SwitchMaterial = view.findViewById(R.id.swSourceEnabled)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_filter_source, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val src = sources[position]
        val openIdx = src.name.indexOf('(')
        if (openIdx > 0 && src.name.endsWith(")")) {
            holder.tvTitle.text = src.name.substring(0, openIdx).trim()
            holder.tvDesc.text = src.name.substring(openIdx + 1, src.name.length - 1).trim()
            holder.tvDesc.visibility = View.VISIBLE
        } else {
            holder.tvTitle.text = src.name
            holder.tvDesc.visibility = View.GONE
        }

        NetShieldSheets.applySwitchStyle(holder.itemView.context, holder.sw)
        holder.sw.isChecked = selected.contains(src.id)

        holder.itemView.setOnClickListener {
            val nowChecked = !selected.contains(src.id)
            if (nowChecked) selected.add(src.id) else selected.remove(src.id)
            holder.sw.isChecked = nowChecked
            onToggle()
        }
    }

    override fun getItemCount(): Int = sources.size
}

private class DomainListAdapter(
    private val onDelete: (String) -> Unit
) : RecyclerView.Adapter<DomainListAdapter.VH>() {

    private var items: List<String> = emptyList()

    fun submit(newItems: List<String>) {
        items = newItems
        notifyDataSetChanged()
    }

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvDomain: TextView = view.findViewById(R.id.tvDomainName)
        val btnDelete: TextView = view.findViewById(R.id.btnDeleteDomain)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_domain_row, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val domain = items[position]
        holder.tvDomain.text = domain
        holder.btnDelete.setOnClickListener { onDelete(domain) }
    }

    override fun getItemCount(): Int = items.size
}

private class BypassAppAdapter(
    private val selected: MutableSet<String>,
    private val onToggle: () -> Unit
) : RecyclerView.Adapter<BypassAppAdapter.VH>() {

    private var items: List<AppEntry> = emptyList()

    fun submit(newItems: List<AppEntry>) {
        items = newItems
        notifyDataSetChanged()
    }

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val ivIcon: ImageView = view.findViewById(R.id.ivAppIcon)
        val tvName: TextView = view.findViewById(R.id.tvAppName)
        val tvPkg: TextView = view.findViewById(R.id.tvAppPackage)
        val sw: SwitchMaterial = view.findViewById(R.id.swAppBypass)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_bypass_app, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val app = items[position]
        holder.tvName.text = app.label
        holder.tvPkg.text = app.packageName
        if (app.icon != null) {
            holder.ivIcon.setImageDrawable(app.icon)
        } else {
            holder.ivIcon.setImageResource(R.drawable.ic_shield)
        }
        NetShieldSheets.applySwitchStyle(holder.itemView.context, holder.sw)
        holder.sw.isChecked = selected.contains(app.packageName)

        holder.itemView.setOnClickListener {
            val nowChecked = !selected.contains(app.packageName)
            if (nowChecked) selected.add(app.packageName) else selected.remove(app.packageName)
            holder.sw.isChecked = nowChecked
            onToggle()
        }
    }

    override fun getItemCount(): Int = items.size
}
