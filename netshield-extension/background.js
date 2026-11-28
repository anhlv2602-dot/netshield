const DEFAULT_SETTINGS = {
  enabled: true,
  blockFacebook: true,
  blockYoutube: true,
  blockMusic: true,
  blockVnNews: true,
  defuseAntiAdblock: true,
  whitelist: [],
  customRules: {},
  totalBlocked: 0,
};

// Vùng bảo vệ tuyệt đối — đồng bộ với content.js (Thuế/GDT, HĐĐT, Chữ ký số, Ngân hàng)
const PROTECTED_SUFFIXES = [
  'gov.vn', 'gdt.gov.vn', 'misa.vn', 'misa.com.vn', 'meinvoice.vn', 'amis.vn',
  'sinvoice.vn', 'vnpt-invoice.com.vn', 'ehoadon.vn', 'bkav.com.vn', 'bkav.vn',
  'easyinvoice.vn', 'easyinvoice.com.vn', 'minvoice.vn', 'cyberbill.vn',
  'fast.com.vn', 'einvoice.vn', 'thaison.vn', 'efy.com.vn', 'ihoadon.vn',
  'viettel-ca.vn', 'vnpt-ca.vn', 'bkavca.vn', 'fpt-ca.vn', 'newca.vn', 'fastca.vn',
  'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn', 'bidv.com.vn',
  'vietinbank.vn', 'agribank.com.vn', 'acb.com.vn', 'vpbank.com.vn', 'tpb.vn',
  'sacombank.com.vn', 'hdbank.com.vn', 'vib.com.vn', 'shb.com.vn', 'seabank.com.vn',
  'ocb.com.vn', 'msb.com.vn', 'eximbank.com.vn', 'lpbank.com.vn', 'napas.com.vn',
  'vnpay.vn', 'vnpayment.vn', 'localhost', '127.0.0.1',
];

const MAIN_SCRIPT_ID = 'netshield-anti-adblock-main';

// Các script Anti-Adblock & video ad phổ biến chặn ở tầng mạng (DNR) trước khi tải
const ANTI_ADBLOCK_DNR_FILTERS = [
  { id: 1001, urlFilter: '||investing.com/*/ad-notification-popup' },
  { id: 1002, urlFilter: '||fundingchoicesmessages.google.com^' },
  { id: 1003, urlFilter: '||getadmiral.com^' },
  { id: 1004, urlFilter: '||admiral.com^' },
  { id: 1005, urlFilter: '||blockadblock.com^' },
  { id: 1006, urlFilter: '||fuckadblock.com^' },
  { id: 1007, urlFilter: '||btloader.com^' },
  { id: 1008, urlFilter: '||live.primis.tech^' },
];

const ALL_DNR_IDS = ANTI_ADBLOCK_DNR_FILTERS.map((r) => r.id);

const tabCounts = new Map();
let syncChain = Promise.resolve();

function sanitizeDomains(list) {
  const seen = new Set();
  for (const raw of list || []) {
    const d = String(raw || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!d || /[^a-z0-9.-]/.test(d)) continue;
    seen.add(d);
  }
  return [...seen];
}

function buildExcludeMatches(domains) {
  const patterns = [];
  for (const d of domains) {
    patterns.push(`*://${d}/*`);
    const isIpOrLocal = d === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(d);
    if (!isIpOrLocal) {
      patterns.push(`*://*.${d}/*`);
    }
  }
  return patterns;
}

async function applyDynamicProtections() {
  const stored = await chrome.storage.local.get(['enabled', 'defuseAntiAdblock', 'whitelist']);
  const enabled = stored.enabled !== false;
  const defuseAntiAdblock = stored.defuseAntiAdblock !== false;
  const shouldRun = enabled && defuseAntiAdblock;
  const excludedDomains = sanitizeDomains([
    ...PROTECTED_SUFFIXES,
    ...(Array.isArray(stored.whitelist) ? stored.whitelist : []),
  ]);

  // 1. Đồng bộ declarativeNetRequest dynamic rules
  if (chrome.declarativeNetRequest?.updateDynamicRules) {
    try {
      const addRules = shouldRun
        ? ANTI_ADBLOCK_DNR_FILTERS.map((r) => ({
            id: r.id,
            priority: 1,
            action: { type: 'block' },
            condition: {
              urlFilter: r.urlFilter,
              resourceTypes: ['script', 'xmlhttprequest', 'sub_frame'],
              excludedInitiatorDomains: excludedDomains,
            },
          }))
        : [];

      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ALL_DNR_IDS,
        addRules,
      });
    } catch (err) {
      console.warn('[NetShield] DNR sync failed:', err);
    }
  }

  // 2. Đồng bộ MAIN-world scriptlet (tôn trọng nút bật/tắt & whitelist)
  if (chrome.scripting?.registerContentScripts) {
    try {
      await chrome.scripting
        .unregisterContentScripts({ ids: [MAIN_SCRIPT_ID] })
        .catch(() => {});

      if (shouldRun) {
        await chrome.scripting.registerContentScripts([
          {
            id: MAIN_SCRIPT_ID,
            js: ['content/anti-adblock-main.js'],
            matches: ['http://*/*', 'https://*/*'],
            excludeMatches: buildExcludeMatches(excludedDomains),
            runAt: 'document_start',
            world: 'MAIN',
            persistAcrossSessions: true,
          },
        ]);
      }
    } catch (err) {
      console.warn('[NetShield] MAIN scriptlet sync failed:', err);
    }
  }
}

function scheduleSync() {
  syncChain = syncChain.then(applyDynamicProtections).catch(() => {});
  return syncChain;
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (existing[k] === undefined) toSet[k] = v;
  }
  if (Object.keys(toSet).length > 0) {
    await chrome.storage.local.set(toSet);
  }
  await scheduleSync();
});

chrome.runtime.onStartup.addListener(() => {
  scheduleSync();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  if (changes.enabled || changes.defuseAntiAdblock || changes.whitelist) {
    scheduleSync();
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabCounts.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabCounts.set(tabId, 0);
    updateBadge(tabId, 0);
  }
});

function updateBadge(tabId, count) {
  const text = count > 0 ? (count > 99 ? '99+' : String(count)) : '';
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#0F172A' }).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'AD_BLOCKED' && sender.tab?.id != null) {
    const tabId = sender.tab.id;
    const delta = Number(msg.delta) || 1;
    const nextTabCount = (tabCounts.get(tabId) || 0) + delta;
    tabCounts.set(tabId, nextTabCount);
    updateBadge(tabId, nextTabCount);

    chrome.storage.local.get(['totalBlocked']).then(({ totalBlocked = 0 }) => {
      chrome.storage.local.set({ totalBlocked: totalBlocked + delta });
    });
    sendResponse({ ok: true, tabCount: nextTabCount });
    return true;
  }

  if (msg?.type === 'GET_TAB_COUNT') {
    sendResponse({ count: tabCounts.get(msg.tabId) || 0 });
    return true;
  }

  return false;
});
