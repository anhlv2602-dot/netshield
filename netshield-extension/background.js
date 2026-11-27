const DEFAULT_SETTINGS = {
  enabled: true,
  blockFacebook: true,
  blockYoutube: true,
  blockMusic: true,
  blockVnNews: true,
  whitelist: [],
  totalBlocked: 0,
};

const tabCounts = new Map();

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (existing[k] === undefined) toSet[k] = v;
  }
  if (Object.keys(toSet).length > 0) {
    await chrome.storage.local.set(toSet);
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
