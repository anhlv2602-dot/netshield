const PROTECTED_SUFFIXES = [
  'gov.vn', 'gdt.gov.vn', 'misa.vn', 'meinvoice.vn', 'sinvoice.vn',
  'vnpt-invoice.com.vn', 'ehoadon.vn', 'bkav.com.vn', 'viettel-ca.vn',
  'vnpt-ca.vn', 'efy.com.vn', 'vietcombank.com.vn', 'techcombank.com.vn',
  'mbbank.com.vn', 'bidv.com.vn', 'vietinbank.vn', 'acb.com.vn',
];

function isProtected(host) {
  return PROTECTED_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
}

let currentHost = '';
let currentTabId = null;
let state = {
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

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId = tab?.id ?? null;
  if (tab?.url) {
    try {
      const u = new URL(tab.url);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        currentHost = u.hostname.toLowerCase();
      }
    } catch (_) {}
  }

  document.getElementById('currentHost').textContent = currentHost || 'Trang hệ thống';

  if (tab?.id != null) {
    chrome.runtime.sendMessage({ type: 'GET_TAB_COUNT', tabId: tab.id }, (res) => {
      document.getElementById('pageCount').textContent = (res?.count || 0).toLocaleString('vi-VN');
    });
  }

  const stored = await chrome.storage.local.get([
    'enabled', 'blockFacebook', 'blockYoutube', 'blockMusic', 'blockVnNews', 'defuseAntiAdblock', 'whitelist', 'customRules', 'totalBlocked',
  ]);
  state = {
    enabled: stored.enabled !== false,
    blockFacebook: stored.blockFacebook !== false,
    blockYoutube: stored.blockYoutube !== false,
    blockMusic: stored.blockMusic !== false,
    blockVnNews: stored.blockVnNews !== false,
    defuseAntiAdblock: stored.defuseAntiAdblock !== false,
    whitelist: Array.isArray(stored.whitelist) ? stored.whitelist : [],
    customRules: stored.customRules && typeof stored.customRules === 'object' ? stored.customRules : {},
    totalBlocked: stored.totalBlocked || 0,
  };

  render();

  document.getElementById('btnToggleGlobal').addEventListener('click', async () => {
    state.enabled = !state.enabled;
    await chrome.storage.local.set({ enabled: state.enabled });
    render();
  });

  document.getElementById('btnToggleSite').addEventListener('click', async () => {
    if (!currentHost || isProtected(currentHost)) return;
    const idx = state.whitelist.indexOf(currentHost);
    if (idx >= 0) {
      state.whitelist.splice(idx, 1);
    } else {
      state.whitelist.push(currentHost);
    }
    await chrome.storage.local.set({ whitelist: state.whitelist });
    render();
  });

  document.getElementById('btnPickBlank').addEventListener('click', async () => {
    if (currentTabId == null || !currentHost || isProtected(currentHost)) return;
    try {
      await chrome.tabs.sendMessage(currentTabId, { type: 'START_PICKER' });
      window.close();
    } catch (_) {}
  });

  document.getElementById('btnClearPicked').addEventListener('click', async () => {
    if (!currentHost) return;
    const nextRules = { ...state.customRules };
    delete nextRules[currentHost];
    state.customRules = nextRules;
    await chrome.storage.local.set({ customRules: nextRules });
    if (currentTabId != null) {
      chrome.tabs.sendMessage(currentTabId, { type: 'CLEAR_CUSTOM_RULES' }).catch(() => {});
    }
    render();
  });

  document.getElementById('chkFacebook').addEventListener('change', async (e) => {
    state.blockFacebook = e.target.checked;
    await chrome.storage.local.set({ blockFacebook: state.blockFacebook });
  });

  document.getElementById('chkYoutube').addEventListener('change', async (e) => {
    state.blockYoutube = e.target.checked;
    await chrome.storage.local.set({ blockYoutube: state.blockYoutube });
  });

  document.getElementById('chkMusic').addEventListener('change', async (e) => {
    state.blockMusic = e.target.checked;
    await chrome.storage.local.set({ blockMusic: state.blockMusic });
  });

  document.getElementById('chkVnNews').addEventListener('change', async (e) => {
    state.blockVnNews = e.target.checked;
    await chrome.storage.local.set({ blockVnNews: state.blockVnNews });
  });

  document.getElementById('chkAntiAdblock').addEventListener('change', async (e) => {
    state.defuseAntiAdblock = e.target.checked;
    await chrome.storage.local.set({ defuseAntiAdblock: state.defuseAntiAdblock });
  });
}

function render() {
  document.getElementById('totalCount').textContent = state.totalBlocked.toLocaleString('vi-VN');
  document.getElementById('chkFacebook').checked = state.blockFacebook;
  document.getElementById('chkYoutube').checked = state.blockYoutube;
  document.getElementById('chkMusic').checked = state.blockMusic;
  document.getElementById('chkVnNews').checked = state.blockVnNews;
  document.getElementById('chkAntiAdblock').checked = state.defuseAntiAdblock;

  const pill = document.getElementById('statusPill');
  const statusText = document.getElementById('statusText');
  const btnGlobal = document.getElementById('btnToggleGlobal');
  const btnSite = document.getElementById('btnToggleSite');
  const btnPick = document.getElementById('btnPickBlank');
  const btnClear = document.getElementById('btnClearPicked');

  const protectedSite = currentHost && isProtected(currentHost);
  const siteWhitelisted = currentHost && state.whitelist.includes(currentHost);
  const customCount = currentHost && Array.isArray(state.customRules[currentHost])
    ? state.customRules[currentHost].length
    : 0;

  if (!state.enabled) {
    pill.className = 'pill inactive';
    statusText.textContent = 'Đang tắt';
    btnGlobal.textContent = 'Bật lại bảo vệ';
    btnGlobal.classList.remove('paused');
  } else if (protectedSite) {
    pill.className = 'pill inactive';
    statusText.textContent = 'Trang bảo vệ';
    btnGlobal.textContent = 'Tạm dừng bảo vệ';
    btnGlobal.classList.add('paused');
  } else if (siteWhitelisted) {
    pill.className = 'pill inactive';
    statusText.textContent = 'Bỏ qua trang';
    btnGlobal.textContent = 'Tạm dừng bảo vệ';
    btnGlobal.classList.add('paused');
  } else {
    pill.className = 'pill active';
    statusText.textContent = 'Đang bật';
    btnGlobal.textContent = 'Tạm dừng bảo vệ';
    btnGlobal.classList.add('paused');
  }

  if (!currentHost) {
    btnSite.disabled = true;
    btnSite.textContent = 'Không áp dụng trên trang này';
  } else if (protectedSite) {
    btnSite.disabled = true;
    btnSite.textContent = 'Trang Thuế / Ngân hàng (luôn cho qua)';
  } else if (siteWhitelisted) {
    btnSite.disabled = false;
    btnSite.textContent = 'Bật lại trên trang này';
  } else {
    btnSite.disabled = false;
    btnSite.textContent = 'Tạm dừng trên trang này';
  }

  btnPick.disabled = !currentHost || protectedSite || siteWhitelisted || !state.enabled;
  if (customCount > 0 && currentHost && !protectedSite) {
    btnClear.classList.remove('hidden');
    btnClear.textContent = `Khôi phục (${customCount})`;
  } else {
    btnClear.classList.add('hidden');
  }
}

init();
