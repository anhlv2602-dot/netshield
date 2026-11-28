(() => {
  'use strict';

  const HOST = location.hostname.toLowerCase();

  // Vùng bảo vệ tuyệt đối — KHÔNG BAO GIỜ can thiệp DOM (Thuế/GDT, HĐĐT, Chữ ký số, Ngân hàng)
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

  function isProtectedHost(host) {
    return PROTECTED_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
  }

  if (isProtectedHost(HOST)) return;

  const IS_FACEBOOK = HOST === 'facebook.com' || HOST.endsWith('.facebook.com');
  const IS_YOUTUBE = HOST === 'youtube.com' || HOST.endsWith('.youtube.com');
  const IS_ZINGMP3 = HOST === 'zingmp3.vn' || HOST.endsWith('.zingmp3.vn') || HOST === 'mp3.zing.vn';
  const IS_SPOTIFY = HOST === 'open.spotify.com' || HOST.endsWith('.spotify.com');
  const IS_INVESTING = HOST === 'investing.com' || HOST.endsWith('.investing.com');

  let settings = {
    enabled: true,
    blockFacebook: true,
    blockYoutube: true,
    blockMusic: true,
    blockVnNews: true,
    defuseAntiAdblock: true,
    whitelist: [],
  };

  let spotifyMutedByUs = false;

  let observer = null;
  let scanTimer = null;
  let pollInterval = null;

  function isWhitelisted(host, list) {
    return (list || []).some((d) => host === d || host.endsWith('.' + d));
  }

  function reportBlocked(delta) {
    if (delta <= 0) return;
    try {
      chrome.runtime.sendMessage({ type: 'AD_BLOCKED', delta });
    } catch (_) {}
  }

  const IS_TOP_FRAME = window === window.top;

  function hideElement(el) {
    if (!el || el.dataset.nsHidden === '1') return false;
    el.dataset.nsHidden = '1';
    el.dataset.nsOrigDisplay = el.style.getPropertyValue('display') || '';
    el.classList.add('ns-hidden');
    el.style.setProperty('display', 'none', 'important');
    el.style.setProperty('visibility', 'hidden', 'important');
    return true;
  }

  function unhideAll() {
    document.querySelectorAll('[data-ns-hidden="1"]').forEach((el) => {
      el.classList.remove('ns-hidden');
      if (el.dataset.nsOrigDisplay) {
        el.style.setProperty('display', el.dataset.nsOrigDisplay);
      } else {
        el.style.removeProperty('display');
      }
      el.style.removeProperty('visibility');
      delete el.dataset.nsHidden;
      delete el.dataset.nsOrigDisplay;
    });
  }

  // Trích xuất chỉ chữ thực sự hiển thị (chống kỹ thuật chèn span ẩn của Facebook)
  function getVisibleText(root) {
    if (!root) return '';
    let result = '';
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const text = node.nodeValue;
      if (!text || !text.trim()) continue;
      const parent = node.parentElement;
      if (!parent) continue;
      const style = window.getComputedStyle(parent);
      if (
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        parseFloat(style.opacity) === 0 ||
        parseFloat(style.fontSize) === 0 ||
        style.position === 'absolute' && (parent.offsetWidth === 0 || parent.offsetHeight === 0)
      ) {
        continue;
      }
      result += text;
    }
    return result.replace(/\s+/g, ' ').trim();
  }

  function cleanText(raw) {
    return (raw || '')
      .replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase();
  }

  function isSponsoredLabel(text) {
    const norm = cleanText(text);
    return norm === 'được tài trợ' || norm === 'sponsored' || norm === 'tài trợ';
  }

  const RIGHT_RAIL_STOP_WORDS = [
    'người liên hệ',
    'contacts',
    'sinh nhật',
    'birthdays',
    'cuộc trò chuyện nhóm',
    'group conversations',
    'trang và trang cá nhân',
    'your pages',
    'lời mời kết bạn',
    'friend requests',
  ];

  // =========================================================================
  // 1. FACEBOOK: Cột "Được tài trợ" bên phải + Bài tài trợ trên News Feed
  // =========================================================================
  function scanFacebook() {
    let blocked = 0;

    // 1A. Quét toàn bộ tiêu đề "Được tài trợ" / "Sponsored" ở cột phải (không phụ thuộc role="complementary")
    const candidates = document.querySelectorAll(
      '[data-pagelet="RightRail"] h2, [data-pagelet="RightRail"] h3, [data-pagelet="RightRail"] h4, [data-pagelet="RightRail"] span, ' +
      '[role="complementary"] h2, [role="complementary"] h3, [role="complementary"] h4, [role="complementary"] span, ' +
      'h3, h4'
    );

    for (const el of candidates) {
      if (el.dataset.nsHidden === '1') continue;
      if (el.closest('[data-ns-hidden="1"]')) continue;

      const rawNorm = cleanText(el.textContent);
      if (rawNorm.length === 0 || rawNorm.length > 30) continue;
      if (!isSponsoredLabel(rawNorm) && !isSponsoredLabel(getVisibleText(el))) continue;

      // Xác nhận đang nằm ở cột phải (tránh đụng vào tiêu đề bài viết giữa trang)
      const rect = el.getBoundingClientRect();
      const inRightRail =
        Boolean(el.closest('[data-pagelet="RightRail"], [role="complementary"]')) ||
        (rect.width > 0 && rect.left > window.innerWidth * 0.52);

      if (!inRightRail) continue;

      // Leo lên tìm khối bao trọn tiêu đề "Được tài trợ" + các thẻ quảng cáo bên dưới
      let node = el.parentElement;
      let target = null;
      for (let depth = 0; depth < 10 && node && node !== document.body; depth++) {
        const nodeText = cleanText(node.textContent);
        const hitsOtherSection = RIGHT_RAIL_STOP_WORDS.some((w) => nodeText.includes(w));
        if (hitsOtherSection) break;

        const r = node.getBoundingClientRect();
        if (r.width > 520 || r.height > 1100) break;

        const hasMediaOrLink = node.querySelector('a[href], img') !== null;
        if (hasMediaOrLink && r.height >= 70) {
          target = node;
        }
        node = node.parentElement;
      }

      if (target && hideElement(target)) {
        blocked++;
      } else if (hideElement(el)) {
        blocked++;
      }
    }

    // 1B. Chặn dự phòng các thẻ quảng cáo cột phải có link /ads/ hoặc ad_id
    const rightContainers = document.querySelectorAll('[data-pagelet="RightRail"], [role="complementary"]');
    for (const rail of rightContainers) {
      const adLinks = rail.querySelectorAll(
        'a[href*="/ads/"], a[href*="ad_id="], a[aria-label*="Được tài trợ"], a[aria-label*="Sponsored"]'
      );
      for (const a of adLinks) {
        if (a.closest('[data-ns-hidden="1"]')) continue;
        let card = a.closest('div') || a;
        for (let i = 0; i < 5 && card.parentElement && card.parentElement !== rail; i++) {
          const p = card.parentElement;
          const pText = cleanText(p.textContent);
          if (RIGHT_RAIL_STOP_WORDS.some((w) => pText.includes(w))) break;
          if (p.offsetHeight < 500 && p.offsetWidth < 480) {
            card = p;
          } else {
            break;
          }
        }
        if (hideElement(card)) blocked++;
      }
    }

    // 1C. Bài đăng "Được tài trợ" / "Sponsored" trong Bảng tin (News Feed)
    const feedUnits = document.querySelectorAll(
      '[role="article"], div[data-pagelet^="FeedUnit_"], div[data-pagelet^="MainFeed"] > div > div'
    );
    for (const unit of feedUnits) {
      if (unit.dataset.nsHidden === '1' || unit.closest('[data-ns-hidden="1"]')) continue;

      const directAdSignal = unit.querySelector(
        'a[aria-label="Được tài trợ"], a[aria-label="Sponsored"], a[href*="/ads/about"], a[href*="ad_id="]'
      );
      if (directAdSignal) {
        if (hideElement(unit)) blocked++;
        continue;
      }

      const headerLinks = unit.querySelectorAll('a[role="link"], span > a');
      let foundAd = false;
      for (const link of headerLinks) {
        const txt = cleanText(link.textContent);
        if (txt.length > 0 && txt.length <= 40) {
          if (isSponsoredLabel(txt) || isSponsoredLabel(getVisibleText(link))) {
            foundAd = true;
            break;
          }
        }
      }

      if (foundAd && hideElement(unit)) {
        blocked++;
      }
    }

    if (blocked > 0) reportBlocked(blocked);
  }

  // =========================================================================
  // 2. YOUTUBE: Ẩn quảng cáo giao diện & tự bỏ qua video quảng cáo
  // =========================================================================
  function scanYoutube() {
    let blocked = 0;

    const adSelectors = [
      'ytd-ad-slot-renderer',
      'ytd-promoted-sparkles-web-renderer',
      'ytd-promoted-video-renderer',
      'ytd-display-ad-renderer',
      'ytd-banner-promo-renderer',
      'ytd-in-feed-ad-layout-renderer',
      '#player-ads',
      '.ytp-ad-overlay-container',
    ];
    for (const sel of adSelectors) {
      document.querySelectorAll(sel).forEach((el) => {
        if (hideElement(el)) blocked++;
      });
    }

    // Tự bấm nút "Bỏ qua quảng cáo" / "Skip"
    const skipBtn = document.querySelector(
      '.ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern'
    );
    if (skipBtn && skipBtn.offsetParent !== null) {
      skipBtn.click();
      blocked++;
    }

    // Nếu đang phát video quảng cáo không cho bỏ qua ngay -> tắt tiếng & tua nhanh cuối
    const player = document.querySelector('.html5-video-player');
    if (player && player.classList.contains('ad-showing')) {
      const video = player.querySelector('video');
      if (video) {
        video.muted = true;
        if (Number.isFinite(video.duration) && video.duration > 0) {
          video.currentTime = video.duration;
        }
      }
    }

    if (blocked > 0) reportBlocked(blocked);
  }

  // =========================================================================
  // 2B. ZING MP3 & SPOTIFY WEB: Ẩn banner, khung nâng cấp & tự tắt tiếng QC audio
  // =========================================================================
  function scanZingMp3() {
    let blocked = 0;
    const selectors = [
      '[id*="adtima"]',
      '.zm-ads',
      '.ad-banner',
      '.vip-banner-sidebar',
      'iframe[src*="adtima"]',
      'iframe[src*="ad.zing.vn"]',
      'iframe[src*="doubleclick.net"]',
    ];
    for (const sel of selectors) {
      document.querySelectorAll(sel).forEach((el) => {
        if (hideElement(el)) blocked++;
      });
    }
    if (blocked > 0) reportBlocked(blocked);
  }

  function scanSpotify() {
    let blocked = 0;
    const selectors = [
      '[data-testid="ad-slot-container"]',
      '[data-testid="leaderboard-ad"]',
      '[data-testid="billboard-ad"]',
      '[data-testid="hpto-parent-container"]',
      '[data-testid="in-app-message-container"]',
      '[aria-label*="Advertisement"]',
      '[aria-label*="Quảng cáo"]',
    ];
    for (const sel of selectors) {
      document.querySelectorAll(sel).forEach((el) => {
        if (hideElement(el)) blocked++;
      });
    }

    // Tự động tắt tiếng khi Spotify Web phát quảng cáo âm thanh và bật lại ngay khi hết
    const titleLower = (document.title || '').toLowerCase();
    const adBadge = document.querySelector(
      '[data-testid="context-item-info-ad-subtitle"], [data-testid="ad-companion-card"]'
    );
    const isAdPlaying =
      Boolean(adBadge) ||
      titleLower.startsWith('advertisement') ||
      titleLower.startsWith('quảng cáo') ||
      titleLower.includes('spotify – advertisement');

    const muteBtn = document.querySelector('[data-testid="volume-bar-toggle-mute-button"]');
    if (muteBtn) {
      const label = (muteBtn.getAttribute('aria-label') || '').toLowerCase();
      const isCurrentlyMuted = label.includes('unmute') || label.includes('bật âm');
      if (isAdPlaying && !isCurrentlyMuted) {
        muteBtn.click();
        spotifyMutedByUs = true;
        blocked++;
      } else if (!isAdPlaying && spotifyMutedByUs && isCurrentlyMuted) {
        muteBtn.click();
        spotifyMutedByUs = false;
      }
    }

    if (blocked > 0) reportBlocked(blocked);
  }

  // =========================================================================
  // 3. BÁO VIỆT NAM & WEB PHỔ THÔNG: Dọn khung trống quảng cáo (Admicro/eClick/AdSense)
  // =========================================================================
  function scanGenericAds() {
    let blocked = 0;
    const selectors = [
      'ins.adsbygoogle',
      '[id^="admzone"]',
      '[id^="admicro"]',
      '.adm-ad',
      '.admicro-ad',
      '.eclick-ad',
      'iframe[src*="admicro.vn"]',
      'iframe[src*="amcdn.vn"]',
      'iframe[src*="doubleclick.net"]',
      'iframe[src*="googlesyndication.com"]',
      'iframe[src*="eclick.vn"]',
      'iframe[src*="mgid.com"]',
      'iframe[src*="taboola.com"]',
    ];
    for (const sel of selectors) {
      document.querySelectorAll(sel).forEach((el) => {
        if (hideElement(el)) blocked++;
      });
    }
    if (blocked > 0) reportBlocked(blocked);
  }

  // =========================================================================
  // 4. VƯỢT MÀN HÌNH CHỐNG ADBLOCK (Investing.com & Google Funding Choices)
  // =========================================================================
  const ANTI_ADBLOCK_TEXT_RE =
    /phần mềm chặn quảng cáo|trình chặn quảng cáo|cho phép miền này|ad\s*blocker|disable your adblock|turn off your ad\s*block|whitelist this site/i;

  function unlockPageScroll() {
    for (const root of [document.documentElement, document.body]) {
      if (!root) continue;
      const cs = getComputedStyle(root);
      if (cs.overflow === 'hidden' || cs.overflowY === 'hidden') {
        root.style.setProperty('overflow', 'auto', 'important');
        root.style.setProperty('overflow-y', 'auto', 'important');
      }
      if (cs.position === 'fixed') {
        root.style.setProperty('position', 'static', 'important');
      }
    }
  }

  function hideFullscreenBackdrops() {
    let hidden = 0;
    const vw = window.innerWidth || 1024;
    const vh = window.innerHeight || 768;
    document.querySelectorAll('body > div, body > section, body > aside').forEach((el) => {
      if (el.dataset.nsHidden === '1') return;
      const cs = getComputedStyle(el);
      if (cs.position !== 'fixed' && cs.position !== 'absolute') return;
      const z = parseInt(cs.zIndex, 10) || 0;
      if (z < 10) return;
      const r = el.getBoundingClientRect();
      const coversScreen = r.width >= vw * 0.8 && r.height >= vh * 0.8;
      const textLen = (el.innerText || '').trim().length;
      if (coversScreen && textLen === 0) {
        if (hideElement(el)) hidden++;
      }
    });
    return hidden;
  }

  function findModalRoot(el) {
    let target = el;
    let cur = el.parentElement;
    while (cur && cur !== document.body && cur !== document.documentElement) {
      const txtLen = (cur.innerText || '').trim().length;
      // Dừng nếu leo tới vùng chứa toàn bộ nội dung trang
      if (txtLen > 2500 || cur.id === '__next' || cur.tagName === 'MAIN') break;
      const cs = getComputedStyle(cur);
      target = cur;
      if (cs.position === 'fixed') {
        // Nếu đã gặp container fixed ngoài cùng của modal thì lấy nó làm gốc
        const parentCs = cur.parentElement && cur.parentElement !== document.body
          ? getComputedStyle(cur.parentElement)
          : null;
        if (!parentCs || parentCs.position !== 'fixed') break;
      }
      cur = cur.parentElement;
    }
    return target;
  }

  function getShadowRootSafe(el) {
    try {
      if (typeof chrome !== 'undefined' && chrome.dom && typeof chrome.dom.openOrClosedShadowRoot === 'function') {
        return chrome.dom.openOrClosedShadowRoot(el);
      }
    } catch (_) {}
    return el.shadowRoot || null;
  }

  // Nhận tín hiệu từ iframe con nếu popup anti-adblock nằm trong cross-origin iframe
  if (IS_TOP_FRAME) {
    window.addEventListener('message', (e) => {
      if (!e.data || e.data.type !== 'NS_ADBLOCK_IFRAME') return;
      if (!settings.enabled || !settings.defuseAntiAdblock || isWhitelisted(HOST, settings.whitelist)) return;
      let blocked = 0;
      document.querySelectorAll('iframe').forEach((frame) => {
        if (frame.contentWindow === e.source) {
          const target = findModalRoot(frame);
          if (hideElement(target)) blocked++;
        }
      });
      if (blocked > 0) {
        blocked += hideFullscreenBackdrops();
        unlockPageScroll();
        reportBlocked(blocked);
      }
    });
  }

  function scanAntiAdblock() {
    let blocked = 0;

    // Nếu đang ở trong iframe con: chỉ kiểm tra xem chính iframe này có phải popup anti-adblock không
    if (!IS_TOP_FRAME) {
      const bodyText = (document.body?.innerText || '').trim();
      if (bodyText.length > 0 && bodyText.length < 2500 && ANTI_ADBLOCK_TEXT_RE.test(bodyText)) {
        try {
          window.top.postMessage({ type: 'NS_ADBLOCK_IFRAME' }, '*');
        } catch (_) {}
        hideElement(document.documentElement);
      }
      return;
    }

    // 4A. Các khung anti-adblock nhận diện rõ ràng (Funding Choices + Investing.com)
    const knownSelectors = IS_INVESTING
      ? [
          '.fc-ab-root',
          '.fc-dialog-overlay',
          '[id^="adNotification"]',
          '[class^="ad-notification"]',
          '[class*="adBlock"]',
          '[class*="overlay_overlay"]',
          '.ad-blockers-section',
        ]
      : ['.fc-ab-root', '.fc-dialog-overlay'];

    for (const sel of knownSelectors) {
      document.querySelectorAll(sel).forEach((el) => {
        if (hideElement(el)) blocked++;
      });
    }

    // 4B. Quét same-origin / about:blank / srcdoc iframes chứa popup anti-adblock
    document.querySelectorAll('iframe').forEach((frame) => {
      if (frame.dataset.nsHidden === '1' || frame.closest('[data-ns-hidden="1"]')) return;
      try {
        const fBody = frame.contentDocument?.body;
        if (!fBody) return;
        const fText = (fBody.innerText || '').trim();
        if (fText.length > 0 && fText.length < 2500 && ANTI_ADBLOCK_TEXT_RE.test(fText)) {
          const target = findModalRoot(frame);
          if (hideElement(target)) blocked++;
        }
      } catch (_) {}
    });

    // 4C. Quét tổng quát mọi popup/overlay chứa thông điệp yêu cầu tắt Adblock
    // (Hỗ trợ cả Open Shadow DOM lẫn Closed Shadow DOM qua chrome.dom.openOrClosedShadowRoot)
    const rootsToScan = [document.body];
    if (document.body) {
      document.body.querySelectorAll('*').forEach((host) => {
        const sr = getShadowRootSafe(host);
        if (sr) rootsToScan.push(sr);
      });
    }

    for (const root of rootsToScan) {
      if (!root) continue;
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const val = (node.nodeValue || '').trim();
        if (val.length < 10 || val.length > 300) continue;
        if (!ANTI_ADBLOCK_TEXT_RE.test(val)) continue;

        const el = node.parentElement;
        if (!el || el.dataset.nsHidden === '1' || el.closest('[data-ns-hidden="1"]')) continue;

        // Nếu nằm trong Shadow DOM (open/closed) thì ẩn thẳng phần tử host ngoài light DOM
        if (root !== document.body && root.host) {
          const hostTarget = findModalRoot(root.host);
          if (hostTarget !== document.body && hostTarget !== document.documentElement) {
            if (hideElement(hostTarget)) blocked++;
          }
          continue;
        }

        // Xác nhận nằm trong một lớp nổi (fixed/absolute) hoặc container nhỏ của popup
        const modalRoot = findModalRoot(el);
        const cs = getComputedStyle(modalRoot);
        const isFloating =
          cs.position === 'fixed' ||
          cs.position === 'absolute' ||
          modalRoot.getAttribute('role') === 'dialog' ||
          modalRoot.getAttribute('aria-modal') === 'true' ||
          IS_INVESTING;

        if (isFloating && modalRoot !== document.body && modalRoot !== document.documentElement) {
          if (hideElement(modalRoot)) blocked++;
        }
      }
    }

    if (blocked > 0) {
      blocked += hideFullscreenBackdrops();
      unlockPageScroll();
      reportBlocked(blocked);
    }
  }

  function runScan() {
    if (!settings.enabled || isWhitelisted(HOST, settings.whitelist)) return;
    if (settings.defuseAntiAdblock) scanAntiAdblock();
    if (!IS_TOP_FRAME) return;
    if (IS_FACEBOOK && settings.blockFacebook) scanFacebook();
    else if (IS_YOUTUBE && settings.blockYoutube) scanYoutube();
    else if (IS_ZINGMP3 && settings.blockMusic) scanZingMp3();
    else if (IS_SPOTIFY && settings.blockMusic) scanSpotify();
    else if (settings.blockVnNews) scanGenericAds();
  }

  function scheduleScan() {
    if (scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      runScan();
    }, 180);
  }

  function applyActivation() {
    const active = settings.enabled && !isWhitelisted(HOST, settings.whitelist);
    const antiAdblockOn = active && settings.defuseAntiAdblock;
    if (active) {
      document.documentElement.classList.add('ns-active');
      document.documentElement.classList.toggle('ns-anti-adblock', antiAdblockOn);
      document.documentElement.classList.toggle('ns-investing', antiAdblockOn && IS_INVESTING);
      if (document.body) runScan();
      if (!observer) {
        observer = new MutationObserver(scheduleScan);
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
        });
      }
      if ((IS_FACEBOOK || IS_YOUTUBE || IS_SPOTIFY || IS_INVESTING) && !pollInterval) {
        pollInterval = setInterval(runScan, 1500);
      }
    } else {
      document.documentElement.classList.remove('ns-active', 'ns-anti-adblock', 'ns-investing');
      if (observer) {
        observer.disconnect();
        observer = null;
      }
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      unhideAll();
    }
  }

  // Khởi tạo từ chrome.storage
  chrome.storage.local.get(
    ['enabled', 'blockFacebook', 'blockYoutube', 'blockMusic', 'blockVnNews', 'defuseAntiAdblock', 'whitelist'],
    (res) => {
      settings = {
        enabled: res.enabled !== false,
        blockFacebook: res.blockFacebook !== false,
        blockYoutube: res.blockYoutube !== false,
        blockMusic: res.blockMusic !== false,
        blockVnNews: res.blockVnNews !== false,
        defuseAntiAdblock: res.defuseAntiAdblock !== false,
        whitelist: Array.isArray(res.whitelist) ? res.whitelist : [],
      };
      applyActivation();
    }
  );

  // Lắng nghe khi người dùng bật/tắt trong popup
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.enabled) settings.enabled = changes.enabled.newValue;
    if (changes.blockFacebook) settings.blockFacebook = changes.blockFacebook.newValue;
    if (changes.blockYoutube) settings.blockYoutube = changes.blockYoutube.newValue;
    if (changes.blockMusic) settings.blockMusic = changes.blockMusic.newValue;
    if (changes.blockVnNews) settings.blockVnNews = changes.blockVnNews.newValue;
    if (changes.defuseAntiAdblock) settings.defuseAntiAdblock = changes.defuseAntiAdblock.newValue;
    if (changes.whitelist) settings.whitelist = changes.whitelist.newValue || [];
    applyActivation();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runScan, { once: true });
  }
})();
