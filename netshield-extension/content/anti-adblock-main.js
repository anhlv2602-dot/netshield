(() => {
  'use strict';

  if (window.__nsAntiAdblockMainLoaded) return;
  window.__nsAntiAdblockMainLoaded = true;

  const HOST = (location.hostname || '').toLowerCase();

  // Lớp bảo vệ kép — KHÔNG BAO GIỜ can thiệp trang Thuế, HĐĐT, Chữ ký số, Ngân hàng
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
    'facebook.com', 'messenger.com', 'youtube.com', 'spotify.com', 'zingmp3.vn', 'mp3.zing.vn',
  ];

  if (PROTECTED_SUFFIXES.some((s) => HOST === s || HOST.endsWith('.' + s))) {
    return;
  }

  // 1. Khóa các cờ phát hiện Adblock phổ biến (Investing.com, generic scripts)
  function lockProperty(obj, prop, value) {
    try {
      Object.defineProperty(obj, prop, {
        configurable: true,
        enumerable: false,
        get() {
          return value;
        },
        set() {
          // Bỏ qua mọi nỗ lực ghi đè cờ phát hiện adblock
        },
      });
    } catch (_) {}
  }

  lockProperty(window, 'adNotificationDetected', false);
  lockProperty(window, 'google_ad_status', 1);
  lockProperty(window, 'canRunAds', true);
  lockProperty(window, 'isAdBlockActive', false);

  // 2. Giả lập fetch() thành công cho các URL mồi kiểm tra Adblock bị NetShield DNS chặn
  // (Tránh lỗi Failed to fetch kích hoạt popup anti-adblock trên Investing.com & báo quốc tế)
  const AD_BAIT_URL_RE =
    /pagead2\.googlesyndication\.com|doubleclick\.net|fundingchoicesmessages\.google\.com|pagead\/show_ads\.js|static\.ads-twitter\.com\/uwt\.js/i;

  const origFetch = window.fetch;
  if (typeof origFetch === 'function') {
    window.fetch = function netshieldFetch(input, init) {
      try {
        const url =
          typeof input === 'string'
            ? input
            : input && typeof input.url === 'string'
              ? input.url
              : '';
        if (url && AD_BAIT_URL_RE.test(url)) {
          return Promise.resolve(
            new Response('', {
              status: 200,
              statusText: 'OK',
              headers: { 'Content-Type': 'application/javascript' },
            })
          );
        }
      } catch (_) {}
      return origFetch.apply(this, arguments);
    };
  }

  // 3. Giả lập XHR thành công cho các URL mồi kiểm tra Adblock (bản legacy jQuery)
  const origXhrOpen = XMLHttpRequest.prototype.open;
  const origXhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function netshieldXhrOpen(method, url) {
    this.__nsBaitUrl = typeof url === 'string' && AD_BAIT_URL_RE.test(url);
    return origXhrOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function netshieldXhrSend() {
    if (this.__nsBaitUrl) {
      try {
        Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
        Object.defineProperty(this, 'status', { value: 200, configurable: true });
        Object.defineProperty(this, 'responseText', { value: '', configurable: true });
        setTimeout(() => {
          this.dispatchEvent(new Event('readystatechange'));
          this.dispatchEvent(new Event('load'));
          this.dispatchEvent(new Event('loadend'));
        }, 0);
        return;
      } catch (_) {}
    }
    return origXhrSend.apply(this, arguments);
  };
})();
