"""Install to home screen — the app, without an app store.

Chrome and Edge (Android, Windows, Mac) read the manifest below and offer to
install. Safari on iPhone never fires that prompt, so the same button explains
Share -> Add to Home Screen instead of pretending nothing is there.

Everything is served from this file rather than from disk on purpose: no icons
to drag into GitHub, and no edits to the big HTML pages — inject() adds the
tags to whatever HTML the app already serves. Changing the icon or the name is
a one-line change here and nothing else moves.
"""
import base64

from fastapi import APIRouter, Response

router = APIRouter(tags=["install"])

APP_NAME = "Buddy's Catalog"
APP_SHORT = "Catalog"          # what sits under the icon on a phone
APP_DESC = "Browse the catalog and place store orders."
THEME = "#16213f"                  # the phone's status bar while open
BACKGROUND = "#16213f"        # the splash screen behind the icon
START_URL = "/"
CACHE_VERSION = "v1"                 # bump to retire every installed cache

_ICON_180 = "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"
_ICON_192 = "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"
_ICON_512 = "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"


def _png(data_b64: str, seconds: int = 604800) -> Response:
    return Response(base64.b64decode(data_b64), media_type="image/png",
                    headers={"Cache-Control": f"public, max-age={seconds}"})


# ---------------------------------------------------------------- the manifest

@router.get("/manifest.webmanifest")
def manifest():
    """What the phone reads to decide this is installable."""
    return Response(
        __import__("json").dumps({
            "name": APP_NAME,
            "short_name": APP_SHORT,
            "description": APP_DESC,
            "start_url": START_URL,
            "scope": "/",
            "display": "standalone",       # no address bar once installed
            "orientation": "any",
            "theme_color": THEME,
            "background_color": BACKGROUND,
            "icons": [
                {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
                 "purpose": "any"},
                {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
                 "purpose": "any"},
                {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
                 "purpose": "maskable"},
            ],
        }),
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, max-age=3600"})


@router.get("/icon-192.png")
def icon_192():
    return _png(_ICON_192)


@router.get("/icon-512.png")
def icon_512():
    return _png(_ICON_512)


@router.get("/apple-touch-icon.png")
def apple_icon():
    return _png(_ICON_180)


@router.get("/apple-touch-icon-precomposed.png")
def apple_icon_precomposed():
    return _png(_ICON_180)


# ---------------------------------------------------------------- the worker

SW_JS = """
/* A phone will not offer to install a page that cannot answer a request, so
   this exists mostly to be here. It is network-first on purpose: the live
   answer always wins, and the cache is only reached for when there is no
   signal. Data is never cached — a stale price is worse than no price. */
const CACHE = 'shell-__CACHE_VERSION__';
const SHELL = ['/icon-192.png', '/apple-touch-icon.png'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim()));
});

function offlinePage() {
  return new Response(
    '<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">' +
    '<body style="margin:0;display:grid;place-items:center;height:100vh;' +
    'font:16px system-ui;background:#16213f;color:#fff;text-align:center">' +
    '<div><h2 style="margin:0 0 6px">No connection</h2>' +
    '<p style="opacity:.75;margin:0">Catalog needs a signal. ' +
    'It will pick up where you left off.</p></div>',
    {headers: {'Content-Type': 'text/html'}});
}

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (err) { return; }
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;     /* live data only */

  e.respondWith(
    fetch(req).then(res => {
      if (res && res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
      }
      return res;
    }).catch(() =>
      caches.match(req).then(hit =>
        hit || (req.mode === 'navigation' ? offlinePage() : Response.error()))));
});
"""


@router.get("/sw.js")
def service_worker():
    return Response(SW_JS.replace("__CACHE_VERSION__", CACHE_VERSION)
                         .replace("#16213f", BACKGROUND)
                         .replace("Catalog", APP_SHORT),
                    media_type="application/javascript",
                    headers={"Cache-Control": "no-cache",
                             "Service-Worker-Allowed": "/"})


# ---------------------------------------------------------------- the button

PWA_JS = """
/* The install button. Lives here rather than in the page so that changing it
   never means re-uploading a 190KB HTML file.

   Three states, and only one of them is a real prompt:
     Chrome/Edge  - the browser hands us a prompt, we show a button that fires it
     iPhone       - no prompt exists, so the button explains the two taps
     installed    - nothing at all
   Anything with data-install-app on it becomes a trigger too, so a menu item
   can open the same thing later without touching this file. */
(function () {
  var THEME = '#16213f';
  var NAME = 'Catalog';
  var KEY = 'installHidden';
  var deferred = null;

  function standalone() {
    return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches)
        || window.navigator.standalone === true;
  }
  function isIOS() {
    return /iphone|ipad|ipod/i.test(navigator.userAgent)
        || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  }
  function snoozed() {
    try {
      var t = parseInt(localStorage.getItem(KEY) || '0', 10);
      return t && (Date.now() - t) < 14 * 864e5;      /* asked recently, leave them be */
    } catch (e) { return false; }
  }
  function snooze() { try { localStorage.setItem(KEY, String(Date.now())); } catch (e) {} }

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/sw.js', {scope: '/'}).catch(function () {});
    });
  }

  var css = document.createElement('style');
  css.textContent =
    /* Bottom LEFT on purpose. The catalog already has a cart button bottom
       right at the top of the stacking order; anything put beside it is
       invisible to a thumb even though it looks fine on screen. */
    '#installBar{position:fixed;left:12px;right:12px;bottom:calc(12px + env(safe-area-inset-bottom));' +
    'z-index:2147482900;display:none;align-items:center;gap:13px;background:#fff;color:#1b2130;' +
    'border-radius:16px;padding:12px 14px;font:14px system-ui,-apple-system,Segoe UI,sans-serif;' +
    'box-shadow:0 10px 34px rgba(10,20,40,.3);border:1px solid #e7eaf2}' +
    '#installBar.show{display:flex}' +
    'body.has-installbar #cat-admin-link,body.has-installbar #__dtabs,'+
    'body.has-installbar #qcFab{bottom:calc(86px + env(safe-area-inset-bottom))!important}' +
    'body.qc-open #installBar{display:none!important}' +   /* cart is full screen */
    '#installBar img{width:40px;height:40px;border-radius:10px;flex:none;background:' + THEME + '}' +
    '#installBar .tx{min-width:0}' +
    '#installBar .tx b{display:block;font-size:15px;font-weight:800}' +
    '#installBar .tx span{display:block;font-size:12.5px;color:#5a6273;margin-top:1px}' +
    '#installBar .sp{margin-left:auto}' +
    '#installBar .go{border:0;border-radius:999px;background:#e0592a;color:#fff;font:800 14px system-ui;' +
    'padding:10px 20px;cursor:pointer;flex:none}' +
    '#installBar .x{width:28px;height:28px;border-radius:50%;border:0;background:#f0f2f7;' +
    'color:#5a6273;font:700 15px/1 system-ui;cursor:pointer;flex:none}' +
    '#installHow{position:fixed;inset:0;z-index:2147483600;display:none;align-items:flex-end;' +
    'justify-content:center;background:rgba(10,18,34,.5)}' +
    '#installHow.show{display:flex}' +
    '#installHow .card{background:#fff;color:#1b2130;border-radius:18px 18px 0 0;width:100%;' +
    'max-width:460px;padding:22px 22px calc(26px + env(safe-area-inset-bottom));' +
    'font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}' +
    '#installHow h3{margin:0 0 10px;font-size:18px}' +
    '#installHow ol{margin:0 0 16px;padding-left:20px}' +
    '#installHow li{margin-bottom:7px}' +
    '#installHow button{width:100%;padding:12px;border:0;border-radius:11px;background:' + THEME + ';' +
    'color:#fff;font:700 15px system-ui;cursor:pointer}';
  document.head.appendChild(css);

  var bar = document.createElement('div');
  bar.id = 'installBar';
  bar.innerHTML = '<img src="/icon-192.png" alt="">' +
                  '<div class="tx"><b>Install ' + NAME + '</b>' +
                  '<span>Runs full screen, works like an app.</span></div>' +
                  '<span class="sp"></span>' +
                  '<button class="go" type="button">Install</button>' +
                  '<button class="x" type="button" aria-label="Not now">\\u00d7</button>';
  var sheet = document.createElement('div');
  sheet.id = 'installHow';
  sheet.innerHTML =
    '<div class="card"><h3>Add ' + NAME + ' to your Home Screen</h3>' +
    '<ol><li>Tap the <b>Share</b> button at the bottom of Safari.</li>' +
    '<li>Scroll down and tap <b>Add to Home Screen</b>.</li>' +
    '<li>Tap <b>Add</b>. It opens like an app, with no address bar.</li></ol>' +
    '<button type="button">Got it</button></div>';

  function attach() {
    if (!document.body) return;
    document.body.appendChild(bar);
    new MutationObserver(function () {
      document.body.classList.toggle('has-installbar', bar.classList.contains('show'));
    }).observe(bar, {attributes: true, attributeFilter: ['class']});
    document.body.appendChild(sheet);
    bar.querySelector('.x').addEventListener('click', function (e) {
      e.stopPropagation(); bar.classList.remove('show'); snooze();
    });
    bar.querySelector('.go').addEventListener('click', function (e) { e.stopPropagation(); open(); });
    sheet.addEventListener('click', function (e) {
      if (e.target === sheet || e.target.tagName === 'BUTTON') sheet.classList.remove('show');
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-install-app]'), function (el) {
      el.addEventListener('click', function (e) { e.preventDefault(); open(); });
    });
    if (!standalone() && isIOS() && !snoozed()) show();
    window.addEventListener('resize', function () {
      if (bar.classList.contains('show')) place();
    });
  }

  /* Both bottom corners of the catalog are already spoken for — the cart on the
     right, the sign-out badge on the left — and a button underneath another one
     looks perfectly fine while being impossible to tap. So after showing the
     pill, ask the browser what is actually on top at that spot and step above
     whatever is in the way. */
  function place() {
    return;   /* full-width banner needs no corner-dodging */
    try {
      bar.style.bottom = 'calc(14px + env(safe-area-inset-bottom))';
      for (var pass = 0; pass < 4; pass++) {
        var r = bar.getBoundingClientRect();
        if (!r.width) return;
        var pts = [[r.left + 8, r.top + 8],
                   [r.left + r.width / 2, r.top + r.height / 2],
                   [r.right - 8, r.bottom - 8]];
        var lift = 0;
        for (var i = 0; i < pts.length; i++) {
          var els = document.elementsFromPoint(pts[i][0], pts[i][1]) || [];
          var top = els[0];
          if (!top || top === bar || bar.contains(top)) continue;
          /* Measure the whole floating thing, not the bit under the finger:
             the sign-out badge is fixed, but the button inside it is not, and
             stepping above the button alone still lands on the badge. */
          var node = top, pinned = null;
          while (node && node !== document.body) {
            var cs = window.getComputedStyle(node);
            if (cs.position === 'fixed' || cs.position === 'sticky') { pinned = node; break; }
            node = node.parentElement;
          }
          var er = (pinned || top).getBoundingClientRect();
          lift = Math.max(lift, window.innerHeight - er.top + 10);
        }
        if (!lift) return;
        bar.style.bottom = Math.min(lift, window.innerHeight / 2) + 'px';
      }
    } catch (e) {}
  }

  function show() {
    bar.classList.add('show');
    /* The sign-out badge and the cart button are built by the page after it
       loads, so a single measurement taken now would be taken against a corner
       that is still empty. Re-check for a few seconds while the page settles. */
    [0, 300, 1000, 2500, 5000].forEach(function (ms) { setTimeout(place, ms); });
  }

  function open() {
    if (deferred) {
      bar.classList.remove('show');
      deferred.prompt();
      deferred.userChoice.then(function (c) {
        if (c && c.outcome !== 'accepted') snooze();
        deferred = null;
      });
    } else {
      sheet.classList.add('show');
    }
  }

  window.addEventListener('beforeinstallprompt', function (e) {
    /* No preventDefault: the browser shows its own install popup, the same
       one the other apps get. We keep the event so our button works too. */
    deferred = e;
    if (!snoozed()) show();
  });
  window.addEventListener('appinstalled', function () {
    bar.classList.remove('show');
    try { localStorage.removeItem(KEY); } catch (err) {}
  });

  window.installApp = open;          /* so a menu item can call it later */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attach);
  } else { attach(); }
})();
"""


@router.get("/pwa.js")
def pwa_js():
    return Response(PWA_JS.replace("#16213f", THEME).replace("Catalog", APP_SHORT),
                    media_type="application/javascript",
                    headers={"Cache-Control": "no-cache"})


# ---------------------------------------------------------------- page tags

HEAD_TAGS = (
    '<link rel="manifest" href="/manifest.webmanifest">'
    '<meta name="theme-color" content="#16213f">'
    '<meta name="mobile-web-app-capable" content="yes">'
    '<meta name="apple-mobile-web-app-capable" content="yes">'
    '<meta name="apple-mobile-web-app-status-bar-style" content="default">'
    '<meta name="apple-mobile-web-app-title" content="Catalog">'
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">'
    '<link rel="icon" href="/icon-192.png">'
)


def inject(html):
    """Add the install tags to a page that knows nothing about them.

    Takes str or bytes and gives back the same kind, so it can sit in front of
    either way of serving a file. Doing nothing at all is the correct outcome
    for a page that already has them.
    """
    raw = isinstance(html, (bytes, bytearray))
    text = html.decode("utf-8", "replace") if raw else html
    if "manifest.webmanifest" not in text:
        tags = HEAD_TAGS.replace("#16213f", THEME).replace("Catalog", APP_SHORT)
        if "</head>" in text:
            text = text.replace("</head>", tags + "</head>", 1)
        else:
            text = tags + text
    if "/pwa.js" not in text:
        tag = '<script src="/pwa.js" defer></script>'
        if "</body>" in text:
            text = text.replace("</body>", tag + "</body>", 1)
        else:
            text = text + tag
    return text.encode("utf-8") if raw else text
