/**
 * THE OPTICAL HUB — High Reliability Service Worker (v3)
 * Completely eliminates CSP & MIME type conflicts.
 */

const CACHE_NAME = 'optical-hub-v4';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(keys.map((key) => caches.delete(key)));
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // 1. NEVER intercept third-party CDN scripts, fonts, or APIs
  if (!event.request.url.startsWith(self.location.origin)) {
    return;
  }

  // 2. Pass-through for all dynamic APIs
  if (event.request.url.includes('/api/')) {
    return;
  }

  // 3. For page navigation (HTML document) only, fallback to offline index if network fails
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/index.html') || caches.match('/'))
    );
    return;
  }

  // 4. For local images/assets: network-first, do NOT fallback to HTML
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
