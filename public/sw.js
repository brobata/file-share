// Service worker for PWA install support
// Network-first strategy — always fetch fresh, fall back to cache for offline shell
// v3: stop caching /files/ previews (v2 kept file contents in Cache Storage,
// bad on a shared laptop); bumping the name makes activate delete the old cache
const CACHE = "file-explorer-v3";
const SHELL = ["/", "/manifest.json", "/icon-192.svg", "/icon-512.svg"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Only cache same-origin navigation and static assets — never cache API calls
  // Never cache API calls or file contents (previews under /files/)
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/files/")) return;

  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok && e.request.method === "GET") {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
