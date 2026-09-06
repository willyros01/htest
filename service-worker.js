/* FIDUNIO 0.9.6.4 isolated test-host service worker. Cache/transport only; no semantic transforms. */
const CACHE="fidunio-htest-0.9.6.4-bda5efee";
const PIN="https://cdn.jsdelivr.net/gh/willyros01/hermes@bda5efee19333b4b3a3108341d30431d20447754/";
const LOCAL=["./","./index.html","./version.js","./manifest.json","./htest-overrides.css","./test-diagnostics.html"];
const REMOTE=["styles.css","styles-0.9.0.css","local-security-ui.css","settings-sidebar.css","message-bubbles.css","back-button-visibility.css","iphone-overflow-fix.css","bootstrap.js","account-guard.js","auth-ui-clean.js","account-storage.js","app.js","firebase.js","firebase-config.js","local-security.js","new-message-owner.js","settings-lifecycle.js","e2ee-account-runtime.js","e2ee-account-lifecycle.js","e2ee-account-identity-manager.js","e2ee-account-firebase-adapter.js","e2ee-account-firestore-adapter.js","e2ee-account-crypto.js","e2ee-account-recovery-client.js","e2ee-account-message-runtime.js","e2ee-account-message-service.js","e2ee-account-message-crypto.js","test-diagnostics.css","test-diagnostics.js"].map(x=>PIN+x);
self.addEventListener("install",event=>event.waitUntil(caches.open(CACHE).then(cache=>Promise.allSettled([...LOCAL,...REMOTE].map(url=>cache.add(url)))).then(()=>self.skipWaiting())));
self.addEventListener("activate",event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener("fetch",event=>{
  if(event.request.method!=="GET")return;
  const u=new URL(event.request.url);
  if(u.hostname.endsWith("googleapis.com")||u.hostname.endsWith("firebaseio.com"))return;
  event.respondWith(fetch(event.request,{cache:"no-store"}).then(r=>{if(r&&r.ok){const c=r.clone();caches.open(CACHE).then(cache=>cache.put(event.request,c));}return r;}).catch(async()=>{const hit=await caches.match(event.request);if(hit)return hit;if(event.request.mode==="navigate")return caches.match("./index.html");throw new Error("offline and not cached");}));
});
