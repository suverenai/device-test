// Service worker: makes the page installable and receives test notifications.
// Every push is logged to IndexedDB so the page can count what arrived.
const DB = 'device-test', STORE = 'kv';

function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function appendLog(key, item) {
  const d = await db();
  return new Promise((res, rej) => {
    const tx = d.transaction(STORE, 'readwrite');
    const st = tx.objectStore(STORE);
    const g = st.get(key);
    g.onsuccess = () => { const list = g.result || []; list.push(item); st.put(list, key); };
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {}); // presence of a fetch handler helps installability on Android

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = { text: event.data && event.data.text() }; }
  event.waitUntil((async () => {
    await appendLog('push_log', { n: data.n ?? null, sent_at: data.sent_at ?? null, received_at: Date.now() });
    await self.registration.showNotification('Suveren device test', {
      body: 'Test notification ' + (data.n ?? '') + '. Tap to open the app.',
      tag: 'test-' + (data.n ?? Date.now()),
      icon: 'icon-192.png',
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    await appendLog('push_taps', { tag: event.notification.tag, at: Date.now() });
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) { if ('focus' in c) { c.navigate('./?from=push'); return c.focus(); } }
    return self.clients.openWindow('./?from=push');
  })());
});
