// Suveren device test — step 1 of the device-keys plan (checklist 12.1).
// Every result is stored on this device and exported as JSON with "Copy results".
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from 'https://cdn.jsdelivr.net/npm/@hpke/core@1.9.0/+esm';

const VERSION = 'device-test 3';
const $ = (id) => document.getElementById(id);
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
};
const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const sessionId = Math.random().toString(36).slice(2, 10);

// ---------- storage ----------
function openDb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('device-test', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
const dbp = openDb();
async function kvGet(k) { const d = await dbp; return new Promise((res, rej) => { const q = d.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); }
async function kvSet(k, v) { const d = await dbp; return new Promise((res, rej) => { const tx = d.transaction('kv', 'readwrite'); tx.objectStore('kv').put(v, k); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); }

let results = {};
async function setResult(id, status, detail) {
  results[id] = { status, detail, at: new Date().toISOString(), standalone };
  await kvSet('results', results);
  render();
}

// ---------- check list (numbers = plan 12.1) ----------
const CHECKS = [
  { id: '1', title: 'Ed25519 key that cannot be exported; sign and verify', auto: true },
  { id: '2', title: 'X25519 key that cannot be exported; key agreement', auto: true },
  { id: '3', title: 'Keys survive closing the app, a phone restart and 8 days', auto: true },
  { id: '3b', title: 'Which key types survive being stored (diagnostic for 3)', auto: true },
  { id: '3c', title: 'Fallback: reading key stored wrapped, survives restart and 8 days', auto: true },
  { id: '4', title: "Open a proposal that today's gateway encrypted", auto: true },
  { id: '5', title: 'Signatures: phone ↔ hap-core, both ways', auto: true },
  { id: '6', title: 'Persistent storage granted', auto: true },
  { id: '17', title: 'Speed: 30 decryptions and 1 signature', auto: true },
  { id: '18', title: 'hap-core 0.13.0 loads and verifies a signature', auto: true },
  { id: '7', title: 'Camera inside the app reads a 400-character QR code, also after reopening' },
  { id: '8', title: 'Create a passkey with Face ID / fingerprint' },
  { id: '9', title: 'Use the passkey 10 times in a row (Face ID, and once with the PIN)' },
  { id: '11', title: 'PRF extension available (recorded with 8 and 9)' },
  { id: '12', title: 'Notification arrives with the app closed and the phone locked; tapping opens the app' },
  { id: '13', title: '20 notifications over two days all arrive' },
  { id: '14', title: 'App switcher shows a blank page' },
  { id: '15', title: 'Removing the icon and adding it again gives an empty app' },
  { id: '16', title: 'A second "Add to Home Screen" gives a second, separate app' },
  { id: '20', title: 'Print the recovery sheet, and save it as PDF to Files' },
  { id: '21', title: 'An email link: does it open the installed app or the browser?' },
  { id: '10', title: '(optional) Use this passkey from the Mac via "passkey from another device"' },
];

function render() {
  for (const c of CHECKS) {
    const el = $('c' + c.id);
    if (!el) continue;
    const r = results[c.id];
    const st = el.querySelector('.st');
    st.className = 'st ' + (r ? r.status : 'todo');
    st.textContent = r ? r.status.toUpperCase() : 'not run';
    el.querySelector('.detail').textContent = r ? (typeof r.detail === 'string' ? r.detail : JSON.stringify(r.detail)) : '';
  }
}

function card(c, bodyHtml = '') {
  const div = document.createElement('div');
  div.className = 'check'; div.id = 'c' + c.id;
  div.innerHTML = `<div class="head"><span class="title">${c.id}. ${c.title}</span><span class="st todo">not run</span></div>${bodyHtml}<div class="detail"></div>`;
  return div;
}
function yesNo(id, question) {
  return `<p>${question}</p><button data-yes="${id}">Yes</button><button class="sec" data-no="${id}">No</button>`;
}

// ---------- automatic checks ----------
let fixtures;
async function loadFixtures() { fixtures = fixtures || await (await fetch('fixtures.json', { cache: 'no-store' })).json(); return fixtures; }
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

async function c1() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  let exportBlocked = false;
  try { await crypto.subtle.exportKey('pkcs8', kp.privateKey); } catch { exportBlocked = true; }
  const msg = new TextEncoder().encode('suveren device test');
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, msg);
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, kp.publicKey, sig, msg);
  if (ok && exportBlocked && kp.privateKey.extractable === false) return ['pass', 'sign/verify ok, export refused'];
  return ['fail', { verify: ok, exportBlocked, extractable: kp.privateKey.extractable }];
}
async function c2() {
  const a = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const b = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const ab = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: b.publicKey }, a.privateKey, 256));
  const ba = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: a.publicKey }, b.privateKey, 256));
  let exportBlocked = false;
  try { await crypto.subtle.exportKey('pkcs8', a.privateKey); } catch { exportBlocked = true; }
  const same = ab.every((v, i) => v === ba[i]);
  return same && exportBlocked ? ['pass', 'agreement ok, export refused'] : ['fail', { same, exportBlocked }];
}
async function c3() {
  let keys = await kvGet('keys');
  const now = Date.now();
  const hadStored = (await kvGet('keys_written_at')) || null;
  if (hadStored && !(keys && keys.sign && keys.sign.privateKey)) {
    return ['fail', { stored_at: new Date(hadStored).toISOString(), read_back: keys === null ? 'null' : typeof keys, note: 'keys were written but do not read back' }];
  }
  const log = (await kvGet('open_log')) || [];
  if (!keys) {
    const sign = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    const read = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    keys = { sign, read, created_at: now };
    await kvSet('keys', keys);
    await kvSet('keys_written_at', now);
    const back = await kvGet('keys');
    if (!(back && back.sign && back.sign.privateKey)) return ['fail', { read_back_same_session: back === null ? 'null' : typeof back, note: 'keys written but read back empty' }];
  }
  const msg = new TextEncoder().encode('persist ' + now);
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, keys.sign.privateKey, msg);
  const ok1 = await crypto.subtle.verify({ name: 'Ed25519' }, keys.sign.publicKey, sig, msg);
  const other = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  let ok2 = true;
  try { await crypto.subtle.deriveBits({ name: 'X25519', public: other.publicKey }, keys.read.privateKey, 256); } catch { ok2 = false; }
  const restartMarked = (await kvGet('restart_marked_at')) || null;
  log.push({ at: now, session: sessionId, ok: ok1 && ok2, standalone });
  await kvSet('open_log', log);
  const days = (now - keys.created_at) / 86400000;
  const sessions = new Set(log.filter((l) => l.ok).map((l) => l.session)).size;
  const afterRestart = restartMarked && log.some((l) => l.ok && l.at > restartMarked);
  const detail = { created: new Date(keys.created_at).toISOString(), days_since: +days.toFixed(2), app_opens_ok: sessions, after_restart_ok: !!afterRestart, last_ok: ok1 && ok2 };
  if (!(ok1 && ok2)) return ['fail', detail];
  if (days >= 8 && afterRestart && sessions >= 3) return ['pass', detail];
  return ['record', { ...detail, still_needed: [days < 8 && 'open again after 8 days', !afterRestart && 'restart the phone, then open the app', sessions < 3 && 'close and reopen the app'].filter(Boolean) }];
}
// Keys for this session: the stored ones if they read back, else fresh ones (so 5 and 17 test
// their own subject even when storage fails; storage itself is check 3 and 3b).
let _sessionKeys;
async function sessionKeys() {
  if (_sessionKeys) return _sessionKeys;
  const k = await kvGet('keys');
  if (k && k.sign && k.sign.privateKey) return (_sessionKeys = k);
  return (_sessionKeys = { sign: await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) });
}
// 3b: which key types survive a write and read in IndexedDB, in a fresh transaction.
async function c3b() {
  const kinds = {
    ed25519: () => crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']),
    x25519: () => crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']),
    ecdsa_p256: () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']),
    ecdh_p256: () => crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']),
    aes_gcm: () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
  };
  const out = {};
  for (const [name, gen] of Object.entries(kinds)) {
    const key = await gen();
    const priv = key.privateKey || key;
    const r = { write: null, read_back: null, usable: null };
    try { await kvSet('diag_' + name, priv); r.write = 'ok'; } catch (e) { r.write = e.name; }
    try {
      const back = await kvGet('diag_' + name);
      r.read_back = back === null ? 'null' : back === undefined ? 'undefined' : (back instanceof CryptoKey ? 'CryptoKey' : typeof back);
      if (back instanceof CryptoKey) {
        if (name === 'ed25519') await crypto.subtle.sign({ name: 'Ed25519' }, back, new Uint8Array(8));
        if (name === 'ecdsa_p256') await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, back, new Uint8Array(8));
        if (name === 'aes_gcm') await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, back, new Uint8Array(8));
        if (name === 'x25519') { const o = await kinds.x25519(); await crypto.subtle.deriveBits({ name: 'X25519', public: o.publicKey }, back, 256); }
        if (name === 'ecdh_p256') { const o = await kinds.ecdh_p256(); await crypto.subtle.deriveBits({ name: 'ECDH', public: o.publicKey }, back, 256); }
        r.usable = true;
      }
    } catch (e) { r.usable = e.name; }
    // wrapped in an object, as check 3 stores them
    try { await kvSet('diag_obj_' + name, { k: priv }); const b = await kvGet('diag_obj_' + name); r.in_object = b === null ? 'null' : (b && b.k instanceof CryptoKey) ? 'CryptoKey' : JSON.stringify(b); } catch (e) { r.in_object = e.name; }
    out[name] = r;
  }
  const okOkp = out.ed25519.read_back === 'CryptoKey' && out.x25519.read_back === 'CryptoKey' && out.ed25519.usable === true && out.x25519.usable === true;
  return [okOkp ? 'pass' : 'fail', out];
}
// 3c: fallback for the reading key. The X25519 key is wrapped by a non-extractable AES key
// (which IndexedDB stores), kept only as ciphertext, and unwrapped as non-extractable for use.
async function c3c() {
  const now = Date.now();
  let st = await kvGet('wrapped_reader');
  let wk = await kvGet('wrap_key');
  if (!st || !(wk instanceof CryptoKey)) {
    wk = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
    const x = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.wrapKey('pkcs8', x.privateKey, wk, { name: 'AES-GCM', iv }));
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', x.publicKey));
    st = { wrapped: b64u.enc(wrapped), iv: b64u.enc(iv), pub: b64u.enc(pub), created_at: now };
    await kvSet('wrap_key', wk);
    await kvSet('wrapped_reader', st);
    wk = await kvGet('wrap_key');
    if (!(wk instanceof CryptoKey)) return ['fail', 'AES wrapping key does not read back'];
  }
  const priv = await crypto.subtle.unwrapKey('pkcs8', b64u.dec(st.wrapped), wk, { name: 'AES-GCM', iv: b64u.dec(st.iv) }, { name: 'X25519' }, false, ['deriveBits']);
  const pubKey = await crypto.subtle.importKey('raw', b64u.dec(st.pub), { name: 'X25519' }, true, []);
  // seal a test CEK to our own public key with today's suite, then open it with the unwrapped key
  const sender = await suite.createSenderContext({ recipientPublicKey: pubKey });
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const ct = await sender.seal(secret);
  const rc = await suite.createRecipientContext({ recipientKey: { privateKey: priv, publicKey: pubKey }, enc: sender.enc });
  const opened = new Uint8Array(await rc.open(ct));
  const ok = opened.every((v, i) => v === secret[i]) && priv.extractable === false;
  const log = (await kvGet('wrapped_log')) || [];
  log.push({ at: now, session: sessionId, ok });
  await kvSet('wrapped_log', log);
  const restartMarked = (await kvGet('restart_marked_at')) || null;
  const days = (now - st.created_at) / 86400000;
  const sessions = new Set(log.filter((l) => l.ok).map((l) => l.session)).size;
  const afterRestart = restartMarked && log.some((l) => l.ok && l.at > restartMarked);
  const detail = { created: new Date(st.created_at).toISOString(), days_since: +days.toFixed(2), app_opens_ok: sessions, after_restart_ok: !!afterRestart, unwrapped_extractable: priv.extractable, opened: ok };
  if (!ok) return ['fail', detail];
  if (days >= 8 && afterRestart && sessions >= 3) return ['pass', detail];
  return ['record', { ...detail, still_needed: [days < 8 && 'open again after 8 days', !afterRestart && 'restart the phone, then open the app', sessions < 3 && 'close and reopen the app'].filter(Boolean) }];
}
async function importFixtureReader() {
  const f = await loadFixtures();
  const privateKey = await crypto.subtle.importKey('jwk', f.x25519_jwk, { name: 'X25519' }, false, ['deriveBits']);
  const publicKey = await crypto.subtle.importKey('raw', b64u.dec(f.x25519_jwk.x), { name: 'X25519' }, true, []);
  return { privateKey, publicKey };
}
async function openFixture(reader) {
  const f = await loadFixtures();
  const ctx = await suite.createRecipientContext({ recipientKey: reader, enc: b64u.dec(f.hpke.enc) });
  const cek = new Uint8Array(await ctx.open(b64u.dec(f.hpke.ct)));
  const all = b64u.dec(f.hpke.intentCiphertext);
  const aes = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12) }, aes, all.slice(12));
  return new TextDecoder().decode(plain);
}
async function c4() {
  const f = await loadFixtures();
  const reader = await importFixtureReader();
  if (reader.privateKey.extractable) return ['fail', 'imported key is extractable'];
  const text = await openFixture(reader);
  return text === f.hpke.plaintext ? ['pass', 'opened with a non-extractable X25519 key: "' + text.slice(0, 40) + '…"'] : ['fail', 'wrong plaintext'];
}
let hap;
async function loadHap() { hap = hap || await import('https://cdn.jsdelivr.net/npm/@humanagencyp/hap-core@0.13.0/+esm'); return hap; }
async function c5() {
  const f = await loadFixtures();
  const h = await loadHap();
  // a) hap-core (noble) signature, verified by the phone's own WebCrypto
  const pub = await crypto.subtle.importKey('raw', b64u.dec(f.ed25519.public_key), { name: 'Ed25519' }, false, ['verify']);
  const bytes = h.approvalSigningBytes(f.ed25519.approval);
  const okA = await crypto.subtle.verify({ name: 'Ed25519' }, pub, b64u.dec(f.ed25519.signature), bytes);
  // b) phone signature, verified by hap-core's verifier
  const keys = await sessionKeys();
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keys.sign.publicKey));
  const did = h.encodeDidKey(rawPub);
  const approval = { ...f.ed25519.approval, approver_did: did, nonce: 'phone-' + sessionId, decided_at: Math.floor(Date.now() / 1000) };
  const sig = b64u.enc(await crypto.subtle.sign({ name: 'Ed25519' }, keys.sign.privateKey, h.approvalSigningBytes(approval)));
  let okB = true, errB = null;
  try { await h.verifyApproval(approval, sig, did); } catch (e) { okB = false; errB = String(e.message || e); }
  const detail = { hapcore_to_phone: okA, phone_to_hapcore: okB, err: errB, phone_did: did, phone_approval: approval, phone_signature: sig };
  return okA && okB ? ['pass', detail] : ['fail', detail];
}
async function c6() {
  const has = !!(navigator.storage && navigator.storage.persist);
  if (!has) return ['record', 'navigator.storage.persist not available'];
  const before = await navigator.storage.persisted();
  const granted = before || await navigator.storage.persist();
  const est = navigator.storage.estimate ? await navigator.storage.estimate() : null;
  return ['record', { persisted_before: before, persist_answer: granted, quota_mb: est ? Math.round(est.quota / 1e6) : null }];
}
async function c17() {
  const reader = await importFixtureReader();
  const t0 = performance.now();
  for (let i = 0; i < 30; i++) await openFixture(reader);
  const t1 = performance.now();
  const keys = await sessionKeys();
  await crypto.subtle.sign({ name: 'Ed25519' }, keys.sign.privateKey, new Uint8Array(64));
  const t2 = performance.now();
  return ['record', { ms_30_opens: Math.round(t1 - t0), ms_1_sign: +(t2 - t1).toFixed(1) }];
}
async function c18() {
  const f = await loadFixtures();
  const h = await loadHap();
  try { await h.verifyApproval(f.ed25519.approval, f.ed25519.signature, f.ed25519.did); return ['pass', 'loaded and verified']; }
  catch (e) { return ['fail', String(e.message || e)]; }
}
const AUTO = { '1': c1, '2': c2, '3': c3, '3b': c3b, '3c': c3c, '4': c4, '5': c5, '6': c6, '17': c17, '18': c18 };
async function runAuto() {
  for (const id of ['1', '2', '3', '3b', '3c', '4', '5', '6', '18', '17']) {
    try { const [s, d] = await AUTO[id](); await setResult(id, s, d); }
    catch (e) { await setResult(id, 'fail', String(e && (e.name + ': ' + e.message) || e)); }
  }
}

// ---------- camera (7) ----------
let stream;
async function scan() {
  const f = await loadFixtures();
  const v = $('video');
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch (e) { return setResult('7', 'fail', 'camera refused: ' + e.name); }
  v.srcObject = stream; v.style.display = 'block'; await v.play();
  const canvas = document.createElement('canvas'); const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const started = Date.now();
  const tick = async () => {
    if (!stream) return;
    if (v.videoWidth) {
      canvas.width = v.videoWidth; canvas.height = v.videoHeight;
      ctx.drawImage(v, 0, 0);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data) {
        stopScan();
        const log = (await kvGet('scan_log')) || [];
        log.push({ at: Date.now(), session: sessionId, ok: code.data === f.qr_text, len: code.data.length, ms: Date.now() - started });
        await kvSet('scan_log', log);
        const okSessions = new Set(log.filter((l) => l.ok).map((l) => l.session)).size;
        if (code.data !== f.qr_text) return setResult('7', 'fail', { read_length: code.data.length, matches: false });
        return setResult('7', okSessions >= 2 ? 'pass' : 'record', { scans_ok: log.filter((l) => l.ok).length, app_opens_with_ok_scan: okSessions, last_ms: Date.now() - started, still_needed: okSessions >= 2 ? [] : ['close the app, reopen it, scan again'] });
      }
    }
    if (Date.now() - started > 60000) { stopScan(); return setResult('7', 'fail', 'no QR code read within 60 s'); }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
function stopScan() { if (stream) stream.getTracks().forEach((t) => t.stop()); stream = null; $('video').style.display = 'none'; }

// ---------- passkeys (8, 9, 11) ----------
function flagsOf(authData) { const f = new Uint8Array(authData)[32]; return { up: !!(f & 1), uv: !!(f & 4), be: !!(f & 8), bs: !!(f & 16) }; }
async function createPasskey() {
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: location.hostname, name: 'Suveren device test' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'device-test', displayName: 'Device test' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      timeout: 120000,
      extensions: { prf: {} },
    } });
    const ad = cred.response.getAuthenticatorData ? cred.response.getAuthenticatorData() : null;
    const fl = ad ? flagsOf(ad) : null;
    const ext = cred.getClientExtensionResults();
    await kvSet('passkey_id', b64u.enc(cred.rawId));
    await kvSet('passkey_uses', []);
    const alg = cred.response.getPublicKeyAlgorithm ? cred.response.getPublicKeyAlgorithm() : null;
    await setResult('8', fl && fl.uv ? 'pass' : 'fail', { uv: fl && fl.uv, flags: fl, alg, attachment: cred.authenticatorAttachment, rp_id: location.hostname });
    await setResult('11', 'record', { prf_at_create: ext.prf ? ext.prf : 'no prf result' });
  } catch (e) { await setResult('8', 'fail', e.name + ': ' + e.message); }
}
async function usePasskey() {
  const id = await kvGet('passkey_id');
  if (!id) return setResult('9', 'fail', 'create the passkey first (check 8)');
  try {
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: b64u.dec(id) }],
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: new TextEncoder().encode('suveren-device-test-prf') } } },
    } });
    const fl = flagsOf(cred.response.authenticatorData);
    const ext = cred.getClientExtensionResults();
    const uses = (await kvGet('passkey_uses')) || [];
    uses.push({ at: Date.now(), uv: fl.uv, session: sessionId });
    await kvSet('passkey_uses', uses);
    const okCount = uses.filter((u) => u.uv).length;
    await setResult('9', okCount >= 10 && fl.uv ? 'pass' : (fl.uv ? 'record' : 'fail'), { uses_with_uv: okCount, of: uses.length, last_uv: fl.uv, still_needed: okCount >= 10 ? ['once with the PIN instead of Face ID: confirm below'] : [`${10 - okCount} more`] });
    const prev = results['11'] && results['11'].detail || {};
    await setResult('11', 'record', { ...prev, prf_at_get: ext.prf && ext.prf.results ? 'result returned' : 'no prf result' });
  } catch (e) {
    const uses = (await kvGet('passkey_uses')) || [];
    uses.push({ at: Date.now(), error: e.name });
    await kvSet('passkey_uses', uses);
    await setResult('9', 'fail', e.name + ': ' + e.message);
  }
}

// ---------- notifications (12, 13) ----------
async function subscribePush() {
  const f = await loadFixtures();
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return setResult('12', 'fail', 'no push support in this mode' + (standalone ? '' : ' (open from the home screen)'));
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') return setResult('12', 'fail', 'permission: ' + perm);
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64u.dec(f.vapid_public_key) });
  await kvSet('push_sub', sub.toJSON());
  await setResult('12', 'record', { subscribed: true, still_needed: ['copy results to the Mac; test notifications are then sent', 'lock the phone and wait'] });
}
async function pushStatus() {
  const log = (await kvGet('push_log')) || [];
  const taps = (await kvGet('push_taps')) || [];
  const sub = await kvGet('push_sub');
  if (!sub) return;
  const nums = new Set(log.map((l) => l.n).filter((n) => n !== null));
  const fromPush = new URLSearchParams(location.search).get('from') === 'push';
  await setResult('12', log.length && (taps.length || fromPush) ? 'pass' : 'record', { received: log.length, tapped: taps.length, opened_from_push_now: fromPush });
  await setResult('13', nums.size >= 20 ? 'pass' : 'record', { distinct_received: nums.size, of: 20 });
}

// ---------- email link (21) ----------
function linkCheck() {
  const p = new URLSearchParams(location.search);
  if (p.get('from') === 'link') setResult('21', 'record', { link_opened_in: standalone ? 'installed app' : 'browser' });
}

// ---------- build the page ----------
async function build() {
  results = (await kvGet('results')) || {};
  $('mode').className = 'banner' + (standalone ? ' ok' : '');
  $('mode').innerHTML = standalone
    ? '<b>Running as the installed app.</b> Good: results count.'
    : '<b>Running in the browser tab.</b> First add this page to your home screen (Share → Add to Home Screen), then open it from the icon. Results from the tab are marked and do not count.';

  const auto = $('auto');
  for (const c of CHECKS.filter((c) => c.auto)) auto.appendChild(card(c, c.id === '3' ? '<button class="sec" id="markRestart">I am about to restart the phone</button>' : ''));
  const man = $('manual');
  const bodies = {
    '7': `<p>On your Mac, open <b>suverenai.github.io/device-test/qr.html</b>. Then press Scan and point the phone at the code.</p><button id="scan">Scan</button><button class="sec" id="stopScan">Stop</button><video id="video" playsinline muted style="display:none"></video>`,
    '8': `<button id="pkCreate">Create passkey</button>`,
    '9': `<button id="pkUse">Use passkey</button>` + yesNo('9pin', 'Did one of the uses go through with the phone PIN instead of Face ID? (Cover the camera or look away until it offers the PIN.)'),
    '11': `<p class="muted">Recorded automatically with 8 and 9.</p>`,
    '12': `<button id="pushSub">Allow notifications</button><p class="muted">Then copy results to the Mac. I send test notifications; lock the phone and wait for them.</p>`,
    '13': `<p class="muted">Counted automatically from the notifications that arrived.</p>`,
    '14': yesNo('14', 'Swipe up to the app switcher. Is the preview of this app blank (no text)?'),
    '15': yesNo('15', 'Do this last. Remove the home-screen icon, add the page again, open it. Is the app empty (all checks "not run")?'),
    '16': yesNo('16', 'Add the page to the home screen a second time. Is the second icon a separate app (its checks "not run")?'),
    '20': `<button id="print">Print test sheet</button>` + yesNo('20print', 'Did the print dialog open?') + yesNo('20pdf', 'Could you save it as a PDF to Files?'),
    '21': `<p>Copy this link, send it to yourself by email, and tap it in Mail on this phone:</p><input readonly value="${location.origin}${location.pathname}?from=link"><button id="copyLink">Copy link</button><p class="muted">The result records where it opened.</p>`,
    '10': `<p>On the Mac in Chrome or Safari, open <b>suverenai.github.io/device-test/desktop.html</b> and follow it.</p>` + yesNo('10', 'Did the Mac sign in with the passkey from this phone?'),
  };
  for (const c of CHECKS.filter((c) => !c.auto)) man.appendChild(card(c, bodies[c.id] || ''));
  render();

  $('runAuto').onclick = runAuto;
  $('markRestart').onclick = async () => { await kvSet('restart_marked_at', Date.now()); alert('Now restart the phone, then open the app from the icon and run the automatic checks again.'); };
  $('scan').onclick = scan; $('stopScan').onclick = stopScan;
  $('pkCreate').onclick = createPasskey; $('pkUse').onclick = usePasskey;
  $('pushSub').onclick = subscribePush;
  $('print').onclick = () => window.print();
  $('copyLink').onclick = () => navigator.clipboard.writeText(`${location.origin}${location.pathname}?from=link`);
  document.querySelectorAll('[data-yes],[data-no]').forEach((b) => b.onclick = async () => {
    const key = b.dataset.yes || b.dataset.no; const yes = !!b.dataset.yes;
    const map = { '9pin': '9', '20print': '20', '20pdf': '20' };
    const id = map[key] || key;
    if (map[key]) {
      const prev = (results[id] && typeof results[id].detail === 'object') ? results[id].detail : {};
      const detail = { ...prev, [key]: yes };
      const status = id === '20' ? (detail['20print'] && detail['20pdf'] ? 'pass' : (detail['20print'] === false || detail['20pdf'] === false ? 'fail' : 'record')) : (results[id] ? results[id].status : 'record');
      await setResult(id, status, detail);
    } else {
      await setResult(id, yes ? 'pass' : 'fail', yes ? 'confirmed by you' : 'not as expected');
    }
  });
  $('copy').onclick = async () => {
    const out = JSON.stringify({ version: VERSION, at: new Date().toISOString(), ua: navigator.userAgent, standalone,
      results, open_log: await kvGet('open_log'), scan_log: await kvGet('scan_log'), passkey_uses: await kvGet('passkey_uses'),
      push_sub: await kvGet('push_sub'), push_log: await kvGet('push_log'), push_taps: await kvGet('push_taps') });
    $('out').value = out;
    try { await navigator.clipboard.writeText(out); $('copy').textContent = 'Copied'; } catch { $('out').select(); }
  };
  $('reset').onclick = async () => {
    if (!confirm('Delete all test data on this phone?')) return;
    const d = await dbp; d.close(); indexedDB.deleteDatabase('device-test'); location.reload();
  };
  const blank = (on) => { $('blank').style.display = on ? 'block' : 'none'; };
  document.addEventListener('visibilitychange', () => blank(document.hidden));
  window.addEventListener('blur', () => blank(true));
  window.addEventListener('focus', () => blank(false));
  window.addEventListener('pagehide', () => blank(true));
  window.addEventListener('pageshow', () => blank(false));

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  linkCheck();
  pushStatus();
  if (results['3']) c3().then(([s, d]) => setResult('3', s, d)).catch(() => {});
  if (results['3c']) c3c().then(([s, d]) => setResult('3c', s, d)).catch((e) => setResult('3c', 'fail', String(e && e.name + ': ' + e.message)));
}
build();
