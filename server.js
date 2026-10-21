// WhisprSpace matchmaker + signaling + safety + anonymous world heat.   (scaling + bot protection build)
// Privacy: no audio, names or accounts. State is in memory, or in Redis if REDIS_URL is set. No logs, no IP storage.
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const REQUIRE_AUTH = process.env.REQUIRE_AUTH !== 'false';
const POW_BITS = parseInt(process.env.POW_BITS ?? '16', 10);        // proof-of-work difficulty for new devices (0 = off)
const POW_HARD = POW_BITS ? POW_BITS + 4 : 0;
const AUTHS_SOFT = 12, AUTHS_HARD = 40;                              // new-device sign-ins per network address per hour
const PROXY_HOPS = parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
const MAX_CONN_PER_IP = parseInt(process.env.MAX_CONN_PER_IP || '8', 10);
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS || '8000', 10);
const HEAT_MIN = parseInt(process.env.HEAT_MIN || '5', 10);
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL = 12 * 3600e3;

// ---- safety policy ----
const WINDOW = 24 * 3600e3, THRESH = 3;
const WEIGHT = { 'Underage voice': 2, 'Sexual content': 2, 'Hate or threats': 2 };
const BAN_STEPS = [2 * 3600e3, 24 * 3600e3, 7 * 24 * 3600e3, 30 * 24 * 3600e3];
const BLOCK_TTL = 6 * 3600e3;
const MSGS_PER_10S = 150;

// ---- relay (TURN) credentials: Cloudflare short-lived, or a static server ----
const CF_ID = process.env.CF_TURN_KEY_ID, CF_TOKEN = process.env.CF_TURN_API_TOKEN;
const STUN = [{ urls: process.env.STUN_URL || 'stun:stun.l.google.com:19302' }];
let ice = STUN.slice(), relay = false;
if (process.env.TURN_URL) {
  ice = STUN.concat([{ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS }]);
  relay = true;
}
async function refreshIce() {
  if (!CF_ID || !CF_TOKEN) return;
  try {
    const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${CF_ID}/credentials/generate`, {
      method: 'POST', headers: { Authorization: `Bearer ${CF_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ ttl: 14400 }),
    });
    if (!r.ok) throw new Error('cf ' + r.status);
    const j = await r.json(); const s = j.iceServers;
    ice = (Array.isArray(s) ? s : [s]).filter(Boolean); relay = true;
  } catch { /* keep the last good credentials */ }
}
refreshIce(); setInterval(refreshIce, 30 * 60e3).unref();

// ---- state store: memory (default) or Redis (REDIS_URL) so bans survive restarts ----
function memoryStore() {
  const bans = new Map(), bc = new Map(), st = new Map(), bl = new Map(), rp = new Map(), tr = new Map();
  return {
    async getBan(id) { const u = bans.get(id); return u && u > Date.now() ? u : 0; },
    async setBan(id, u) { bans.set(id, u); },
    async bumpBanCount(id) { const e = bc.get(id); const n = e && e.exp > Date.now() ? e.n : 0; bc.set(id, { n: n + 1, exp: Date.now() + 30 * 24 * 3600e3 }); return n; },
    async addStrike(t, by, w, ts) {
      const a = (st.get(t) || []).filter((s) => ts - s.ts < WINDOW); a.push({ by, w, ts }); st.set(t, a);
      const per = new Map(); for (const s of a) per.set(s.by, Math.max(per.get(s.by) || 0, s.w));
      let tot = 0; for (const v of per.values()) tot += v; return tot;
    },
    async clearStrikes(t) { st.delete(t); },
    async markReported(by, t) { const k = by + '>' + t, e = rp.get(k); if (e && e > Date.now()) return false; rp.set(k, Date.now() + 3600e3); return true; },
    async addBlock(a, b) { let m = bl.get(a); if (!m) { m = new Map(); bl.set(a, m); } m.set(b, Date.now() + BLOCK_TTL); },
    async getBlocks(id) { const s = new Set(), m = bl.get(id); if (m) for (const [b, e] of m) if (e > Date.now()) s.add(b); return s; },
    async getTrust(id) { return tr.get(id) || 0; },
    async addTrust(id) { const n = Math.min(50, (tr.get(id) || 0) + 1); tr.set(id, n); return n; },
    sweep() {
      const t = Date.now();
      for (const [k, v] of bans) if (v < t) bans.delete(k);
      for (const [k, v] of bc) if (v.exp < t) bc.delete(k);
      for (const [k, v] of st) { const a = v.filter((s) => t - s.ts < WINDOW); if (a.length) st.set(k, a); else st.delete(k); }
      for (const [k, m] of bl) { for (const [b, e] of m) if (e < t) m.delete(b); if (!m.size) bl.delete(k); }
      for (const [k, v] of rp) if (v < t) rp.delete(k);
    },
  };
}
function redisStore(r) {
  return {
    async getBan(id) { const v = await r.get('ban:' + id); return v ? +v : 0; },
    async setBan(id, until) { await r.set('ban:' + id, String(until), 'PX', Math.max(1, until - Date.now())); },
    async bumpBanCount(id) { const n = await r.incr('bc:' + id); await r.pexpire('bc:' + id, 30 * 24 * 3600e3); return n - 1; },
    async addStrike(t, by, w, ts) {
      const k = 'st:' + t;
      await r.zadd(k, ts, `${by}|${w}|${ts}`); await r.zremrangebyscore(k, 0, ts - WINDOW); await r.pexpire(k, WINDOW);
      const per = new Map(); for (const x of await r.zrange(k, 0, -1)) { const [b, ww] = x.split('|'); per.set(b, Math.max(per.get(b) || 0, +ww)); }
      let tot = 0; for (const v of per.values()) tot += v; return tot;
    },
    async clearStrikes(t) { await r.del('st:' + t); },
    async markReported(by, t) { return (await r.set(`rp:${by}:${t}`, '1', 'PX', 3600e3, 'NX')) === 'OK'; },
    async addBlock(a, b) { const k = 'bl:' + a; await r.zadd(k, Date.now() + BLOCK_TTL, b); await r.pexpire(k, BLOCK_TTL); },
    async getBlocks(id) { const k = 'bl:' + id; await r.zremrangebyscore(k, 0, Date.now()); return new Set(await r.zrange(k, 0, -1)); },
    async getTrust(id) { return +(await r.get('tr:' + id)) || 0; },
    async addTrust(id) { const n = await r.incr('tr:' + id); await r.pexpire('tr:' + id, 90 * 24 * 3600e3); return n; },
  };
}
const SAFE_DEFAULT = { getBan: 0, bumpBanCount: 0, addStrike: 0, markReported: true, getTrust: 0, addTrust: 0 };
function failSoft(s) { // if Redis hiccups, keep the app running rather than crash
  const o = {};
  for (const k of Object.keys(s)) o[k] = typeof s[k] === 'function' && k !== 'sweep'
    ? async (...a) => { try { return await s[k](...a); } catch { return k === 'getBlocks' ? new Set() : SAFE_DEFAULT[k]; } }
    : s[k];
  return o;
}
let store = memoryStore();
if (process.env.REDIS_URL) {
  try { const Redis = require('ioredis'); store = failSoft(redisStore(new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 2 }))); } catch { /* stay in memory */ }
}
if (process.env.WHISPR_TEST) global.__whisprStore = store;

// ---- crypto helpers ----
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
function identify(pubB64, nonce, sigB64) {
  try {
    const raw = Buffer.from(String(pubB64), 'base64');
    if (raw.length !== 32) return null;
    if (REQUIRE_AUTH) {
      const key = crypto.createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });
      if (!crypto.verify(null, Buffer.from(nonce), key, Buffer.from(String(sigB64), 'base64'))) return null;
    }
    return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  } catch { return null; }
}
const mac = (s) => crypto.createHmac('sha256', AUTH_SECRET).update(s).digest('hex').slice(0, 32);
const makeToken = (id) => { const exp = Date.now() + TOKEN_TTL; return `${id}.${exp}.${mac(id + '.' + exp)}`; };
function checkToken(tok, id) {
  try {
    if (typeof tok !== 'string') return false;
    const [i, e, m] = tok.split('.');
    return i === id && +e > Date.now() && crypto.timingSafeEqual(Buffer.from(m), Buffer.from(mac(i + '.' + e)));
  } catch { return false; }
}
function powOk(nonce, pub, counter, bits) {
  if (!bits) return true;
  const c = String(counter);
  if (!/^\d{1,12}$/.test(c)) return false;
  const h = crypto.createHash('sha256').update(nonce + pub + ':' + c).digest();
  let n = 0;
  for (const b of h) { if (b === 0) { n += 8; continue; } n += Math.clz32(b) - 24; break; }
  return n >= bits;
}
function clientIp(req) {
  const parts = String((req.headers && req.headers['x-forwarded-for']) || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length) return parts[Math.max(0, parts.length - PROXY_HOPS)]; // trust only what our own proxy appended
  return (req.socket && req.socket.remoteAddress) || 'x';
}

// ---- geography: coarse 2-degree cells (~220 km) ----
function cellCenter(key) {
  const m = /^(\d{1,3}):(\d{1,2})$/.exec(String(key || ''));
  if (!m) return null;
  const ix = +m[1], iy = +m[2];
  if (ix > 179 || iy > 89) return null;
  return { lon: -180 + (ix + 0.5) * 2, lat: -90 + (iy + 0.5) * 2 };
}
function km(a, b) {
  const R = 6371, rad = Math.PI / 180, dl = (b.lat - a.lat) * rad, dn = (b.lon - a.lon) * rad;
  const h = Math.sin(dl / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dn / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}
const inArea = (area, home) => !area || (!!home && km(area, home) <= area.r);
function parseArea(a) {
  if (!a || typeof a !== 'object') return null;
  const lat = +a.lat, lon = +a.lon; let r = +a.r;
  if (![lat, lon, r].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  r = Math.min(1500, Math.max(300, r));
  const c = cellCenter(`${Math.min(179, Math.floor((lon + 180) / 2))}:${Math.min(89, Math.floor((lat + 90) / 2))}`);
  return c ? { lat: c.lat, lon: c.lon, r } : null;
}

// ---- server ----
const authLog = new Map(), ipConns = new Map(), findLog = new Map(), byId = new Map();
const waiting = new Set();
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    let calls = 0; wss.clients.forEach((c) => { if (c.peer) calls++; });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, online: wss.clients.size, waiting: waiting.size, calls: calls / 2 }));
  }
  res.writeHead(200); res.end('ok');
});
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

function addBlock(a, b) {
  if (!a || !b) return;
  store.addBlock(a, b);
  const sa = byId.get(a); if (sa) for (const s of sa) s.blocked.add(b);
}
function dequeue(ws) {
  if (!ws.waiting) return;
  waiting.delete(ws); ws.waiting = false;
  (ws.timers || []).forEach(clearTimeout); ws.timers = [];
}
function unpair(ws) {
  const p = ws.peer; if (!p) return;
  const t = Date.now();
  if (ws.pairedAt && t - ws.pairedAt >= 60000 && !ws.flagged && !p.flagged) { // a clean 60s+ call builds trust
    store.addTrust(ws.id); store.addTrust(p.id); ws.trust = (ws.trust || 0) + 1; p.trust = (p.trust || 0) + 1;
  }
  ws.lastPeerId = p.id; ws.lastPeerAt = t; p.lastPeerId = ws.id; p.lastPeerAt = t;
  ws.peer = null; p.peer = null; send(p, { t: 'bye' });
}
function peerTarget(ws) {
  if (ws.peer) return ws.peer.id;
  return ws.lastPeerId && Date.now() - ws.lastPeerAt < 120000 ? ws.lastPeerId : null;
}
function kick(id) {
  const set = byId.get(id); if (!set) return;
  store.getBan(id).then((until) => {
    for (const c of [...set]) { send(c, { t: 'banned', until }); dequeue(c); unpair(c); setTimeout(() => c.close(), 200); }
  });
}
async function handleReport(ws, reason) {
  const target = peerTarget(ws); if (!target || target === ws.id) return;
  const peer = ws.peer;
  if (!(await store.markReported(ws.id, target))) return;
  addBlock(ws.id, target); addBlock(target, ws.id);
  ws.flagged = true; if (peer) peer.flagged = true;
  const w = (WEIGHT[reason] || 1) * ((ws.trust || 0) >= 2 ? 1 : 0.5); // brand-new devices carry half weight: bot swarms can't brigade
  const total = await store.addStrike(target, ws.id, w, Date.now());
  if (total >= THRESH) {
    const prev = await store.bumpBanCount(target);
    await store.setBan(target, Date.now() + BAN_STEPS[Math.min(prev, BAN_STEPS.length - 1)]);
    await store.clearStrikes(target); kick(target);
  }
}

function compatible(a, b) {
  if (a.id === b.id || a.blocked.has(b.id) || b.blocked.has(a.id)) return false;
  if (a.mood && b.mood && a.mood !== b.mood) return false;
  return inArea(a.area, b.home) && inArea(b.area, a.home);
}
function pair(a, b) {
  dequeue(a); dequeue(b);
  a.peer = b; b.peer = a; a.pairedAt = b.pairedAt = Date.now(); a.flagged = b.flagged = false;
  const shared = a.mood || b.mood || null;
  send(b, { t: 'match', role: 'offer', mood: shared, ice, relay });
  send(a, { t: 'match', role: 'answer', mood: shared, ice, relay });
}
function tryMatch(ws) {
  for (const o of waiting) if (o !== ws && compatible(ws, o)) { pair(ws, o); return true; }
  return false;
}
function widen(ws, what) { // nobody found yet: loosen mood first, then the region radius (never to "anywhere")
  if (!ws.waiting) return;
  let changed = false;
  if (what === 'mood' && ws.mood) { ws.mood = null; changed = true; send(ws, { t: 'widen', what: 'mood' }); }
  if (what === 'region' && ws.area && ws.area.r < 1500) { ws.area = { ...ws.area, r: Math.min(1500, ws.area.r * 2) }; changed = true; send(ws, { t: 'widen', what: 'region', km: ws.area.r }); }
  if (changed) tryMatch(ws);
}
function startWait(ws) {
  ws.waiting = true; waiting.add(ws);
  ws.timers = [
    setTimeout(() => widen(ws, 'mood'), 15000),
    setTimeout(() => widen(ws, 'region'), 30000),
    setTimeout(() => { dequeue(ws); send(ws, { t: 'none' }); }, 60000),
  ];
}
if (process.env.WHISPR_TEST) global.__whisprWiden = widen;

function sendHeat() {
  const cells = new Map(); let total = 0;
  wss.clients.forEach((c) => {
    if (!(c.waiting || c.peer)) return;
    total++;
    if (!c.homeKey) return;
    const e = cells.get(c.homeKey) || { l: 0, t: 0 };
    if (c.peer) e.t++; else e.l++;
    cells.set(c.homeKey, e);
  });
  const jit = () => Math.floor(Math.random() * 3) - 1, out = [];
  for (const [k, e] of cells) {
    if (e.l + e.t < HEAT_MIN) continue;
    const [ix, iy] = k.split(':').map(Number);
    out.push([ix, iy, Math.max(0, e.l + jit()), Math.max(0, e.t + jit())]);
    if (out.length >= 400) break;
  }
  const msg = JSON.stringify({ t: 'heat', cells: out, total: total >= HEAT_MIN ? total : 0 });
  wss.clients.forEach((c) => { if (c.watch && c.readyState === 1) c.send(msg); });
}
if (process.env.WHISPR_TEST) global.__whisprHeat = sendHeat;

wss.on('connection', (ws, req) => {
  if (wss.clients.size > MAX_CONNECTIONS) { send(ws, { t: 'busy' }); return ws.close(); }
  const ip = clientIp(req); ws.ip = ip;
  const n = (ipConns.get(ip) || 0) + 1;
  if (n > MAX_CONN_PER_IP) { ws.close(); return; }
  ipConns.set(ip, n);

  const now0 = Date.now();
  const recent = (authLog.get(ip) || []).filter((x) => now0 - x < 3600e3).length;
  ws.powBits = !POW_BITS ? 0 : recent >= AUTHS_HARD ? -1 : recent >= AUTHS_SOFT ? POW_HARD : POW_BITS;
  ws.isAlive = true; ws.win = now0; ws.count = 0; ws.blocked = new Set();
  ws.nonce = crypto.randomBytes(16).toString('hex');
  ws.authTimer = setTimeout(() => ws.close(), 15000);
  ws.on('pong', () => { ws.isAlive = true; });
  send(ws, { t: 'hello', nonce: ws.nonce, pow: ws.powBits === -1 ? POW_HARD : ws.powBits });

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    const now = Date.now();
    if (now - ws.win > 10000) { ws.win = now; ws.count = 0; }
    if (++ws.count > MSGS_PER_10S) { send(ws, { t: 'ratelimit' }); return ws.close(); }

    if (m.t === 'auth') { auth(ws, m).catch(() => ws.close()); return; }
    if (!ws.id) return;

    if (m.t === 'watch') { ws.watch = !!m.on; if (ws.watch) sendHeat(); }
    else if (m.t === 'find') {
      const log = (findLog.get(ws.id) || []).filter((x) => now - x < 60000);
      if (log.length >= ((ws.trust || 0) >= 2 ? 10 : 5)) return send(ws, { t: 'ratelimit' }); // new devices search more slowly
      log.push(now); findLog.set(ws.id, log);
      dequeue(ws); unpair(ws);
      ws.mood = typeof m.mood === 'string' ? m.mood.slice(0, 16) : null;
      ws.homeKey = cellCenter(m.home) ? String(m.home) : null;
      ws.home = ws.homeKey ? cellCenter(ws.homeKey) : null;
      ws.area = m.scope === 'nearby' ? parseArea(m.area) : null;
      if (m.scope === 'nearby' && !ws.area) return send(ws, { t: 'none' });
      if (!tryMatch(ws)) startWait(ws);
    } else if (m.t === 'signal' && ws.peer) {
      send(ws.peer, { t: 'signal', d: m.d });
    } else if (m.t === 'report') {
      handleReport(ws, typeof m.reason === 'string' ? m.reason.slice(0, 40) : '').catch(() => {});
    } else if (m.t === 'block') {
      const target = peerTarget(ws); if (target) { addBlock(ws.id, target); addBlock(target, ws.id); }
    } else if (m.t === 'cancel') {
      dequeue(ws);
    } else if (m.t === 'leave') {
      dequeue(ws); unpair(ws);
    }
  });

  ws.on('close', () => {
    clearTimeout(ws.authTimer); dequeue(ws); unpair(ws);
    const s = byId.get(ws.id); if (s) { s.delete(ws); if (!s.size) byId.delete(ws.id); }
    const c = (ipConns.get(ip) || 1) - 1; if (c <= 0) ipConns.delete(ip); else ipConns.set(ip, c);
  });
  ws.on('error', () => {});
});

async function auth(ws, m) {
  if (ws.id || ws.authing) return;
  ws.authing = true;
  const id = identify(m.pub, ws.nonce, m.sig);
  if (!id) { send(ws, { t: 'reject' }); return ws.close(); }
  if (!checkToken(m.token, id) && POW_BITS) {
    if (ws.powBits === -1) { send(ws, { t: 'ratelimit' }); return ws.close(); }
    const log = (authLog.get(ws.ip) || []).filter((x) => Date.now() - x < 3600e3); log.push(Date.now()); authLog.set(ws.ip, log);
    if (!powOk(ws.nonce, String(m.pub), m.pow, ws.powBits)) { send(ws, { t: 'reject', why: m.token ? 'token' : 'pow' }); return ws.close(); }
  }
  const until = await store.getBan(id);
  if (until > Date.now()) { send(ws, { t: 'banned', until }); return setTimeout(() => ws.close(), 200); }
  ws.trust = await store.getTrust(id);
  ws.blocked = await store.getBlocks(id);
  if (ws.readyState !== 1) return;
  ws.id = id; clearTimeout(ws.authTimer);
  let s = byId.get(id); if (!s) { s = new Set(); byId.set(id, s); } s.add(ws);
  send(ws, { t: 'ready', token: makeToken(id) });
}

setInterval(() => { wss.clients.forEach((ws) => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); }); }, 30000).unref();
setInterval(sendHeat, 5000).unref();
setInterval(() => {
  const t = Date.now();
  if (store.sweep) store.sweep();
  for (const [k, v] of findLog) { const a = v.filter((x) => t - x < 60000); if (a.length) findLog.set(k, a); else findLog.delete(k); }
  for (const [k, v] of authLog) { const a = v.filter((x) => t - x < 3600e3); if (a.length) authLog.set(k, a); else authLog.delete(k); }
}, 300000).unref();

function shutdown() { // tell phones to reconnect instead of dropping them silently
  wss.clients.forEach((c) => send(c, { t: 'restart' }));
  setTimeout(() => process.exit(0), 2500);
}
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);

server.listen(PORT);
