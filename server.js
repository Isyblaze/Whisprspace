// WhisprSpace matchmaker + signaling relay + safety + anonymous world heat.
// Privacy: in-memory only. No database, no logs, no IP storage (IPs are only counted live).
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const REQUIRE_AUTH = process.env.REQUIRE_AUTH !== 'false';
const MAX_CONN_PER_IP = parseInt(process.env.MAX_CONN_PER_IP || '8', 10);
const HEAT_MIN = parseInt(process.env.HEAT_MIN || '5', 10); // a 2-degree cell only shows once this many are active

const ice = [{ urls: process.env.STUN_URL || 'stun:stun.l.google.com:19302' }];
let relay = false;
if (process.env.TURN_URL) {
  ice.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  relay = true;
}

// ---- safety policy ----
const WINDOW = 24 * 3600e3, THRESH = 3;
const WEIGHT = { 'Underage voice': 2, 'Sexual content': 2, 'Hate or threats': 2 };
const BAN_STEPS = [2 * 3600e3, 24 * 3600e3, 7 * 24 * 3600e3, 30 * 24 * 3600e3];
const BLOCK_TTL = 6 * 3600e3;
const FIND_PER_MIN = 10, MSGS_PER_10S = 150;

const bans = new Map(), banCount = new Map(), strikes = new Map(), blocks = new Map();
const reported = new Map(), findLog = new Map(), ipConns = new Map();

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

// ---- geography: everything is coarse (2-degree cells, ~220 km) ----
function cellCenter(key) {
  const m = /^(\d{1,3}):(\d{1,2})$/.exec(String(key || ''));
  if (!m) return null;
  const ix = +m[1], iy = +m[2];
  if (ix > 179 || iy > 89) return null;
  return { lon: -180 + (ix + 0.5) * 2, lat: -90 + (iy + 0.5) * 2 };
}
function km(a, b) {
  const R = 6371, rad = Math.PI / 180;
  const dl = (b.lat - a.lat) * rad, dn = (b.lon - a.lon) * rad;
  const h = Math.sin(dl / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dn / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}
const inArea = (area, home) => !area || (!!home && km(area, home) <= area.r);
function parseArea(a) {
  if (!a || typeof a !== 'object') return null;
  let lat = +a.lat, lon = +a.lon, r = +a.r;
  if (![lat, lon, r].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  r = Math.min(1500, Math.max(300, r)); // never smaller than ~300 km, so nobody can target a neighbourhood
  const c = cellCenter(`${Math.min(179, Math.floor((lon + 180) / 2))}:${Math.min(89, Math.floor((lat + 90) / 2))}`);
  return c ? { lat: c.lat, lon: c.lon, r } : null;
}

const server = http.createServer((_, res) => { res.writeHead(200); res.end('ok'); });
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const waiting = new Set();
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

function isBlocked(a, b) { const m = blocks.get(a); const e = m && m.get(b); return !!e && e > Date.now(); }
function addBlock(a, b) { if (!a || !b) return; let m = blocks.get(a); if (!m) { m = new Map(); blocks.set(a, m); } m.set(b, Date.now() + BLOCK_TTL); }
function dequeue(ws) { if (!ws.waiting) return; waiting.delete(ws); ws.waiting = false; clearTimeout(ws.timer); }
function unpair(ws) {
  const p = ws.peer; if (!p) return;
  const t = Date.now();
  ws.lastPeerId = p.id; ws.lastPeerAt = t; p.lastPeerId = ws.id; p.lastPeerAt = t;
  ws.peer = null; p.peer = null; send(p, { t: 'bye' });
}
function peerTarget(ws) {
  if (ws.peer) return ws.peer.id;
  return ws.lastPeerId && Date.now() - ws.lastPeerAt < 120000 ? ws.lastPeerId : null;
}
function kick(id) {
  wss.clients.forEach((c) => { if (c.id === id) { send(c, { t: 'banned', until: bans.get(id) }); dequeue(c); unpair(c); setTimeout(() => c.close(), 200); } });
}
function handleReport(ws, reason) {
  const target = peerTarget(ws); if (!target || target === ws.id) return;
  const key = ws.id + '>' + target;
  if (reported.has(key)) return;
  reported.set(key, Date.now());
  addBlock(ws.id, target); addBlock(target, ws.id);
  const t = Date.now(), w = WEIGHT[reason] || 1;
  const arr = (strikes.get(target) || []).filter((s) => t - s.ts < WINDOW);
  arr.push({ by: ws.id, w, ts: t }); strikes.set(target, arr);
  const per = new Map(); for (const s of arr) per.set(s.by, Math.max(per.get(s.by) || 0, s.w));
  let total = 0; for (const v of per.values()) total += v;
  if (total >= THRESH) {
    const bc = banCount.get(target) || { n: 0 };
    bans.set(target, t + BAN_STEPS[Math.min(bc.n, BAN_STEPS.length - 1)]);
    banCount.set(target, { n: bc.n + 1, exp: t + 30 * 24 * 3600e3 });
    strikes.delete(target); kick(target);
  }
}

// both people must be happy with each other's region, and mood must fit
function compatible(a, b) {
  if (a.id === b.id || isBlocked(a.id, b.id) || isBlocked(b.id, a.id)) return false;
  if (a.mood && b.mood && a.mood !== b.mood) return false;
  return inArea(a.area, b.home) && inArea(b.area, a.home);
}

// anonymous world heat: only cells with >= HEAT_MIN active people, with +/-1 noise on the counts
function sendHeat() {
  const cells = new Map(); let total = 0;
  wss.clients.forEach((c) => {
    const active = c.waiting || c.peer; if (!active) return;
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
  const msg = { t: 'heat', cells: out, total: total >= HEAT_MIN ? total : 0 };
  wss.clients.forEach((c) => { if (c.watch) send(c, msg); });
}
if (process.env.WHISPR_TEST) global.__whisprHeat = sendHeat;

wss.on('connection', (ws, req) => {
  const ip = (req.headers && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : '') || (req.socket && req.socket.remoteAddress) || 'x';
  const n = (ipConns.get(ip) || 0) + 1;
  if (n > MAX_CONN_PER_IP) { ws.close(); return; }
  ipConns.set(ip, n);

  ws.isAlive = true; ws.win = Date.now(); ws.count = 0;
  ws.nonce = crypto.randomBytes(16).toString('hex');
  ws.authTimer = setTimeout(() => ws.close(), 10000);
  ws.on('pong', () => { ws.isAlive = true; });
  send(ws, { t: 'hello', nonce: ws.nonce });

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    const now = Date.now();
    if (now - ws.win > 10000) { ws.win = now; ws.count = 0; }
    if (++ws.count > MSGS_PER_10S) { send(ws, { t: 'ratelimit' }); return ws.close(); }

    if (m.t === 'auth') {
      if (ws.id) return;
      const id = identify(m.pub, ws.nonce, m.sig);
      if (!id) { send(ws, { t: 'reject' }); return ws.close(); }
      const until = bans.get(id);
      if (until && until > now) { send(ws, { t: 'banned', until }); return setTimeout(() => ws.close(), 200); }
      ws.id = id; clearTimeout(ws.authTimer); send(ws, { t: 'ready' });
      return;
    }
    if (!ws.id) return;

    if (m.t === 'watch') { ws.watch = !!m.on; if (ws.watch) sendHeat(); }
    else if (m.t === 'find') {
      const log = (findLog.get(ws.id) || []).filter((x) => now - x < 60000);
      if (log.length >= FIND_PER_MIN) return send(ws, { t: 'ratelimit' });
      log.push(now); findLog.set(ws.id, log);
      dequeue(ws); unpair(ws);
      ws.mood = typeof m.mood === 'string' ? m.mood.slice(0, 16) : null;
      ws.homeKey = cellCenter(m.home) ? String(m.home) : null;
      ws.home = ws.homeKey ? cellCenter(ws.homeKey) : null;
      ws.area = m.scope === 'nearby' ? parseArea(m.area) : null;
      if (m.scope === 'nearby' && !ws.area) return send(ws, { t: 'none' });
      for (const other of waiting) {
        if (compatible(ws, other)) {
          dequeue(other);
          ws.peer = other; other.peer = ws;
          const shared = ws.mood || other.mood || null;
          send(other, { t: 'match', role: 'offer', mood: shared, ice, relay });
          send(ws, { t: 'match', role: 'answer', mood: shared, ice, relay });
          return;
        }
      }
      ws.waiting = true; waiting.add(ws);
      ws.timer = setTimeout(() => { dequeue(ws); send(ws, { t: 'none' }); }, 60000);
    } else if (m.t === 'signal' && ws.peer) {
      send(ws.peer, { t: 'signal', d: m.d });
    } else if (m.t === 'report') {
      handleReport(ws, typeof m.reason === 'string' ? m.reason.slice(0, 40) : '');
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
    const c = (ipConns.get(ip) || 1) - 1; if (c <= 0) ipConns.delete(ip); else ipConns.set(ip, c);
  });
  ws.on('error', () => {});
});

setInterval(() => { wss.clients.forEach((ws) => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); }); }, 30000);
setInterval(sendHeat, 5000);
setInterval(() => {
  const t = Date.now();
  for (const [k, v] of bans) if (v < t) bans.delete(k);
  for (const [k, v] of banCount) if (v.exp < t) banCount.delete(k);
  for (const [k, v] of strikes) { const a = v.filter((s) => t - s.ts < WINDOW); if (a.length) strikes.set(k, a); else strikes.delete(k); }
  for (const [k, m] of blocks) { for (const [b, e] of m) if (e < t) m.delete(b); if (!m.size) blocks.delete(k); }
  for (const [k, v] of reported) if (t - v > 3600e3) reported.delete(k);
  for (const [k, v] of findLog) { const a = v.filter((x) => t - x < 60000); if (a.length) findLog.set(k, a); else findLog.delete(k); }
}, 300000);

server.listen(PORT);
