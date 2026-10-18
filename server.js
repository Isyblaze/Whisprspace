// WhisprSpace matchmaker + signaling relay + safety.
// Privacy: in-memory only. No database, no logs, no IP storage (IPs are only counted live).
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const REQUIRE_AUTH = process.env.REQUIRE_AUTH !== 'false';
const MAX_CONN_PER_IP = parseInt(process.env.MAX_CONN_PER_IP || '8', 10);

const ice = [{ urls: process.env.STUN_URL || 'stun:stun.l.google.com:19302' }];
let relay = false;
if (process.env.TURN_URL) {
  ice.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  relay = true;
}

// ---- safety policy ----
const WINDOW = 24 * 3600e3;                    // strikes count for 24h
const THRESH = 3;                              // weighted distinct reporters needed
const WEIGHT = { 'Underage voice': 2, 'Sexual content': 2, 'Hate or threats': 2 };
const BAN_STEPS = [2 * 3600e3, 24 * 3600e3, 7 * 24 * 3600e3, 30 * 24 * 3600e3];
const BLOCK_TTL = 6 * 3600e3;                  // "block for this session" lasts 6h
const FIND_PER_MIN = 10, MSGS_PER_10S = 150;

const bans = new Map();      // id -> until
const banCount = new Map();  // id -> { n, exp }
const strikes = new Map();   // target -> [{ by, w, ts }]
const blocks = new Map();    // id -> Map(blockedId -> exp)
const reported = new Map();  // "by>target" -> ts
const findLog = new Map();   // id -> [ts]
const ipConns = new Map();   // ip -> live count (never persisted)

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

const server = http.createServer((_, res) => { res.writeHead(200); res.end('ok'); });
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const queues = new Map();
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

function isBlocked(a, b) { const m = blocks.get(a); const e = m && m.get(b); return !!e && e > Date.now(); }
function addBlock(a, b) { if (!a || !b) return; let m = blocks.get(a); if (!m) { m = new Map(); blocks.set(a, m); } m.set(b, Date.now() + BLOCK_TTL); }

function dequeue(ws) {
  if (!ws.key) return;
  const q = queues.get(ws.key);
  if (q) { q.delete(ws); if (!q.size) queues.delete(ws.key); }
  ws.key = null; clearTimeout(ws.timer);
}
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
  wss.clients.forEach((c) => {
    if (c.id === id) { send(c, { t: 'banned', until: bans.get(id) }); dequeue(c); unpair(c); setTimeout(() => c.close(), 200); }
  });
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

    if (m.t === 'find') {
      const log = (findLog.get(ws.id) || []).filter((x) => now - x < 60000);
      if (log.length >= FIND_PER_MIN) return send(ws, { t: 'ratelimit' });
      log.push(now); findLog.set(ws.id, log);
      dequeue(ws); unpair(ws);
      const scope = m.scope === 'nearby' ? 'nearby' : 'global';
      const cell = scope === 'nearby' && typeof m.cell === 'string' ? m.cell.slice(0, 32) : '';
      if (scope === 'nearby' && !cell) return send(ws, { t: 'none' });
      const mood = typeof m.mood === 'string' ? m.mood.slice(0, 16) : null;
      const key = scope + '|' + cell;
      const q = queues.get(key) || new Set();
      for (const other of q) {
        if (other.id === ws.id || isBlocked(ws.id, other.id) || isBlocked(other.id, ws.id)) continue;
        if (!other.mood || !mood || other.mood === mood) {
          dequeue(other);
          ws.peer = other; other.peer = ws;
          const shared = mood || other.mood || null;
          send(other, { t: 'match', role: 'offer', mood: shared, ice, relay });
          send(ws, { t: 'match', role: 'answer', mood: shared, ice, relay });
          return;
        }
      }
      ws.mood = mood; ws.key = key; q.add(ws); queues.set(key, q);
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

setInterval(() => {
  wss.clients.forEach((ws) => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); });
}, 30000);
setInterval(() => { // forget everything that expired
  const t = Date.now();
  for (const [k, v] of bans) if (v < t) bans.delete(k);
  for (const [k, v] of banCount) if (v.exp < t) banCount.delete(k);
  for (const [k, v] of strikes) { const a = v.filter((s) => t - s.ts < WINDOW); if (a.length) strikes.set(k, a); else strikes.delete(k); }
  for (const [k, m] of blocks) { for (const [b, e] of m) if (e < t) m.delete(b); if (!m.size) blocks.delete(k); }
  for (const [k, v] of reported) if (t - v > 3600e3) reported.delete(k);
  for (const [k, v] of findLog) { const a = v.filter((x) => t - x < 60000); if (a.length) findLog.set(k, a); else findLog.delete(k); }
}, 300000);

server.listen(PORT);
