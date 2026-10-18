// WhisprSpace matchmaker + signaling relay.
// Privacy: in-memory only. No database, no logs, no IP storage.
const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const ice = [{ urls: process.env.STUN_URL || 'stun:stun.l.google.com:19302' }];
let relay = false;
if (process.env.TURN_URL) {
  ice.push({
    urls: process.env.TURN_URL.split(','),
    username: process.env.TURN_USER,
    credential: process.env.TURN_PASS,
  });
  relay = true; // force relayed calls so peers never see each other's IP
}

const server = http.createServer((_, res) => { res.writeHead(200); res.end('ok'); });
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const queues = new Map(); // "scope|cell" -> Set of waiting sockets

const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

function dequeue(ws) {
  if (!ws.key) return;
  const q = queues.get(ws.key);
  if (q) { q.delete(ws); if (!q.size) queues.delete(ws.key); }
  ws.key = null;
  clearTimeout(ws.timer);
}

function unpair(ws) {
  const p = ws.peer;
  ws.peer = null;
  if (p) { p.peer = null; send(p, { t: 'bye' }); }
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.t === 'find') {
      dequeue(ws); unpair(ws);
      const scope = m.scope === 'nearby' ? 'nearby' : 'global';
      const cell = scope === 'nearby' && typeof m.cell === 'string' ? m.cell.slice(0, 32) : '';
      if (scope === 'nearby' && !cell) return send(ws, { t: 'none' });
      const mood = typeof m.mood === 'string' ? m.mood.slice(0, 16) : null;
      const key = scope + '|' + cell;
      const q = queues.get(key) || new Set();

      for (const other of q) {
        if (!other.mood || !mood || other.mood === mood) {
          dequeue(other);
          ws.peer = other; other.peer = ws;
          const shared = mood || other.mood || null;
          send(other, { t: 'match', role: 'offer', mood: shared, ice, relay });
          send(ws, { t: 'match', role: 'answer', mood: shared, ice, relay });
          return;
        }
      }
      ws.mood = mood; ws.key = key;
      q.add(ws); queues.set(key, q);
      ws.timer = setTimeout(() => { dequeue(ws); send(ws, { t: 'none' }); }, 60000);
    } else if (m.t === 'signal' && ws.peer) {
      send(ws.peer, { t: 'signal', d: m.d });
    } else if (m.t === 'cancel') {
      dequeue(ws);
    } else if (m.t === 'leave') {
      dequeue(ws); unpair(ws);
    }
  });

  ws.on('close', () => { dequeue(ws); unpair(ws); });
  ws.on('error', () => {});
});

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

server.listen(PORT);
