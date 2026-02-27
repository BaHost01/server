'use strict';

/**
 * @rterm/relay — Central WebSocket relay server
 *
 * Architecture:
 *
 *   [Host Agent] ──ws──► [Relay] ◄──ws── [Client CLI / Web]
 *
 * Message flow:
 *   Client → Relay → Host   (input, resize)
 *   Host   → Relay → Client (output, shell_exit)
 *
 * Each host registers with { type:"host_register", roomId, password }
 * Each client joins with   { type:"client_join",   roomId, password }
 * The relay validates, then stitches the two sockets together.
 */

require('dotenv').config();
const http      = require('http');
const express   = require('express');
const WebSocket = require('ws');
const chalk     = require('chalk');
const { v4: uuid } = require('uuid');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT         = parseInt(process.env.PORT || 4242, 10);
const RELAY_SECRET = process.env.RELAY_SECRET || null; // optional server-level secret
const AUTH_TIMEOUT = 12_000; // ms to authenticate before kick

// ── State ─────────────────────────────────────────────────────────────────────
/**
 * rooms: Map<roomId, { hostWs, passwordHash, hostInfo, clients: Set<ws>, createdAt }>
 *
 * We store a tiny SHA-256-style hash of the password (using Node crypto, no bcrypt dep)
 * for comparison. Not perfect but keeps passwords out of memory in plaintext.
 */
const crypto = require('crypto');
const rooms  = new Map();

function hashPass(pass) {
  return crypto.createHash('sha256').update(pass).digest('hex');
}

// ── Express app (HTTP status / health) ───────────────────────────────────────
const app    = express();
const server = http.createServer(app);

app.use(express.json());

app.get('/', (_req, res) => {
  res.json({ service: 'rterm-relay', status: 'ok', rooms: rooms.size });
});

app.get('/rooms', (_req, res) => {
  const list = [];
  for (const [id, room] of rooms) {
    list.push({
      roomId:    id,
      hasClient: room.clients.size > 0,
      clients:   room.clients.size,
      createdAt: room.createdAt,
    });
  }
  res.json(list);
});

// ── WebSocket server ──────────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const ip       = req.socket.remoteAddress;
  const connId   = uuid().slice(0, 8);
  ws._rterm      = { id: connId, ip, role: null };

  log('gray', `[${connId}] ← connected from ${ip}`);

  // ── Auth timeout ─────────────────────────────────────────────────────────
  const authTimer = setTimeout(() => {
    if (!ws._rterm.role) {
      sendTo(ws, { type: 'error', message: 'Auth timeout. Closing.' });
      ws.close(4001, 'auth_timeout');
      log('red', `[${connId}] timed out before identifying`);
    }
  }, AUTH_TIMEOUT);

  // ── Prompt identification ─────────────────────────────────────────────────
  sendTo(ws, { type: 'identify', message: 'Send host_register or client_join.' });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); }
    catch { return sendTo(ws, { type: 'error', message: 'JSON only.' }); }

    // Not yet identified — handle identification
    if (!ws._rterm.role) {
      return handleIdentify(ws, msg, authTimer, connId);
    }

    // Already identified — route based on role
    if (ws._rterm.role === 'host')   return handleHostMessage(ws, msg);
    if (ws._rterm.role === 'client') return handleClientMessage(ws, msg);
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    handleDisconnect(ws);
  });

  ws.on('error', (err) => {
    log('red', `[${connId}] socket error: ${err.message}`);
  });
});

// ── Identify ──────────────────────────────────────────────────────────────────
function handleIdentify(ws, msg, authTimer, connId) {

  // ── HOST REGISTRATION ─────────────────────────────────────────────────────
  if (msg.type === 'host_register') {
    const { roomId, password, hostInfo = {} } = msg;

    if (!roomId || !password) {
      return sendTo(ws, { type: 'error', message: 'host_register requires roomId and password.' });
    }
    if (rooms.has(roomId)) {
      return sendTo(ws, { type: 'error', message: `Room "${roomId}" already exists. Choose another.` });
    }

    clearTimeout(authTimer);
    ws._rterm.role   = 'host';
    ws._rterm.roomId = roomId;

    rooms.set(roomId, {
      hostWs:       ws,
      passwordHash: hashPass(password),
      hostInfo,
      clients:      new Set(),
      createdAt:    new Date().toISOString(),
    });

    log('green', `[${connId}] HOST registered → room "${roomId}" (${hostInfo.platform || 'unknown OS'})`);
    sendTo(ws, {
      type:    'host_registered',
      roomId,
      message: `Room "${roomId}" is live. Waiting for clients.`,
    });
    return;
  }

  // ── CLIENT JOIN ───────────────────────────────────────────────────────────
  if (msg.type === 'client_join') {
    const { roomId, password, cols = 80, rows = 24 } = msg;

    if (!roomId || !password) {
      return sendTo(ws, { type: 'error', message: 'client_join requires roomId and password.' });
    }

    const room = rooms.get(roomId);
    if (!room) {
      return sendTo(ws, { type: 'error', message: `Room "${roomId}" not found.` });
    }
    if (hashPass(password) !== room.passwordHash) {
      log('red', `[${connId}] failed auth for room "${roomId}"`);
      sendTo(ws, { type: 'auth_fail', message: 'Wrong password.' });
      ws.close(4002, 'auth_fail');
      return;
    }

    clearTimeout(authTimer);
    ws._rterm.role   = 'client';
    ws._rterm.roomId = roomId;
    room.clients.add(ws);

    log('green', `[${connId}] CLIENT joined room "${roomId}"`);
    sendTo(ws, {
      type:    'joined',
      roomId,
      message: 'Connected to host terminal.',
      hostInfo: room.hostInfo,
    });

    // Tell host a client arrived
    sendTo(room.hostWs, {
      type:    'client_connected',
      clientId: connId,
      cols,
      rows,
    });
    return;
  }

  sendTo(ws, { type: 'error', message: 'Unknown message type. Send host_register or client_join.' });
}

// ── Host message handling ─────────────────────────────────────────────────────
function handleHostMessage(ws, msg) {
  const room = rooms.get(ws._rterm.roomId);
  if (!room) return;

  // Host sends output → broadcast to all clients
  if (msg.type === 'output' || msg.type === 'shell_exit') {
    for (const client of room.clients) {
      sendTo(client, msg);
    }
    return;
  }

  // Host sends a notice to a specific client (optional)
  if (msg.type === 'host_notice') {
    for (const client of room.clients) {
      sendTo(client, { type: 'notice', message: msg.message });
    }
  }
}

// ── Client message handling ───────────────────────────────────────────────────
function handleClientMessage(ws, msg) {
  const room = rooms.get(ws._rterm.roomId);
  if (!room) return;

  // Forward input/resize to host
  if (msg.type === 'input' || msg.type === 'resize') {
    sendTo(room.hostWs, msg);
  }
}

// ── Disconnect handling ───────────────────────────────────────────────────────
function handleDisconnect(ws) {
  const { role, roomId, id } = ws._rterm;

  if (!role) return; // never identified

  const room = rooms.get(roomId);
  if (!room) return;

  if (role === 'host') {
    log('yellow', `[${id}] HOST disconnected → closing room "${roomId}"`);
    // Notify all clients
    for (const client of room.clients) {
      sendTo(client, { type: 'host_disconnected', message: 'Host closed the room.' });
      client.close(4010, 'host_disconnected');
    }
    rooms.delete(roomId);
    return;
  }

  if (role === 'client') {
    room.clients.delete(ws);
    log('gray', `[${id}] CLIENT left room "${roomId}" (${room.clients.size} remaining)`);
    // Notify host
    sendTo(room.hostWs, { type: 'client_disconnected', clientId: id });
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function sendTo(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function log(color, msg) {
  const ts = new Date().toLocaleTimeString();
  console.log(chalk[color](`  [relay ${ts}] ${msg}`));
}

// ── Boot ─────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(chalk.bgCyan.black.bold(`\n  rterm-relay running on port ${PORT}  \n`));
  console.log(chalk.gray(`  HTTP health : http://localhost:${PORT}/`));
  console.log(chalk.gray(`  Room list   : http://localhost:${PORT}/rooms`));
  console.log(chalk.gray(`  WebSocket   : ws://localhost:${PORT}\n`));
});

process.on('SIGINT', () => {
  console.log(chalk.yellow('\n\n  [relay] Shutting down...\n'));
  wss.close();
  server.close();
  process.exit(0);
});
