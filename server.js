// server.js
// HTTP + WebSocket proxy that bridges browser clients to the C chat system.
//
// Browser <-- WebSocket --> this proxy <-- TLS/TCP --> C directory & chat servers
//
// Run with: node server.js
//
// Config below: edit DIRECTORY_HOST / DIRECTORY_PORT / CA_FILE if needed.

const http = require('http');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const { WebSocketServer } = require('ws');

// --- Configuration -----------------------------------------------------------
// These should match your C code's inet.h (SERV_HOST_ADDR / SERV_TCP_PORT).
// When proxy + servers are on the same machine, 127.0.0.1 is safest.
const DIRECTORY_HOST = process.env.DIRECTORY_HOST || '127.0.0.1';
const DIRECTORY_PORT = parseInt(process.env.DIRECTORY_PORT || '57535', 10);
const CA_FILE        = process.env.CA_FILE || path.join(__dirname, 'certs', 'ca-cert.pem');
const HTTP_PORT      = parseInt(process.env.HTTP_PORT || '8080', 10);

// Read the CA cert your C servers were signed by.
let caCert;
try {
  caCert = fs.readFileSync(CA_FILE);
  console.log(`[proxy] Loaded CA from ${CA_FILE}`);
} catch (err) {
  console.error(`[proxy] FATAL: cannot read CA file at ${CA_FILE}`);
  console.error(`        ${err.message}`);
  console.error(`        Copy your certs/ca-cert.pem into ${path.dirname(CA_FILE)}/`);
  process.exit(1);
}

// --- Helper: TLS connect to one of your C servers ----------------------------
// expectedCN is the Common Name we expect on the server's cert.
//   - directory server: "Directory Server"
//   - chat servers: the topic name (e.g. "KSU Football")
function connectToServer(host, port, expectedCN) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({
      host,
      port,
      ca: caCert,
      // Your certs are likely issued to "Directory Server" / "KSU Football" etc.,
      // not to a hostname matching DIRECTORY_HOST. Disable hostname check and
      // verify CN ourselves below.
      checkServerIdentity: () => undefined,
      minVersion: 'TLSv1.3',
      rejectUnauthorized: true, // still verify against CA chain
    });

    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate();
      const cn = cert && cert.subject && cert.subject.CN;
      if (!cn) {
        sock.destroy();
        return reject(new Error('Peer presented no certificate / no CN'));
      }
      if (cn.toLowerCase() !== expectedCN.toLowerCase()) {
        sock.destroy();
        return reject(new Error(`CN mismatch: expected "${expectedCN}", got "${cn}"`));
      }
      resolve(sock);
    });

    sock.once('error', reject);
  });
}

// --- Talk to the directory server: get the room list -------------------------
function fetchRoomList() {
  return new Promise(async (resolve, reject) => {
    let dirSock;
    try {
      dirSock = await connectToServer(DIRECTORY_HOST, DIRECTORY_PORT, 'Directory Server');
    } catch (e) {
      return reject(e);
    }

    let buf = Buffer.alloc(0);
    dirSock.on('data', (chunk) => { buf = Buffer.concat([buf, chunk]); });
    dirSock.on('end', () => {
      const text = buf.toString('utf8');
      // Format from directoryServer5.c: one room per line, "Topic IP Port".
      // Topic may contain spaces; IP and Port are the last two whitespace-separated tokens.
      const rooms = text
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean)
        .map(line => {
          const parts = line.split(' ');
          if (parts.length < 3) return null;
          const port = parseInt(parts[parts.length - 1], 10);
          const ip = parts[parts.length - 2];
          const topic = parts.slice(0, -2).join(' ');
          if (!topic || !ip || !Number.isFinite(port)) return null;
          return { topic, ip, port };
        })
        .filter(Boolean);
      resolve(rooms);
    });
    dirSock.on('error', reject);

    // "L" = list request (no cert needed on directory side for this op).
    dirSock.write('L');
  });
}

// --- HTTP server: serves the static frontend ---------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
};

const httpServer = http.createServer((req, res) => {
  // Only serve from public/, no path traversal.
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.join(__dirname, 'public', urlPath);
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403); return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
});

// --- WebSocket server: same port, handles browser <-> chat bridging ----------
const wss = new WebSocketServer({ server: httpServer });

wss.on('connection', (ws, req) => {
  console.log(`[proxy] WS connection from ${req.socket.remoteAddress}`);

  // State: is this WS already bridged to a chat server? If so, raw bytes
  // flow both directions and we ignore JSON commands.
  let chatSock = null;

  const sendJson = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  ws.on('message', async (data, isBinary) => {
    // After bridging, browser text becomes raw bytes to the chat server.
    if (chatSock) {
      // ws gives us a Buffer; pass through to TLS socket.
      try { chatSock.write(data); } catch (_) {}
      return;
    }

    // Pre-bridge: expect JSON commands.
    let msg;
    try {
      msg = JSON.parse(data.toString('utf8'));
    } catch (e) {
      return sendJson({ type: 'error', message: 'Expected JSON command before joining' });
    }

    if (msg.type === 'list') {
      try {
        const rooms = await fetchRoomList();
        sendJson({ type: 'rooms', rooms });
      } catch (e) {
        console.error('[proxy] list failed:', e.message);
        sendJson({ type: 'error', message: `Could not reach directory server: ${e.message}` });
      }
      return;
    }

    if (msg.type === 'join') {
      const { topic, ip, port } = msg;
      if (!topic || !ip || !port) {
        return sendJson({ type: 'error', message: 'join requires topic, ip, port' });
      }
      try {
        // For local dev: if the directory advertises a non-loopback IP for
        // a chat server running on this same box, you may want to override
        // here. Uncomment if needed:
        // const dialIp = (DIRECTORY_HOST === '127.0.0.1') ? '127.0.0.1' : ip;
        const dialIp = ip;
        chatSock = await connectToServer(dialIp, port, topic);
        console.log(`[proxy] bridged WS -> chat "${topic}" at ${dialIp}:${port}`);

        sendJson({ type: 'joined', topic });

        // Pipe chat server output to the browser as text frames.
        chatSock.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) {
            ws.send(chunk.toString('utf8'));
          }
        });
        chatSock.on('end', () => {
          sendJson({ type: 'closed', message: 'Chat server closed connection' });
          ws.close();
        });
        chatSock.on('error', (e) => {
          console.error('[proxy] chat sock error:', e.message);
          sendJson({ type: 'error', message: `Chat connection error: ${e.message}` });
          try { ws.close(); } catch (_) {}
        });
      } catch (e) {
        console.error('[proxy] join failed:', e.message);
        sendJson({ type: 'error', message: `Could not join "${topic}": ${e.message}` });
      }
      return;
    }

    sendJson({ type: 'error', message: `Unknown command: ${msg.type}` });
  });

  ws.on('close', () => {
    if (chatSock) {
      try { chatSock.end(); } catch (_) {}
      chatSock = null;
    }
    console.log('[proxy] WS closed');
  });

  ws.on('error', (e) => console.error('[proxy] WS error:', e.message));
});

httpServer.listen(HTTP_PORT, () => {
  console.log(`[proxy] HTTP + WS listening on http://localhost:${HTTP_PORT}`);
  console.log(`[proxy] Directory server at ${DIRECTORY_HOST}:${DIRECTORY_PORT}`);
});
