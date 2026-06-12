const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], sessions: {}, resumes: {} }, null, 2));
  }
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDb(db) {
  ensureDb();
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    ...headers
  });
  res.end(JSON.stringify(body));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 2_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function safeUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

function createSession(db, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[token] = { userId, createdAt: new Date().toISOString() };
  return token;
}

function getUserFromRequest(req, db) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const session = token ? db.sessions[token] : null;
  if (!session) return null;
  return db.users.find(user => user.id === session.userId) || null;
}

async function handleApi(req, res) {
  if (req.method === 'OPTIONS') return send(res, 200, {});

  try {
    const db = readDb();

    if (req.url === '/api/auth/signup' && req.method === 'POST') {
      const { name = '', email = '', password = '' } = await parseBody(req);
      const normalizedEmail = String(email).trim().toLowerCase();
      if (!name.trim()) return send(res, 400, { error: 'Name is required' });
      if (!normalizedEmail.includes('@')) return send(res, 400, { error: 'Valid email is required' });
      if (String(password).length < 6) return send(res, 400, { error: 'Password must be at least 6 characters' });
      if (db.users.some(user => user.email === normalizedEmail)) return send(res, 409, { error: 'Email already registered' });

      const passwordHash = hashPassword(String(password));
      const user = {
        id: crypto.randomUUID(),
        name: String(name).trim(),
        email: normalizedEmail,
        password: passwordHash,
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      const token = createSession(db, user.id);
      writeDb(db);
      return send(res, 201, { token, user: safeUser(user) });
    }

    if (req.url === '/api/auth/login' && req.method === 'POST') {
      const { email = '', password = '' } = await parseBody(req);
      const normalizedEmail = String(email).trim().toLowerCase();
      const user = db.users.find(item => item.email === normalizedEmail);
      if (!user) return send(res, 401, { error: 'Invalid email or password' });
      const check = hashPassword(String(password), user.password.salt);
      if (check.hash !== user.password.hash) return send(res, 401, { error: 'Invalid email or password' });

      const token = createSession(db, user.id);
      writeDb(db);
      return send(res, 200, { token, user: safeUser(user) });
    }

    if (req.url === '/api/me' && req.method === 'GET') {
      const user = getUserFromRequest(req, db);
      if (!user) return send(res, 401, { error: 'Login required' });
      return send(res, 200, { user: safeUser(user) });
    }

    if (req.url === '/api/resume' && req.method === 'GET') {
      const user = getUserFromRequest(req, db);
      if (!user) return send(res, 401, { error: 'Login required' });
      return send(res, 200, { resume: db.resumes[user.id] || null });
    }

    if (req.url === '/api/resume' && req.method === 'POST') {
      const user = getUserFromRequest(req, db);
      if (!user) return send(res, 401, { error: 'Login required' });
      const { resume } = await parseBody(req);
      if (!resume || typeof resume !== 'object') return send(res, 400, { error: 'Resume data is required' });
      db.resumes[user.id] = { ...resume, updatedAt: new Date().toISOString() };
      writeDb(db);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'API route not found' });
  } catch (err) {
    return send(res, 500, { error: err.message || 'Server error' });
  }
}

function serveStatic(req, res) {
  let filePath = decodeURIComponent(req.url.split('?')[0]);
  if (filePath === '/') filePath = '/index.html';
  const resolved = path.normalize(path.join(ROOT, filePath));
  if (!resolved.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(resolved, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME_TYPES[path.extname(resolved)] || 'application/octet-stream' });
    res.end(content);
  });
}

ensureDb();

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return handleApi(req, res);
  return serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`ResumeForge running at http://localhost:${PORT}`);
});
