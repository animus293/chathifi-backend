const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const cors = require('cors');

const app = express();
// Behind a reverse proxy (Railway/Render), req.ip is the real client address
// only when Express trusts the immediate proxy hop.
app.set('trust proxy', 1);
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
  }
});

const PORT = process.env.PORT || 8083;
const FEEDBACK_HUB_ID = 'feedback-global-hub';
// Comma-separated usernames that are always treated as global admins,
// regardless of DB state (e.g. ADMIN_USERNAMES=alice,bob). The first
// registered account also becomes an admin so a fresh deploy is usable.
const ADMIN_USERNAMES = (process.env.ADMIN_USERNAMES || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_PATH = path.join(DATA_DIR, 'db.json');
const UPLOADS_PATH = path.join(DATA_DIR, 'uploads');

// Create uploads folder if not exists
if (!fs.existsSync(UPLOADS_PATH)) {
  fs.mkdirSync(UPLOADS_PATH, { recursive: true });
}

// Multer storage for file uploads. SECURITY: the stored extension is derived
// ONLY from the validated MIME type (never from the client-supplied original
// filename) — so an uploaded "evil.html" (or any non-media extension) can
// never be served back as same-origin HTML/JS from /uploads.
const MIME_EXT = {
  'image/jpeg': '.jpg',
  // Some Android cameras report image/jpg with a .jpg filename.
  'image/jpg': '.jpg',
  'image/png': '.png',
  'image/gif': '.gif',
  'image/webp': '.webp',
  'audio/mpeg': '.mp3',
  'audio/ogg': '.ogg',
  'audio/wav': '.wav',
  'video/mp4': '.mp4',
  'video/webm': '.webm'
};
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_PATH),
  filename: (req, file, cb) => {
    // Server-side extension from the MIME allowlist — originalname is ignored.
    cb(null, `${uuidv4()}${MIME_EXT[file.mimetype] || '.bin'}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Require BOTH a known MIME type AND a matching extension. The old
    // `extOk || mimeOk` accepted files like .html with a spoofed image MIME,
    // which were then stored with their original extension and served as
    // same-origin HTML (stored XSS). MIME is authoritative; the extension
    // must agree so the stored name can never be an executable type.
    const ext = path.extname(file.originalname).toLowerCase();
    const expectedExt = MIME_EXT[file.mimetype];
    cb(null, !!expectedExt && ext === expectedExt);
  }
});

// ============ RATE LIMITING ============
// In-memory sliding-window limiters — no new dependencies. Buckets live in
// memory by design: limits exist to stop bursts, and a server restart
// naturally resets them (unlike sessions, which persist in db.json).
//
// Keys are namespaced: authenticated actions are scoped to the verified user
// id; auth-attempt limits are scoped to IP (req.ip) and to the identifier so
// a shared mobile/CGNAT IP can never lock out an entire network on its own.
const rateLimitBuckets = new Map();

// Record one attempt for `key` and report whether it is still allowed.
// Returns { allowed, retryAfterMs } with retryAfterMs > 0 only when blocked.
// Allows exactly `max` attempts per window (the (max+1)th is blocked).
function rateLimit(key, { windowMs, max }) {
  const now = Date.now();
  let entry = rateLimitBuckets.get(key);
  if (!entry || now - entry.start >= entry.windowMs) {
    entry = { start: now, count: 0, windowMs };
    rateLimitBuckets.set(key, entry);
  }
  entry.count++;
  if (entry.count > max) {
    return { allowed: false, retryAfterMs: Math.max(0, entry.windowMs - (now - entry.start)) };
  }
  return { allowed: true, retryAfterMs: 0 };
}

// Check whether `key` is currently blocked WITHOUT consuming an attempt.
// Used for buckets that should only count failures (e.g. login IP bucket), so
// legitimate traffic never burns budget. Blocks once `max` attempts are used.
function checkRateLimit(key, { windowMs, max }) {
  const now = Date.now();
  const entry = rateLimitBuckets.get(key);
  if (!entry || now - entry.start >= entry.windowMs) return { allowed: true, retryAfterMs: 0 };
  if (entry.count >= max) {
    return { allowed: false, retryAfterMs: Math.max(0, entry.windowMs - (now - entry.start)) };
  }
  return { allowed: true, retryAfterMs: 0 };
}

// Periodic sweep so abandoned keys never accumulate in memory.
setInterval(() => {
  const now = Date.now();
  rateLimitBuckets.forEach((entry, key) => {
    if (now - entry.start >= entry.windowMs) rateLimitBuckets.delete(key);
  });
}, 60 * 1000);

// HTTP 429 helper (sets the standard Retry-After header).
function sendTooMany(res, retryAfterMs, message) {
  res.set('Retry-After', String(Math.ceil(retryAfterMs / 1000)));
  return res.status(429).json({ error: message, retryAfterMs });
}

// Socket-side limit. Fire-and-forget events have no acks, so on violation we
// emit `rate_limited` back so the client can tell the user why nothing
// happened and how long to wait.
function socketRateLimit(socket, key, { windowMs, max, event, label }) {
  const result = rateLimit(key, { windowMs, max });
  if (!result.allowed) {
    const secs = Math.ceil(result.retryAfterMs / 1000);
    socket.emit('rate_limited', {
      event,
      retryAfterMs: result.retryAfterMs,
      message: `${label} — try again in ${secs}s.`
    });
    return false;
  }
  return true;
}

// ---- Limits ----
// Auth attempts (brute-force protection)
const AUTH_IP_WINDOW_MS = 15 * 60 * 1000;   // 15 min
const AUTH_IP_MAX = 30;                     // login attempts per IP per window
const AUTH_USER_WINDOW_MS = 15 * 60 * 1000; // 15 min
const AUTH_USER_MAX = 5;                    // failed logins per username per window
const SIGNUP_WINDOW_MS = 60 * 60 * 1000;    // 1 hour
const SIGNUP_MAX = 20;                      // signups per IP per hour

// Authenticated actions (spam protection)
const MSG_WINDOW_MS = 15 * 1000;
const MSG_MAX = 30;                  // sends per user per 15s (socket + HTTP reply share one bucket)
const REACT_WINDOW_MS = 30 * 1000;
const REACT_MAX = 30;
const EDIT_DELETE_WINDOW_MS = 60 * 1000;
const EDIT_DELETE_MAX = 20;
const VOTE_WINDOW_MS = 30 * 1000;
const VOTE_MAX = 30;
const UPLOAD_WINDOW_MS = 60 * 1000;
const UPLOAD_MAX = 10;
const SEARCH_WINDOW_MS = 30 * 1000;
const SEARCH_MAX = 20;
const POLL_WINDOW_MS = 60 * 1000;
const POLL_MAX = 60;  // the Android background service polls ~15/min
const UNREAD_WINDOW_MS = 15 * 1000;
const UNREAD_MAX = 60; // feedback unread badge refresh (read-only scan guard)

// Feedback submissions (bug/feature/thread replies) — kept as a named helper
// because several socket handlers call it.
function checkFeedbackRateLimit(userId) {
  return rateLimit(`feedback:${userId}`, { windowMs: 15000, max: 5 }).allowed;
}

function ensureFeedbackHub() {
  const db = loadDB();
  let hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
  if (!hub) {
    const firstUser = db.users[0];
    const adminId = firstUser ? firstUser.id : 'system';
    hub = {
      id: FEEDBACK_HUB_ID,
      name: 'HiFi Feedback',
      description: 'Report bugs, suggest features, and vote on priorities. All users are auto-joined.',
      type: 'feedback',
      avatar: null,
      members: db.users.map(u => u.id),
      admins: [adminId],
      createdBy: adminId,
      createdAt: new Date().toISOString(),
      rules: ['Be constructive and respectful', 'Search before submitting duplicates', 'No spam']
    };
    db.groups.push(hub);
    saveDB(db);
    console.log('📋 Feedback Hub created');
  } else {
    let changed = false;
    db.users.forEach(u => {
      if (!hub.members.includes(u.id)) {
        hub.members.push(u.id);
        changed = true;
      }
    });
    if (changed) saveDB(db);
  }
}

// Load/Save DB
let dbCache = null;
let dbCacheMtime = 0;

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    const initial = { users: [], groups: [], messages: [], sessions: [], reports: [], appeals: [], reactions: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial));
    dbCache = initial;
    dbCacheMtime = fs.statSync(DB_PATH).mtimeMs;
    return initial;
  }
  const stat = fs.statSync(DB_PATH);
  if (dbCache && stat.mtimeMs === dbCacheMtime) return dbCache;
  dbCache = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  // Normalize legacy databases: missing collections + missing per-user fields.
  if (!Array.isArray(dbCache.sessions)) dbCache.sessions = [];
  if (!Array.isArray(dbCache.reports)) dbCache.reports = [];
  if (!Array.isArray(dbCache.appeals)) dbCache.appeals = [];
  if (!Array.isArray(dbCache.reactions)) dbCache.reactions = [];
  let changed = false;
  (dbCache.users || []).forEach(u => {
    if (u.role === undefined) { u.role = 'user'; changed = true; }
    if (u.banned === undefined) { u.banned = false; changed = true; }
    if (u.bannedAt === undefined) { u.bannedAt = null; changed = true; }
  });
  // Per-user read migration: read state is now per-user via readBy (the old
  // single `read` boolean made one member's read look global). Legacy DMs with
  // `read: true` can be attributed to the recipient; group reads can't be
  // attributed, so those self-heal on each member's next open+mark_read.
  (dbCache.messages || []).forEach(m => {
    if (!Array.isArray(m.readBy)) {
      m.readBy = (m.read === true && !m.groupId && m.to) ? [m.to] : [];
      changed = true;
    }
  });
  // Reaction "seen" state: readAt[userId] = when THAT user (the author of the
  // reacted message) saw the reaction — powers the chat-list "reacted to your
  // message" unread preview. Same per-user pattern as message readAt. Placed
  // AFTER `let changed` so legacy DBs with existing reactions can't hit a
  // temporal-dead-zone ReferenceError (crashed the deployed backend).
  (dbCache.reactions || []).forEach(r => {
    if (!r.readAt || typeof r.readAt !== 'object') { r.readAt = {}; changed = true; }
  });
  // Promote any env-configured admin usernames on every load (cheap, idempotent).
  if (ADMIN_USERNAMES.length) {
    (dbCache.users || []).forEach(u => {
      if (ADMIN_USERNAMES.includes(String(u.username || '').toLowerCase()) && u.role !== 'admin') {
        u.role = 'admin'; changed = true;
      }
    });
  }
  if (changed) saveDB(dbCache); // saveDB records the correct post-write mtime
  else dbCacheMtime = stat.mtimeMs; // untouched file: cache the stat we just read
  return dbCache;
}

function saveDB(data) {
  dbCache = data;
  // Compact JSON (no pretty-print) keeps the on-disk file ~3x smaller, so the
  // occasional cold read + every write is much faster on large databases.
  fs.writeFileSync(DB_PATH, JSON.stringify(data));
  // Record the FILE's mtime (float with sub-ms precision), not Date.now():
  // comparing stat.mtimeMs to a Date.now() integer NEVER matched, which forced
  // loadDB to re-read + re-parse the whole db.json on every single request
  // (multi-second latency on the deployed backend).
  dbCacheMtime = fs.statSync(DB_PATH).mtimeMs;
}

// ============ SESSION TOKENS ============
// Opaque, server-generated bearer tokens. A token maps to exactly one user.
// Client-supplied identity (userId in body/query/socket payload) is NEVER
// trusted — the authenticated userId always comes from the verified session.
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const db = loadDB();
  if (!Array.isArray(db.sessions)) db.sessions = [];
  pruneSessions(db);
  db.sessions.push({ token, userId, createdAt: new Date().toISOString() });
  saveDB(db);
  return token;
}

function deleteSession(token) {
  if (!token) return;
  const db = loadDB();
  if (!Array.isArray(db.sessions)) return;
  const before = db.sessions.length;
  db.sessions = db.sessions.filter(s => s.token !== token);
  if (db.sessions.length !== before) saveDB(db);
}

function pruneSessions(db) {
  // Returns true if any expired sessions were removed (caller persists once).
  if (!Array.isArray(db.sessions)) return false;
  const cutoff = Date.now() - SESSION_TTL_MS;
  const before = db.sessions.length;
  db.sessions = db.sessions.filter(s => {
    const t = new Date(s.createdAt || 0).getTime();
    return !isNaN(t) && t > cutoff;
  });
  return db.sessions.length !== before;
}

function getSessionByToken(token) {
  if (!token) return null;
  const db = loadDB();
  const session = (db.sessions || []).find(s => s.token === token) || null;
  if (!session) return null;
  // Enforce TTL on every lookup so an expired session can never be reused.
  const t = new Date(session.createdAt || 0).getTime();
  if (isNaN(t) || Date.now() - t > SESSION_TTL_MS) {
    deleteSession(token);
    return null;
  }
  return session;
}

function isUserPartyToMessage(msg, userId) {
  if (!msg) return false;
  if (msg.groupId) {
    const group = loadDB().groups.find(g => g.id === msg.groupId);
    return !!group && group.members.includes(userId);
  }
  return String(msg.from) === String(userId) || String(msg.to) === String(userId);
}

// Shared DM-send authorization. Used by BOTH the socket send_message handler
// and the HTTP /api/messages/reply endpoint so the two paths can never drift
// again (a previous drift left the HTTP path without block checks — a real
// bypass). Returns { ok: true } or { ok: false, error, status }.
function checkDMSend(db, from, to) {
  const recipient = db.users.find(u => String(u.id) === String(to));
  if (!recipient) return { ok: false, error: 'Recipient not found', status: 404 };
  if ((recipient.blockedUsers || []).some(b => String(b) === String(from))) {
    return { ok: false, error: 'You are blocked by this user', status: 403 };
  }
  const sender = db.users.find(u => String(u.id) === String(from));
  if (sender && (sender.blockedUsers || []).some(b => String(b) === String(to))) {
    return { ok: false, error: 'You have blocked this user. Unblock to send messages.', status: 403 };
  }
  return { ok: true };
}

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : (req.headers['x-auth-token'] || '');
  const session = getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  const user = loadDB().users.find(u => u.id === session.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  // Banned users are locked out of every authenticated API (including the
  // Android notification poll) until an admin unbans them.
  if (user.banned) return res.status(403).json({ error: 'Account banned', banned: true });
  req.userId = session.userId;
  req.user = user;
  next();
}

// Global admin gate — used on all /api/admin/* routes. Requires the opaque
// session from requireAuth (req.user is the verified user record).
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admins only' });
  }
  next();
}

function isAdminUser(user) {
  return !!user && user.role === 'admin';
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: 0 }));
// Defense in depth: never let the browser sniff a served upload as a different
// type than its extension (blocks HTML/JS polyglot payloads even if a file
// slips through validation).
app.use('/uploads', (req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  next();
}, express.static(UPLOADS_PATH));

// ============ AUTH ROUTES ============

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, displayName } = req.body;

    // Anti-spam: cap account creation per IP. Generous because mobile CGNATs
    // share public IPs; the per-username login limiter is the real gate.
    const ipLimit = rateLimit(`signup:ip:${req.ip}`, { windowMs: SIGNUP_WINDOW_MS, max: SIGNUP_MAX });
    if (!ipLimit.allowed) {
      return sendTooMany(res, ipLimit.retryAfterMs, 'Too many accounts created from this network. Please try again later.');
    }

    const db = loadDB();

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }

    // Check if username exists
    const exists = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (exists) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // First registered account becomes the global admin (bootstraps a usable
    // deploy); env-configured usernames are always promoted too.
    const isFirstUser = db.users.length === 0;
    const newUser = {
      id: uuidv4(),
      username: username.toLowerCase(),
      displayName: displayName || username,
      password: hashedPassword,
      avatar: null,
      mutedConversations: [],
      blockedUsers: [],
      online: false,
      lastSeen: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      role: (isFirstUser || ADMIN_USERNAMES.includes(username.toLowerCase())) ? 'admin' : 'user',
      banned: false,
      bannedAt: null
    };

    db.users.push(newUser);
    // Auto-join feedback hub
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (hub && !hub.members.includes(newUser.id)) {
      hub.members.push(newUser.id);
    }
    saveDB(db);

    const { password: _, ...userWithoutPassword } = newUser;
    const token = createSession(newUser.id);
    res.json({ success: true, user: userWithoutPassword, token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Brute-force protection. Both the per-IP and per-username buckets count
    // FAILURES only (via checkRateLimit/rateLimit below), so a shared/CGNAT
    // network can never be locked out by its own legitimate logins, and a
    // legit owner's typos can never lock their own account — only actual
    // brute-forcing consumes the budget.
    const ipBlocked = checkRateLimit(`auth:ip:${req.ip}`, { windowMs: AUTH_IP_WINDOW_MS, max: AUTH_IP_MAX });
    if (!ipBlocked.allowed) {
      return sendTooMany(res, ipBlocked.retryAfterMs, 'Too many failed login attempts from this network. Please try again later.');
    }

    const db = loadDB();

    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      // Count the failure against the IP bucket (username is unknown).
      rateLimit(`auth:ip:${req.ip}`, { windowMs: AUTH_IP_WINDOW_MS, max: AUTH_IP_MAX });
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      rateLimit(`auth:ip:${req.ip}`, { windowMs: AUTH_IP_WINDOW_MS, max: AUTH_IP_MAX });
      const userLimit = rateLimit(`auth:user:${username.toLowerCase()}`, { windowMs: AUTH_USER_WINDOW_MS, max: AUTH_USER_MAX });
      if (!userLimit.allowed) {
        return sendTooMany(res, userLimit.retryAfterMs, 'Too many failed login attempts. Please wait before trying again.');
      }
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Banned accounts cannot sign in at all.
    if (user.banned) {
      return res.status(403).json({ error: 'This account has been banned.', banned: true });
    }

    // Env-configured admins are promoted at login too (covers pre-existing DBs).
    if (ADMIN_USERNAMES.includes(String(user.username || '').toLowerCase()) && user.role !== 'admin') {
      user.role = 'admin';
      saveDB(db);
    }

    user.online = true;
    user.lastSeen = new Date().toISOString();
    saveDB(db);

    const { password: _, ...userWithoutPassword } = user;
    const token = createSession(user.id);
    res.json({ success: true, user: userWithoutPassword, token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ AUTH MIDDLEWARE (applies to all /api routes below) ============
// Requires a valid session token. Sets req.userId from the verified session;
// client-supplied userId parameters are only honored when they match req.userId.
app.use('/api', (req, res, next) => {
  // Public endpoints: signup + login only. Appeals are also public because a
  // banned user cannot authenticate — the appeal identifies them by username
  // and is only accepted when the account is actually banned.
  if (req.path === '/signup' || req.path === '/login' || req.path === '/appeals') return next();
  // Update manifest is public on GET — clients must be able to check for
  // updates before (or without) authenticating.
  if (req.method === 'GET' && req.path === '/update/manifest') return next();
  return requireAuth(req, res, next);
});

// Logout — revoke the current session server-side (requires auth).
app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : (req.headers['x-auth-token'] || '');
  deleteSession(token);
  res.json({ success: true });
});

// Search users
app.get('/api/users/search', (req, res) => {
  try {
    const { q, exclude } = req.query;
    const db = loadDB();

    let users = db.users.filter(u => u.id !== exclude);

    if (q) {
      const query = q.toLowerCase();
      users = users.filter(u =>
        u.username.includes(query) || u.displayName.toLowerCase().includes(query)
      );
    }

    // Public listing — never expose moderation fields (role/banned) to regular
    // users; the admin panel has its own admin-only endpoint for that. The
    // isAdmin boolean is safe: it only advertises who the global admins are.
    const results = users.map(({ password, role, banned, bannedAt, ...u }) => ({ ...u, isAdmin: role === 'admin' }));
    res.json({ users: results });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user by ID (own profile includes role/banned; other users see public data)
app.get('/api/users/:id', (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const isSelf = String(user.id) === String(req.userId);
  const isAdmin = isAdminUser(req.user);
  const { password, role, banned, bannedAt, ...rest } = user;
  // Everyone sees an isAdmin flag (powers the crown badges); role/banned stay
  // private unless viewing your own profile or you're an admin.
  const publicUser = { ...rest, isAdmin: role === 'admin' };
  const u = (isSelf || isAdmin) ? { ...publicUser, role, banned, bannedAt } : publicUser;
  res.json({ user: u });
});

// ============ FILE UPLOAD ============
app.post('/api/upload',
  // Check the per-user limit BEFORE multer saves the file (no orphan uploads).
  (req, res, next) => {
    const result = rateLimit(`upload:${req.userId}`, { windowMs: UPLOAD_WINDOW_MS, max: UPLOAD_MAX });
    if (!result.allowed) return sendTooMany(res, result.retryAfterMs, 'Uploading too fast — try again shortly.');
    next();
  },
  upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ success: true, url: fileUrl, filename: req.file.filename });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ============ MESSAGE SEARCH ============
app.get('/api/messages/search', (req, res) => {
  try {
    const { q, groupId } = req.query;
    const userId = req.userId;

    // Search scans all messages — prevent scripted hammering of the DB.
    const result = rateLimit(`search:${userId}`, { windowMs: SEARCH_WINDOW_MS, max: SEARCH_MAX });
    if (!result.allowed) return sendTooMany(res, result.retryAfterMs, 'Searching too fast — try again shortly.');

    const db = loadDB();
    if (!q) return res.json({ messages: [] });

    const query = q.toLowerCase();
    let results;

    if (groupId) {
      const group = db.groups.find(g => g.id === groupId);
      if (!group || !group.members.includes(userId)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      results = db.messages.filter(m => m.groupId === groupId && !m.deleted && m.text && m.text.toLowerCase().includes(query));
    } else {
      results = db.messages.filter(m =>
        !m.groupId && !m.deleted && m.text && m.text.toLowerCase().includes(query) &&
        (m.from === userId || m.to === userId)
      );
    }

    results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    res.json({ messages: results.slice(0, 50) });
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ============ UPDATE PROFILE ============
app.put('/api/users/:id/profile', (req, res) => {
  try {
    if (req.params.id !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const db = loadDB();
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { displayName, bio, avatar } = req.body;
    if (displayName) user.displayName = displayName;
    if (bio !== undefined) user.bio = bio;
    if (avatar !== undefined) user.avatar = avatar;
    saveDB(db);
    const { password, ...u } = user;
    
    // Real-time broadcast to all connected devices / users
    if (avatar !== undefined) {
      io.emit('user_avatar_updated', { userId: user.id, avatarUrl: user.avatar });
    }
    if (displayName !== undefined || bio !== undefined) {
      io.emit('user_profile_updated', { userId: user.id, displayName: user.displayName, bio: user.bio, avatar: user.avatar });
    }

    res.json({ success: true, user: u });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ BLOCK USER ============
app.post('/api/users/:userId/block', (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const { targetUserId, action } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.blockedUsers) user.blockedUsers = [];

    if (action === 'block') {
      if (!user.blockedUsers.includes(targetUserId)) {
        user.blockedUsers.push(targetUserId);
      }
    } else if (action === 'unblock') {
      user.blockedUsers = user.blockedUsers.filter(id => id !== targetUserId);
    } else {
      return res.status(400).json({ error: 'Invalid action' });
    }

    saveDB(db);
    const { password, ...u } = user;
    res.json({ success: true, blockedUsers: u.blockedUsers });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get blocked users with details
app.get('/api/users/:userId/blocked', (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const db = loadDB();
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const blockedIds = user.blockedUsers || [];
    const blockedUsers = blockedIds.map(id => {
      const u = db.users.find(usr => usr.id === id);
      if (!u) return null;
      const { password, ...rest } = u;
      return rest;
    }).filter(Boolean);
    res.json({ blockedUsers });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ MUTE CONVERSATION ============
app.post('/api/users/:userId/mute', (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const { conversationId, action } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.mutedConversations) user.mutedConversations = [];

    const cid = String(conversationId);
    if (action === 'mute') {
      if (!user.mutedConversations.includes(cid)) {
        user.mutedConversations.push(cid);
      }
    } else if (action === 'unmute') {
      user.mutedConversations = user.mutedConversations.filter(id => String(id) !== cid);
    } else {
      return res.status(400).json({ error: 'Invalid action' });
    }

    saveDB(db);
    res.json({ success: true, mutedConversations: user.mutedConversations });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get muted conversation IDs for a user
app.get('/api/users/:userId/muted', (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const db = loadDB();
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ mutedConversations: user.mutedConversations || [] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ CONVERSATIONS ============

// Get all conversations for a user (DM partners + groups)
app.get('/api/conversations/:userId', async (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const db = loadDB();
    const userId = req.userId;

    // Get blocked + muted sets for the requesting user
    const currentUser = db.users.find(u => u.id === userId);
    const blockedSet = new Set(currentUser?.blockedUsers || []);
    const mutedSet = new Set(currentUser?.mutedConversations || []);

    // Single pass through messages to collect everything
    const dmPartnerIds = new Set();
    const dmLastMsg = {};
    const dmUnread = {};
    const groupLastMsg = {};
    const groupUnread = {};

    for (let i = 0; i < db.messages.length; i++) {
      const m = db.messages[i];
      const ts = new Date(m.timestamp).getTime();
      const text = m.deleted ? '🚫 Deleted' : (m.text || (m.type === 'image' ? '📷 Photo' : m.type === 'location' ? '📍 Location' : ''));

      if (m.groupId) {
        // Group message
        if (!groupLastMsg[m.groupId] || ts > groupLastMsg[m.groupId].timestamp) {
          groupLastMsg[m.groupId] = { text, timestamp: ts };
        }
        // Per-user read state: a message is unread for THIS user until THEIR id
        // is in readBy. Bob reading Alice's message must never clear Carol's
        // badge — or prevent Carol's receipt avatar from ever appearing.
        if (m.from !== userId && !(m.readBy || []).includes(userId)) {
          groupUnread[m.groupId] = (groupUnread[m.groupId] || 0) + 1;
        }
      } else if (m.from === userId || m.to === userId) {
        // DM message
        const partnerId = m.from === userId ? m.to : m.from;
        dmPartnerIds.add(partnerId);
        if (!dmLastMsg[partnerId] || ts > dmLastMsg[partnerId].timestamp) {
          dmLastMsg[partnerId] = { text, timestamp: ts };
        }
        if (m.from === partnerId && !(m.readBy || []).includes(userId)) {
          dmUnread[partnerId] = (dmUnread[partnerId] || 0) + 1;
        }
      }
    }

    // Reactions targeting THIS user that they haven't seen yet (readAt[userId]
    // unset). Each becomes a chat-list preview "reacted 🧐 to your message"
    // (WhatsApp-style, name omitted per request), counts as unread, and bumps
    // the conversation to the top if it's newer than the last real message.
    // Keyed by conversationId; only the most recent unseen reaction per
    // conversation drives the preview, all of them count toward unread.
    const convReactions = {}; // conversationId -> { preview, ts, count }
    (db.reactions || []).forEach(r => {
      if (String(r.targetUserId) !== String(userId)) return;
      if (r.readAt && r.readAt[userId]) return;
      const convId = String(r.conversationId || '');
      if (!convId) return;
      // Skip stale log entries: the reactions log is append-only (un-reacting
      // deletes msg.reactions[reactorId] but never the log row), so verify the
      // reaction still exists on the message before showing the preview.
      const reactedMsg = db.messages.find(m => m.id === r.messageId);
      if (!reactedMsg || !reactedMsg.reactions || reactedMsg.reactions[r.reactorId] !== r.emoji) return;
      const ts = new Date(r.timestamp).getTime();
      const prev = convReactions[convId];
      if (!prev) {
        convReactions[convId] = { preview: `reacted ${r.emoji} to your message`, ts, count: 1 };
      } else if (ts > prev.ts) {
        // Newest reaction drives the preview emoji; keep accumulating count
        // across ALL unseen reactions in this conversation.
        prev.preview = `reacted ${r.emoji} to your message`;
        prev.ts = ts;
        prev.count++;
      } else {
        prev.count++;
      }
    });

    // Global admin ids — stamps the gold crown on DM rows and group member lists.
    const adminIdSet = new Set(db.users.filter(u => u.role === 'admin').map(u => String(u.id)));

    // Build DM conversations
    const dmConvs = Array.from(dmPartnerIds).map(pid => {
      const user = db.users.find(u => u.id === pid);
      if (!user) return null;
      const { password, role, banned, bannedAt, ...u } = user;
      const rx = convReactions[String(pid)];
      const lastMsgTs = dmLastMsg[pid]?.timestamp || 0;
      // A newer unseen reaction takes over the preview + last-activity time.
      const reactionNewer = rx && rx.ts > lastMsgTs;
      return {
        type: 'dm',
        id: pid,
        isAdmin: role === 'admin',
        name: u.displayName || u.username,
        username: u.username,
        avatar: u.avatar || null,
        online: u.online,
        lastSeen: u.lastSeen,
        lastMessage: reactionNewer ? rx.preview : (dmLastMsg[pid]?.text || ''),
        lastMessageTime: reactionNewer ? rx.ts : lastMsgTs,
        unread: (dmUnread[pid] || 0) + (rx ? rx.count : 0),
        blocked: blockedSet.has(pid),
        muted: mutedSet.has(pid)
      };
    }).filter(Boolean);

    // Build group conversations (pre-computed data from single pass)
    const userGroups = db.groups
      .filter(g => g.members.includes(userId))
      .map(g => {
        const lm = groupLastMsg[g.id];
        const rx = convReactions[String(g.id)];
        const lastMsgTs = lm ? lm.timestamp : 0;
        const reactionNewer = rx && rx.ts > lastMsgTs;
        return {
          type: 'group',
          id: g.id,
          name: g.name,
          avatar: g.avatar || null,
          members: g.members,
          admins: g.admins || [],
          memberAdmins: g.members.filter(id => adminIdSet.has(String(id))),
          createdBy: g.createdBy,
          countdown: g.countdown || null,
          lastMessage: reactionNewer ? rx.preview : (lm ? lm.text : ''),
          lastMessageTime: reactionNewer ? rx.ts : lastMsgTs,
          unread: (groupUnread[g.id] || 0) + (rx ? rx.count : 0),
          muted: mutedSet.has(g.id)
        };
      });

    // Combine and sort by last message time
    const allConvs = [...dmConvs, ...userGroups].sort((a, b) => b.lastMessageTime - a.lastMessageTime);

    res.json({ conversations: allConvs });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ FRIEND COMPATIBILITY ============
// A fun "how compatible are you two" score computed from the real DM history
// between the current user and a partner: message balance (who talks more),
// emoji vocabulary overlap, reply-speed rhythm, and friendship longevity.
// Read-only scan of that one thread — guarded by a light limiter like the
// other read-heavy endpoints (search/poll/unread).
const COMPAT_WINDOW_MS = 30 * 1000;
const COMPAT_MAX = 20;

app.get('/api/compatibility/:userId', (req, res) => {
  try {
    const limit = rateLimit(`compat:${req.userId}`, { windowMs: COMPAT_WINDOW_MS, max: COMPAT_MAX });
    if (!limit.allowed) return sendTooMany(res, limit.retryAfterMs, 'Checking too fast — try again shortly.');

    const db = loadDB();
    const me = db.users.find(u => u.id === req.userId);
    const them = db.users.find(u => u.id === req.params.userId);
    if (!me || !them) return res.status(404).json({ error: 'User not found' });
    if (String(them.id) === String(me.id)) return res.status(400).json({ error: 'Compare with a friend, not yourself' });

    // DM messages only (never group messages), in either direction.
    const thread = db.messages.filter(m => !m.groupId && !m.deleted &&
      ((String(m.from) === String(me.id) && String(m.to) === String(them.id)) ||
       (String(m.from) === String(them.id) && String(m.to) === String(me.id))));

    const EMOJI_RE = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{2190}-\u{21FF}\u{2B50}\u{2764}\u{1F1E6}-\u{1F1FF}]/gu;

    let youCount = 0, themCount = 0;
    const youEmoji = {}, themEmoji = {};
    const youGaps = [], themGaps = []; // reply gaps in minutes per direction
    const days = new Set();
    let prev = null;
    const sorted = [...thread].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    for (const m of sorted) {
      const ts = new Date(m.timestamp).getTime();
      const fromMe = String(m.from) === String(me.id);
      if (fromMe) youCount++; else themCount++;
      days.add(new Date(ts).toDateString());
      const emojis = (m.text || '').match(EMOJI_RE) || [];
      const bucket = fromMe ? youEmoji : themEmoji;
      emojis.forEach(e => { bucket[e] = (bucket[e] || 0) + 1; });
      if (prev && prev.from !== String(m.from)) {
        const gap = Math.round((ts - prev.ts) / 60000);
        if (gap >= 0 && gap < 48 * 60) (fromMe ? youGaps : themGaps).push(gap);
      }
      prev = { from: String(m.from), ts };
    }

    const median = (arr) => {
      if (!arr.length) return null;
      const s = [...arr].sort((a, b) => a - b);
      const mid = Math.floor(s.length / 2);
      return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
    };
    const youMedian = median(youGaps);
    const themMedian = median(themGaps);

    const total = youCount + themCount;

    // No chat history yet — don't fake a "50/100 Good friends" score for a
    // thread that has never had a single message. Return a clean "say hi"
    // state (hasData:false) that the frontend renders as a friendly empty
    // card instead of a misleading ring.
    if (total === 0) {
      const yourName0 = me.displayName || me.username;
      const theirName0 = them.displayName || them.username;
      return res.json({
        score: 0, verdict: 'Say hi first', emoji: '👋', total: 0, hasData: false,
        youCount: 0, themCount: 0, youSharePct: 0, emojiOverlapPct: 0,
        sharedEmojis: [], yourTopEmojis: [], theirTopEmojis: [],
        youMedian: null, themMedian: null,
        replyLine: 'Send a few messages to unlock your compatibility score',
        friendshipDays: 0, activeDays: 0,
        yourName: yourName0, theirName: theirName0,
        shareText: `✨ Friend Compatibility — ${yourName0} & ${theirName0}\nSay hi first 👋 — send a few messages to unlock your score`
      });
    }

    const youShare = total ? youCount / total : 0.5;
    const balance = 1 - Math.abs(youShare - 0.5) * 2; // 1 when perfectly 50/50

    const youSet = new Set(Object.keys(youEmoji));
    const themSet = new Set(Object.keys(themEmoji));
    const shared = [...youSet].filter(e => themSet.has(e));
    const union = new Set([...youSet, ...themSet]);
    const emojiOverlap = union.size ? shared.length / union.size : 0;

    let replyScore = 0.5; // neutral when neither side has rhythm data
    if (youMedian != null && themMedian != null) {
      const ratio = Math.min(youMedian, themMedian) / Math.max(youMedian, themMedian);
      replyScore = 0.5 + 0.5 * ratio;
    } else if (youMedian != null || themMedian != null) {
      replyScore = 0.6;
    }

    const firstTs = sorted.length ? new Date(sorted[0].timestamp).getTime() : 0;
    const lastTs = sorted.length ? new Date(sorted[sorted.length - 1].timestamp).getTime() : 0;
    const friendshipDays = firstTs ? Math.max(1, Math.round((lastTs - firstTs) / 86400000)) : 0;
    const longevity = Math.min(friendshipDays, 730) / 730; // saturates at ~2 years

    const score = Math.round(100 * (0.4 * balance + 0.25 * emojiOverlap + 0.2 * replyScore + 0.15 * longevity));

    let verdict, emoji;
    if (score >= 85) { verdict = 'Soulmates'; emoji = '💞'; }
    else if (score >= 70) { verdict = 'Besties'; emoji = '✨'; }
    else if (score >= 55) { verdict = 'Great vibes'; emoji = '😄'; }
    else if (score >= 40) { verdict = 'Good friends'; emoji = '🤝'; }
    else if (score >= 20) { verdict = 'Getting to know each other'; emoji = '🌱'; }
    else { verdict = 'Just acquaintances'; emoji = '👋'; }

    let replyLine;
    if (youMedian != null && themMedian != null) {
      // Fast replies round to 0 minutes — dividing by a zero median would print
      // "Infinity× faster", so use a minute as the floor for the ratio.
      const youM = Math.max(youMedian, 1);
      const themM = Math.max(themMedian, 1);
      if (youMedian < themMedian) {
        replyLine = `You reply ${(themM / youM).toFixed(1)}× faster than ${them.displayName || them.username}`;
      } else if (themMedian < youMedian) {
        replyLine = `${them.displayName || them.username} replies ${(youM / themM).toFixed(1)}× faster than you`;
      } else {
        replyLine = 'You reply at the same speed ⚡';
      }
    } else {
      replyLine = 'Not enough messages to compare reply speed yet';
    }

    const topEmojis = (obj, n) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n).map(([e]) => e);
    const yourName = me.displayName || me.username;
    const theirName = them.displayName || them.username;

    const shareText =
`✨ Friend Compatibility — ${yourName} & ${theirName}
` +
`${score}/100 · ${verdict} ${emoji}
` +
`💬 ${youCount} from you · ${themCount} from ${theirName}
` +
`🎭 ${Math.round(emojiOverlap * 100)}% same emojis
` +
`⚡ ${replyLine}
` +
`📅 Friends for ${friendshipDays} day${friendshipDays === 1 ? '' : 's'} · ${days.size} active day${days.size === 1 ? '' : 's'}`;

    res.json({
      score, verdict, emoji, total,
      youCount, themCount, youSharePct: Math.round(youShare * 100),
      emojiOverlapPct: Math.round(emojiOverlap * 100),
      sharedEmojis: shared.slice(0, 6),
      yourTopEmojis: topEmojis(youEmoji, 3),
      theirTopEmojis: topEmojis(themEmoji, 3),
      youMedian, themMedian, replyLine,
      friendshipDays, activeDays: days.size,
      yourName, theirName, shareText
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ GROUP ROUTES ============

// Create group
app.post('/api/groups', (req, res) => {
  try {
    const { name, description, members } = req.body;
    const db = loadDB();
    const createdBy = req.userId;

    if (!name || !createdBy) {
      return res.status(400).json({ error: 'Group name required' });
    }

    const group = {
      id: uuidv4(),
      name,
      description: description || '',
      avatar: null,
      members: [...new Set([createdBy, ...(members || [])])],
      admins: [createdBy],
      createdBy,
      createdAt: new Date().toISOString()
    };

    db.groups.push(group);
    saveDB(db);

    res.json({ success: true, group });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's groups
app.get('/api/groups/:userId', (req, res) => {
  if (req.params.userId !== req.userId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const db = loadDB();
  const groups = db.groups.filter(g => g.members.includes(req.userId));
  res.json({ groups });
});

// Notify all online members of a group about a change
function notifyGroupMembers(group, event, payload, exceptUserId) {
  group.members.forEach(memberId => {
    if (memberId === exceptUserId) return;
    const sock = onlineUsers.get(memberId);
    if (sock) io.to(sock).emit(event, payload);
  });
}

// Add member to group (admin only)
app.post('/api/groups/:groupId/members', (req, res) => {
  const { userId } = req.body;
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);
  const requestedBy = req.userId;

  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (!group.admins.includes(requestedBy)) {
    return res.status(403).json({ error: 'Only admins can add members' });
  }
  if (group.members.includes(userId)) {
    return res.status(400).json({ error: 'Already a member' });
  }

  group.members.push(userId);
  saveDB(db);
  notifyGroupMembers(group, 'group_updated', { groupId: group.id });
  res.json({ success: true, group });
});

// Remove member from group (admin or self-leave)
app.post('/api/groups/:groupId/remove-member', (req, res) => {
  const { userId } = req.body;
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);
  const requestedBy = req.userId;

  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (userId !== requestedBy && !group.admins.includes(requestedBy)) {
    return res.status(403).json({ error: 'Only admins can remove other members' });
  }
  if (userId === group.createdBy) {
    return res.status(400).json({ error: 'Cannot remove the group creator' });
  }

  group.members = group.members.filter(m => m !== userId);
  group.admins = group.admins.filter(a => a !== userId);
  saveDB(db);
  // Tell the removed user too, so their list updates
  if (userId !== requestedBy) {
    const removedSock = onlineUsers.get(userId);
    if (removedSock) io.to(removedSock).emit('removed_from_group', { groupId: group.id });
  }
  notifyGroupMembers(group, 'group_updated', { groupId: group.id });
  res.json({ success: true, group });
});

// Delete whole group (creator/admin only)
app.post('/api/groups/:groupId/delete', (req, res) => {
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);
  const requestedBy = req.userId;

  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (!group.admins.includes(requestedBy)) {
    return res.status(403).json({ error: 'Only admins can delete the group' });
  }

  const members = [...group.members];
  // Remove the group and all its messages
  db.groups = db.groups.filter(g => g.id !== group.id);
  db.messages = db.messages.filter(m => m.groupId !== group.id);
  saveDB(db);

  // Notify every member (including the actor's other devices)
  members.forEach(memberId => {
    const sock = onlineUsers.get(memberId);
    if (sock) io.to(sock).emit('group_deleted', { groupId: group.id, name: group.name });
  });
  res.json({ success: true });
});

// Update group name/avatar (admin only)
app.put('/api/groups/:groupId/update', (req, res) => {
  try {
    const { name, avatar } = req.body;
    const db = loadDB();
    const group = db.groups.find(g => g.id === req.params.groupId);
    const requestedBy = req.userId;
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (!group.admins.includes(requestedBy)) {
      return res.status(403).json({ error: 'Only admins can update the group' });
    }
    if (name !== undefined) group.name = name;
    if (avatar !== undefined) group.avatar = avatar;
    saveDB(db);
    notifyGroupMembers(group, 'group_updated', { groupId: group.id, name: group.name, avatar: group.avatar });
    res.json({ success: true, group: { ...group } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Set or update a group countdown (any member). Broadcasts to every online
// member so the live banner updates without a refetch.
app.post('/api/groups/:groupId/countdown', (req, res) => {
  try {
    const { label, target } = req.body;
    const db = loadDB();
    const group = db.groups.find(g => g.id === req.params.groupId);
    const userId = req.userId;
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (!(group.admins || []).includes(userId)) return res.status(403).json({ error: 'Only group admins can set a countdown' });
    const targetMs = new Date(target).getTime();
    if (!target || isNaN(targetMs)) return res.status(400).json({ error: 'A valid target date is required' });
    if (targetMs <= Date.now()) return res.status(400).json({ error: 'Countdown time must be in the future' });
    const countdown = {
      label: (label || '').toString().slice(0, 60),
      target: new Date(targetMs).toISOString(),
      createdBy: userId,
      createdAt: new Date().toISOString()
    };
    group.countdown = countdown;
    saveDB(db);
    notifyGroupMembers(group, 'group_updated', { groupId: group.id, countdown }, userId);
    res.json({ success: true, countdown });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove a group countdown (any member).
app.delete('/api/groups/:groupId/countdown', (req, res) => {
  try {
    const db = loadDB();
    const group = db.groups.find(g => g.id === req.params.groupId);
    const userId = req.userId;
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (!(group.admins || []).includes(userId)) return res.status(403).json({ error: 'Only group admins can remove the countdown' });
    delete group.countdown;
    saveDB(db);
    notifyGroupMembers(group, 'group_updated', { groupId: group.id, countdown: null }, userId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ FEEDBACK HUB ROUTES ============

// Ensure the feedback hub exists
app.get('/api/groups/feedback/info', (req, res) => {
  try {
    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.json({ exists: false });
    res.json({ exists: true, hub });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Auto-join endpoint (called after login if not joined)
app.post('/api/feedback/auto-join', (req, res) => {
  try {
    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.status(404).json({ error: 'Feedback hub not found' });
    const userId = req.userId;
    if (!hub.members.includes(userId)) {
      hub.members.push(userId);
      saveDB(db);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update feedback hub info (admin only)
app.put('/api/groups/feedback/update', (req, res) => {
  try {
    const { name, description, rules } = req.body;
    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.status(404).json({ error: 'Feedback hub not found' });
    const requestedBy = req.userId;
    if (!hub.admins.includes(requestedBy)) {
      return res.status(403).json({ error: 'Only admins can update the feedback hub' });
    }
    if (name !== undefined) hub.name = name;
    if (description !== undefined) hub.description = description;
    if (rules !== undefined) hub.rules = rules;
    saveDB(db);
    notifyGroupMembers(hub, 'group_updated', { groupId: hub.id, name: hub.name, description: hub.description, rules: hub.rules });
    res.json({ success: true, hub: { ...hub } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update bug status (admin only)
app.put('/api/bugs/:messageId/status', (req, res) => {
  try {
    const { status } = req.body;
    const requestedBy = req.userId;
    const validStatuses = ['open', 'confirmed', 'in-progress', 'fixed', 'wontfix'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub || !hub.admins.includes(requestedBy)) {
      return res.status(403).json({ error: 'Only feedback admins can update bug status' });
    }

    const msg = db.messages.find(m => m.id === req.params.messageId);
    if (!msg || !msg._bug) return res.status(404).json({ error: 'Bug not found' });

    msg._bug.status = status;
    msg._bug.statusUpdatedAt = new Date().toISOString();
    saveDB(db);
    io.emit('bug_status_updated', { messageId: req.params.messageId, status, statusUpdatedAt: msg._bug.statusUpdatedAt });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update feature status (admin only)
app.put('/api/features/:messageId/status', (req, res) => {
  try {
    const { status } = req.body;
    const requestedBy = req.userId;
    const validStatuses = ['suggested', 'under-review', 'planned', 'in-progress', 'completed', 'declined'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub || !hub.admins.includes(requestedBy)) {
      return res.status(403).json({ error: 'Only feedback admins can update feature status' });
    }

    const msg = db.messages.find(m => m.id === req.params.messageId);
    if (!msg || !msg._feature) return res.status(404).json({ error: 'Feature not found' });

    msg._feature.status = status;
    msg._feature.statusUpdatedAt = new Date().toISOString();
    saveDB(db);
    io.emit('feature_status_updated', { messageId: req.params.messageId, status, statusUpdatedAt: msg._feature.statusUpdatedAt });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/feedback/messages', (req, res) => {
  try {
    const { type, hubId = FEEDBACK_HUB_ID } = req.query;
    const db = loadDB();
    const hub = db.groups.find(g => g.id === hubId);
    if (!hub) return res.status(404).json({ error: 'Hub not found' });

    let messages = db.messages.filter(m => m.groupId === hubId);
    if (type) messages = messages.filter(m => m[`_${type}`]);
    messages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const users = db.users.map(u => ({ id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar, isAdmin: u.role === 'admin' }));
    res.json({ messages, users });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Unread "for me" thread replies for the requesting user. A reply is "for me"
// when it @mentions me OR replies to a post I authored; it is unread until MY
// id is in its readBy (per-user read state — Bob reading never clears mine).
// Returns the total so the client can badge the Feedback Hub nav button (card
// pills are computed client-side from loaded messages for instant sync). Uses
// the verified session userId (never client-supplied identity).
app.get('/api/feedback/unread', (req, res) => {
  try {
    // Read-only scan of all hub messages — light limiter matches the other
    // read-heavy endpoints (poll/search) so a scripted client can't hammer it.
    const limit = rateLimit(`feedbackUnread:${req.userId}`, { windowMs: UNREAD_WINDOW_MS, max: UNREAD_MAX });
    if (!limit.allowed) return sendTooMany(res, limit.retryAfterMs, 'Checking too fast — try again shortly.');

    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.json({ count: 0 });

    const myId = String(req.userId);
    const parentById = {};
    db.messages.forEach(m => { if (m.id) parentById[m.id] = m; });

    let count = 0;
    db.messages.forEach(m => {
      if (m.groupId !== FEEDBACK_HUB_ID || !m._threadReply || m.deleted) return;
      if (String(m.from) === myId) return;
      const mentionedMe = Array.isArray(m.mentions) && m.mentions.some(id => String(id) === myId);
      const parent = parentById[m.parentId];
      const repliedToMyPost = parent && String(parent.from) === myId;
      if (!mentionedMe && !repliedToMyPost) return;
      if (Array.isArray(m.readBy) && m.readBy.some(id => String(id) === myId)) return;
      count++;
    });

    res.json({ count });
  } catch (e) {
    res.json({ count: 0 });
  }
});

// Poll new unread messages for background native service (0 dependencies, 100% private)
app.get('/api/notifications/poll', (req, res) => {
  try {
    const { since } = req.query;
    const userId = req.userId;
    if (!userId) return res.json({ unread: [] });
    // The Android background service polls every ~4s (15/min); 60/min is a
    // generous safety net against runaway or misconfigured clients.
    const result = rateLimit(`poll:${userId}`, { windowMs: POLL_WINDOW_MS, max: POLL_MAX });
    if (!result.allowed) return sendTooMany(res, result.retryAfterMs, 'Polling too frequently.');
    const db = loadDB();
    const sinceDate = since ? new Date(Number(since)) : new Date(Date.now() - 30000);

    // Parent lookup so feedback-hub replies can be checked "for me" (I was
    // @mentioned, or it replies to a post I authored) — the SAME rule the
    // in-app Notifications drawer uses, so native + drawer stay consistent.
    // A hub reply's parent is always a hub message itself, so index only the
    // hub's messages (cheaper than mapping the whole DB on every 4s poll).
    const hubParentById = {};
    db.messages.forEach(m => {
      if (m.id && String(m.groupId || '') === FEEDBACK_HUB_ID) hubParentById[m.id] = m;
    });

    const unread = db.messages.filter(m => {
      if (m.deleted) return false;
      // Per-user read state: someone else reading must never suppress THIS
      // user's notification — only their own readBy entry does.
      if (m.readBy && Array.isArray(m.readBy) && m.readBy.includes(userId)) return false;
      if (String(m.from) === String(userId)) return false;
      if (new Date(m.timestamp) <= sinceDate) return false;

      if (m.groupId) {
        const group = db.groups.find(g => String(g.id) === String(m.groupId));
        if (!group || !group.members || !group.members.some(memId => String(memId) === String(userId))) return false;
        // The Feedback Hub is NOT a normal group chat. Only thread replies
        // that are "for me" become native notifications; every other hub post
        // stays in the hub's in-app drawer/badge instead of spamming the
        // status bar with non-mentions and unrelated messages.
        if (String(m.groupId) === FEEDBACK_HUB_ID) {
          if (!m._threadReply) return false;
          const mentionedMe = Array.isArray(m.mentions) && m.mentions.some(id => String(id) === String(userId));
          if (mentionedMe) return true;
          const parent = hubParentById[m.parentId];
          return !!(parent && String(parent.from) === String(userId));
        }
        return true;
      } else {
        return String(m.to) === String(userId);
      }
    });

    const userMap = {};
    const avatarMap = {};
    db.users.forEach(u => {
      userMap[u.id] = u.displayName || u.username;
      avatarMap[u.id] = u.avatar || null;
    });
    // Group context so the native notification can title itself "RR Test Group"
    // instead of just "Bob" — Android has no other way to learn the group name.
    const groupMap = {};
    db.groups.forEach(g => { groupMap[g.id] = { name: g.name, avatar: g.avatar || null }; });

    const formatted = unread.slice(0, 5).map(m => ({
      id: m.id,
      from: m.from,
      groupId: m.groupId || null,
      // Thread root id for feedback-hub replies so a notification tap can
      // deep-link straight into the discussion thread (parentId is the root
      // post; only thread replies are ever polled for the hub).
      parentId: m.parentId || null,
      // Root post text so Android can title each hub notification with the
      // discussion thread it belongs to — separate threads = separate trays.
      parentText: (m.parentId && hubParentById[m.parentId]) ? (hubParentById[m.parentId].text || null) : null,
      groupName: m.groupId ? (groupMap[m.groupId] ? groupMap[m.groupId].name : null) : null,
      groupAvatar: m.groupId ? (groupMap[m.groupId] ? groupMap[m.groupId].avatar : null) : null,
      senderName: userMap[m.from] || 'Someone',
      senderAvatar: avatarMap[m.from] || null,
      text: m.text || (m.type === 'image' ? '📷 Photo' : m.type === 'voice' ? '🎤 Voice' : 'New message'),
      timestamp: m.timestamp
    }));

    // Message ids this user has READ since the last poll (per-user readAt is
    // recorded by mark_read). The Android background service uses these to
    // prune/dismiss its tray notifications, so read mentions disappear from
    // the status bar instead of lingering after the user reads them in-app.
    // Capped to the most recent reads — the service only tracks a handful of
    // shown messages per conversation.
    // Reactions to the USER'S OWN messages (someone reacted to what I sent).
    // Only the message author is targeted — the reactor is never notified.
    // Mute is respected per conversation (dm partner id or group id).
    // Reactions are GROUPED BY MESSAGE: multiple people reacting to the same
    // message collapse into ONE entry (reactor count + names + newest emoji),
    // so the client renders "Pawan and 2 others reacted 👍" instead of firing
    // one alert per reactor. A group is delivered when ANY of its reactions is
    // newer than sinceDate; capped at 5 groups like unread.
    const myMuted = new Set((db.users.find(u => String(u.id) === String(userId)) || {}).mutedConversations || []);
    const reactions = (() => {
      // messageId -> group accumulator
      const groups = new Map();
      (db.reactions || [])
        .filter(r => String(r.targetUserId) === String(userId))
        .filter(r => !myMuted.has(String(r.conversationId)))
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .forEach(r => {
          // Skip stale log entries (un-reacted): the reactions log is
          // append-only, so verify the reaction still exists on the message.
          const reacted = db.messages.find(m => m.id === r.messageId);
          if (!reacted || !reacted.reactions || reacted.reactions[r.reactorId] !== r.emoji) return;
          let g = groups.get(r.messageId);
          if (!g) {
            g = { messageId: r.messageId, reactors: new Map(), newestTs: 0 };
            groups.set(r.messageId, g);
          }
          // One row per reactor (a reactor changing emoji stays one reactor);
          // keep the newest reaction's emoji + timestamp for the group.
          const prev = g.reactors.get(r.reactorId);
          if (!prev) {
            g.reactors.set(r.reactorId, { id: r.reactorId, name: userMap[r.reactorId] || 'Someone', avatar: avatarMap[r.reactorId] || null, emoji: r.emoji, ts: new Date(r.timestamp).getTime() });
          } else if (new Date(r.timestamp).getTime() > prev.ts) {
            prev.emoji = r.emoji;
            prev.ts = new Date(r.timestamp).getTime();
          }
          const ts = new Date(r.timestamp).getTime();
          if (ts > g.newestTs) g.newestTs = ts;
        });
      // Build group entries, newest-first, only groups with fresh activity.
      return Array.from(groups.values())
        .filter(g => g.newestTs > sinceDate.getTime())
        .sort((a, b) => b.newestTs - a.newestTs)
        .slice(0, 5)
        .map(g => {
          const newest = Array.from(g.reactors.values()).sort((a, b) => b.ts - a.ts)[0];
          const names = Array.from(g.reactors.values()).sort((a, b) => b.ts - a.ts).map(x => x.name);
          const reacted = db.messages.find(m => m.id === g.messageId);
          return {
            // Stable id across polls so the client can dedupe the GROUP (not
            // per reaction): messageId + reactor count.
            id: `${g.messageId}:${g.reactors.size}`,
            messageId: g.messageId,
            reactorId: g.reactors.size === 1 ? newest.id : null,
            reactorName: newest ? newest.name : 'Someone',
            reactorNames: names,
            reactorCount: g.reactors.size,
            emoji: newest ? newest.emoji : '👍',
            reactorAvatar: newest ? newest.avatar : null,
            // If the reacted message was deleted afterward, don't surface the
            // original text in the notification — just say it was a message.
            text: reacted ? (reacted.deleted ? 'a deleted message'
              : (reacted.text || (reacted.type === 'image' ? '📷 Photo' : reacted.type === 'voice' ? '🎤 Voice' : 'New message'))) : 'New message',
            groupId: reacted ? (reacted.groupId || null) : null,
            dmPartnerId: reacted ? (reacted.groupId ? null : (reacted.to || null)) : null,
            groupName: (reacted && reacted.groupId && groupMap[reacted.groupId]) ? groupMap[reacted.groupId].name : null,
            conversationId: reacted ? String(reacted.groupId || reacted.to || '') : '',
            timestamp: new Date(g.newestTs).toISOString()
          };
        });
    })();

    const readIds = db.messages
      .filter(m => m.readAt && m.readAt[userId] && new Date(m.readAt[userId]) > sinceDate)
      .map(m => String(m.id))
      .slice(-200);

    res.json({ unread: formatted, readIds, reactions });
  } catch (e) {
    res.json({ unread: [], reactions: [] });
  }
});

// HTTP endpoint for Android status bar inline replies (0 dependencies)
app.post('/api/messages/reply', (req, res) => {
  try {
    // Shares the same per-user budget as socket sends (one bucket per user).
    const result = rateLimit(`msg:${req.userId}`, { windowMs: MSG_WINDOW_MS, max: MSG_MAX });
    if (!result.allowed) return sendTooMany(res, result.retryAfterMs, 'Sending messages too fast — try again shortly.');

    const { to, groupId, text, replyTo } = req.body;
    const from = req.userId;
    if (!from || (!to && !groupId) || !text) return res.status(400).json({ error: 'Missing required parameters' });

    const db = loadDB();

    // Access control — must mirror the socket path exactly (this is the
    // Android inline-reply endpoint, so it must not be a bypass):
    //   * group: sender must be a member of the group;
    //   * DM: recipient must exist, and neither party may have blocked the
    //     other (silently drop like the socket path, or 403).
    if (groupId) {
      const group = db.groups.find(g => String(g.id) === String(groupId));
      if (!group || !group.members.some(m => String(m) === String(from))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    } else if (to) {
      // Shared authorization — same rule as the socket send_message handler.
      const sendCheck = checkDMSend(db, from, to);
      if (!sendCheck.ok) {
        return res.status(sendCheck.status).json({ error: sendCheck.error });
      }
    }

    const message = {
      id: uuidv4(),
      from,
      to: groupId ? null : to,
      groupId: groupId || null,
      text: text.trim(),
      type: 'text',
      replyTo: replyTo || null,
      timestamp: new Date().toISOString(),
      read: false,
      // Read receipts track who else has read a message; the author is not a
      // reader, so HTTP-replied messages start empty (consistent with socket sends).
      readBy: []
    };

    db.messages.push(message);
    saveDB(db);

    if (groupId) {
      const group = db.groups.find(g => String(g.id) === String(groupId));
      if (group) {
        group.members.forEach(memberId => {
          if (String(memberId) === String(from)) return;
          onlineUsers.forEach((sId, uId) => {
            if (String(uId) === String(memberId)) io.to(sId).emit('new_group_message', message);
          });
        });
      }
    } else if (to) {
      onlineUsers.forEach((sId, uId) => {
        if (String(uId) === String(to)) {
          io.to(sId).emit('new_message', message);
        }
        if (String(uId) === String(from)) {
          io.to(sId).emit('message_sent', message);
          io.to(sId).emit('new_message', message);
        }
      });
    }

    res.json({ success: true, message });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// ============ MESSAGES ROUTES ============

// Get messages (DM or group)
app.get('/api/messages', (req, res) => {
  try {
    const { from, to, groupId, limit = 50, skip = 0 } = req.query;
    const db = loadDB();
    const limitNum = Number(limit);
    const skipNum = Number(skip);

    // Only allow reading conversations the authenticated user is party to.
    if (groupId) {
      const group = db.groups.find(g => g.id === groupId);
      if (!group || !group.members.includes(req.userId)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    } else if (String(from) !== String(req.userId) && String(to) !== String(req.userId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // Messages are stored in chronological order (newest last).
    // Iterate backwards from the end to collect the most recent `limit` matches.
    const result = [];
    let total = 0;
    let skipped = 0;

    for (let i = db.messages.length - 1; i >= 0; i--) {
      const m = db.messages[i];
      let match;
      if (groupId) {
        match = m.groupId === groupId;
      } else {
        match = (m.from === from && m.to === to) || (m.from === to && m.to === from);
      }
      if (!match) continue;
      total++;
      if (skipped < skipNum) { skipped++; continue; }
      result.push(m);
      if (result.length === limitNum) break;
    }

    result.reverse();

    res.json({ messages: result, total });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ REPORTING & ADMIN MODERATION ============

const REPORT_WINDOW_MS = 15 * 60 * 1000; // 15 min
const REPORT_MAX = 15;                   // reports per user per window
const REPORT_REASONS = ['spam', 'harassment', 'inappropriate', 'impersonation', 'other'];

// Revoke every session a user holds (used when banning).
function deleteAllSessionsForUser(userId) {
  const db = loadDB();
  if (!Array.isArray(db.sessions)) return;
  const before = db.sessions.length;
  db.sessions = db.sessions.filter(s => s.userId !== userId);
  if (db.sessions.length !== before) saveDB(db);
}

// Report a message for moderation. Any authenticated user who is party to the
// conversation may report (they cannot report their own message).
app.post('/api/messages/:id/report', (req, res) => {
  try {
    const result = rateLimit(`report:${req.userId}`, { windowMs: REPORT_WINDOW_MS, max: REPORT_MAX });
    if (!result.allowed) return sendTooMany(res, result.retryAfterMs, 'Reporting too fast — try again shortly.');

    const { reason } = req.body;
    const reasonOk = REPORT_REASONS.includes(reason);
    if (!reasonOk) return res.status(400).json({ error: 'Invalid report reason' });

    const db = loadDB();
    const msg = db.messages.find(m => m.id === req.params.id);
    if (!msg || msg.deleted) return res.status(404).json({ error: 'Message not found' });
    if (String(msg.from) === String(req.userId)) {
      return res.status(400).json({ error: 'You cannot report your own message' });
    }
    if (!isUserPartyToMessage(msg, req.userId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (!Array.isArray(db.reports)) db.reports = [];
    // Idempotent per user: don't stack duplicate open reports.
    const existing = db.reports.find(r =>
      r.messageId === msg.id && r.reporterId === req.userId && r.status === 'open');
    if (existing) return res.json({ success: true, alreadyReported: true });

    db.reports.push({
      id: uuidv4(),
      messageId: msg.id,
      reporterId: req.userId,
      reason,
      status: 'open',
      createdAt: new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null
    });
    saveDB(db);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- ADMIN: all routes below require the global admin role ----

// List every user with moderation metadata (never the password).
// Media types that count as "shared media" for bot detection.
const MEDIA_TYPES = ['image', 'video', 'voice', 'file', 'document'];

// Shared heuristic for the admin Bot Check. Returns 0-100 plus the signals it
// derived — evidence to help an admin judge, NEVER an automated verdict (a
// legit power-user can look bot-like). Kept in one place so the users list and
// the per-user detail page always agree.
function botSignalsFor(user, sentMsgs) {
  const created = new Date(user.createdAt || Date.now()).getTime();
  const ageDays = Math.max((Date.now() - created) / 86400000, 0.001);
  const msgsPerDay = sentMsgs.length / ageDays;
  const mediaCount = sentMsgs.filter(m => m.mediaUrl && MEDIA_TYPES.includes(m.type)).length;
  let score = 0;
  // Rate-based signals only apply once there is real volume — a brand-new
  // user who sends their first few messages must NEVER look like a bot
  // (1 message in an 86-second-old account = ~1000/day without this gate).
  if (sentMsgs.length >= 10) {
    if (msgsPerDay > 120) score += 40;
    else if (msgsPerDay > 60) score += 30;
    else if (msgsPerDay > 25) score += 15;
    // Text-only flood (no media ever but many messages).
    if (mediaCount === 0 && sentMsgs.length > 50) score += 10;
    // Media flood (mostly media, lots of it).
    if (sentMsgs.length > 20 && mediaCount / sentMsgs.length > 0.8) score += 10;
    // Brand-new account already very active (only with substantial volume).
    if (sentMsgs.length > 20 && ageDays < 1) score += 15;
  }
  return {
    score: Math.min(100, score),
    ageDays: +ageDays.toFixed(1),
    msgsPerDay: +msgsPerDay.toFixed(2),
    mediaCount
  };
}

app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const users = db.users.map(u => {
      const { password, ...safe } = u;
      const sentMsgs = db.messages.filter(m => m.from === u.id && !m.deleted);
      safe.messageCount = sentMsgs.length;
      safe.reportCount = (db.reports || []).filter(r => r.messageId && db.messages.some(m => m.id === r.messageId && m.from === u.id)).length;
      const bot = botSignalsFor(u, sentMsgs);
      safe.mediaCount = bot.mediaCount;
      safe.botScore = bot.score;
      return safe;
    }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Bot Check — media + behavioral signals for one user. Everything here
// is data the app already legitimately stores (media the user SENT through the
// app, message timestamps, account age) — no device/file access is involved.
app.get('/api/admin/users/:id/media', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Every non-deleted message the user sent, newest first.
    const sent = db.messages
      .filter(m => String(m.from) === String(user.id) && !m.deleted)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Media the user actually shared through the app (photo/video/voice/file).
    const media = sent
      .filter(m => m.mediaUrl && MEDIA_TYPES.includes(m.type))
      .map(m => ({
        id: m.id,
        type: m.type,
        mediaUrl: m.mediaUrl,
        text: m.text || null,
        groupId: m.groupId || null,
        timestamp: m.timestamp
      }));

    const bot = botSignalsFor(user, sent);
    const partners = new Set(sent.filter(m => !m.groupId).map(m => String(m.from) === String(user.id) ? m.to : m.from));
    const groups = new Set(sent.filter(m => m.groupId).map(m => m.groupId));
    const risk = bot.score >= 50 ? 'high' : bot.score >= 25 ? 'medium' : 'low';

    res.json({
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar,
        role: user.role,
        banned: !!user.banned,
        createdAt: user.createdAt
      },
      signals: {
        accountAgeDays: bot.ageDays,
        totalMessages: sent.length,
        mediaCount: bot.mediaCount,
        msgsPerDay: bot.msgsPerDay,
        uniquePartners: partners.size,
        uniqueGroups: groups.size,
        firstMessageAt: sent.length ? sent[sent.length - 1].timestamp : null,
        lastMessageAt: sent.length ? sent[0].timestamp : null
      },
      botScore: bot.score,
      risk,
      media
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Ban a user: locks them out of login, every /api route, and live sockets.
app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.id === req.userId) return res.status(400).json({ error: 'You cannot ban yourself' });
    user.banned = true;
    user.bannedAt = new Date().toISOString();
    deleteAllSessionsForUser(user.id);
    saveDB(db);
    kickBannedUser(user.id, 'Your account has been banned by an admin.');
    res.json({ success: true, user: { id: user.id, username: user.username, banned: true } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Unban a user — restores login + API + socket access.
app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.banned = false;
    user.bannedAt = null;
    saveDB(db);
    res.json({ success: true, user: { id: user.id, username: user.username, banned: false } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// List open reports with message + reporter + author context.
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const reports = (db.reports || [])
      .filter(r => r.status === 'open')
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map(r => {
        const msg = db.messages.find(m => m.id === r.messageId);
        const reporter = db.users.find(u => u.id === r.reporterId);
        const author = msg ? db.users.find(u => u.id === msg.from) : null;
        return {
          id: r.id,
          reason: r.reason,
          createdAt: r.createdAt,
          message: msg ? {
            id: msg.id, text: msg.text, type: msg.type, timestamp: msg.timestamp,
            deleted: !!msg.deleted, groupId: msg.groupId || null, from: msg.from
          } : null,
          reporter: reporter ? { id: reporter.id, username: reporter.username, displayName: reporter.displayName, avatar: reporter.avatar } : { id: r.reporterId, username: 'deleted', displayName: 'Deleted user' },
          author: author ? { id: author.id, username: author.username, displayName: author.displayName, avatar: author.avatar, banned: !!author.banned } : null
        };
      });
    res.json({ reports });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Resolve a report: action 'dismiss' keeps the message, 'delete' soft-deletes
// it (and any thread replies under it), 'delete-ban' also bans the author.
app.post('/api/admin/reports/:id/resolve', requireAdmin, (req, res) => {
  try {
    const { action } = req.body;
    if (!['dismiss', 'delete', 'delete-ban'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const db = loadDB();
    const report = (db.reports || []).find(r => r.id === req.params.id);
    if (!report || report.status !== 'open') return res.status(404).json({ error: 'Report not found' });

    const msg = db.messages.find(m => m.id === report.messageId);
    const author = msg ? db.users.find(u => u.id === msg.from) : null;

    if (action === 'delete' || action === 'delete-ban') {
      if (msg && !msg.deleted) {
        msg.deleted = true;
        // Soft-delete thread replies attached to feedback posts too.
        if (msg.groupId === FEEDBACK_HUB_ID) {
          db.messages.forEach(m => {
            if (m.parentId === msg.id) m.deleted = true;
          });
        }
        io.emit('message_deleted', { messageId: msg.id });
      }
    }
    if (action === 'delete-ban' && author && author.id !== req.userId) {
      author.banned = true;
      author.bannedAt = new Date().toISOString();
      deleteAllSessionsForUser(author.id);
      kickBannedUser(author.id, 'Your account has been banned for policy violations.');
    }

    report.status = 'resolved';
    report.resolvedAt = new Date().toISOString();
    report.resolvedBy = req.userId;
    report.actionTaken = action;
    saveDB(db);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove an abusive feedback-hub post (bug/feature/poll/reply) outright.
app.post('/api/admin/feedback/:messageId/delete', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const msg = db.messages.find(m => m.id === req.params.messageId);
    if (!msg || msg.groupId !== FEEDBACK_HUB_ID) return res.status(404).json({ error: 'Feedback post not found' });
    msg.deleted = true;
    db.messages.forEach(m => { if (m.parentId === msg.id) m.deleted = true; });
    saveDB(db);
    io.emit('message_deleted', { messageId: msg.id });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ BAN APPEALS ============
// A banned user cannot authenticate, so appeals are PUBLIC (exempted in the
// /api auth middleware). They identify the account by username and are only
// accepted when that account is actually banned — one open appeal per user.

const APPEAL_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const APPEAL_MAX = 3;                    // appeals per IP per hour
const APPEAL_REASON_MIN = 10;            // min chars so appeals are substantive

app.post('/api/appeals', (req, res) => {
  try {
    const ipLimit = rateLimit(`appeal:ip:${req.ip}`, { windowMs: APPEAL_WINDOW_MS, max: APPEAL_MAX });
    if (!ipLimit.allowed) return sendTooMany(res, ipLimit.retryAfterMs, 'Too many appeals from this network. Please wait.');

    const { username, reason } = req.body;
    if (!username || !reason || String(reason).trim().length < APPEAL_REASON_MIN) {
      return res.status(400).json({ error: 'Please explain your appeal in a few sentences.' });
    }

    const db = loadDB();
    const user = db.users.find(u => String(u.username).toLowerCase() === String(username).toLowerCase());
    if (!user || !user.banned) {
      // Don't reveal whether the account exists; only banned accounts can appeal.
      return res.status(403).json({ error: 'This account is not eligible to appeal.' });
    }

    if (!Array.isArray(db.appeals)) db.appeals = [];
    const open = db.appeals.find(a => a.userId === user.id && a.status === 'open');
    if (open) return res.json({ success: true, alreadyAppealed: true });

    db.appeals.push({
      id: uuidv4(),
      userId: user.id,
      username: user.username,
      displayName: user.displayName || user.username,
      reason: String(reason).trim().slice(0, 2000),
      status: 'open',
      createdAt: new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null
    });
    saveDB(db);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// List open appeals with user context (admin only).
app.get('/api/admin/appeals', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const appeals = (db.appeals || [])
      .filter(a => a.status === 'open')
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map(a => {
        const user = db.users.find(u => u.id === a.userId);
        return {
          id: a.id,
          username: a.username,
          displayName: a.displayName,
          reason: a.reason,
          createdAt: a.createdAt,
          bannedAt: user ? user.bannedAt : null,
          messageCount: user ? db.messages.filter(m => m.from === user.id && !m.deleted).length : 0,
          priorReports: user ? (db.reports || []).filter(r => {
            const m = db.messages.find(x => x.id === r.messageId);
            return m && m.from === user.id;
          }).length : 0
        };
      });
    res.json({ appeals });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Approve an appeal — unbans the user so they can log in again.
app.post('/api/admin/appeals/:id/approve', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const appeal = (db.appeals || []).find(a => a.id === req.params.id);
    if (!appeal || appeal.status !== 'open') return res.status(404).json({ error: 'Appeal not found' });
    const user = db.users.find(u => u.id === appeal.userId);
    if (user) {
      user.banned = false;
      user.bannedAt = null;
    }
    appeal.status = 'approved';
    appeal.resolvedAt = new Date().toISOString();
    appeal.resolvedBy = req.userId;
    saveDB(db);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Reject an appeal — the user stays banned.
app.post('/api/admin/appeals/:id/reject', requireAdmin, (req, res) => {
  try {
    const db = loadDB();
    const appeal = (db.appeals || []).find(a => a.id === req.params.id);
    if (!appeal || appeal.status !== 'open') return res.status(404).json({ error: 'Appeal not found' });
    appeal.status = 'rejected';
    appeal.resolvedAt = new Date().toISOString();
    appeal.resolvedBy = req.userId;
    saveDB(db);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ SOCKET.IO ============
const onlineUsers = new Map(); // userId -> socketId

// P2P signaling queue: if the intended recipient isn't registered online at the
// exact instant a signal arrives (socket race, brief reconnect, app just
// opened), the signal used to be dropped — forcing users to reload until a
// transfer finally connected. Now we park signals here and flush them to the
// recipient's socket on user_online. Entries expire so stale offers never linger.
const pendingP2P = new Map(); // userId -> [{ event, payload, ts }]
const P2P_SIGNAL_TTL = 120000; // 2 minutes

function queueP2P(userId, event, payload) {
  if (!pendingP2P.has(userId)) pendingP2P.set(userId, []);
  const arr = pendingP2P.get(userId);
  arr.push({ event, payload, ts: Date.now() });
  while (arr.length > 200) arr.shift(); // hard cap per user
}

function flushP2P(userId, socket) {
  const arr = pendingP2P.get(userId);
  if (!arr || !arr.length) return;
  pendingP2P.delete(userId);
  const now = Date.now();
  for (const p of arr) {
    if (now - p.ts > P2P_SIGNAL_TTL) continue; // expired
    socket.emit(p.event, p.payload);
  }
}

// Deliver an event to a user's live socket, or park it for delivery the moment
// they register online. Never silently drops a P2P signal.
function relayOrQueueP2P(userId, event, payload) {
  const s = onlineUsers.get(userId);
  if (s) io.to(s).emit(event, payload);
  else queueP2P(userId, event, payload);
}

// Authenticate every socket connection with the same opaque session token
// used for HTTP. The verified user id is attached as socket.userId and is the
// ONLY trusted identity for all subsequent events (client-supplied ids are
// ignored everywhere below).
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  const session = getSessionByToken(token);
  if (!session) return next(new Error('Unauthorized'));
  const user = loadDB().users.find(u => u.id === session.userId);
  if (!user) return next(new Error('Unauthorized'));
  // Banned users cannot establish a realtime connection at all.
  if (user.banned) return next(new Error('Banned'));
  socket.userId = session.userId;
  next();
});

// Kick a banned user's live socket(s) and tell their clients why.
function kickBannedUser(userId, message) {
  const sockId = onlineUsers.get(userId);
  if (sockId) {
    io.to(sockId).emit('account_banned', { message });
    const sock = io.sockets.sockets.get(sockId);
    if (sock) sock.disconnect(true);
  }
  onlineUsers.delete(userId);
}

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // User comes online
  socket.on('user_online', () => {
    const userId = socket.userId;
    onlineUsers.set(userId, socket.id);

    // Broadcast to all
    io.emit('user_status', { userId, online: true });

    // Send online users list
    socket.emit('online_users', Array.from(onlineUsers.keys()));

    // Deliver any P2P signals parked while this user was offline/reconnecting.
    flushP2P(userId, socket);
  });

  // Avatar (DP) update
  socket.on('update_avatar', (data) => {
    const userId = socket.userId;
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (user) {
      user.avatar = data.avatarUrl;
      saveDB(db);
      io.emit('user_avatar_updated', { userId, avatarUrl: data.avatarUrl });
    }
  });

  // Profile update (name/bio) sync
  socket.on('update_profile', (data) => {
    const userId = socket.userId;
    io.emit('user_profile_updated', { userId, displayName: data.displayName, bio: data.bio });
  });

  // Send DM
  socket.on('send_message', (data) => {
    if (!socketRateLimit(socket, `msg:${socket.userId}`, { windowMs: MSG_WINDOW_MS, max: MSG_MAX, event: 'send_message', label: 'Sending messages too fast' })) return;
    const { to, text, type = 'text', mediaUrl = null, replyTo = null, p2pId = null, p2pMeta = null } = data;
    const from = socket.userId;
    const db = loadDB();

    // Shared authorization — recipient must exist and neither party may have
    // blocked the other (identical rule to the HTTP inline-reply endpoint).
    const sendCheck = checkDMSend(db, from, to);
    if (!sendCheck.ok) {
      return socket.emit('message_blocked', { to, error: sendCheck.error });
    }

    const message = {
      id: uuidv4(),
      from,
      to,
      groupId: null,
      text,
      type,
      mediaUrl,
      replyTo,
      p2pId,
      p2pMeta,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false
    };

    db.messages.push(message);
    saveDB(db);

    // Send to recipient if online
    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('new_message', message);
    }

    // Confirm to sender
    socket.emit('message_sent', message);
  });

  // Send group message (shares the same per-user budget as DMs)
  socket.on('send_group_message', (data) => {
    if (!socketRateLimit(socket, `msg:${socket.userId}`, { windowMs: MSG_WINDOW_MS, max: MSG_MAX, event: 'send_group_message', label: 'Sending messages too fast' })) return;
    const { groupId, text, type = 'text', mediaUrl = null, replyTo = null, p2pId = null, p2pMeta = null } = data;
    const from = socket.userId;
    const db = loadDB();

    const group = db.groups.find(g => g.id === groupId);
    // Membership check: a user must be a member of the group to post into it.
    // Without this, any authenticated user could inject messages into any
    // group whose id they know (IDOR / broken access control).
    if (!group || !group.members.includes(from)) return;

    const message = {
      id: uuidv4(),
      from,
      to: null,
      groupId,
      text,
      type,
      mediaUrl,
      replyTo,
      p2pId,
      p2pMeta,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false
    };

    db.messages.push(message);
    saveDB(db);

    // Send to all group members except sender
    group.members.forEach(memberId => {
      if (memberId !== from) {
        const memberSocket = onlineUsers.get(memberId);
        if (memberSocket) {
          io.to(memberSocket).emit('new_group_message', message);
        }
      }
    });

    socket.emit('group_message_sent', message);
  });

  // Typing indicator
  socket.on('typing', (data) => {
    const { to, groupId } = data;
    const from = socket.userId;
    // Send the display name so recipients can show "Alice is typing…" without
    // waiting for a name-cache prefetch.
    const sender = loadDB().users.find(u => u.id === from);
    const name = sender ? (sender.displayName || sender.username) : null;
    if (groupId) {
      const group = loadDB().groups.find(g => g.id === groupId);
      // Only members may broadcast typing state in a group (no spoofing into
      // groups you're not part of).
      if (group && group.members.includes(from)) {
        group.members.forEach(memberId => {
          if (memberId === from) return;
          const ms = onlineUsers.get(memberId);
          if (ms) io.to(ms).emit('user_typing', { from, groupId, name });
        });
      }
    } else {
      const recipientSocket = onlineUsers.get(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('user_typing', { from, name });
      }
    }
  });

  socket.on('stop_typing', (data) => {
    const { to, groupId } = data;
    const from = socket.userId;
    const sender = loadDB().users.find(u => u.id === from);
    const name = sender ? (sender.displayName || sender.username) : null;
    if (groupId) {
      const group = loadDB().groups.find(g => g.id === groupId);
      if (group && group.members.includes(from)) {
        group.members.forEach(memberId => {
          if (memberId === from) return;
          const ms = onlineUsers.get(memberId);
          if (ms) io.to(ms).emit('user_stop_typing', { from, groupId, name });
        });
      }
    } else {
      const recipientSocket = onlineUsers.get(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('user_stop_typing', { from, name });
      }
    }
  });

  // Mark read
  socket.on('mark_read', (data) => {
    const { messageIds } = data;
    const userId = socket.userId;
    const db = loadDB();
    const processed = [];
    messageIds.forEach(id => {
      const msg = db.messages.find(m => m.id === id);
      // Only allow marking messages in conversations the user is party to,
      // and never the user's own messages (authors can't "read" their own
      // text — a crafted socket event must not self-pollute readBy, which
      // would show the author in their own Seen By card).
      if (msg && isUserPartyToMessage(msg, userId) && String(msg.from) !== String(userId)) {
        msg.read = true;
        if (!msg.readBy) msg.readBy = [];
        if (userId && !msg.readBy.includes(userId)) {
          msg.readBy.push(userId);
          // First-read time per reader — powers the Chat Info "Seen by" list
          // (name + when). Only set on the first read so it is never bumped.
          if (!msg.readAt) msg.readAt = {};
          msg.readAt[userId] = new Date().toISOString();
        }
        processed.push(id);
      }
    });
    saveDB(db);
    // Only broadcast the ids that were actually updated, and only to sockets
    // party to those conversations (a DM read receipt must never leak to an
    // unrelated user). Include the reader's display name so the recipient can
    // render the avatar immediately without an extra fetch.
    if (processed.length > 0) {
      const partyIds = new Set();
      processed.forEach(id => {
        const m = db.messages.find(x => x.id === id);
        if (!m) return;
        if (m.groupId) {
          const g = db.groups.find(x => x.id === m.groupId);
          if (g) g.members.forEach(mid => partyIds.add(mid));
        } else {
          partyIds.add(m.from);
          partyIds.add(m.to);
        }
      });
      const reader = db.users.find(u => u.id === userId);
      // Per-message first-read timestamps so recipients can render "Seen by"
      // times live (initial loads get them straight from the HTTP response).
      const readAt = {};
      processed.forEach(id => {
        const m = db.messages.find(x => x.id === id);
        readAt[id] = (m && m.readAt) ? (m.readAt[userId] || null) : null;
      });
      const payload = {
        messageIds: processed,
        userId,
        displayName: reader ? (reader.displayName || reader.username) : null,
        readAt
      };
      partyIds.forEach(pid => {
        const sid = onlineUsers.get(pid);
        if (sid) io.to(sid).emit('messages_read', payload);
      });
    }
  });

  // Mark ALL reactions targeting the caller as seen in a conversation. Called
  // when the user opens a chat — clears the "reacted to your message" unread
  // preview in the chat list. Only reactions where the caller is the target
  // (author of the reacted message) are touched; the reactor's own view is
  // never affected.
  socket.on('mark_reactions_read', (data) => {
    const { conversationId } = data;
    const userId = socket.userId;
    if (!userId || !conversationId) return;
    const db = loadDB();
    const now = new Date().toISOString();
    let changed = false;
    (db.reactions || []).forEach(r => {
      if (String(r.targetUserId) !== String(userId)) return;
      if (String(r.conversationId) !== String(conversationId)) return;
      if (!r.readAt || typeof r.readAt !== 'object') r.readAt = {};
      if (!r.readAt[userId]) { r.readAt[userId] = now; changed = true; }
    });
    if (changed) saveDB(db);
  });

  // Edit message — only the author may edit
  socket.on('edit_message', (data) => {
    if (!socketRateLimit(socket, `edit:${socket.userId}`, { windowMs: EDIT_DELETE_WINDOW_MS, max: EDIT_DELETE_MAX, event: 'edit_message', label: 'Editing messages too fast' })) return;
    const { messageId, text } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || msg.from !== socket.userId) return;
    msg.text = text;
    msg.edited = true;
    msg.editedAt = new Date().toISOString();
    saveDB(db);
    io.emit('message_edited', { messageId, text, editedAt: msg.editedAt });
  });

  // React to message — identity is the verified socket user, and the user
  // must be party to the message's conversation.
  socket.on('react', (data) => {
    if (!socketRateLimit(socket, `react:${socket.userId}`, { windowMs: REACT_WINDOW_MS, max: REACT_MAX, event: 'react', label: 'Reacting too fast' })) return;
    const { messageId, emoji } = data;
    const userId = socket.userId;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (msg && isUserPartyToMessage(msg, userId)) {
      const removing = msg.reactions && msg.reactions[userId] === emoji;
      if (!msg.reactions) msg.reactions = {};
      if (removing) delete msg.reactions[userId];
      else msg.reactions[userId] = emoji;
      // Log the reaction so the message AUTHOR gets a native notification
      // (WhatsApp-style "X reacted 👍 to \"...\""). Only on ADD, never on
      // remove, and never notify the reactor themself.
      if (!removing && String(msg.from) !== String(userId)) {
        if (!Array.isArray(db.reactions)) db.reactions = [];
        db.reactions.push({
          id: uuidv4(),
          messageId,
          reactorId: userId,
          emoji,
          timestamp: new Date().toISOString(),
          targetUserId: msg.from,              // the author — the only notified party
          groupId: msg.groupId || null,
          dmPartnerId: msg.groupId ? null : userId, // DM tap → open that chat
          conversationId: msg.groupId ? String(msg.groupId) : String(userId),
          // Per-user "seen" map: readAt[targetUserId] is set when the author
          // opens that conversation (mark_reactions_read) — until then the
          // reaction counts as an unread "reacted to your message" in the
          // chat list.
          readAt: {}
        });
        // Bounded: reactions are a transient notification log, not history.
        if (db.reactions.length > 2000) db.reactions = db.reactions.slice(-1500);
      }
      saveDB(db);
      // Rich payload so the web client can show a WhatsApp-style toast
      // ("X reacted 🧐 to your message") when someone reacts to MY message
      // while I'm not looking at that chat: authorId (whose message), the
      // conversation ids, plus who reacted + what emoji.
      const reactor = db.users.find(u => String(u.id) === String(userId));
      const reactedGroup = msg.groupId ? db.groups.find(g => String(g.id) === String(msg.groupId)) : null;
      io.emit('message_reacted', {
        messageId,
        reactions: msg.reactions,
        authorId: msg.from,
        groupId: msg.groupId || null,
        groupName: reactedGroup ? reactedGroup.name : null,
        dmPartnerId: msg.groupId ? null : userId,
        reactorId: userId,
        reactorName: reactor ? (reactor.displayName || reactor.username || 'Someone') : 'Someone',
        emoji,
        // True when a reaction was ADDED, false when it was toggled OFF — lets
        // clients bump the chat-list unread preview only on real adds (the
        // emit fires for both, and a removal must never count as new activity).
        added: !removing
      });
    }
  });

  // Delete message — only the author may delete
  socket.on('delete_message', (data) => {
    if (!socketRateLimit(socket, `del:${socket.userId}`, { windowMs: EDIT_DELETE_WINDOW_MS, max: EDIT_DELETE_MAX, event: 'delete_message', label: 'Deleting messages too fast' })) return;
    const { messageId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || msg.from !== socket.userId) return;
    msg.deleted = true;
    saveDB(db);
    io.emit('message_deleted', { messageId });
  });

  // ===== WEBRTC DIRECT P2P FILE SIGNALING =====
  socket.on('p2p_signal', (data) => {
    const { to, signal, transferId, fileMeta } = data;
    if (!to || !signal) return;
    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('p2p_signal', {
        from: socket.userId,
        signal,
        transferId,
        fileMeta
      });
    } else {
      // Recipient isn't registered this exact instant — park the signal and
      // deliver it when they come online instead of dropping it.
      queueP2P(to, 'p2p_signal', { from: socket.userId, signal, transferId, fileMeta });
      if (signal.type === 'offer') {
        // Tell the sender the offer is parked, not lost.
        socket.emit('p2p_queued', { transferId });
      }
    }
  });

  // A receiver who lost the offer (reload / reconnect) asks the sender to
  // re-send it. Relayed to the sender's live socket, or queued if offline.
  socket.on('p2p_request_offer', (data) => {
    const { to, transferId } = data;
    if (!to) return;
    relayOrQueueP2P(to, 'p2p_request_offer', { from: socket.userId, transferId });
  });

  socket.on('p2p_complete', (data) => {
    const { to, transferId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.p2pId === transferId || (m.p2pMeta && m.p2pMeta.p2pId === transferId));
    // Only a party to the transfer's message may change its status.
    if (msg && isUserPartyToMessage(msg, socket.userId)) {
      msg.p2pStatus = 'completed';
      saveDB(db);
    }
    if (to) {
      relayOrQueueP2P(to, 'p2p_complete', { from: socket.userId, transferId });
    }
  });

  socket.on('p2p_cancel', (data) => {
    const { to, transferId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.p2pId === transferId || (m.p2pMeta && m.p2pMeta.p2pId === transferId));
    if (msg && isUserPartyToMessage(msg, socket.userId)) {
      msg.p2pStatus = 'declined';
      saveDB(db);
    }
    if (to) {
      relayOrQueueP2P(to, 'p2p_cancel', { from: socket.userId, transferId });
    }
  });

  socket.on('p2p_failed', (data) => {
    const { to, transferId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.p2pId === transferId || (m.p2pMeta && m.p2pMeta.p2pId === transferId));
    if (msg && isUserPartyToMessage(msg, socket.userId)) {
      msg.p2pStatus = 'failed';
      saveDB(db);
    }
    if (to) {
      relayOrQueueP2P(to, 'p2p_failed', { from: socket.userId, transferId });
    }
  });

  socket.on('p2p_update_status', (data) => {
    const { transferId, msgId, status } = data;
    if (!status) return;
    const db = loadDB();
    const msg = db.messages.find(m =>
      (transferId && (m.p2pId === transferId || (m.p2pMeta && m.p2pMeta.p2pId === transferId))) ||
      (msgId && m.id === msgId)
    );
    if (msg && isUserPartyToMessage(msg, socket.userId)) {
      msg.p2pStatus = status;
      saveDB(db);
    }
  });

  // Delete feedback message (author or admin only)
  socket.on('feedback_delete_message', (data) => {
    const { messageId } = data;
    const userId = socket.userId;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || msg.groupId !== FEEDBACK_HUB_ID) return;
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return;
    if (msg.from !== userId && !hub.admins.includes(userId)) return;
    msg.deleted = true;
    // Cascade: deleting a thread root must also hide every reply under it, or
    // the deleted thread's replies would keep showing in the admin Feedback
    // Hub (and in the app's thread list) as orphaned posts.
    db.messages.forEach(m => { if (m.parentId === msg.id) m.deleted = true; });
    saveDB(db);
    io.emit('message_deleted', { messageId });
  });

  // ========== FEEDBACK EVENTS ==========

  // Submit bug report
  socket.on('submit_bug', (data) => {
    const from = socket.userId;
    const { text, mediaUrl } = data;
    if (!text || !text.trim()) return socket.emit('feedback_error', { error: 'Bug description is required' });

    const db = loadDB();
    const user = db.users.find(u => u.id === from);
    if (!user) return;
    if (!checkFeedbackRateLimit(from)) return socket.emit('feedback_error', { error: 'You are submitting too fast. Please wait.' });

    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return;

    const message = {
      id: uuidv4(),
      from,
      to: null,
      groupId: FEEDBACK_HUB_ID,
      text: text.trim(),
      type: 'text',
      mediaUrl: mediaUrl || null,
      replyTo: null,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false,
      _bug: { status: 'open', votes: [], statusUpdatedAt: null }
    };

    db.messages.push(message);
    saveDB(db);
    io.emit('new_group_message', message);
    socket.emit('feedback_success', { type: 'bug', messageId: message.id });
  });

  // Submit feature suggestion
  socket.on('submit_feature', (data) => {
    const from = socket.userId;
    const { text, mediaUrl } = data;
    if (!text || !text.trim()) return socket.emit('feedback_error', { error: 'Feature description is required' });

    const db = loadDB();
    const user = db.users.find(u => u.id === from);
    if (!user) return;
    if (!checkFeedbackRateLimit(from)) return socket.emit('feedback_error', { error: 'You are submitting too fast. Please wait.' });

    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return;

    const message = {
      id: uuidv4(),
      from,
      to: null,
      groupId: FEEDBACK_HUB_ID,
      text: text.trim(),
      type: 'text',
      mediaUrl: mediaUrl || null,
      replyTo: null,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false,
      _feature: { status: 'suggested', votes: [], statusUpdatedAt: null }
    };

    db.messages.push(message);
    saveDB(db);
    io.emit('new_group_message', message);
    socket.emit('feedback_success', { type: 'feature', messageId: message.id });
  });

  // Vote on feature
  socket.on('vote_feature', (data) => {
    if (!socketRateLimit(socket, `vote:${socket.userId}`, { windowMs: VOTE_WINDOW_MS, max: VOTE_MAX, event: 'vote_feature', label: 'Voting too fast' })) return;
    const { messageId } = data;
    const userId = socket.userId;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || !msg._feature) return;

    const idx = msg._feature.votes.indexOf(userId);
    if (idx > -1) {
      msg._feature.votes.splice(idx, 1);
    } else {
      msg._feature.votes.push(userId);
    }
    saveDB(db);
    io.emit('feature_votes_updated', { messageId, votes: msg._feature.votes });
  });

  // Create priority poll
  socket.on('create_poll', (data) => {
    const from = socket.userId;
    const { question, quadrant } = data;
    if (!question || !question.trim()) return socket.emit('feedback_error', { error: 'Poll question is required' });
    if (!quadrant || !quadrant.length) return socket.emit('feedback_error', { error: 'At least one quadrant required' });

    const db = loadDB();
    const user = db.users.find(u => u.id === from);
    if (!user) return;

    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return;

    const message = {
      id: uuidv4(),
      from,
      to: null,
      groupId: FEEDBACK_HUB_ID,
      text: question.trim(),
      type: 'text',
      mediaUrl: null,
      replyTo: null,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false,
      _poll: {
        quadrant: quadrant, // array of cell labels
        votes: {} // userId -> cell label
      }
    };

    db.messages.push(message);
    saveDB(db);
    io.emit('new_group_message', message);
    socket.emit('feedback_success', { type: 'poll', messageId: message.id });
  });

  // Vote on poll
  socket.on('vote_poll', (data) => {
    if (!socketRateLimit(socket, `vote:${socket.userId}`, { windowMs: VOTE_WINDOW_MS, max: VOTE_MAX, event: 'vote_poll', label: 'Voting too fast' })) return;
    const { messageId, cell } = data;
    const userId = socket.userId;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || !msg._poll) return;
    if (msg._poll.votes[userId] === cell) {
      delete msg._poll.votes[userId];
    } else {
      msg._poll.votes[userId] = cell;
    }
    saveDB(db);
    io.emit('poll_votes_updated', { messageId, votes: msg._poll.votes });
  });

  // Thread reply (for bug/feature discussions). Supports @mentions: the client
  // sends a `mentions` array of user ids; we validate them against real users
  // (never self), persist them, and ping the mentioned users if they're online.
  socket.on('thread_reply', (data) => {
    const from = socket.userId;
    const { parentId, text, mediaUrl, mentions } = data;
    if (!text || !text.trim()) return socket.emit('feedback_error', { error: 'Reply text is required' });
    if (!checkFeedbackRateLimit(from)) return socket.emit('feedback_error', { error: 'You are replying too fast. Please wait.' });

    const db = loadDB();
    const parent = db.messages.find(m => m.id === parentId);
    if (!parent || parent.groupId !== FEEDBACK_HUB_ID) return;

    // Only trust mentions of real users, never self-mentions, dedupe.
    const mentionIds = (Array.isArray(mentions) ? mentions : [])
      .map(id => String(id))
      .filter(id => id && id !== String(from))
      .filter(id => db.users.some(u => String(u.id) === id));
    const uniqueMentions = [...new Set(mentionIds)];

    const reply = {
      id: uuidv4(),
      from,
      to: null,
      groupId: FEEDBACK_HUB_ID,
      parentId,
      text: text.trim(),
      type: 'text',
      mediaUrl: mediaUrl || null,
      replyTo: null,
      reactions: {},
      readBy: [],
      deleted: false,
      timestamp: new Date().toISOString(),
      read: false,
      _threadReply: true,
      mentions: uniqueMentions
    };

    db.messages.push(reply);
    saveDB(db);
    io.emit('new_group_message', reply);
    socket.emit('feedback_success', { type: 'thread_reply', messageId: reply.id, parentId });

    // Notify mentioned users who are online right now.
    if (uniqueMentions.length) {
      const author = db.users.find(u => String(u.id) === String(from));
      const fromName = author ? (author.displayName || author.username || 'Someone') : 'Someone';
      const parentText = parent.text ? String(parent.text).slice(0, 60) : '';
      uniqueMentions.forEach(uid => {
        const sockId = onlineUsers.get(uid);
        if (sockId) {
          io.to(sockId).emit('feedback_mention', {
            to: uid,
            from: String(from),
            fromName,
            parentId,
            replyId: reply.id,
            parentText
          });
        }
      });
    }
  });

  // Disconnect
  socket.on('disconnect', () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      io.emit('user_status', { userId: socket.userId, online: false });

      // Update DB
      const db = loadDB();
      const user = db.users.find(u => u.id === socket.userId);
      if (user) {
        user.online = false;
        user.lastSeen = new Date().toISOString();
        saveDB(db);
      }
    }
    console.log('Socket disconnected:', socket.id);
  });
});

// ============ IN-APP UPDATE MANIFEST ============
// The public "what's new" catalog that clients poll to discover web/APK
// updates. GET is public (checked before login on first launch); POST is
// admin-only and is what release.js calls to publish a new build. The file
// lives next to db.json (DATA_DIR) so it persists across redeploys exactly
// like the database.
const UPDATE_MANIFEST_PATH = process.env.UPDATE_MANIFEST_PATH || path.join(DATA_DIR, 'update-manifest.json');

function readUpdateManifest() {
  try {
    if (!fs.existsSync(UPDATE_MANIFEST_PATH)) return null;
    return JSON.parse(fs.readFileSync(UPDATE_MANIFEST_PATH, 'utf-8'));
  } catch (e) {
    return null;
  }
}

// Public: any client can ask "is there an update?" without a session.
app.get('/api/update/manifest', (req, res) => {
  const manifest = readUpdateManifest();
  if (!manifest) return res.status(404).json({ error: 'No update published yet' });
  res.json(manifest);
});

// Publish (admin only). Body is the full manifest object produced by release.js.
app.post('/api/update/manifest', requireAdmin, (req, res) => {
  try {
    const manifest = req.body;
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      return res.status(400).json({ error: 'Manifest object required' });
    }
    fs.writeFileSync(UPDATE_MANIFEST_PATH, JSON.stringify(manifest, null, 2));
    res.json({ success: true, manifest });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save manifest' });
  }
});

ensureFeedbackHub();

// Global error handler — return JSON instead of HTML (e.g. multer/file errors)
app.use((err, req, res, next) => {
  console.error('[UPLOAD/API ERROR]', err);
  res.status(err.status || 500).json({ error: err.message || 'Upload failed' });
});

server.listen(PORT, () => {
  console.log(`🚀 Chat server running on http://localhost:${PORT}`);
});
