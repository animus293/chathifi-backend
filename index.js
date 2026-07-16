const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const cors = require('cors');

const app = express();
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
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_PATH = path.join(DATA_DIR, 'db.json');
const UPLOADS_PATH = path.join(DATA_DIR, 'uploads');

// Create uploads folder if not exists
if (!fs.existsSync(UPLOADS_PATH)) {
  fs.mkdirSync(UPLOADS_PATH, { recursive: true });
}

// Multer storage for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_PATH),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp3|ogg|wav|mp4|webm/;
    const extOk = allowed.test(path.extname(file.originalname).toLowerCase());
    const mimeOk = allowed.test(file.mimetype.split('/')[1]);
    cb(null, extOk || mimeOk);
  }
});

// Feedback rate limiting
const feedbackRateLimitMap = new Map();
const FEEDBACK_RATE_LIMIT_WINDOW = 15000;
const FEEDBACK_RATE_LIMIT_MAX = 5;
function checkFeedbackRateLimit(userId) {
  const now = Date.now();
  const entry = feedbackRateLimitMap.get(userId);
  if (!entry) {
    feedbackRateLimitMap.set(userId, { count: 1, start: now });
    return true;
  }
  if (now - entry.start > FEEDBACK_RATE_LIMIT_WINDOW) {
    feedbackRateLimitMap.set(userId, { count: 1, start: now });
    return true;
  }
  if (entry.count >= FEEDBACK_RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
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
    const initial = { users: [], groups: [], messages: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
    dbCache = initial;
    dbCacheMtime = Date.now();
    return initial;
  }
  const stat = fs.statSync(DB_PATH);
  if (dbCache && stat.mtimeMs === dbCacheMtime) return dbCache;
  dbCache = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  dbCacheMtime = stat.mtimeMs;
  return dbCache;
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  dbCache = data;
  dbCacheMtime = Date.now();
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: 0 }));
app.use('/uploads', express.static(UPLOADS_PATH));

// ============ AUTH ROUTES ============

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, displayName } = req.body;
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
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    // Auto-join feedback hub
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (hub && !hub.members.includes(newUser.id)) {
      hub.members.push(newUser.id);
    }
    saveDB(db);

    const { password: _, ...userWithoutPassword } = newUser;
    res.json({ success: true, user: userWithoutPassword, token: newUser.id });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = loadDB();

    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    user.online = true;
    user.lastSeen = new Date().toISOString();
    saveDB(db);

    const { password: _, ...userWithoutPassword } = user;
    res.json({ success: true, user: userWithoutPassword, token: user.id });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
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

    const results = users.map(({ password, ...u }) => u);
    res.json({ users: results });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user by ID
app.get('/api/users/:id', (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...u } = user;
  res.json({ user: u });
});

// ============ FILE UPLOAD ============
app.post('/api/upload', upload.single('file'), (req, res) => {
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
    const { q, userId, groupId } = req.query;
    const db = loadDB();
    if (!q) return res.json({ messages: [] });

    const query = q.toLowerCase();
    let results;

    if (groupId) {
      results = db.messages.filter(m => m.groupId === groupId && !m.deleted && m.text && m.text.toLowerCase().includes(query));
    } else if (userId) {
      results = db.messages.filter(m =>
        !m.groupId && !m.deleted && m.text && m.text.toLowerCase().includes(query) &&
        (m.from === userId || m.to === userId)
      );
    } else {
      results = db.messages.filter(m => !m.deleted && m.text && m.text.toLowerCase().includes(query) && (m.from === userId || m.to === userId));
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
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { displayName, bio, avatar } = req.body;
    if (displayName) user.displayName = displayName;
    if (bio !== undefined) user.bio = bio;
    if (avatar !== undefined) user.avatar = avatar;
    saveDB(db);
    const { password, ...u } = user;
    res.json({ success: true, user: u });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ BLOCK USER ============
app.post('/api/users/:userId/block', (req, res) => {
  try {
    const { targetUserId, action } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.userId);
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
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.userId);
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
    const { conversationId, action } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.mutedConversations) user.mutedConversations = [];

    if (action === 'mute') {
      if (!user.mutedConversations.includes(conversationId)) {
        user.mutedConversations.push(conversationId);
      }
    } else if (action === 'unmute') {
      user.mutedConversations = user.mutedConversations.filter(id => id !== conversationId);
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
    const db = loadDB();
    const user = db.users.find(u => u.id === req.params.userId);
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
    const db = loadDB();
    const userId = req.params.userId;

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
        if (m.from !== userId && !m.read) {
          groupUnread[m.groupId] = (groupUnread[m.groupId] || 0) + 1;
        }
      } else if (m.from === userId || m.to === userId) {
        // DM message
        const partnerId = m.from === userId ? m.to : m.from;
        dmPartnerIds.add(partnerId);
        if (!dmLastMsg[partnerId] || ts > dmLastMsg[partnerId].timestamp) {
          dmLastMsg[partnerId] = { text, timestamp: ts };
        }
        if (m.from === partnerId && !m.read) {
          dmUnread[partnerId] = (dmUnread[partnerId] || 0) + 1;
        }
      }
    }

    // Build DM conversations
    const dmConvs = Array.from(dmPartnerIds).map(pid => {
      const user = db.users.find(u => u.id === pid);
      if (!user) return null;
      const { password, ...u } = user;
      return {
        type: 'dm',
        id: pid,
        name: u.displayName || u.username,
        username: u.username,
        avatar: u.avatar || null,
        online: u.online,
        lastSeen: u.lastSeen,
        lastMessage: dmLastMsg[pid]?.text || '',
        lastMessageTime: dmLastMsg[pid]?.timestamp || 0,
        unread: dmUnread[pid] || 0,
        blocked: blockedSet.has(pid),
        muted: mutedSet.has(pid)
      };
    }).filter(Boolean);

    // Build group conversations (pre-computed data from single pass)
    const userGroups = db.groups
      .filter(g => g.members.includes(userId))
      .map(g => {
        const lm = groupLastMsg[g.id];
        return {
          type: 'group',
          id: g.id,
          name: g.name,
          avatar: g.avatar || null,
          members: g.members,
          admins: g.admins || [],
          createdBy: g.createdBy,
          lastMessage: lm ? lm.text : '',
          lastMessageTime: lm ? lm.timestamp : 0,
          unread: groupUnread[g.id] || 0,
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

// ============ GROUP ROUTES ============

// Create group
app.post('/api/groups', (req, res) => {
  try {
    const { name, description, members, createdBy } = req.body;
    const db = loadDB();

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
  const db = loadDB();
  const groups = db.groups.filter(g => g.members.includes(req.params.userId));
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
  const { userId, requestedBy } = req.body;
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);

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
  const { userId, requestedBy } = req.body;
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);

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
  const { requestedBy } = req.body;
  const db = loadDB();
  const group = db.groups.find(g => g.id === req.params.groupId);

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
    const { name, avatar, requestedBy } = req.body;
    const db = loadDB();
    const group = db.groups.find(g => g.id === req.params.groupId);
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
    const { userId } = req.body;
    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.status(404).json({ error: 'Feedback hub not found' });
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
    const { name, description, rules, requestedBy } = req.body;
    const db = loadDB();
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return res.status(404).json({ error: 'Feedback hub not found' });
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
    const { status, requestedBy } = req.body;
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
    const { status, requestedBy } = req.body;
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
    const users = db.users.map(u => ({ id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar }));
    res.json({ messages, users });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
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

// ============ SOCKET.IO ============
const onlineUsers = new Map(); // userId -> socketId

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // User comes online
  socket.on('user_online', (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.userId = userId;

    // Broadcast to all
    io.emit('user_status', { userId, online: true });

    // Send online users list
    socket.emit('online_users', Array.from(onlineUsers.keys()));
  });

  // Avatar (DP) update
  socket.on('update_avatar', (data) => {
    const db = loadDB();
    const user = db.users.find(u => u.id === data.userId);
    if (user) {
      user.avatar = data.avatarUrl;
      saveDB(db);
      io.emit('user_avatar_updated', { userId: data.userId, avatarUrl: data.avatarUrl });
    }
  });

  // Profile update (name/bio) sync
  socket.on('update_profile', (data) => {
    io.emit('user_profile_updated', { userId: data.userId, displayName: data.displayName, bio: data.bio });
  });

  // Send DM
  socket.on('send_message', (data) => {
    const { from, to, text, type = 'text', mediaUrl = null, replyTo = null } = data;
    const db = loadDB();

    // Check if sender is blocked by the recipient
    const recipient = db.users.find(u => u.id === to);
    if (recipient && (recipient.blockedUsers || []).includes(from)) {
      return socket.emit('message_blocked', { to, error: 'You are blocked by this user' });
    }
    // Check if recipient is blocked by the sender
    const sender = db.users.find(u => u.id === from);
    if (sender && (sender.blockedUsers || []).includes(to)) {
      return socket.emit('message_blocked', { to, error: 'You have blocked this user. Unblock to send messages.' });
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

  // Send group message
  socket.on('send_group_message', (data) => {
    const { from, groupId, text, type = 'text', mediaUrl = null, replyTo = null } = data;
    const db = loadDB();

    const group = db.groups.find(g => g.id === groupId);
    if (!group) return;

    const message = {
      id: uuidv4(),
      from,
      to: null,
      groupId,
      text,
      type,
      mediaUrl,
      replyTo,
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
    const { to, from, groupId } = data;
    if (groupId) {
      const group = loadDB().groups.find(g => g.id === groupId);
      if (group) {
        group.members.forEach(memberId => {
          if (memberId === from) return;
          const ms = onlineUsers.get(memberId);
          if (ms) io.to(ms).emit('user_typing', { from, groupId });
        });
      }
    } else {
      const recipientSocket = onlineUsers.get(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('user_typing', { from });
      }
    }
  });

  socket.on('stop_typing', (data) => {
    const { to, from, groupId } = data;
    if (groupId) {
      const group = loadDB().groups.find(g => g.id === groupId);
      if (group) {
        group.members.forEach(memberId => {
          if (memberId === from) return;
          const ms = onlineUsers.get(memberId);
          if (ms) io.to(ms).emit('user_stop_typing', { from, groupId });
        });
      }
    } else {
      const recipientSocket = onlineUsers.get(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('user_stop_typing', { from });
      }
    }
  });

  // Mark read
  socket.on('mark_read', (data) => {
    const { messageIds, userId } = data;
    const db = loadDB();
    messageIds.forEach(id => {
      const msg = db.messages.find(m => m.id === id);
      if (msg) {
        msg.read = true;
        if (!msg.readBy) msg.readBy = [];
        if (userId && !msg.readBy.includes(userId)) {
          msg.readBy.push(userId);
        }
      }
    });
    saveDB(db);
    io.emit('messages_read', { messageIds, userId });
  });

  // Edit message
  socket.on('edit_message', (data) => {
    const { messageId, text } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg) return;
    msg.text = text;
    msg.edited = true;
    msg.editedAt = new Date().toISOString();
    saveDB(db);
    io.emit('message_edited', { messageId, text, editedAt: msg.editedAt });
  });

  // React to message
  socket.on('react', (data) => {
    const { messageId, userId, emoji } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (msg) {
      if (!msg.reactions) msg.reactions = {};
      if (msg.reactions[userId] === emoji) delete msg.reactions[userId];
      else msg.reactions[userId] = emoji;
      saveDB(db);
      io.emit('message_reacted', { messageId, reactions: msg.reactions });
    }
  });

  // Delete message
  socket.on('delete_message', (data) => {
    const { messageId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (msg) {
      msg.deleted = true;
      saveDB(db);
      io.emit('message_deleted', { messageId });
    }
  });

  // Delete feedback message (author or admin only)
  socket.on('feedback_delete_message', (data) => {
    const { messageId, userId } = data;
    const db = loadDB();
    const msg = db.messages.find(m => m.id === messageId);
    if (!msg || msg.groupId !== FEEDBACK_HUB_ID) return;
    const hub = db.groups.find(g => g.id === FEEDBACK_HUB_ID);
    if (!hub) return;
    if (msg.from !== userId && !hub.admins.includes(userId)) return;
    msg.deleted = true;
    saveDB(db);
    io.emit('message_deleted', { messageId });
  });

  // ========== FEEDBACK EVENTS ==========

  // Submit bug report
  socket.on('submit_bug', (data) => {
    const { from, text, mediaUrl } = data;
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
    const { from, text, mediaUrl } = data;
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
    const { messageId, userId } = data;
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
    const { from, question, quadrant } = data;
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
    const { messageId, userId, cell } = data;
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

  // Thread reply (for bug/feature discussions)
  socket.on('thread_reply', (data) => {
    const { from, parentId, text, mediaUrl } = data;
    if (!text || !text.trim()) return socket.emit('feedback_error', { error: 'Reply text is required' });
    if (!checkFeedbackRateLimit(from)) return socket.emit('feedback_error', { error: 'You are replying too fast. Please wait.' });

    const db = loadDB();
    const parent = db.messages.find(m => m.id === parentId);
    if (!parent || parent.groupId !== FEEDBACK_HUB_ID) return;

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
      _threadReply: true
    };

    db.messages.push(reply);
    saveDB(db);
    io.emit('new_group_message', reply);
    socket.emit('feedback_success', { type: 'thread_reply', messageId: reply.id, parentId });
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

ensureFeedbackHub();

// Global error handler — return JSON instead of HTML (e.g. multer/file errors)
app.use((err, req, res, next) => {
  console.error('[UPLOAD/API ERROR]', err);
  res.status(err.status || 500).json({ error: err.message || 'Upload failed' });
});

server.listen(PORT, () => {
  console.log(`🚀 Chat server running on http://localhost:${PORT}`);
});
