require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

const TREE_PATH = path.join(__dirname, 'data', 'tree.json');
const ADMINS_PATH = path.join(__dirname, 'data', 'admins.json');
const BACKUPS_DIR = path.join(__dirname, 'backups');

if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

function readTree() {
  try {
    return JSON.parse(fs.readFileSync(TREE_PATH, 'utf8'));
  } catch {
    return { start: { question: "Type de bien?", options: [] } };
  }
}

function writeTree(data) {
  const backup = path.join(BACKUPS_DIR, `tree-${new Date().toISOString().replace(/:/g, '-')}.json`);
  if (fs.existsSync(TREE_PATH)) fs.copyFileSync(TREE_PATH, backup);
  fs.writeFileSync(TREE_PATH, JSON.stringify(data, null, 2), 'utf8');
  const files = fs.readdirSync(BACKUPS_DIR).sort().reverse();
  for (let i = 10; i < files.length; i++) {
    fs.unlinkSync(path.join(BACKUPS_DIR, files[i]));
  }
}

function readAdmins() {
  try {
    return JSON.parse(fs.readFileSync(ADMINS_PATH, 'utf8'));
  } catch {
    return { admins: [] };
  }
}

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/tree', (req, res) => {
  try {
    const tree = readTree();
    res.json(tree);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  const admins = readAdmins();
  const admin = admins.admins?.find(a => a.email === email);
  if (!admin || !bcrypt.compareSync(password, admin.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ email, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, admin: { email, role: admin.role } });
});

app.get('/api/admin/tree', verifyToken, (req, res) => {
  try {
    const tree = readTree();
    res.json(tree);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/tree', verifyToken, (req, res) => {
  try {
    writeTree(req.body);
    res.json({ success: true, message: 'Tree updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/backups', verifyToken, (req, res) => {
  try {
    const files = fs.readdirSync(BACKUPS_DIR).sort().reverse().slice(0, 10);
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🚀 Serveur IRSI/CIDE COP démarré`);
  console.log(`📊 Application : http://localhost:${PORT}`);
  console.log(`🔧 Admin : http://localhost:${PORT}/admin.html\n`);
});