const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const DATA_FILE = path.join(__dirname, 'data.json');
const PERIOD = 30;
const DIGITS = 6;
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutos

// ---------- almacenamiento en archivo ----------
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = { accounts: [], adminHash: null };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let data = loadData();
const sessions = new Map(); // token -> expira_en (timestamp)

// ---------- TOTP (calculado en el servidor, el secreto nunca sale) ----------
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/=+$/, '').toUpperCase().replace(/\s+/g, '');
  let bits = '';
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error('caracter base32 invalido');
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function totp(secretB32, period = PERIOD, digits = DIGITS) {
  const key = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(counter, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) |
               ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) |
               (hmac[offset + 3] & 0xff);
  return (code % (10 ** digits)).toString().padStart(digits, '0');
}

function secondsLeft(period = PERIOD) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a || '', 'utf8');
  const bufB = Buffer.from(b || '', 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const expiry = token && sessions.get(token);
  if (!token || !expiry || expiry < Date.now()) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  sessions.set(token, Date.now() + SESSION_TTL_MS); // renueva la sesion con actividad
  next();
}

// ---------- publico: buscar cuenta ----------
app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.json({ results: [] });
  const matches = data.accounts
    .filter(a => (a.email || 'Cuenta sin nombre').toLowerCase().includes(q))
    .map(a => ({
      id: a.id,
      label: a.email || 'Cuenta sin nombre',
      code: totp(a.secret),
      secondsLeft: secondsLeft()
    }));
  res.json({ results: matches });
});

// ---------- admin: estado / login ----------
app.get('/api/admin/status', (req, res) => {
  res.json({ hasPin: !!data.adminHash });
});

app.post('/api/admin/login', (req, res) => {
  const { pin, confirmPin } = req.body || {};
  if (!pin || pin.length < 4) {
    return res.status(400).json({ error: 'El PIN debe tener al menos 4 caracteres' });
  }

  if (!data.adminHash) {
    if (pin !== confirmPin) return res.status(400).json({ error: 'Los PIN no coinciden' });
    data.adminHash = sha256Hex(pin);
    saveData(data);
  } else {
    if (!safeEqual(sha256Hex(pin), data.adminHash)) {
      return res.status(401).json({ error: 'PIN incorrecto' });
    }
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  res.json({ token });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers.authorization.slice(7);
  sessions.delete(token);
  res.json({ ok: true });
});

// ---------- admin: gestion de cuentas ----------
app.get('/api/admin/accounts', requireAdmin, (req, res) => {
  const list = data.accounts.map(a => ({
    id: a.id,
    label: a.email || 'Cuenta sin nombre',
    code: totp(a.secret),
    secondsLeft: secondsLeft()
  }));
  res.json({ accounts: list });
});

app.post('/api/admin/accounts', requireAdmin, (req, res) => {
  const { secret, email } = req.body || {};
  const cleanSecret = (secret || '').trim().replace(/\s+/g, '');
  if (!cleanSecret) return res.status(400).json({ error: 'Falta el codigo secreto' });
  try { totp(cleanSecret); } catch {
    return res.status(400).json({ error: 'Codigo secreto invalido (debe ser Base32)' });
  }
  const acc = { id: crypto.randomUUID(), email: (email || '').trim(), secret: cleanSecret };
  data.accounts.push(acc);
  saveData(data);
  res.json({ ok: true, id: acc.id });
});

app.delete('/api/admin/accounts/:id', requireAdmin, (req, res) => {
  data.accounts = data.accounts.filter(a => a.id !== req.params.id);
  saveData(data);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Codigos Manguito backend escuchando en http://localhost:${PORT}`));
