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

// ---------- almacenamiento en archivo ----------
// Las cuentas se agregan/editan directamente en data.json.
// Se relee el archivo en cada búsqueda para reflejar cambios sin reiniciar el servidor.
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = { accounts: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

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

// ---------- publico: buscar cuenta ----------
app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.json({ results: [] });
  const data = loadData();
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Codigos Manguito backend escuchando en http://localhost:${PORT}`));
