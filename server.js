// Portail cloud gaming - v0.1
// Authentifie l'utilisateur, gère des "slots" GPU et lance/arrête des conteneurs Docker de jeu.
const express = require('express');
const crypto = require('crypto');
const { execFile } = require('child_process');
const path = require('path');

const {
  PORT = 3000, ADMIN_USER = 'admin', ADMIN_PASSWORD,
  MAX_SESSIONS = 1, MAX_MINUTES = 120, PUBLIC_HOST = 'localhost', BASE_PORT = 9000,
} = process.env;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
if (!ADMIN_PASSWORD) { console.error('ADMIN_PASSWORD est requis (voir .env.example)'); process.exit(1); }

const games = require('./games.json');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Authentification (cookie signé) ----------
const sign = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
function makeToken(user) {
  const p = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + 12 * 3600e3 })).toString('base64url');
  return p + '.' + sign(p);
}
function readUser(req) {
  const m = /(?:^|;\s*)cg=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [p, s] = m[1].split('.');
  if (!p || !s || !safeEq(s, sign(p))) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url')); return d.exp > Date.now() ? d.u : null; }
  catch { return null; }
}
const auth = (req, res, next) => { const u = readUser(req); if (!u) return res.status(401).json({ error: 'Non connecté' }); req.user = u; next(); };

const attempts = new Map(); // anti brute-force simple, par IP
app.post('/api/login', (req, res) => {
  const ip = req.ip, a = attempts.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 15 * 60e3) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 5) return res.status(429).json({ error: 'Trop d\'essais, réessayez dans 15 minutes.' });
  const { user, password } = req.body || {};
  if (safeEq(user, ADMIN_USER) && safeEq(password, ADMIN_PASSWORD)) {
    attempts.delete(ip);
    res.setHeader('Set-Cookie', `cg=${makeToken(user)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);
    return res.json({ user });
  }
  a.n++; attempts.set(ip, a);
  res.status(401).json({ error: 'Identifiants incorrects' });
});
app.post('/api/logout', (_req, res) => { res.setHeader('Set-Cookie', 'cg=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

// ---------- Sessions de jeu ----------
const sessions = new Map(); // utilisateur -> { game, port, container, startedAt, endsAt, timer }
const docker = (args) => new Promise((ok, ko) =>
  execFile('docker', args, (e, out, err) => (e ? ko(new Error(err || e.message)) : ok(out.trim()))));

function freePort() {
  const used = new Set([...sessions.values()].map((s) => s.port));
  for (let i = 0; i < Number(MAX_SESSIONS); i++) if (!used.has(Number(BASE_PORT) + i)) return Number(BASE_PORT) + i;
  return null;
}
const view = (s) => s && { game: s.game, url: `http://${PUBLIC_HOST}:${s.port}`, endsAt: s.endsAt };

app.get('/api/games', auth, (_req, res) =>
  res.json(games.map(({ id, name, description }) => ({ id, name, description }))));

app.get('/api/session', auth, (req, res) =>
  res.json({ session: view(sessions.get(req.user)), used: sessions.size, max: Number(MAX_SESSIONS) }));

app.post('/api/session', auth, async (req, res) => {
  if (sessions.has(req.user)) return res.json({ session: view(sessions.get(req.user)) });
  const game = games.find((g) => g.id === req.body?.gameId);
  if (!game) return res.status(400).json({ error: 'Jeu inconnu' });
  const port = freePort();
  if (port === null) return res.status(409).json({ error: 'Tous les GPU sont occupés. Réessayez plus tard.' });

  const name = `cg-${req.user}-${Date.now()}`.replace(/[^a-zA-Z0-9_.-]/g, '');
  const envArgs = Object.entries(game.env || {}).flatMap(([k, v]) => ['-e', `${k}=${v}`]);
  const placeholder = { game: game.id, port, container: name }; // réserve le slot pendant le démarrage
  sessions.set(req.user, placeholder);
  try {
    await docker(['run', '-d', '--rm', '--name', name, '--gpus', 'all',
      '-p', `${port}:${game.internalPort}`, ...envArgs, game.image]);
  } catch (e) {
    sessions.delete(req.user);
    return res.status(500).json({ error: 'Échec du démarrage : ' + e.message });
  }
  Object.assign(placeholder, {
    startedAt: Date.now(), endsAt: Date.now() + MAX_MINUTES * 60e3,
    timer: setTimeout(() => stop(req.user), MAX_MINUTES * 60e3),
  });
  res.json({ session: view(placeholder) });
});

async function stop(user) {
  const s = sessions.get(user);
  if (!s) return;
  clearTimeout(s.timer);
  sessions.delete(user);
  try { await docker(['stop', '-t', '5', s.container]); } catch { /* déjà arrêté */ }
}
app.delete('/api/session', auth, async (req, res) => { await stop(req.user); res.json({ ok: true }); });

// Arrêt propre : ne laisse pas de conteneurs orphelins
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => {
  await Promise.all([...sessions.keys()].map(stop)); process.exit(0);
});

app.listen(PORT, () => console.log(`Portail cloud gaming sur http://localhost:${PORT}`));
