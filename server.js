// StarryPicks server - no npm packages needed, just Node 20.6+
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PASS = process.env.ADMIN_PASSWORD;
if (!PASS || PASS.length < 8) { console.error('Set ADMIN_PASSWORD in .env (8+ characters). Copy .env.example to .env first.'); process.exit(1); }
const SECURE = process.env.COOKIE_SECURE === '1';
const DISCORD_URL = process.env.DISCORD_INVITE_URL || '';
if (DISCORD_URL) {
  try {
    const invite = new URL(DISCORD_URL);
    if (invite.protocol !== 'https:' || !['discord.gg', 'discord.com', 'www.discord.com'].includes(invite.hostname)) throw new Error();
  } catch {
    console.error('DISCORD_INVITE_URL must be an HTTPS Discord invite URL.');
    process.exit(1);
  }
}
const SECRET = crypto.randomBytes(32);          // sessions reset when the server restarts
const DB = path.join(__dirname, 'data', 'products.json');
const PAGE = path.join(__dirname, 'public', 'index.html');

const SEED = {
  shop: { name: 'StarryPicks', by: 'by Elora', tagline: 'Prices & availability, updated by Elora ✦' },
  products: [
    {
      id: 'mlbb-diamonds',
      name: 'MLBB Diamonds',
      category: 'MLBB',
      imageUrl: '',
      denominations: [
        { id: 'mlbb-100', name: '100 diamonds', price: 112, note: '', available: true },
        { id: 'mlbb-200', name: '200 diamonds', price: 200, note: '', available: true }
      ]
    }
  ],
  categories: ['Mobile Games', 'Roblox', 'PC Games', 'MLBB']
};
function load() { try { return JSON.parse(fs.readFileSync(DB, 'utf8')); } catch { fs.mkdirSync(path.dirname(DB), { recursive: true }); save(SEED); return structuredClone(SEED); } }
function save(d) { const tmp = DB + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(d, null, 2)); fs.renameSync(tmp, DB); }
let data = load();
let migrated = !Array.isArray(data.categories);
if (!Array.isArray(data.categories)) data.categories = [];
function ensureCategory(category) {
  const name = String(category || '').trim().slice(0, 50);
  if (name && !data.categories.some(x => x.toLowerCase() === name.toLowerCase())) {
    data.categories.push(name);
    return true;
  }
  return false;
}
if (data.products.some(product => !Array.isArray(product.denominations))) {
  const grouped = new Map();
  for (const item of data.products) {
    const name = String(item.product || item.name || '').trim();
    const key = name.toLowerCase();
    let product = grouped.get(key);
    if (!product) {
      product = { id: crypto.randomUUID().slice(0, 8), name, category: item.category || '', imageUrl: item.imageUrl || '', denominations: [] };
      grouped.set(key, product);
    }
    product.denominations.push({
      id: item.id || crypto.randomUUID().slice(0, 8),
      name: item.name || name,
      price: Number(item.price) || 0,
      note: item.note || '',
      available: item.available !== false
    });
  }
  data.products = [...grouped.values()];
  migrated = true;
}
for (const product of data.products) {
  if (!Array.isArray(product.denominations)) product.denominations = [];
  if (ensureCategory(product.category)) migrated = true;
}
if (migrated) save(data);
function publicData() { return { ...data, shop: { ...data.shop, discordUrl: DISCORD_URL } }; }

const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
function makeToken() { const exp = Date.now() + 8 * 3600e3; return exp + '.' + sign(String(exp)); }
function isAdmin(req) {
  const m = /(?:^|;\s*)sp_admin=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return false;
  const [exp, sig] = m[1].split('.'); if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp)); return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const fails = new Map(); // ip -> {n, t}
function tooMany(ip) { const f = fails.get(ip); return f && f.n >= 5 && Date.now() - f.t < 10 * 60e3; }
function passOk(p) { const a = crypto.createHash('sha256').update(String(p)).digest(), b = crypto.createHash('sha256').update(PASS).digest(); return crypto.timingSafeEqual(a, b); }

function send(res, code, obj, headers = {}) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(obj)); }
function body(req) { return new Promise((ok, no) => { let s = ''; req.on('data', c => { s += c; if (s.length > 1e5) { no(new Error('Too big')); req.destroy(); } }); req.on('end', () => { try { ok(s ? JSON.parse(s) : {}); } catch { no(new Error('Bad JSON')); } }); }); }
function cleanProduct(b) {
  const name = String(b.name || '').trim().slice(0, 100);
  if (!name) return null;
  const imageUrl = String(b.imageUrl || '').trim().slice(0, 1000);
  if (imageUrl) {
    try { if (new URL(imageUrl).protocol !== 'https:') return null; } catch { return null; }
  }
  return { name, category: String(b.category || '').trim().slice(0, 50), imageUrl };
}
function cleanDenomination(b) {
  const name = String(b.name || '').trim().slice(0, 100), price = Number(b.price);
  if (!name || !Number.isFinite(price) || price < 0) return null;
  return { name, price, note: String(b.note || '').trim().slice(0, 200), available: !!b.available };
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname, ip = req.socket.remoteAddress;
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY');
  try {
    if (req.method === 'GET' && p === '/healthz') return send(res, 200, { ok: true });
    if (req.method === 'GET' && (p === '/' || p === '/admin' || p === '/product')) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(PAGE)); }
    if (!p.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (req.method === 'GET' && p === '/api/products') return send(res, 200, publicData());
    if (req.method === 'GET' && p === '/api/me') return send(res, 200, { admin: isAdmin(req) });
    if (req.method !== 'GET' && !(req.headers['content-type'] || '').includes('application/json') && req.method !== 'DELETE') return send(res, 415, { error: 'JSON only' });

    if (req.method === 'POST' && p === '/api/login') {
      if (tooMany(ip)) return send(res, 429, { error: 'Too many tries, wait 10 minutes' });
      const b = await body(req);
      if (!passOk(b.password)) { const f = fails.get(ip) || { n: 0 }; fails.set(ip, { n: f.n + 1, t: Date.now() }); return send(res, 401, { error: 'Wrong password' }); }
      fails.delete(ip);
      return send(res, 200, { admin: true }, { 'Set-Cookie': `sp_admin=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${SECURE ? '; Secure' : ''}` });
    }
    if (req.method === 'POST' && p === '/api/logout') return send(res, 200, { admin: false }, { 'Set-Cookie': 'sp_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

    if (!isAdmin(req)) return send(res, 401, { error: 'Admin only' });
    if (req.method === 'POST' && p === '/api/categories') {
      const b = await body(req), category = String(b.category || '').trim();
      if (!category || category.length > 50) return send(res, 400, { error: 'Category must be between 1 and 50 characters.' });
      if (data.categories.some(x => x.toLowerCase() === category.toLowerCase())) return send(res, 409, { error: 'That category already exists.' });
      data.categories.push(category); save(data); return send(res, 200, publicData());
    }
    if (req.method === 'PUT' && p === '/api/categories') {
      const b = await body(req), oldCategory = String(b.oldCategory || '').trim(), category = String(b.category || '').trim();
      const index = data.categories.findIndex(x => x.toLowerCase() === oldCategory.toLowerCase());
      if (index < 0) return send(res, 404, { error: 'Category not found.' });
      if (!category || category.length > 50) return send(res, 400, { error: 'Category must be between 1 and 50 characters.' });
      if (data.categories.some(x => x.toLowerCase() === category.toLowerCase() && x.toLowerCase() !== oldCategory.toLowerCase())) return send(res, 409, { error: 'That category already exists.' });
      const storedCategory = data.categories[index];
      data.categories[index] = category;
      for (const product of data.products) if (product.category === storedCategory) product.category = category;
      save(data); return send(res, 200, publicData());
    }
    if (req.method === 'DELETE' && p === '/api/categories') {
      const b = await body(req), category = String(b.category || '').trim();
      const index = data.categories.findIndex(x => x.toLowerCase() === category.toLowerCase());
      if (index < 0) return send(res, 404, { error: 'Category not found.' });
      const storedCategory = data.categories[index];
      data.categories.splice(index, 1);
      for (const product of data.products) if (product.category === storedCategory) product.category = '';
      save(data); return send(res, 200, publicData());
    }
    const d = /^\/api\/products\/([\w-]+)\/denominations(?:\/([\w-]+))?$/.exec(p);
    if (d) {
      const product = data.products.find(x => x.id === d[1]);
      if (!product) return send(res, 404, { error: 'Product not found.' });
      if (req.method === 'POST' && !d[2]) {
        const v = cleanDenomination(await body(req));
        if (!v) return send(res, 400, { error: 'Enter a denomination name and a non-negative price.' });
        product.denominations.push({ id: crypto.randomUUID().slice(0, 8), ...v });
        save(data); return send(res, 200, publicData());
      }
      if (d[2] && req.method === 'PUT') {
        const v = cleanDenomination(await body(req)), index = product.denominations.findIndex(x => x.id === d[2]);
        if (!v) return send(res, 400, { error: 'Enter a denomination name and a non-negative price.' });
        if (index < 0) return send(res, 404, { error: 'Denomination not found.' });
        product.denominations[index] = { id: d[2], ...v };
        save(data); return send(res, 200, publicData());
      }
      if (d[2] && req.method === 'DELETE') {
        const index = product.denominations.findIndex(x => x.id === d[2]);
        if (index < 0) return send(res, 404, { error: 'Denomination not found.' });
        product.denominations.splice(index, 1);
        save(data); return send(res, 200, publicData());
      }
    }
    const m = /^\/api\/products\/([\w-]+)$/.exec(p);
    if (req.method === 'POST' && p === '/api/products') {
      const v = cleanProduct(await body(req)); if (!v) return send(res, 400, { error: 'Enter a product name and a valid HTTPS image URL (if using one).' });
      ensureCategory(v.category); data.products.push({ id: crypto.randomUUID().slice(0, 8), ...v, denominations: [] }); save(data); return send(res, 200, publicData());
    }
    if (m && req.method === 'PUT') {
      const v = cleanProduct(await body(req)), product = data.products.find(x => x.id === m[1]);
      if (!v) return send(res, 400, { error: 'Enter a product name and a valid HTTPS image URL (if using one).' });
      if (!product) return send(res, 404, { error: 'Product not found.' });
      ensureCategory(v.category); Object.assign(product, v); save(data); return send(res, 200, publicData());
    }
    if (m && req.method === 'DELETE') {
      const index = data.products.findIndex(x => x.id === m[1]);
      if (index < 0) return send(res, 404, { error: 'Product not found.' });
      data.products.splice(index, 1); save(data); return send(res, 200, publicData());
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 400, { error: e.message }); }
}).listen(PORT, '0.0.0.0', () => console.log(`StarryPicks running on port ${PORT}  (admin: /admin)`));
