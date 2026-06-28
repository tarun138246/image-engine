// pratima.js
import 'dotenv/config';
import express from 'express';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { Readable } from 'stream';
import Redis from 'ioredis';
import NodeClam from 'clamscan';
import { fileURLToPath } from 'url';

// ------------------- Configuration & Startup Validation -------------------
const PORT       = process.env.PORT       || 3001;
const HOST       = process.env.HOST       || '127.0.0.1';
const API_KEY    = process.env.API_KEY;
const ENC_KEY_HEX = process.env.ENCRYPTION_KEY || '';

const CLAMD_SOCKET      = process.env.CLAMD_SOCKET      || '/var/run/clamav/clamd.ctl';
const MAX_FILE_SIZE     = parseInt(process.env.MAX_FILE_SIZE,    10) || 10 * 1024 * 1024;
const WEBP_QUALITY      = parseInt(process.env.WEBP_QUALITY,     10) || 92;
const CONCURRENCY_LIMIT = parseInt(process.env.CONCURRENCY_LIMIT,10) || 2;
const STORAGE_PATH      = process.env.STORAGE_PATH || '/var/pratima';
const REDIS_URL         = process.env.REDIS_URL    || 'redis://127.0.0.1:6379';
const PUBLIC_URL        = (process.env.PUBLIC_URL  || `http://localhost:${PORT}`).replace(/\/$/, '');

// Fail fast on missing / bad configuration
const PLACEHOLDER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

if (!API_KEY) {
  console.error('FATAL: API_KEY env var is not set');
  process.exit(1);
}
if (!/^[0-9a-fA-F]{64}$/.test(ENC_KEY_HEX)) {
  console.error(
    'FATAL: ENCRYPTION_KEY must be a 64-character hex string (32 bytes).\n' +
    '  Generate one: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
  );
  process.exit(1);
}
if (ENC_KEY_HEX === PLACEHOLDER_KEY) {
  console.error('FATAL: ENCRYPTION_KEY is the default placeholder — replace it with a real random key.');
  process.exit(1);
}

const ENCRYPTION_KEY = Buffer.from(ENC_KEY_HEX, 'hex');
const __dirname      = path.dirname(fileURLToPath(import.meta.url));

// ------------------- Log Capture -------------------
const logBuffer  = [];
const sseClients = new Set();

function emitLog(level, ...args) {
  const message = args
    .map(a => a instanceof Error ? (a.stack || a.message) : typeof a === 'object' ? JSON.stringify(a) : String(a))
    .join(' ');
  const entry   = { time: new Date().toISOString(), level, message };
  logBuffer.push(entry);
  if (logBuffer.length > 500) logBuffer.shift();
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const client of sseClients) client.write(payload);
}

const _log   = console.log.bind(console);
const _warn  = console.warn.bind(console);
const _error = console.error.bind(console);
console.log   = (...a) => { _log(...a);   emitLog('info',  ...a); };
console.warn  = (...a) => { _warn(...a);  emitLog('warn',  ...a); };
console.error = (...a) => { _error(...a); emitLog('error', ...a); };

// ------------------- Storage & Companies -------------------
await fs.mkdir(STORAGE_PATH, { recursive: true });
const COMPANIES_FILE = path.join(STORAGE_PATH, 'companies.json');

// Simple in-process mutex to serialise companies.json writes
let companiesLock = Promise.resolve();
async function withCompaniesLock(fn) {
  let resolveLock;
  const newLock  = new Promise(r => (resolveLock = r));
  const prevLock = companiesLock;
  companiesLock  = newLock;
  await prevLock;
  try   { return await fn(); }
  finally { resolveLock(); }
}

async function loadCompanies() {
  try { return JSON.parse(await fs.readFile(COMPANIES_FILE, 'utf-8')); }
  catch { return []; }
}

async function saveCompanies(list) {
  await fs.writeFile(COMPANIES_FILE, JSON.stringify(list, null, 2), 'utf-8');
}

// ------------------- ClamAV -------------------
let clamscan = null;
try {
  clamscan = await new NodeClam().init({
    clamdscan: { socket: CLAMD_SOCKET, timeout: 60_000 },
  });
  console.log('ClamAV daemon connected');
} catch (err) {
  console.warn('ClamAV unavailable — uploads proceed without malware scanning:', err.message);
}

// ------------------- Redis -------------------
function makeRedis(url) {
  return new Redis(url, {
    maxRetriesPerRequest: null,
    retryStrategy: (times) => Math.min(times * 200, 5_000),
    enableOfflineQueue: true,
  });
}

const redis    = makeRedis(REDIS_URL);
const redisSub = makeRedis(REDIS_URL);

let redisReady = false;
redis.on('ready', () => { redisReady = true;  console.log('Redis connected'); });
redis.on('close', () => { redisReady = false; console.warn('Redis connection closed — reconnecting…'); });
// Log errors but do NOT exit — ioredis will reconnect automatically
redis.on('error',    err => console.error('Redis error:',    err.message));
redisSub.on('error', err => console.error('RedisSub error:', err.message));

// ------------------- Distributed semaphore -------------------
const NOTIFY_CHANNEL = 'semaphore:notify';
const ACTIVE_KEY     = 'semaphore:active';
const WAIT_KEY       = 'semaphore:wait';

// Reset stale counter from any previous unclean shutdown
await redis.set(ACTIVE_KEY, 0);
await redis.del(WAIT_KEY);

// ------------------- Startup migration -------------------
// Backfill apiKey for any companies created before per-company keys were introduced
await withCompaniesLock(async () => {
  const list = await loadCompanies();
  const changed = list.filter(co => !co.apiKey);
  if (changed.length === 0) return;
  changed.forEach(co => { co.apiKey = generateCompanyKey(); });
  await saveCompanies(list);
  console.log(`Migrated ${changed.length} existing company/companies with new API keys`);
});

redis.defineCommand('acquireSemaphore', {
  numberOfKeys: 2,
  lua: `
    local active = tonumber(redis.call('GET', KEYS[1]) or '0')
    if active < tonumber(ARGV[1]) then
      redis.call('INCR', KEYS[1])
      return 'ACQUIRED'
    end
    redis.call('RPUSH', KEYS[2], ARGV[2])
    return 'QUEUED'
  `,
});

redis.defineCommand('releaseSemaphore', {
  numberOfKeys: 2,
  lua: `
    local val = tonumber(redis.call('DECR', KEYS[1]))
    if val < 0 then redis.call('SET', KEYS[1], 0) end
    local next = redis.call('LPOP', KEYS[2])
    if next then redis.call('PUBLISH', ARGV[1], next) end
  `,
});

// FIX: one persistent subscription + local Map resolvers — no per-request subscribe/unsubscribe
const pendingWaiters = new Map();
await redisSub.subscribe(NOTIFY_CHANNEL);
redisSub.on('message', (channel, message) => {
  if (channel !== NOTIFY_CHANNEL) return;
  const resolve = pendingWaiters.get(message);
  if (resolve) { pendingWaiters.delete(message); resolve(); }
});

async function acquireSlot() {
  const id     = uuidv4();
  const result = await redis.acquireSemaphore(ACTIVE_KEY, WAIT_KEY, CONCURRENCY_LIMIT, id);
  if (result === 'ACQUIRED') return;

  return new Promise(resolve => {
    const tid = setTimeout(() => {
      pendingWaiters.delete(id);
      resolve();
    }, 30_000);
    pendingWaiters.set(id, () => { clearTimeout(tid); resolve(); });
  });
}

async function releaseSlot() {
  await redis.releaseSemaphore(ACTIVE_KEY, WAIT_KEY, NOTIFY_CHANNEL);
}

// ------------------- Encryption -------------------
const ALGORITHM       = 'aes-256-gcm';
const IV_LENGTH       = 12;
const AUTH_TAG_LENGTH = 16;

function encryptBuffer(buf) {
  const iv     = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const body   = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

function decryptBuffer(buf) {
  const iv       = buf.subarray(0, IV_LENGTH);
  const tag      = buf.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const data     = buf.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ------------------- Per-company key helper -------------------
function generateCompanyKey() {
  return 'prtm_' + crypto.randomBytes(24).toString('hex'); // 53-char unguessable key
}

// ------------------- Validation helpers -------------------
// FIX: strict regex prevents path-traversal in image_id
const COMPANY_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IMAGE_ID_RE     = /^pratima_[a-z0-9_]+$/;

function sanitizeName(str, len) {
  const clean = str.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, len);
  return clean.padEnd(len, '0');   // '0' pad instead of 'x' — clearer intent
}

async function fileExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

// ------------------- Express setup -------------------
const app = express();
app.set('trust proxy', 1); // honour X-Forwarded-For behind nginx

// CORS — must come before every other middleware so preflight OPTIONS requests
// are answered before rate-limiting or auth runs
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin',  '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'x-api-key, Content-Type');
  res.set('Access-Control-Max-Age',       '86400'); // cache preflight for 24 h
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '16kb' }));

// Global rate limit (generous baseline; specific routes tighten further)
app.use(rateLimit({
  windowMs: 60_000, max: 300,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests — please slow down' },
}));

const uploadLimiter = rateLimit({
  windowMs: 60_000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Upload rate limit exceeded' },
});

const mgmtLimiter = rateLimit({
  windowMs: 60_000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Management API rate limit exceeded' },
});

// API-key guard — localhost (server shell / health checks) bypasses
const verifyApiKey = (req, res, next) => {
  const ip = req.ip;
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return next();
  if (req.headers['x-api-key'] !== API_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// ------------------- Health -------------------
app.get('/health', (_req, res) =>
  res.json({ status: 'ok', redis: redisReady, clamav: !!clamscan })
);

// ------------------- Company Management -------------------
// FIX: GET /companies now requires auth — was fully open to anonymous callers
app.get('/companies', verifyApiKey, async (_req, res) => {
  res.json(await loadCompanies());
});

app.post('/companies', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Company name is required' });
  }
  const company = { id: uuidv4(), name: name.trim(), apiKey: generateCompanyKey(), created: new Date().toISOString() };
  await withCompaniesLock(async () => {
    const list = await loadCompanies();
    list.push(company);
    await saveCompanies(list);
  });
  console.log(`Company created: ${company.name} (${company.id})`);
  res.status(201).json(company);
});

app.delete('/companies/:id', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { id } = req.params;
  if (!COMPANY_UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid company ID' });

  // FIX: collect result inside lock, send response outside — no response-inside-mutex
  let removed = null;
  const found = await withCompaniesLock(async () => {
    const list = await loadCompanies();
    const idx  = list.findIndex(c => c.id === id);
    if (idx === -1) return false;
    [removed] = list.splice(idx, 1);
    await saveCompanies(list);
    return true;
  });

  if (!found) return res.status(404).json({ error: 'Company not found' });

  const dir = path.join(STORAGE_PATH, 'companies', removed.id);
  try { await fs.rm(dir, { recursive: true, force: true }); }
  catch (e) { console.warn(`Failed to remove company dir ${dir}:`, e.message); }

  console.log(`Company deleted: ${removed.name} (${removed.id})`);
  res.json({ success: true });
});

// ------------------- Image Upload -------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp','image/gif','image/tiff'].includes(file.mimetype);
    cb(null, ok);
  },
});

app.post('/upload', uploadLimiter, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No valid image file provided (accepted: JPEG, PNG, WebP, GIF, TIFF)' });

  const companyId = req.body.company_id || req.query.company_id;
  if (!companyId)                       return res.status(400).json({ error: 'company_id is required' });
  if (!COMPANY_UUID_RE.test(companyId)) return res.status(400).json({ error: 'Invalid company_id format' });

  const companies = await loadCompanies();
  const company   = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: 'Company not found' });

  // Each company authenticates with its own key — not the global admin key
  if (req.headers['x-api-key'] !== company.apiKey) {
    return res.status(403).json({ error: 'Invalid API key for this company' });
  }

  await acquireSlot();
  try {
    const buf      = req.file.buffer;
    const meta     = await sharp(buf).metadata();
    if (!meta.format) throw new Error('Unrecognised image format');

    if (clamscan) {
      const { isInfected, viruses } = await clamscan.scanStream(Readable.from(buf));
      if (isInfected) throw new Error(`Malware detected: ${viruses.join(', ')}`);
    }

    // FIX: removed .withMetadata(false) — sharp strips metadata by default without this call.
    // Calling .withMetadata(false) passes a falsy options object which may re-enable metadata.
    const webpBuf   = await sharp(buf).webp({ quality: WEBP_QUALITY }).toBuffer();
    const encrypted = encryptBuffer(webpBuf);

    const coShort   = sanitizeName(company.name, 4);
    const origName  = path.basename(req.file.originalname, path.extname(req.file.originalname));
    const fileShort = sanitizeName(origName, 4);
    let imageId     = `pratima_${coShort}_${fileShort}`;

    const companyDir = path.join(STORAGE_PATH, 'companies', companyId);
    await fs.mkdir(companyDir, { recursive: true });

    let targetPath = path.join(companyDir, imageId);
    while (await fileExists(targetPath)) {
      imageId    = `pratima_${coShort}_${fileShort}_${crypto.randomBytes(2).toString('hex')}`;
      targetPath = path.join(companyDir, imageId);
    }

    await fs.writeFile(targetPath, encrypted, { mode: 0o600 });
    console.log(`Stored ${imageId} for ${company.name} (${(webpBuf.length / 1024).toFixed(1)} KB WebP)`);

    res.json({ url: `${PUBLIC_URL}/img/${companyId}/${imageId}`, imageId, companyId });
  } catch (err) {
    console.error('Upload error:', err.message);
    res.status(400).json({ error: err.message });
  } finally {
    await releaseSlot();
  }
});

// ------------------- Image Retrieval -------------------
app.get('/img/:company_id/:image_id', async (req, res) => {
  const { company_id, image_id } = req.params;

  // FIX: strict regex on image_id prevents path-traversal attacks
  if (!COMPANY_UUID_RE.test(company_id)) return res.status(400).send('Invalid company ID');
  if (!IMAGE_ID_RE.test(image_id))       return res.status(400).send('Invalid image ID');

  try {
    const encrypted = await fs.readFile(path.join(STORAGE_PATH, 'companies', company_id, image_id));
    const decrypted = decryptBuffer(encrypted);
    res.set('Content-Type',              'image/webp');
    res.set('Cache-Control',             'public, max-age=31536000, immutable');
    res.set('Access-Control-Allow-Origin', '*'); // allow embedding in other domains
    res.send(decrypted);
  } catch {
    res.status(404).send('Not found');
  }
});

// ------------------- UI -------------------
app.get('/ui', async (_req, res) => {
  try {
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(await fs.readFile(path.join(__dirname, 'ui.html')));
  } catch (err) {
    res.status(500).send('UI not available: ' + err.message);
  }
});

app.get('/ui/api/stats', async (_req, res) => {
  let redisStatus = 'disconnected';
  let activeSlots = 0;
  try {
    await redis.ping();
    redisStatus = 'connected';
    activeSlots = Math.max(0, parseInt(await redis.get(ACTIVE_KEY) || '0', 10));
  } catch (_) {}

  const companies  = await loadCompanies();
  let totalImages  = 0;
  let storageBytes = 0;
  for (const co of companies) {
    const dir = path.join(STORAGE_PATH, 'companies', co.id);
    try {
      const files = (await fs.readdir(dir)).filter(f => f.startsWith('pratima_'));
      totalImages += files.length;
      const sizes  = await Promise.all(
        files.map(f => fs.stat(path.join(dir, f)).then(s => s.size).catch(() => 0))
      );
      storageBytes += sizes.reduce((a, b) => a + b, 0);
    } catch (_) {}
  }

  res.json({
    uptime: process.uptime(),
    memoryRss: process.memoryUsage().rss,
    imageCount: totalImages,
    companyCount: companies.length,
    storageBytes,
    activeSlots,
    redisStatus,
    clamavStatus: clamscan ? 'connected' : 'unavailable',
    config: {
      port: PORT,
      maxFileSize: MAX_FILE_SIZE,
      webpQuality: WEBP_QUALITY,
      concurrencyLimit: CONCURRENCY_LIMIT,
      storagePath: STORAGE_PATH,
      publicUrl: PUBLIC_URL,
    },
  });
});

app.get('/ui/api/images', async (req, res) => {
  const filter    = req.query.company_id;
  const companies = await loadCompanies();
  const images    = [];

  for (const co of companies) {
    if (filter && co.id !== filter) continue;
    const dir = path.join(STORAGE_PATH, 'companies', co.id);
    try {
      const files = (await fs.readdir(dir)).filter(f => f.startsWith('pratima_'));
      const stats = await Promise.all(files.map(async f => {
        const s = await fs.stat(path.join(dir, f));
        return {
          id:           f,
          url:          `${PUBLIC_URL}/img/${co.id}/${f}`,
          size:         s.size,
          created:      s.birthtime || s.mtime,
          company_id:   co.id,
          company_name: co.name,
        };
      }));
      images.push(...stats);
    } catch (_) {}
  }

  images.sort((a, b) => new Date(b.created) - new Date(a.created));
  res.json(images);
});

// SSE log stream — sends buffered history then streams live entries
app.get('/ui/api/logs', (req, res) => {
  res.set({
    'Content-Type':      'text/event-stream',
    'Cache-Control':     'no-cache',
    'Connection':        'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  for (const entry of logBuffer) res.write(`data: ${JSON.stringify(entry)}\n\n`);

  const keepAlive = setInterval(() => res.write(': ping\n\n'), 25_000);
  sseClients.add(res);
  req.on('close', () => { clearInterval(keepAlive); sseClients.delete(res); });
});

// ------------------- Global Error Handler -------------------
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(413).json({ error: 'File too large' });
  }
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ------------------- Graceful Shutdown -------------------
const server = app.listen(PORT, HOST, () => {
  console.log(`Pratima image engine listening on http://${HOST}:${PORT}`);
  console.log(`Dashboard: http://${HOST}:${PORT}/ui`);
});

async function shutdown(signal) {
  console.log(`${signal} received — shutting down gracefully`);
  server.close(async () => {
    try { await redis.quit(); await redisSub.quit(); } catch (_) {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000); // force-kill after 10 s
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
