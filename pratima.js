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
import AdmZip from 'adm-zip';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';
import os from 'os';

const execFileAsync = promisify(execFile);

// ------------------- Configuration & Startup Validation -------------------
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '127.0.0.1';
const API_KEY = process.env.API_KEY;
const ENC_KEY_HEX = process.env.ENCRYPTION_KEY || '';

const CLAMD_SOCKET = process.env.CLAMD_SOCKET || '/var/run/clamav/clamd.ctl';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 10 * 1024 * 1024;
const MAX_BACKUP_SIZE = parseInt(process.env.MAX_BACKUP_SIZE, 10) || 200 * 1024 * 1024;
const WEBP_QUALITY = parseInt(process.env.WEBP_QUALITY, 10) || 92;
const CONCURRENCY_LIMIT = parseInt(process.env.CONCURRENCY_LIMIT, 10) || 2;
const STORAGE_PATH = process.env.STORAGE_PATH || '/var/pratima';
const SCHEDULED_DELETION_PATH = path.join(STORAGE_PATH, 'scheduled-deletion');
const DELETION_RETENTION_DAYS = parseInt(process.env.DELETION_RETENTION_DAYS, 10) || 25;
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const GS_BINARY = process.env.GS_BINARY || 'gs';
const PROTECT_HEALTH = process.env.PROTECT_HEALTH === 'true';
const ALLOWED_IPS = process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',').map(ip => ip.trim()) : [];

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
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ------------------- Log Capture -------------------
const logBuffer = [];
const sseClients = new Set();

function emitLog(level, ...args) {
  const message = args
    .map(a => a instanceof Error ? (a.stack || a.message) : typeof a === 'object' ? JSON.stringify(a) : String(a))
    .join(' ');
  const entry = { time: new Date().toISOString(), level, message };
  logBuffer.push(entry);
  if (logBuffer.length > 500) logBuffer.shift();
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const client of sseClients) client.write(payload);
}

const _log = console.log.bind(console);
const _warn = console.warn.bind(console);
const _error = console.error.bind(console);
console.log = (...a) => { _log(...a); emitLog('info', ...a); };
console.warn = (...a) => { _warn(...a); emitLog('warn', ...a); };
console.error = (...a) => { _error(...a); emitLog('error', ...a); };

// ------------------- Storage & Companies -------------------
await fs.mkdir(STORAGE_PATH, { recursive: true });
await fs.mkdir(SCHEDULED_DELETION_PATH, { recursive: true });
const COMPANIES_FILE = path.join(STORAGE_PATH, 'companies.json');

// Simple in-process mutex to serialise companies.json writes
let companiesLock = Promise.resolve();
async function withCompaniesLock(fn) {
  let resolveLock;
  const newLock = new Promise(r => (resolveLock = r));
  const prevLock = companiesLock;
  companiesLock = newLock;
  await prevLock;
  try { return await fn(); }
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

// ------------------- Ghostscript (optional PDF compression) -------------------
let ghostscriptAvailable = false;
try {
  await execFileAsync(GS_BINARY, ['--version']);
  ghostscriptAvailable = true;
  console.log('Ghostscript found — PDF compression enabled');
} catch (err) {
  console.warn('Ghostscript unavailable — PDFs will be stored uncompressed:', err.message);
}

async function compressPdf(buf) {
  if (!ghostscriptAvailable) return buf;
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pratima-pdf-'));
  const inPath = path.join(tmpDir, 'in.pdf');
  const outPath = path.join(tmpDir, 'out.pdf');
  try {
    await fs.writeFile(inPath, buf);
    await execFileAsync(GS_BINARY, [
      '-sDEVICE=pdfwrite', '-dCompatibilityLevel=1.4', '-dPDFSETTINGS=/ebook',
      '-dNOPAUSE', '-dQUIET', '-dBATCH', `-sOutputFile=${outPath}`, inPath,
    ], { timeout: 60_000 });
    const compressed = await fs.readFile(outPath);
    // Only keep the compressed version if Ghostscript actually shrank it
    return compressed.length > 0 && compressed.length < buf.length ? compressed : buf;
  } catch (err) {
    console.warn('Ghostscript compression failed — storing original PDF:', err.message);
    return buf;
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ------------------- Redis -------------------
function makeRedis(url) {
  return new Redis(url, {
    maxRetriesPerRequest: null,
    retryStrategy: (times) => Math.min(times * 200, 5_000),
    enableOfflineQueue: true,
  });
}

const redis = makeRedis(REDIS_URL);
const redisSub = makeRedis(REDIS_URL);

let redisReady = false;
redis.on('ready', () => { redisReady = true; console.log('Redis connected'); });
redis.on('close', () => { redisReady = false; console.warn('Redis connection closed — reconnecting…'); });
// Log errors but do NOT exit — ioredis will reconnect automatically
redis.on('error', err => console.error('Redis error:', err.message));
redisSub.on('error', err => console.error('RedisSub error:', err.message));

// ------------------- Distributed semaphore -------------------
const NOTIFY_CHANNEL = 'semaphore:notify';
const ACTIVE_KEY = 'semaphore:active';
const WAIT_KEY = 'semaphore:wait';

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
  const id = uuidv4();
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
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function encryptBuffer(buf) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const body = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

function decryptBuffer(buf) {
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const data = buf.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ------------------- Per-company key helper -------------------
function generateCompanyKey() {
  return 'prtm_' + crypto.randomBytes(24).toString('hex'); // 53-char unguessable key
}

// ------------------- Scheduled Deletion Helpers -------------------
async function moveToScheduledDeletion(companyId, companyName, itemType, itemId = null) {
  const timestamp = Date.now();
  const deletionId = uuidv4();
  const deletionFolder = path.join(SCHEDULED_DELETION_PATH, deletionId);
  
  await fs.mkdir(deletionFolder, { recursive: true });
  
  // Save deletion metadata
  const metadata = {
    deletionId,
    companyId,
    companyName,
    itemType, // 'company' or 'image'
    imageId: itemId,
    deletedAt: new Date(timestamp).toISOString(),
    scheduledPermanentDeletionAt: new Date(timestamp + (DELETION_RETENTION_DAYS * 24 * 60 * 60 * 1000)).toISOString(),
    timestamp
  };
  
  await fs.writeFile(
    path.join(deletionFolder, 'metadata.json'),
    JSON.stringify(metadata, null, 2),
    'utf-8'
  );
  
  // Move the actual files
  if (itemType === 'company') {
    // Move entire company folder
    const sourceDir = path.join(STORAGE_PATH, 'companies', companyId);
    const targetDir = path.join(deletionFolder, 'files');
    try {
      await fs.rename(sourceDir, targetDir);
      console.log(`Moved company ${companyName} (${companyId}) to scheduled deletion (${deletionId})`);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      // Company folder doesn't exist (no files uploaded yet)
      console.log(`Company ${companyName} (${companyId}) had no files - metadata saved to scheduled deletion`);
    }
  } else if (itemType === 'image') {
    // Move individual image file and its metadata
    const companyDir = path.join(STORAGE_PATH, 'companies', companyId);
    const targetDir = path.join(deletionFolder, 'files');
    await fs.mkdir(targetDir, { recursive: true });
    
    const imageFile = path.join(companyDir, itemId);
    const targetImageFile = path.join(targetDir, itemId);
    await fs.rename(imageFile, targetImageFile);
    
    // Move JSON metadata if exists
    if (UUID_ASSET_ID_RE.test(itemId)) {
      const metaFile = path.join(companyDir, `${itemId}.json`);
      const targetMetaFile = path.join(targetDir, `${itemId}.json`);
      await fs.rename(metaFile, targetMetaFile).catch(() => {});
    }
    
    console.log(`Moved image ${itemId} from company ${companyName} to scheduled deletion (${deletionId})`);
  }
  
  return deletionId;
}

async function cleanupExpiredDeletions() {
  try {
    const now = Date.now();
    const entries = await fs.readdir(SCHEDULED_DELETION_PATH);
    
    let deletedCount = 0;
    let totalSize = 0;
    
    for (const entry of entries) {
      const deletionFolder = path.join(SCHEDULED_DELETION_PATH, entry);
      const metadataFile = path.join(deletionFolder, 'metadata.json');
      
      try {
        const stat = await fs.stat(deletionFolder);
        if (!stat.isDirectory()) continue;
        
        const metadata = JSON.parse(await fs.readFile(metadataFile, 'utf-8'));
        const expiryTime = metadata.timestamp + (DELETION_RETENTION_DAYS * 24 * 60 * 60 * 1000);
        
        if (now >= expiryTime) {
          // Calculate size before deletion
          const filesDir = path.join(deletionFolder, 'files');
          try {
            const files = await fs.readdir(filesDir);
            for (const file of files) {
              const fileStat = await fs.stat(path.join(filesDir, file));
              totalSize += fileStat.size;
            }
          } catch (err) { /* files dir might not exist */ }
          
          // Permanently delete
          await fs.rm(deletionFolder, { recursive: true, force: true });
          deletedCount++;
          
          console.log(
            `Permanently deleted ${metadata.itemType} ` +
            `(${metadata.itemType === 'company' ? metadata.companyName : metadata.imageId}) ` +
            `after ${DELETION_RETENTION_DAYS} days`
          );
        }
      } catch (err) {
        console.warn(`Failed to process scheduled deletion ${entry}:`, err.message);
      }
    }
    
    if (deletedCount > 0) {
      console.log(
        `Cleanup complete: permanently deleted ${deletedCount} item(s), ` +
        `freed ${(totalSize / 1024 / 1024).toFixed(2)} MB`
      );
    }
  } catch (err) {
    console.error('Scheduled deletion cleanup failed:', err);
  }
}

// Run cleanup on startup
await cleanupExpiredDeletions();

// Schedule periodic cleanup (runs every 6 hours)
setInterval(cleanupExpiredDeletions, 6 * 60 * 60 * 1000);

// ------------------- Validation helpers -------------------
// FIX: strict regex prevents path-traversal in image_id
const COMPANY_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Legacy keys (company+filename derived) stay resolvable; new uploads use a UUID storage key.
const LEGACY_IMAGE_ID_RE = /^pratima_[a-z0-9_]+$/;
const UUID_ASSET_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(webp|pdf)$/i;
const IMAGE_ID_RE = new RegExp(`(?:${LEGACY_IMAGE_ID_RE.source})|(?:${UUID_ASSET_ID_RE.source})`, 'i');

function isAssetFile(filename) {
  return LEGACY_IMAGE_ID_RE.test(filename) || UUID_ASSET_ID_RE.test(filename);
}

// ------------------- Express setup -------------------
const app = express();
app.set('trust proxy', 1); // honour X-Forwarded-For behind nginx

// CORS — must come before every other middleware so preflight OPTIONS requests
// are answered before rate-limiting or auth runs
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'x-api-key, Content-Type');
  res.set('Access-Control-Max-Age', '86400'); // cache preflight for 24 h
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

// ------------------- Authentication Middleware -------------------

// IP Whitelist middleware
const ipWhitelist = (req, res, next) => {
  if (ALLOWED_IPS.length === 0) return next();
  const clientIP = req.ip;
  // Check exact IP matches
  if (ALLOWED_IPS.includes(clientIP)) return next();
  // Check CIDR ranges if needed (basic implementation)
  for (const allowedIP of ALLOWED_IPS) {
    if (allowedIP.includes('/')) {
      // Simple CIDR check for /24, /16, /8
      const [range, bits] = allowedIP.split('/');
      const rangeParts = range.split('.');
      const ipParts = clientIP.replace('::ffff:', '').split('.');
      if (ipParts.length === 4 && rangeParts.length === 4) {
        let match = true;
        const significantOctets = Math.floor(parseInt(bits) / 8);
        const remainingBits = parseInt(bits) % 8;
        for (let i = 0; i < significantOctets; i++) {
          if (ipParts[i] !== rangeParts[i]) {
            match = false;
            break;
          }
        }
        if (match && remainingBits > 0) {
          const mask = 256 - Math.pow(2, 8 - remainingBits);
          if ((parseInt(ipParts[significantOctets]) & mask) !== (parseInt(rangeParts[significantOctets]) & mask)) {
            match = false;
          }
        }
        if (match) return next();
      }
    }
  }
  return res.status(403).json({ error: 'Access denied from this IP address' });
};

// Basic API-key guard — localhost (server shell / health checks) bypasses
const verifyApiKey = (req, res, next) => {
  const ip = req.ip;
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return next();
  if (req.headers['x-api-key'] !== API_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// UI-specific API-key guard with HTML login form for /ui route
const verifyApiKeyWithRedirect = (req, res, next) => {
  const ip = req.ip;
  
  // Allow localhost without auth
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return next();
  
  // Check for API key in header or query parameter
  const apiKey = req.headers['x-api-key'] || req.query.key;
  
  if (apiKey === API_KEY) return next();
  
  // For HTML pages, show a login form instead of JSON error
  if ((req.path === '/ui' || req.path === '/ui/') && req.accepts('html')) {
    return res.status(401).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Required - Pratima</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #080b0e; color: #e8edf2; display: flex; 
            align-items: center; justify-content: center; min-height: 100vh;
            margin: 0; line-height: 1.5;
          }
          .login-box {
            background: #0e1318; border: 1px solid #1e2832; border-radius: 12px;
            padding: 32px; max-width: 420px; width: 90%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
          }
          .logo { font-size: 24px; font-weight: 700; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
          .logo-icon {
            width: 36px; height: 36px;
            background: linear-gradient(135deg, #10b981 0%, #3b82f6 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
          }
          .logo-text { background: linear-gradient(135deg, #10b981, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
          .subtitle { color: #5a6875; font-size: 13px; margin-bottom: 24px; }
          input { 
            width: 100%; padding: 10px 12px; background: #141c24; border: 1px solid #253040;
            border-radius: 8px; color: #e8edf2; font-size: 14px; outline: none;
            box-sizing: border-box; transition: border-color 0.15s;
          }
          input:focus { border-color: #10b981; }
          button {
            width: 100%; padding: 10px; background: #10b981; color: #000;
            border: none; border-radius: 8px; font-weight: 600; font-size: 14px;
            cursor: pointer; margin-top: 12px; transition: background 0.15s;
          }
          button:hover { background: #0ea774; }
          button:disabled { opacity: 0.6; cursor: not-allowed; }
          .error { 
            color: #ef4444; font-size: 12px; margin-top: 8px; display: none; 
            padding: 8px; background: rgba(239,68,68,0.1); border-radius: 6px;
          }
          .hint { color: #5a6875; font-size: 11px; margin-top: 16px; text-align: center; }
          .spinner {
            display: inline-block; width: 14px; height: 14px;
            border: 2px solid rgba(0,0,0,0.3); border-top-color: #000;
            border-radius: 50%; animation: spin 0.6s linear infinite;
            vertical-align: middle; margin-right: 6px;
          }
          @keyframes spin { to { transform: rotate(360deg); } }
        </style>
      </head>
      <body>
        <div class="login-box">
          <div class="logo">
            <div class="logo-icon">⚡</div>
            <span class="logo-text">Pratima</span>
          </div>
          <div class="subtitle">Dashboard Authentication</div>
          <form onsubmit="authenticate(event)" id="login-form">
            <input type="password" id="key" placeholder="Enter Admin API Key" autofocus autocomplete="off" />
            <div class="error" id="error"></div>
            <button type="submit" id="submit-btn">Authenticate</button>
          </form>
          <div class="hint">
            Enter your global admin API key to access the dashboard.<br>
            Localhost requests bypass authentication.
          </div>
        </div>
        <script>

        if (location.search.includes('key=')) {
          history.replaceState({}, '', location.pathname);
        }
          async function authenticate(e) {
            e.preventDefault();
            const key = document.getElementById('key').value.trim();
            const btn = document.getElementById('submit-btn');
            const error = document.getElementById('error');
            
            if (!key) {
              error.textContent = 'Please enter an API key';
              error.style.display = 'block';
              return;
            }
            
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>Authenticating...';
            error.style.display = 'none';
            
            try {
              const res = await fetch('/ui/api/stats', { 
                headers: { 'x-api-key': key },
                signal: AbortSignal.timeout(5000)
              });
              if (res.ok) {
                sessionStorage.setItem('pratima_key', key);
                window.location.href = '/ui?key=' + encodeURIComponent(key);
              } else {
                error.textContent = 'Invalid API key. Please try again.';
                error.style.display = 'block';
              }
            } catch (err) {
              error.textContent = 'Connection failed. Check if the server is running.';
              error.style.display = 'block';
            } finally {
              btn.disabled = false;
              btn.innerHTML = 'Authenticate';
              document.getElementById('key').focus();
            }
          }
        </script>
      </body>
      </html>
    `);
  }
  
  // For API calls, check query parameter key as well
  const queryKey = req.query.key;
  if (queryKey === API_KEY) return next();
  
  return res.status(403).json({ error: 'Forbidden - valid API key required' });
};

// ------------------- Health -------------------
app.get('/health', PROTECT_HEALTH ? verifyApiKey : (_req, res, next) => next(), (_req, res) =>
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
    const idx = list.findIndex(c => c.id === id);
    if (idx === -1) return false;
    [removed] = list.splice(idx, 1);
    await saveCompanies(list);
    return true;
  });

  if (!found) return res.status(404).json({ error: 'Company not found' });

  // Move to scheduled deletion instead of permanent delete
  try {
    const deletionId = await moveToScheduledDeletion(removed.id, removed.name, 'company');
    console.log(`Company deleted (soft): ${removed.name} (${removed.id}) - deletion ID: ${deletionId}`);
    res.json({ 
      success: true, 
      deletionId,
      message: `Company moved to scheduled deletion. Will be permanently deleted after ${DELETION_RETENTION_DAYS} days.`
    });
  } catch (e) {
    console.error(`Failed to move company ${removed.id} to scheduled deletion:`, e.message);
    // Fallback: if scheduled deletion fails, we've already removed from companies.json
    res.json({ 
      success: true,
      warning: 'Company removed from system but scheduled deletion failed'
    });
  }
});

// ------------------- Company Domain Restriction -------------------
// Optional per-company allow-list of hostnames permitted to fetch that company's files via
// GET /img. Absent or empty = unrestricted (the default, and the only state any pre-existing
// company will ever have unless someone explicitly opts in from the UI).
app.put('/companies/:id/domains', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { id } = req.params;
  if (!COMPANY_UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid company ID' });

  const { domains } = req.body;
  if (!Array.isArray(domains) || !domains.every(d => typeof d === 'string')) {
    return res.status(400).json({ error: 'domains must be an array of hostname strings (empty array = unrestricted)' });
  }
  const cleaned = [...new Set(domains.map(d => d.trim().toLowerCase()).filter(Boolean))];

  let updated = null;
  const found = await withCompaniesLock(async () => {
    const list = await loadCompanies();
    const co = list.find(c => c.id === id);
    if (!co) return false;
    co.allowedDomains = cleaned;
    updated = co;
    await saveCompanies(list);
    return true;
  });

  if (!found) return res.status(404).json({ error: 'Company not found' });
  console.log(`Updated allowed domains for ${updated.name} (${id}): ${cleaned.join(', ') || '(unrestricted)'}`);
  res.json({ success: true, allowedDomains: cleaned });
});

// ------------------- Company Backup / Restore -------------------
// Single-company ZIP snapshot of every stored file + metadata sidecar. Restore never touches
// company.json (name/apiKey/allowedDomains stay whatever is live) — it only replaces file bytes,
// so a stale backup can never resurrect a rotated/leaked API key.
app.get('/companies/:id/backup', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { id } = req.params;
  if (!COMPANY_UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid company ID' });

  const companies = await loadCompanies();
  const company = companies.find(c => c.id === id);
  if (!company) return res.status(404).json({ error: 'Company not found' });

  const dir = path.join(STORAGE_PATH, 'companies', id);
  const zip = new AdmZip();
  zip.addFile('company.json', Buffer.from(JSON.stringify(company, null, 2)));

  let fileCount = 0;
  try {
    const files = await fs.readdir(dir);
    for (const f of files) {
      zip.addFile(`files/${f}`, await fs.readFile(path.join(dir, f)));
      fileCount++;
    }
  } catch (_) { /* company has no files yet — backup is still valid with just company.json */ }

  const safeName = company.name.replace(/[^a-z0-9_-]+/gi, '_');
  res.set('Content-Type', 'application/zip');
  res.set('Content-Disposition', `attachment; filename="pratima-backup-${safeName}-${id}.zip"`);
  res.send(zip.toBuffer());
  console.log(`Backup created for ${company.name} (${id}) — ${fileCount} file(s)`);
});

const restoreUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BACKUP_SIZE },
});

app.post('/companies/:id/restore', verifyApiKey, mgmtLimiter, restoreUpload.single('backup'), async (req, res) => {
  const { id } = req.params;
  if (!COMPANY_UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid company ID' });
  if (!req.file) return res.status(400).json({ error: 'No backup ZIP provided (field name: backup)' });

  const companies = await loadCompanies();
  const company = companies.find(c => c.id === id);
  if (!company) return res.status(404).json({ error: 'Company not found — create it first, then restore its files into it' });

  let zip;
  try { zip = new AdmZip(req.file.buffer); }
  catch { return res.status(400).json({ error: 'Invalid ZIP file' }); }

  const companyDir = path.join(STORAGE_PATH, 'companies', id);
  await fs.mkdir(companyDir, { recursive: true });

  let restored = 0, skipped = 0;
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory || !entry.entryName.startsWith('files/')) continue;

    const basename = entry.entryName.slice('files/'.length);
    // Only a flat filename is ever accepted — rejects nested paths / zip-slip traversal.
    if (!basename || basename.includes('/') || basename.includes('\\')) { skipped++; continue; }

    const assetName = basename.endsWith('.json') ? basename.slice(0, -5) : basename;
    if (!isAssetFile(assetName)) { skipped++; continue; }

    await fs.writeFile(path.join(companyDir, basename), entry.getData(), { mode: 0o600 });
    restored++;
  }

  console.log(`Restored ${restored} file(s) for ${company.name} (${id}) from backup` +
    (skipped ? `, skipped ${skipped} invalid entr${skipped === 1 ? 'y' : 'ies'}` : ''));
  res.json({ success: true, restored, skipped });
});

// ------------------- Image / PDF Upload -------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_req, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/tiff', 'application/pdf'].includes(file.mimetype);
    cb(null, ok);
  },
});

app.post('/upload', uploadLimiter, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No valid file provided (accepted: JPEG, PNG, WebP, GIF, TIFF, PDF)' });

  const companyId = req.body.company_id || req.query.company_id;
  if (!companyId) return res.status(400).json({ error: 'company_id is required' });
  if (!COMPANY_UUID_RE.test(companyId)) return res.status(400).json({ error: 'Invalid company_id format' });

  const companies = await loadCompanies();
  const company = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: 'Company not found' });

  // Each company authenticates with its own key — not the global admin key
  if (req.headers['x-api-key'] !== company.apiKey) {
    return res.status(403).json({ error: 'Invalid API key for this company' });
  }

  await acquireSlot();
  try {
    const buf = req.file.buffer;
    const isPdf = req.file.mimetype === 'application/pdf';

    // Malware scan runs on the raw upload regardless of file type.
    if (clamscan) {
      const { isInfected, viruses } = await clamscan.scanStream(Readable.from(buf));
      if (isInfected) throw new Error(`Malware detected: ${viruses.join(', ')}`);
    }

    let processedBuf, ext, contentType;
    if (isPdf) {
      ext = 'pdf';
      contentType = 'application/pdf';
      processedBuf = await compressPdf(buf); // no-op passthrough if Ghostscript isn't installed
    } else {
      const meta = await sharp(buf).metadata();
      if (!meta.format) throw new Error('Unrecognised image format');
      // FIX: removed .withMetadata(false) — sharp strips metadata by default without this call.
      // Calling .withMetadata(false) passes a falsy options object which may re-enable metadata.
      ext = 'webp';
      contentType = 'image/webp';
      processedBuf = await sharp(buf).webp({ quality: WEBP_QUALITY }).toBuffer();
    }
    const encrypted = encryptBuffer(processedBuf);

    const companyDir = path.join(STORAGE_PATH, 'companies', companyId);
    await fs.mkdir(companyDir, { recursive: true });

    // Storage key is a server-generated UUID — never derived from the client filename,
    // so two uploads can never collide on path even with identical original names.
    let imageId, targetPath;
    const MAX_ID_ATTEMPTS = 5;
    for (let attempt = 1; ; attempt++) {
      imageId = `${uuidv4()}.${ext}`;
      targetPath = path.join(companyDir, imageId);
      try {
        // 'wx' fails loudly (EEXIST) instead of silently overwriting on a collision.
        await fs.writeFile(targetPath, encrypted, { flag: 'wx', mode: 0o600 });
        break;
      } catch (err) {
        if (err.code === 'EEXIST' && attempt < MAX_ID_ATTEMPTS) continue;
        if (err.code === 'EEXIST') throw new Error('Could not allocate a unique storage key — please retry upload');
        throw err;
      }
    }

    // Original filename is kept only as metadata (e.g. Content-Disposition on download),
    // never as part of the storage key/path.
    const metaPath = path.join(companyDir, `${imageId}.json`);
    await fs.writeFile(metaPath, JSON.stringify({
      originalName: req.file.originalname,
      contentType,
      uploadedAt: new Date().toISOString(),
    }), { mode: 0o600 });

    console.log(`Stored ${imageId} for ${company.name} (${(processedBuf.length / 1024).toFixed(1)} KB ${isPdf ? 'PDF' : 'WebP'})`);

    res.json({ url: `${PUBLIC_URL}/img/${companyId}/${imageId}`, imageId, companyId, type: isPdf ? 'pdf' : 'image' });
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
  if (!IMAGE_ID_RE.test(image_id)) return res.status(400).send('Invalid image ID');

  try {
    // Optional per-company domain allow-list. Absent/empty = unrestricted (unchanged default behavior).
    const companies = await loadCompanies();
    const company = companies.find(c => c.id === company_id);
    if (!company) return res.status(404).send('Not found');

    if (Array.isArray(company.allowedDomains) && company.allowedDomains.length > 0) {
      const originHeader = req.headers.origin || req.headers.referer || '';
      let hostname = '';
      try { hostname = new URL(originHeader).hostname.toLowerCase(); } catch { /* missing/invalid origin */ }
      if (!hostname || !company.allowedDomains.includes(hostname)) {
        return res.status(403).send("This company's files are restricted to authorized domains");
      }
    }

    const companyDir = path.join(STORAGE_PATH, 'companies', company_id);
    const encrypted = await fs.readFile(path.join(companyDir, image_id));
    const decrypted = decryptBuffer(encrypted);

    const isPdf = image_id.toLowerCase().endsWith('.pdf');
    res.set('Content-Type', isPdf ? 'application/pdf' : 'image/webp');
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.set('Access-Control-Allow-Origin', '*'); // allow <img>/<embed> tags from other domains

    // Original filename (if we have it) surfaces only in Content-Disposition, never in the path.
    if (UUID_ASSET_ID_RE.test(image_id)) {
      try {
        const sidecar = JSON.parse(await fs.readFile(path.join(companyDir, `${image_id}.json`), 'utf-8'));
        if (sidecar.originalName) {
          res.set('Content-Disposition', `inline; filename="${encodeURIComponent(sidecar.originalName)}"`);
        }
      } catch { /* no metadata sidecar — serve without Content-Disposition */ }
    }

    res.send(decrypted);
  } catch {
    res.status(404).send('Not found');
  }
});

// ------------------- Image Deletion -------------------
app.delete('/img/:company_id/:image_id', async (req, res) => {
  const { company_id, image_id } = req.params;

  if (!COMPANY_UUID_RE.test(company_id)) return res.status(400).json({ error: 'Invalid company ID' });
  if (!IMAGE_ID_RE.test(image_id)) return res.status(400).json({ error: 'Invalid image ID' });

  const companies = await loadCompanies();
  const company = companies.find(c => c.id === company_id);
  if (!company) return res.status(404).json({ error: 'Company not found' });

  // Each company uses its own API key (the prtm_... key)
  if (req.headers['x-api-key'] !== company.apiKey) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  const companyDir = path.join(STORAGE_PATH, 'companies', company_id);
  const filePath = path.join(companyDir, image_id);
  
  try {
    // Check if file exists
    await fs.access(filePath);
    
    // Move to scheduled deletion instead of permanent delete
    const deletionId = await moveToScheduledDeletion(company_id, company.name, 'image', image_id);
    
    console.log(`Image deleted (soft): ${image_id} for ${company.name} (${company_id}) - deletion ID: ${deletionId}`);
    return res.json({ 
      success: true,
      deletionId,
      message: `Image moved to scheduled deletion. Will be permanently deleted after ${DELETION_RETENTION_DAYS} days.`
    });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Image not found' });
    console.error('Delete error:', err);
    return res.status(500).json({ error: 'Failed to delete image' });
  }
});

// ------------------- Scheduled Deletion Management -------------------
// List all items in scheduled deletion
app.get('/scheduled-deletions', verifyApiKey, async (_req, res) => {
  try {
    const entries = await fs.readdir(SCHEDULED_DELETION_PATH);
    const deletions = [];
    
    for (const entry of entries) {
      const deletionFolder = path.join(SCHEDULED_DELETION_PATH, entry);
      const metadataFile = path.join(deletionFolder, 'metadata.json');
      
      try {
        const stat = await fs.stat(deletionFolder);
        if (!stat.isDirectory()) continue;
        
        const metadata = JSON.parse(await fs.readFile(metadataFile, 'utf-8'));
        
        // Calculate days remaining
        const now = Date.now();
        const expiryTime = metadata.timestamp + (DELETION_RETENTION_DAYS * 24 * 60 * 60 * 1000);
        const daysRemaining = Math.ceil((expiryTime - now) / (24 * 60 * 60 * 1000));
        
        deletions.push({
          ...metadata,
          daysRemaining,
          canRestore: daysRemaining > 0
        });
      } catch (err) {
        console.warn(`Failed to read scheduled deletion ${entry}:`, err.message);
      }
    }
    
    // Sort by deletion date (most recent first)
    deletions.sort((a, b) => b.timestamp - a.timestamp);
    
    res.json({ deletions, retentionDays: DELETION_RETENTION_DAYS });
  } catch (err) {
    console.error('Failed to list scheduled deletions:', err);
    res.status(500).json({ error: 'Failed to list scheduled deletions' });
  }
});

// Restore a company or image from scheduled deletion
app.post('/scheduled-deletions/:deletionId/restore', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { deletionId } = req.params;
  
  const deletionFolder = path.join(SCHEDULED_DELETION_PATH, deletionId);
  const metadataFile = path.join(deletionFolder, 'metadata.json');
  
  try {
    const metadata = JSON.parse(await fs.readFile(metadataFile, 'utf-8'));
    
    // Check if still within retention period
    const now = Date.now();
    const expiryTime = metadata.timestamp + (DELETION_RETENTION_DAYS * 24 * 60 * 60 * 1000);
    if (now >= expiryTime) {
      return res.status(410).json({ error: 'This item has already been permanently deleted' });
    }
    
    if (metadata.itemType === 'company') {
      // Restore company
      // First, check if company ID still exists in companies.json
      const companies = await loadCompanies();
      const existingCompany = companies.find(c => c.id === metadata.companyId);
      
      if (!existingCompany) {
        return res.status(400).json({ 
          error: 'Cannot restore: Company no longer exists in system. Please recreate the company first.' 
        });
      }
      
      // Move files back to company folder
      const sourceDir = path.join(deletionFolder, 'files');
      const targetDir = path.join(STORAGE_PATH, 'companies', metadata.companyId);
      
      try {
        await fs.access(sourceDir);
        await fs.rename(sourceDir, targetDir);
        console.log(`Restored company ${metadata.companyName} (${metadata.companyId}) from scheduled deletion`);
      } catch (err) {
        if (err.code === 'ENOENT') {
          console.log(`Company ${metadata.companyName} had no files to restore`);
        } else {
          throw err;
        }
      }
      
      // Remove from scheduled deletion
      await fs.rm(deletionFolder, { recursive: true, force: true });
      
      res.json({ 
        success: true, 
        message: `Company ${metadata.companyName} restored successfully`,
        itemType: 'company',
        companyId: metadata.companyId
      });
      
    } else if (metadata.itemType === 'image') {
      // Restore individual image
      const companies = await loadCompanies();
      const company = companies.find(c => c.id === metadata.companyId);
      
      if (!company) {
        return res.status(400).json({ 
          error: 'Cannot restore: Parent company no longer exists' 
        });
      }
      
      const sourceDir = path.join(deletionFolder, 'files');
      const targetDir = path.join(STORAGE_PATH, 'companies', metadata.companyId);
      await fs.mkdir(targetDir, { recursive: true });
      
      // Move image file back
      const sourceImageFile = path.join(sourceDir, metadata.imageId);
      const targetImageFile = path.join(targetDir, metadata.imageId);
      await fs.rename(sourceImageFile, targetImageFile);
      
      // Move metadata file back if exists
      if (UUID_ASSET_ID_RE.test(metadata.imageId)) {
        const sourceMetaFile = path.join(sourceDir, `${metadata.imageId}.json`);
        const targetMetaFile = path.join(targetDir, `${metadata.imageId}.json`);
        await fs.rename(sourceMetaFile, targetMetaFile).catch(() => {});
      }
      
      // Remove from scheduled deletion
      await fs.rm(deletionFolder, { recursive: true, force: true });
      
      console.log(`Restored image ${metadata.imageId} from company ${metadata.companyName}`);
      
      res.json({ 
        success: true, 
        message: `Image ${metadata.imageId} restored successfully`,
        itemType: 'image',
        companyId: metadata.companyId,
        imageId: metadata.imageId,
        imageUrl: `${PUBLIC_URL}/img/${metadata.companyId}/${metadata.imageId}`
      });
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'Scheduled deletion not found' });
    }
    console.error('Restore error:', err);
    res.status(500).json({ error: 'Failed to restore item' });
  }
});

// Permanently delete an item from scheduled deletion (skip retention period)
app.delete('/scheduled-deletions/:deletionId', verifyApiKey, mgmtLimiter, async (req, res) => {
  const { deletionId } = req.params;
  
  const deletionFolder = path.join(SCHEDULED_DELETION_PATH, deletionId);
  const metadataFile = path.join(deletionFolder, 'metadata.json');
  
  try {
    const metadata = JSON.parse(await fs.readFile(metadataFile, 'utf-8'));
    
    // Permanently delete
    await fs.rm(deletionFolder, { recursive: true, force: true });
    
    console.log(
      `Manually permanently deleted ${metadata.itemType} ` +
      `(${metadata.itemType === 'company' ? metadata.companyName : metadata.imageId})`
    );
    
    res.json({ 
      success: true,
      message: `${metadata.itemType === 'company' ? 'Company' : 'Image'} permanently deleted`
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'Scheduled deletion not found' });
    }
    console.error('Permanent delete error:', err);
    res.status(500).json({ error: 'Failed to permanently delete item' });
  }
});

// ------------------- UI -------------------
app.get('/ui', verifyApiKeyWithRedirect, ipWhitelist, async (_req, res) => {
  try {
    let html = await fs.readFile(path.join(__dirname, 'ui.html'), 'utf-8');
    const injectedKey = JSON.stringify(API_KEY);
    // FIX: inject a script that captures ?key= from the URL into sessionStorage
    // so uiFetch() finds the key on the very first dashboard load.
    const injectedScript = `<script>
      window.PRATIMA_GLOBAL_API_KEY = ${injectedKey};
      (function(){
        var p = new URLSearchParams(location.search);
        var k = p.get('key');
        if (k) { sessionStorage.setItem('pratima_key', k); history.replaceState({}, '', location.pathname); }
      })();
    </script>`;
    html = html.replace('<!-- PRATIMA_API_KEY -->', injectedScript);
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    res.status(500).send('UI not available: ' + err.message);
  }
});

app.get('/ui/api/stats', verifyApiKeyWithRedirect, ipWhitelist, async (_req, res) => {
  let redisStatus = 'disconnected';
  let activeSlots = 0;
  try {
    await redis.ping();
    redisStatus = 'connected';
    activeSlots = Math.max(0, parseInt(await redis.get(ACTIVE_KEY) || '0', 10));
  } catch (_) { }

  const companies = await loadCompanies();
  let totalImages = 0;
  let storageBytes = 0;
  for (const co of companies) {
    const dir = path.join(STORAGE_PATH, 'companies', co.id);
    try {
      const files = (await fs.readdir(dir)).filter(isAssetFile);
      totalImages += files.length;
      const sizes = await Promise.all(
        files.map(f => fs.stat(path.join(dir, f)).then(s => s.size).catch(() => 0))
      );
      storageBytes += sizes.reduce((a, b) => a + b, 0);
    } catch (_) { }
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
    ghostscriptStatus: ghostscriptAvailable ? 'connected' : 'unavailable',
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

app.get('/ui/api/images', verifyApiKeyWithRedirect, ipWhitelist, async (req, res) => {
  const filter = req.query.company_id;
  const companies = await loadCompanies();
  const images = [];

  for (const co of companies) {
    if (filter && co.id !== filter) continue;
    const dir = path.join(STORAGE_PATH, 'companies', co.id);
    try {
      const files = (await fs.readdir(dir)).filter(isAssetFile);
      const stats = await Promise.all(files.map(async f => {
        const s = await fs.stat(path.join(dir, f));
        return {
          id: f,
          url: `${PUBLIC_URL}/img/${co.id}/${f}`,
          type: f.toLowerCase().endsWith('.pdf') ? 'pdf' : 'image',
          size: s.size,
          created: s.birthtime || s.mtime,
          company_id: co.id,
          company_name: co.name,
        };
      }));
      images.push(...stats);
    } catch (_) { }
  }

  images.sort((a, b) => new Date(b.created) - new Date(a.created));
  res.json(images);
});

// SSE log stream — sends buffered history then streams live entries
app.get('/ui/api/logs', verifyApiKeyWithRedirect, ipWhitelist, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
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
  console.log('Authentication: Required for all UI and management endpoints');
  console.log('Security: AES-256-GCM encryption, ClamAV scanning, rate limiting, IP whitelisting available');
});

async function shutdown(signal) {
  console.log(`${signal} received — shutting down gracefully`);
  server.close(async () => {
    try { await redis.quit(); await redisSub.quit(); } catch (_) { }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000); // force-kill after 10 s
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));