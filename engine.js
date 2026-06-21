import 'dotenv/config';
import express from 'express';
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

// ------------------- Configuration -------------------
const PORT = process.env.PORT || 3001;
const API_KEY = process.env.API_KEY;
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const CLAMD_SOCKET = process.env.CLAMD_SOCKET || '/var/run/clamav/clamd.ctl';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 10 * 1024 * 1024;
const WEBP_QUALITY = parseInt(process.env.WEBP_QUALITY, 10) || 92;
const CONCURRENCY_LIMIT = parseInt(process.env.CONCURRENCY_LIMIT, 10) || 2;
const STORAGE_PATH = process.env.STORAGE_PATH || '/var/www/al-nikaah-people-images';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3001';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ------------------- Log Capture -------------------
// Must be set up before anything else logs so the UI shows startup messages.
const LOG_BUFFER_SIZE = 500;
const logBuffer = [];
const sseClients = new Set();

function emitLog(level, ...args) {
  const message = args
    .map((a) => (a instanceof Error ? a.stack || a.message : typeof a === 'object' ? JSON.stringify(a) : String(a)))
    .join(' ');
  const entry = { time: new Date().toISOString(), level, message };
  logBuffer.push(entry);
  if (logBuffer.length > LOG_BUFFER_SIZE) logBuffer.shift();
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const client of sseClients) client.write(payload);
}

const _log = console.log.bind(console);
const _warn = console.warn.bind(console);
const _error = console.error.bind(console);

console.log = (...a) => { _log(...a); emitLog('info', ...a); };
console.warn = (...a) => { _warn(...a); emitLog('warn', ...a); };
console.error = (...a) => { _error(...a); emitLog('error', ...a); };

// ------------------- Storage -------------------
await fs.mkdir(STORAGE_PATH, { recursive: true });

// ------------------- ClamAV -------------------
let clamscan;
try {
  clamscan = await new NodeClam().init({
    clamdscan: { socket: CLAMD_SOCKET, timeout: 60000 },
  });
  console.log('ClamAV daemon connected');
} catch (err) {
  console.error('ClamAV error:', err.message);
  clamscan = null;
}

// ------------------- Redis -------------------
// Separate connections: one for commands, one dedicated to pub/sub subscribing
const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: null });
const redisSub = new Redis(REDIS_URL, { maxRetriesPerRequest: null });

redis.on('error', (err) => { console.error('Redis error:', err); process.exit(1); });
redisSub.on('error', (err) => { console.error('RedisSub error:', err); process.exit(1); });

// ------------------- Distributed semaphore -------------------
const NOTIFY_CHANNEL = 'semaphore:notify';
const ACTIVE_KEY = 'semaphore:active';
const WAIT_KEY = 'semaphore:wait';

// defineCommand registers the Lua script as redis.acquireSemaphore / redis.releaseSemaphore
redis.defineCommand('acquireSemaphore', {
  numberOfKeys: 2,
  lua: `
    local active_key = KEYS[1]
    local wait_key = KEYS[2]
    local limit = tonumber(ARGV[1])
    local client_id = ARGV[2]
    local active = tonumber(redis.call('GET', active_key) or '0')
    if active < limit then
      redis.call('INCR', active_key)
      return 'ACQUIRED'
    else
      redis.call('RPUSH', wait_key, client_id)
      return 'QUEUED'
    end
  `,
});

redis.defineCommand('releaseSemaphore', {
  numberOfKeys: 2,
  lua: `
    local active_key = KEYS[1]
    local wait_key = KEYS[2]
    local notify_channel = ARGV[1]
    redis.call('DECR', active_key)
    local next_client = redis.call('LPOP', wait_key)
    if next_client then
      redis.call('PUBLISH', notify_channel, next_client)
    end
  `,
});

async function acquireSlot() {
  const clientId = uuidv4();
  // Call the registered Lua command via the main redis connection
  const result = await redis.acquireSemaphore(ACTIVE_KEY, WAIT_KEY, CONCURRENCY_LIMIT, clientId);
  if (result === 'ACQUIRED') return;

  // Wait for a publish notification on the dedicated subscriber connection
  return new Promise((resolve) => {
    const onMessage = (channel, message) => {
      if (channel === NOTIFY_CHANNEL && message === clientId) {
        redisSub.removeListener('message', onMessage);
        redisSub.unsubscribe(NOTIFY_CHANNEL);
        resolve();
      }
    };
    redisSub.on('message', onMessage);
    redisSub.subscribe(NOTIFY_CHANNEL);

    setTimeout(() => {
      redisSub.removeListener('message', onMessage);
      redisSub.unsubscribe(NOTIFY_CHANNEL);
      resolve();
    }, 30000);
  });
}

async function releaseSlot() {
  await redis.releaseSemaphore(ACTIVE_KEY, WAIT_KEY, NOTIFY_CHANNEL);
}

// ------------------- Encryption -------------------
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]);
}

function decryptBuffer(encrypted) {
  const iv = encrypted.subarray(0, IV_LENGTH);
  const authTag = encrypted.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const data = encrypted.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ------------------- Express setup -------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/tiff'];
    cb(null, allowed.includes(file.mimetype));
  },
});

const app = express();

const verifyApiKey = (req, res, next) => {
  if (req.headers['x-api-key'] !== API_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// ------------------- Health -------------------
app.get('/health', (req, res) => res.send('OK'));

// ------------------- UI Routes -------------------
// Serve the dashboard HTML
app.get('/ui', async (req, res) => {
  try {
    const html = await fs.readFile(path.join(__dirname, 'ui.html'));
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    res.status(500).send('UI not found: ' + err.message);
  }
});

// Stats endpoint — engine health, config, storage summary
app.get('/ui/api/stats', async (req, res) => {
  let redisStatus = 'disconnected';
  let activeSlots = 0;
  try {
    await redis.ping();
    redisStatus = 'connected';
    const raw = await redis.get(ACTIVE_KEY);
    activeSlots = Math.max(0, parseInt(raw || '0', 10));
  } catch (_) {}

  let imageCount = 0;
  let storageBytes = 0;
  try {
    const files = await fs.readdir(STORAGE_PATH);
    const imageFiles = files.filter((f) => UUID_RE.test(f));
    imageCount = imageFiles.length;
    const sizes = await Promise.all(
      imageFiles.map((f) =>
        fs.stat(path.join(STORAGE_PATH, f))
          .then((s) => s.size)
          .catch(() => 0)
      )
    );
    storageBytes = sizes.reduce((a, b) => a + b, 0);
  } catch (_) {}

  res.json({
    uptime: process.uptime(),
    memoryRss: process.memoryUsage().rss,
    imageCount,
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

// Images listing endpoint — returns metadata for all stored images
app.get('/ui/api/images', async (req, res) => {
  try {
    const files = await fs.readdir(STORAGE_PATH);
    const imageFiles = files.filter((f) => UUID_RE.test(f));
    const images = await Promise.all(
      imageFiles.map(async (f) => {
        const stat = await fs.stat(path.join(STORAGE_PATH, f));
        return {
          id: f,
          url: `${PUBLIC_URL}/img/${f}`,
          size: stat.size,
          created: stat.birthtime || stat.mtime,
        };
      })
    );
    // Newest first
    images.sort((a, b) => new Date(b.created) - new Date(a.created));
    res.json(images);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SSE log stream — sends buffered history then streams new entries live
app.get('/ui/api/logs', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  // Send existing buffer so the UI shows past logs immediately on connect
  for (const entry of logBuffer) {
    res.write(`data: ${JSON.stringify(entry)}\n\n`);
  }

  // Keep-alive ping every 25 s to prevent proxy/browser timeouts
  const keepAlive = setInterval(() => res.write(': ping\n\n'), 25000);

  sseClients.add(res);
  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

// ------------------- Image Upload -------------------
app.post('/upload', verifyApiKey, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image file' });

  await acquireSlot();
  try {
    const buf = req.file.buffer;
    const metadata = await sharp(buf).metadata();
    if (!metadata.format) throw new Error('Invalid image format');

    if (clamscan) {
      const stream = Readable.from(buf);
      const { isInfected, viruses } = await clamscan.scanStream(stream);
      if (isInfected) throw new Error(`Malware detected: ${viruses.join(', ')}`);
    }

    const webpBuffer = await sharp(buf)
      .withMetadata(false)
      .webp({ quality: WEBP_QUALITY })
      .toBuffer();

    const encrypted = encryptBuffer(webpBuffer);
    const fileId = uuidv4();
    await fs.writeFile(path.join(STORAGE_PATH, fileId), encrypted, { mode: 0o600 });

    console.log(`Processed ${fileId} (${(webpBuffer.length / 1024).toFixed(1)} KB)`);
    res.json({ url: `${PUBLIC_URL}/img/${fileId}` });
  } catch (err) {
    console.error('Upload error:', err.message);
    res.status(400).json({ error: err.message });
  } finally {
    await releaseSlot(); // must be awaited so slot is always freed
  }
});

// ------------------- Image Retrieval -------------------
app.get('/img/:id', async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) {
    return res.status(400).send('Invalid ID');
  }
  try {
    const encrypted = await fs.readFile(path.join(STORAGE_PATH, id));
    const decrypted = decryptBuffer(encrypted);
    res.set('Content-Type', 'image/webp');
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(decrypted);
  } catch {
    res.status(404).send('Not found');
  }
});

// ------------------- Error Handler -------------------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(413).json({ error: 'File too large' });
  }
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`Image engine listening on http://127.0.0.1:${PORT}`);
  console.log(`Dashboard UI available at http://127.0.0.1:${PORT}/ui`);
});
