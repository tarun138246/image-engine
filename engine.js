import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import Redis from 'ioredis';
import NodeClam from 'clamscan';

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

app.get('/health', (req, res) => res.send('OK'));

app.post('/upload', verifyApiKey, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image file' });

  await acquireSlot();
  try {
    const buf = req.file.buffer;
    const metadata = await sharp(buf).metadata();
    if (!metadata.format) throw new Error('Invalid image format');

    if (clamscan) {
      const { isInfected, viruses } = await clamscan.scanBuffer(buf, 30000);
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

app.get('/img/:id', async (req, res) => {
  const { id } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
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

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(413).json({ error: 'File too large' });
  }
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`Image engine listening on http://127.0.0.1:${PORT}`);
});
