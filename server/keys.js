const express = require('express');
const crypto = require('crypto');
const db = require('./db');

const router = express.Router();
const ALGORITHM = 'aes-256-gcm';

function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY;
  if (!key || key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be exactly 32 characters');
  }
  return Buffer.from(key, 'utf8');
}

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Store as: iv(24 hex) + authTag(32 hex) + encrypted(hex)
  return iv.toString('hex') + authTag.toString('hex') + encrypted.toString('hex');
}

function decrypt(stored) {
  const iv = Buffer.from(stored.slice(0, 24), 'hex');
  const authTag = Buffer.from(stored.slice(24, 56), 'hex');
  const encrypted = Buffer.from(stored.slice(56), 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

function maskKey(plaintext) {
  if (plaintext.length <= 4) return '****';
  return '*'.repeat(plaintext.length - 4) + plaintext.slice(-4);
}

// GET /api/keys — list all keys for the logged-in user (masked)
router.get('/', (req, res) => {
  try {
    const rows = db
      .prepare('SELECT provider, encrypted_key, created_at FROM api_keys WHERE user_id = ?')
      .all(req.user.userId);

    const keys = rows.map((row) => ({
      provider: row.provider,
      key: decrypt(row.encrypted_key),
      created_at: row.created_at,
    }));

    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve keys' });
  }
});

// POST /api/keys — store an encrypted API key
router.post('/', (req, res) => {
  const { provider, key } = req.body;
  if (!provider || !key) {
    return res.status(400).json({ error: 'provider and key are required' });
  }

  try {
    const encrypted_key = encrypt(key);
    db.prepare(
      `INSERT INTO api_keys (user_id, provider, encrypted_key)
       VALUES (?, ?, ?)
       ON CONFLICT(user_id, provider) DO UPDATE SET encrypted_key = excluded.encrypted_key, created_at = CURRENT_TIMESTAMP`
    ).run(req.user.userId, provider, encrypted_key);

    res.status(201).json({ message: 'Key saved' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save key' });
  }
});

// DELETE /api/keys/:provider — remove a key
router.delete('/:provider', (req, res) => {
  try {
    const result = db
      .prepare('DELETE FROM api_keys WHERE user_id = ? AND provider = ?')
      .run(req.user.userId, req.params.provider);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }

    res.json({ message: 'Key deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete key' });
  }
});

module.exports = router;
