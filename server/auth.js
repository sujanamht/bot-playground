const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { dbReady, saveDb } = require('./db');

const router = express.Router();
const SALT_ROUNDS = 12;

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const db = await dbReady;
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password_hash]);
    saveDb(db);

    const idRes = db.exec('SELECT last_insert_rowid()');
    const userId = idRes[0].values[0][0];

    const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const db = await dbReady;
    const stmt = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
    stmt.bind([username]);
    const user = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
