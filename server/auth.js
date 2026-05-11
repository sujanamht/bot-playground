const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { dbReady, saveDb } = require('./db');

const router = express.Router();
const SALT_ROUNDS = 12;

router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  try {
    const db = await dbReady;
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, password_hash]);
    saveDb(db);

    const idRes = db.exec('SELECT last_insert_rowid()');
    const userId = idRes[0].values[0][0];

    const token = jwt.sign({ userId, username, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('pg_token', token, { httpOnly: true, sameSite: 'Strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ username });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed: users.username')) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    if (err.message.includes('UNIQUE constraint failed: users.email')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) {
    return res.status(400).json({ error: 'Login and password are required' });
  }

  try {
    const db = await dbReady;
    const stmt = db.prepare('SELECT id, username, email, password_hash FROM users WHERE email = ? OR username = ?');
    stmt.bind([login, login]);
    const user = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('pg_token', token, { httpOnly: true, sameSite: 'Strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ username: user.username });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
