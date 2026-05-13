require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const path = require('path');

const authRouter = require('./auth');
const keysRouter = require('./keys');

const app = express();
const PORT = process.env.PORT || 3000;

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json());

app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));
app.use('/api/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 10 }));

// Serve static files from public/
app.use(express.static(path.join(__dirname, '../public')));

// Auth routes (public)
app.use('/api', authRouter);

// JWT middleware for protected routes
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Protected API key routes
app.use('/api/keys', requireAuth, keysRouter);

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
