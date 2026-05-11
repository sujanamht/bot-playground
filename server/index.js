require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');

const authRouter = require('./auth');
const keysRouter = require('./keys');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: ['http://localhost:3000', 'http://127.0.0.1:3000'] }));
app.use(express.json());

// Serve static HTML files from the project root
app.use(express.static(path.join(__dirname, '..')));

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
