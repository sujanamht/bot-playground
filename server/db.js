const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'store.db');

async function saveDb(db) {
  await fs.promises.writeFile(DB_PATH, Buffer.from(db.export()));
}

const dbReady = (async () => {
  const SQL = await initSqlJs();
  const db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Migration: add email column to existing databases
  try { db.run('ALTER TABLE users ADD COLUMN email TEXT UNIQUE'); } catch (_) { /* already exists */ }

  db.run(`CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, provider)
  )`);

  await saveDb(db);
  return db;
})();

module.exports = { dbReady, saveDb };
