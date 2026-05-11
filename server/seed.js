require('dotenv').config({ path: __dirname + '/.env' });

const bcrypt = require('bcrypt');
const { dbReady, saveDb } = require('./db');

(async () => {
  const db = await dbReady;
  const hash = await bcrypt.hash('admin', 12);
  db.run(
    `INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)`,
    ['admin', hash]
  );
  saveDb(db);
  console.log('done');
})();
