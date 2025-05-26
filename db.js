const Database = require('better-sqlite3');
const fs = require('fs-extra');
const path = require('path');
const logger = require('./utils/logger');

const dataPath = path.join(__dirname, 'data');
const dbPath = path.join(dataPath, 'database.db');

if (!fs.existsSync(dataPath)) {
    fs.mkdirSync(dataPath, { recursive: true });
}

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma(`synchronous = ${process.env.DB_MODE || 'NORMAL'}`);
db.pragma('foreign_keys = ON');
db.pragma('temp_store = MEMORY');

// Users Table
db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin', 'superadmin')),
    ban INTEGER NOT NULL DEFAULT 0,
    ban_reason TEXT DEFAULT NULL,
    two_factor TEXT NOT NULL DEFAULT 'false',
    two_factor_secret TEXT DEFAULT NULL,
    register_data TEXT NOT NULL DEFAULT '{}',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);
db.exec(`CREATE INDEX IF NOT EXISTS users_id_index ON users (id)`);
db.exec(`CREATE INDEX IF NOT EXISTS users_email_index ON users (email)`);

// Sessions Table
db.exec(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    active TEXT NOT NULL DEFAULT 'true',
    ip TEXT DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
)`);
db.exec(`CREATE INDEX IF NOT EXISTS sessions_user_id_index ON sessions (user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS sessions_session_id_index ON sessions (session_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS sessions_active_index ON sessions (active)`);

module.exports = db;