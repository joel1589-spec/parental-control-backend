const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, 'parental.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS children (
    id TEXT PRIMARY KEY,
    device_name TEXT,
    pairing_code TEXT,
    paired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    is_active INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS blocking_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_id TEXT,
    day_of_week INTEGER,
    start_hour INTEGER,
    start_minute INTEGER,
    end_hour INTEGER,
    end_minute INTEGER,
    app_package TEXT,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(child_id) REFERENCES children(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_id TEXT,
    app_name TEXT,
    package_name TEXT,
    title TEXT,
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0,
    FOREIGN KEY(child_id) REFERENCES children(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_id TEXT,
    event_type TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

module.exports = db;
