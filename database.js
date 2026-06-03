const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const initTables = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS children (
        id TEXT PRIMARY KEY,
        device_name TEXT,
        pairing_code TEXT,
        paired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        screen_time INTEGER DEFAULT 0
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS blocking_rules (
        id SERIAL PRIMARY KEY,
        child_id TEXT REFERENCES children(id) ON DELETE CASCADE,
        day_of_week INTEGER,
        start_hour INTEGER,
        start_minute INTEGER,
        end_hour INTEGER,
        end_minute INTEGER,
        app_package TEXT,
        is_active INTEGER DEFAULT 1
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        child_id TEXT REFERENCES children(id) ON DELETE CASCADE,
        app_name TEXT,
        package_name TEXT,
        title TEXT,
        content TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0,
        type TEXT DEFAULT 'incoming'
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS connection_logs (
        id SERIAL PRIMARY KEY,
        child_id TEXT REFERENCES children(id) ON DELETE CASCADE,
        event_type TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Tables PostgreSQL initialisées');
  } catch (err) {
    console.error('❌ Erreur initialisation tables', err);
  } finally {
    client.release();
  }
};

initTables();

module.exports = { pool, initTables };
