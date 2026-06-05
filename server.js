require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { pool } = require('./database');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ============ MIDDLEWARE ============
async function authenticateChild(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const childData = auth.verifyChildToken(token);
  if (!childData) return res.status(401).json({ error: 'Token invalide' });

  try {
    const { rows } = await pool.query('SELECT id FROM children WHERE id = $1', [childData.childId]);
    if (rows.length === 0) return res.status(401).json({ error: 'Enfant supprimé' });
    req.childId = childData.childId;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur base de données' });
  }
}

function authenticateAdmin(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!auth.verifyAdminToken(token)) return res.status(401).json({ error: 'Non autorisé' });
  next();
}

// ============ ROUTES PUBLIQUES (aucune route HTML) ============
// Le frontend est hébergé séparément, donc on ne sert plus de fichiers statiques.

// ============ APPAIRAGE ============
app.post('/api/pairing/generate', async (req, res) => {
  const pairingCode = crypto.randomInt(100000, 999999).toString();
  const deviceName = req.body.deviceName || 'Appareil Android';
  const childId = crypto.randomUUID();
  try {
    await pool.query('INSERT INTO children (id, device_name, pairing_code) VALUES ($1, $2, $3)', [childId, deviceName, pairingCode]);
    res.json({ childId, pairingCode, expiresIn: '10 minutes' });
    setTimeout(async () => {
      await pool.query('UPDATE children SET pairing_code = NULL WHERE id = $1 AND pairing_code = $2', [childId, pairingCode]);
    }, 10 * 60 * 1000);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/pairing/validate-child', async (req, res) => {
  const { pairingCode } = req.body;
  try {
    const { rows } = await pool.query('SELECT id, device_name FROM children WHERE pairing_code = $1', [pairingCode]);
    if (rows.length === 0) return res.status(400).json({ error: 'Code invalide ou expiré' });
    const child = rows[0];
    const token = auth.generateChildToken(child.id, child.device_name);
    await pool.query('UPDATE children SET pairing_code = NULL, last_seen = CURRENT_TIMESTAMP WHERE id = $1', [child.id]);
    res.json({ token, childId: child.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN AUTH ============
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (auth.verifyAdminPassword(password)) {
    res.json({ token: auth.generateAdminToken() });
  } else {
    res.status(401).json({ error: 'Mot de passe incorrect' });
  }
});

// ============ ROUTES ENFANT PROTÉGÉES ============
app.post('/api/child/notifications', authenticateChild, async (req, res) => {
  const { notifications } = req.body;
  if (!Array.isArray(notifications)) return res.status(400).json({ error: 'Format invalide' });
  try {
    for (const n of notifications) {
      await pool.query(
        'INSERT INTO notifications (child_id, app_name, package_name, title, content) VALUES ($1, $2, $3, $4, $5)',
        [req.childId, n.appName, n.packageName, n.title, n.content]
      );
    }
    await pool.query('UPDATE children SET last_seen = CURRENT_TIMESTAMP WHERE id = $1', [req.childId]);
    res.json({ success: true, count: notifications.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/child/ping', authenticateChild, async (req, res) => {
  try {
    await pool.query('UPDATE children SET last_seen = CURRENT_TIMESTAMP WHERE id = $1', [req.childId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/child/screen-time', authenticateChild, async (req, res) => {
  const { screenTime } = req.body;
  try {
    await pool.query('UPDATE children SET screen_time = $1 WHERE id = $2', [screenTime, req.childId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/child/rules', authenticateChild, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM blocking_rules WHERE child_id = $1 AND is_active = 1', [req.childId]);
    res.json({ rules: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ROUTES ADMIN PROTÉGÉES ============
app.get('/api/admin/children', authenticateAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, device_name, paired_at, last_seen, is_active, screen_time FROM children ORDER BY paired_at DESC');
    res.json({ children: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/children/:childId/notifications', authenticateAdmin, async (req, res) => {
  const { childId } = req.params;
  try {
    const { rows } = await pool.query('SELECT * FROM notifications WHERE child_id = $1 ORDER BY timestamp DESC LIMIT 100', [childId]);
    res.json({ notifications: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/rules/:childId', authenticateAdmin, async (req, res) => {
  const { childId } = req.params;
  try {
    const { rows } = await pool.query('SELECT * FROM blocking_rules WHERE child_id = $1 ORDER BY day_of_week, start_hour', [childId]);
    res.json({ rules: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/rules', authenticateAdmin, async (req, res) => {
  const { childId, dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO blocking_rules (child_id, day_of_week, start_hour, start_minute, end_hour, end_minute, app_package) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [childId, dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage]
    );
    res.json({ id: rows[0].id, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/rules/:ruleId', authenticateAdmin, async (req, res) => {
  const { ruleId } = req.params;
  const { dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage } = req.body;
  try {
    await pool.query(
      'UPDATE blocking_rules SET day_of_week = $1, start_hour = $2, start_minute = $3, end_hour = $4, end_minute = $5, app_package = $6 WHERE id = $7',
      [dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage, ruleId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/rules/:ruleId', authenticateAdmin, async (req, res) => {
  const { ruleId } = req.params;
  try {
    await pool.query('DELETE FROM blocking_rules WHERE id = $1', [ruleId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/notifications/:notifId/read', authenticateAdmin, async (req, res) => {
  const { notifId } = req.params;
  try {
    await pool.query('UPDATE notifications SET is_read = 1 WHERE id = $1', [notifId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/children/:childId', authenticateAdmin, async (req, res) => {
  const { childId } = req.params;
  try {
    await pool.query('DELETE FROM notifications WHERE child_id = $1', [childId]);
    await pool.query('DELETE FROM blocking_rules WHERE child_id = $1', [childId]);
    await pool.query('DELETE FROM connection_logs WHERE child_id = $1', [childId]);
    await pool.query('DELETE FROM children WHERE id = $1', [childId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ DÉMARRAGE ============
app.listen(PORT, () => {
  console.log(`🚀 API démarrée sur le port ${PORT}`);
});
