require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const db = require('./database');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Middleware
function authenticateChild(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const childData = auth.verifyChildToken(token);
  if (!childData) return res.status(401).json({ error: 'Token invalide' });
  db.get('SELECT id FROM children WHERE id = ?', [childData.childId], (err, child) => {
    if (err || !child) return res.status(401).json({ error: 'Enfant supprimé' });
    req.childId = childData.childId;
    next();
  });
}

function authenticateAdmin(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!auth.verifyAdminToken(token)) return res.status(401).json({ error: 'Non autorisé' });
  next();
}

// Routes publiques
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));
app.get('/parent', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

// Générer code parent
app.post('/api/pairing/generate', (req, res) => {
  const pairingCode = crypto.randomInt(100000, 999999).toString();
  const deviceName = req.body.deviceName || 'Appareil Android';
  const childId = crypto.randomUUID();
  db.run('INSERT INTO children (id, device_name, pairing_code) VALUES (?, ?, ?)',
    [childId, deviceName, pairingCode], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ childId, pairingCode, expiresIn: '10 minutes' });
      setTimeout(() => {
        db.run('UPDATE children SET pairing_code = NULL WHERE id = ? AND pairing_code = ?', [childId, pairingCode]);
      }, 10 * 60 * 1000);
    });
});

// Validation enfant
app.post('/api/pairing/validate-child', (req, res) => {
  const { pairingCode } = req.body;
  db.get('SELECT id, device_name FROM children WHERE pairing_code = ?', [pairingCode], (err, child) => {
    if (err || !child) return res.status(400).json({ error: 'Code invalide ou expiré' });
    const token = auth.generateChildToken(child.id, child.device_name);
    db.run('UPDATE children SET pairing_code = NULL, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [child.id]);
    res.json({ token, childId: child.id });
  });
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (auth.verifyAdminPassword(password)) {
    res.json({ token: auth.generateAdminToken() });
  } else {
    res.status(401).json({ error: 'Mot de passe incorrect' });
  }
});

// Routes enfant protégées
app.post('/api/child/notifications', authenticateChild, (req, res) => {
  const { notifications } = req.body;
  if (!Array.isArray(notifications)) return res.status(400).json({ error: 'Format invalide' });
  const stmt = db.prepare(`INSERT INTO notifications (child_id, app_name, package_name, title, content) VALUES (?, ?, ?, ?, ?)`);
  notifications.forEach(n => stmt.run([req.childId, n.appName, n.packageName, n.title, n.content]));
  stmt.finalize();
  db.run('UPDATE children SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [req.childId]);
  res.json({ success: true, count: notifications.length });
});

app.post('/api/child/ping', authenticateChild, (req, res) => {
  db.run('UPDATE children SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [req.childId]);
  res.json({ success: true });
});

app.post('/api/child/screen-time', authenticateChild, (req, res) => {
  const { screenTime } = req.body;
  db.run('UPDATE children SET screen_time = ? WHERE id = ?', [screenTime, req.childId]);
  res.json({ success: true });
});

app.get('/api/child/rules', authenticateChild, (req, res) => {
  db.all(
    'SELECT * FROM blocking_rules WHERE child_id = ? AND is_active = 1',
    [req.childId],
    (err, rules) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ rules });
    }
  );
});

// Routes admin
app.get('/api/admin/children', authenticateAdmin, (req, res) => {
  db.all('SELECT id, device_name, paired_at, last_seen, is_active, screen_time FROM children ORDER BY paired_at DESC', (err, children) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ children });
  });
});

app.get('/api/admin/children/:childId/notifications', authenticateAdmin, (req, res) => {
  const { childId } = req.params;
  db.all('SELECT * FROM notifications WHERE child_id = ? ORDER BY timestamp DESC LIMIT 100', [childId], (err, notifications) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ notifications });
  });
});

app.get('/api/admin/rules/:childId', authenticateAdmin, (req, res) => {
  const { childId } = req.params;
  db.all('SELECT * FROM blocking_rules WHERE child_id = ? ORDER BY day_of_week, start_hour', [childId], (err, rules) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ rules });
  });
});

app.post('/api/admin/rules', authenticateAdmin, (req, res) => {
  const { childId, dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage } = req.body;
  db.run(`INSERT INTO blocking_rules (child_id, day_of_week, start_hour, start_minute, end_hour, end_minute, app_package)
          VALUES (?, ?, ?, ?, ?, ?, ?)`, [childId, dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, success: true });
  });
});

app.put('/api/admin/rules/:ruleId', authenticateAdmin, (req, res) => {
  const { ruleId } = req.params;
  const { dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage } = req.body;
  db.run(
    `UPDATE blocking_rules SET day_of_week = ?, start_hour = ?, start_minute = ?, end_hour = ?, end_minute = ?, app_package = ? WHERE id = ?`,
    [dayOfWeek, startHour, startMinute, endHour, endMinute, appPackage, ruleId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.delete('/api/admin/rules/:ruleId', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM blocking_rules WHERE id = ?', [req.params.ruleId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

app.put('/api/admin/notifications/:notifId/read', authenticateAdmin, (req, res) => {
  db.run('UPDATE notifications SET is_read = 1 WHERE id = ?', [req.params.notifId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/api/admin/children/:childId', authenticateAdmin, (req, res) => {
  const { childId } = req.params;
  db.serialize(() => {
    db.run('DELETE FROM notifications WHERE child_id = ?', [childId]);
    db.run('DELETE FROM blocking_rules WHERE child_id = ?', [childId]);
    db.run('DELETE FROM connection_logs WHERE child_id = ?', [childId]);
    db.run('DELETE FROM children WHERE id = ?', [childId], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Serveur sur http://localhost:${PORT}`);
});
