const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);

// Générer un token pour un enfant
function generateChildToken(childId, deviceName) {
  return jwt.sign(
    { childId, deviceName, type: 'child' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// Générer un token admin (parent)
function generateAdminToken() {
  return jwt.sign(
    { type: 'admin' },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Vérifier token admin
function verifyAdminToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.type === 'admin';
  } catch (error) {
    return false;
  }
}

// Vérifier token enfant
function verifyChildToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.type === 'child' ? decoded : null;
  } catch (error) {
    return null;
  }
}

// Vérifier mot de passe admin
function verifyAdminPassword(password) {
  return bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
}

module.exports = {
  generateChildToken,
  generateAdminToken,
  verifyAdminToken,
  verifyChildToken,
  verifyAdminPassword
};