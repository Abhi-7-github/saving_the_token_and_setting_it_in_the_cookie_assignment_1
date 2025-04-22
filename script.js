const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const jwtSecret = 'your_jwt_secret';
const encryptionKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

const encrypt = (payload) => {
  const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
};

const decrypt = (token) => {
  const [ivHex, encryptedData] = token.split(':');
  const ivBuffer = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return jwt.verify(decrypted, jwtSecret);
};

module.exports = {
  encrypt,
  decrypt
};
