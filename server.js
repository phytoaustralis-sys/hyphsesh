// Node.js backend with optional encryption-at-rest
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const sodium = require('libsodium-wrappers');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });
let messages = [];
let publicKeys = {};
const settings = { encryptionAtRest: true, p2pDiscovery: false };
const encryptionKey = crypto.randomBytes(32);
const ENCRYPTED_DIR = 'uploads_encrypted';
if (!fs.existsSync(ENCRYPTED_DIR)) fs.mkdirSync(ENCRYPTED_DIR);

(async () => {
  await sodium.ready;

  app.post('/register-key', (req, res) => {
    const { userId, publicKey } = req.body;
    publicKeys[userId] = publicKey;
    res.json({ status: 'ok' });
  });

  app.post('/send', (req, res) => {
    const { to, from, box, nonce } = req.body;
    if (!publicKeys[to]) return res.status(404).json({ error: 'Recipient not found' });
    messages.push({ to, from, box, nonce });
    res.json({ status: 'message stored' });
  });

  app.get('/inbox/:userId', (req, res) => {
    const userId = req.params.userId;
    const userMessages = messages.filter(m => m.to === userId);
    messages = messages.filter(m => m.to !== userId);
    res.json(userMessages);
  });

  app.post('/upload', upload.single('file'), (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).send('No file');
    if (!settings.encryptionAtRest) return res.json({ filename: file.filename, originalName: file.originalname });

    const input = fs.readFileSync(file.path);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const output = Buffer.concat([iv, authTag, encrypted]);
    const encryptedPath = `${ENCRYPTED_DIR}/${file.filename}.enc`;
    fs.writeFileSync(encryptedPath, output);
    fs.unlinkSync(file.path);

    res.json({ filename: `${file.filename}.enc`, originalName: file.originalname });
  });

  app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const encryptedPath = `${ENCRYPTED_DIR}/${filename}`;
    const plaintextPath = `uploads/${filename.replace('.enc', '')}`;

    if (!settings.encryptionAtRest) {
      if (fs.existsSync(plaintextPath)) return res.download(plaintextPath);
      else return res.status(404).send('File not found');
    }

    if (!fs.existsSync(encryptedPath)) return res.status(404).send('Encrypted file not found');
    const data = fs.readFileSync(encryptedPath);
    const iv = data.slice(0, 16);
    const authTag = data.slice(16, 32);
    const encrypted = data.slice(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(authTag);
    try {
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      res.set('Content-Disposition', `attachment; filename="${filename.replace('.enc', '')}"`);
      res.send(decrypted);
    } catch (e) {
      res.status(500).send('Decryption failed');
    }
  });

  app.get('/settings', (req, res) => res.json(settings));
  app.post('/toggle-setting', (req, res) => {
    const { key } = req.body;
    if (key in settings) settings[key] = !settings[key];
    res.json(settings);
  });

  const PORT = 3001;
  app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
})();
