const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Key, KeyDevice, Log, KeyToken } = require('../models');

const AUTO_KEY_SECRET = process.env.AUTO_KEY_SECRET || 'default-secret-change-me';

// Trang claim (đếm ngược + quảng cáo)
router.get('/claim/:token', async (req, res) => {
  const { token } = req.params;
  if (!token) return res.status(400).send('Thiếu token.');
  const keyToken = await KeyToken.findOne({ where: { token } });
  if (!keyToken) return res.status(404).send('Token không tồn tại.');
  if (keyToken.used) return res.status(410).send('Token đã được sử dụng.');
  res.render('portal/claim', { token });
});

// Trang hiển thị key (sau khi claim)
router.get('/getkey', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ success: false, error: 'Thiếu token.' });
  try {
    const keyToken = await KeyToken.findOne({ where: { token } });
    if (!keyToken) return res.status(404).json({ success: false, error: 'Token không tồn tại.' });
    if (keyToken.used) return res.status(410).json({ success: false, error: 'Token đã được sử dụng.' });
    keyToken.used = true;
    await keyToken.save();
    res.render('portal/getkey', { key: keyToken.key });
  } catch (err) { console.error(err); res.status(500).json({ success: false, error: 'Lỗi máy chủ.' }); }
});

module.exports = router;
