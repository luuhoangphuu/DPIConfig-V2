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

// Tạo key tự động (bot)
router.get('/getnewkey', async (req, res) => {
  const { secret, tier, duration } = req.query;
  if (secret !== AUTO_KEY_SECRET) return res.status(403).json({ success: false, error: 'Secret không hợp lệ.' });
  try {
    const chosenTier = (tier === 'Normal') ? 'Normal' : 'VIP';
    let days = parseInt(duration) || 30;
    const expires_at = new Date(); expires_at.setDate(expires_at.getDate() + days);
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `HoangPhu-${randomPart.match(/.{1,4}/g).join('-')}`;
    const newKey = await Key.create({ key, tier: chosenTier, expires_at, max_devices: chosenTier==='VIP'?1:9, created_by: 'auto-bot' });
    await Log.create({ action: 'auto_key_created', details: `Bot tự động tạo key ${key}`, ip_address: req.ip });
    res.json({ success: true, key, tier: chosenTier, expires_at });
  } catch (err) { res.status(500).json({ success: false, error: 'Lỗi máy chủ.' }); }
});

module.exports = router;
