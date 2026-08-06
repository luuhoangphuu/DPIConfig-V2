const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Key, Log, KeyDevice } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');

// ==================== ROUTE BÍ MẬT TẠO KEY ====================
router.post('/gen-key', async (req, res) => {
  try {
    const { secret, tier, duration, prefix, max_devices } = req.body;
    if (secret !== process.env.AUTO_KEY_SECRET) {
      return res.status(403).json({ success: false, error: 'Secret không hợp lệ.' });
    }
    const chosenTier = (tier && tier.toLowerCase() === 'normal') ? 'Normal' : 'VIP';
    let days = parseInt(duration) || 1;
    if (days <= 0) days = 1;
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + days);
    let maxDev = chosenTier === 'VIP' ? 1 : 9;
    if (max_devices) {
      maxDev = parseInt(max_devices) || maxDev;
      if (maxDev < 1) maxDev = 1;
      if (maxDev > 999) maxDev = 999;
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    const newKey = await Key.create({
      key,
      tier: chosenTier,
      expires_at,
      max_devices: maxDev,
      created_by: 'auto-api'
    });
    await Log.create({
      action: 'auto_key_created',
      details: `API tạo key ${key} (${chosenTier}, ${days} ngày, max ${maxDev} TB)`,
      ip_address: req.ip
    });
    return res.json({
      success: true,
      key: key,
      tier: chosenTier,
      expires_at: expires_at.toISOString(),
      max_devices: maxDev
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});

router.get('/gen-key', async (req, res) => {
  try {
    const { secret, tier, duration, prefix, max_devices } = req.query;
    if (secret !== process.env.AUTO_KEY_SECRET) {
      return res.status(403).json({ success: false, error: 'Secret không hợp lệ.' });
    }
    const chosenTier = (tier && tier.toLowerCase() === 'normal') ? 'Normal' : 'VIP';
    let days = parseInt(duration) || 1;
    if (days <= 0) days = 1;
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + days);
    let maxDev = chosenTier === 'VIP' ? 1 : 9;
    if (max_devices) {
      maxDev = parseInt(max_devices) || maxDev;
      if (maxDev < 1) maxDev = 1;
      if (maxDev > 999) maxDev = 999;
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    const newKey = await Key.create({
      key,
      tier: chosenTier,
      expires_at,
      max_devices: maxDev,
      created_by: 'auto-api'
    });
    await Log.create({
      action: 'auto_key_created',
      details: `API GET tạo key ${key} (${chosenTier}, ${days} ngày, max ${maxDev} TB)`,
      ip_address: req.ip
    });
    return res.json({
      success: true,
      key: key,
      tier: chosenTier,
      expires_at: expires_at.toISOString(),
      max_devices: maxDev
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});

// ==================== CÁC ROUTE CHÍNH (cần X-API-Key) ====================
router.use(apiLimiter);
router.use(apiAuth);

function ok(res, data) {
  return res.json({ success: true, data: { ...data, server_time: new Date().toISOString() } });
}
function fail(res, status, code, message, extra) {
  return res.status(status).json({
    success: false,
    error: { code, message, ...extra },
    server_time: new Date().toISOString()
  });
}
function calculateRemainingHours(expiry) {
  const diff = new Date(expiry) - new Date();
  return diff <= 0 ? 0 : Math.floor(diff / 3600000);
}
function calculateRemainingDays(expiry) {
  return Math.floor(calculateRemainingHours(expiry) / 24);
}

router.post('/activate', async (req, res) => {
  // ... (giữ nguyên code activate cũ)
});
router.post('/check', async (req, res) => {
  // ... (giữ nguyên code check cũ)
});

module.exports = router;
