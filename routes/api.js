const express = require('express');
const router = express.Router();
const { Key, Log } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
router.use(apiLimiter);
router.use(apiAuth);

// API duy nhất: kiểm tra trạng thái key theo HWID
router.post('/check', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, error: 'Thiếu hwid' });
    const keyRecord = await Key.findOne({ where: { hwid, is_active: true } });
    if (!keyRecord) return res.json({ success: false, error: 'Không tìm thấy license' });
    if (new Date(keyRecord.expires_at) < new Date()) return res.json({ success: false, error: 'License hết hạn' });
    await Log.create({ action: 'check', details: `HWID ${hwid} kiểm tra`, ip_address: req.ip, key_id: keyRecord.id });
    res.json({ success: true, tier: keyRecord.tier, expiry: keyRecord.expires_at });
  } catch (e) { res.status(500).json({ success: false, error: 'Lỗi server' }); }
});

// KHÔNG còn các route /activate, /extend, /create-key
// Chỉ admin web mới có thể tạo key, gán HWID, gia hạn qua giao diện

module.exports = router;
