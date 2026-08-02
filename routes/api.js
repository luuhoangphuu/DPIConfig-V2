const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Key, Log } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
router.use(apiLimiter);
router.use(apiAuth);

router.post('/activate', async (req, res) => {
  try {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.status(400).json({ success: false, error: 'Thiếu key hoặc hwid' });
    const keyRecord = await Key.findOne({ where: { key, is_active: true } });
    if (!keyRecord) return res.json({ success: false, error: 'Key không hợp lệ' });
    if (new Date(keyRecord.expires_at) < new Date()) return res.json({ success: false, error: 'Key đã hết hạn' });
    if (keyRecord.hwid && keyRecord.hwid !== hwid) return res.json({ success: false, error: 'Key đã được kích hoạt trên máy khác' });
    if (!keyRecord.hwid) {
      keyRecord.hwid = hwid;
      await keyRecord.save();
      await Log.create({ action: 'activate_success', details: `Key ${key} gắn HWID ${hwid}`, ip_address: req.ip, key_id: keyRecord.id });
    }
    res.json({ success: true, tier: keyRecord.tier, expiry: keyRecord.expires_at });
  } catch (e) { res.status(500).json({ success: false, error: 'Lỗi server' }); }
});

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

router.post('/extend', async (req, res) => {
  try {
    const { key, hwid, days, new_expiry } = req.body;
    let keyRecord;
    if (key) keyRecord = await Key.findOne({ where: { key } });
    else if (hwid) keyRecord = await Key.findOne({ where: { hwid } });
    if (!keyRecord) return res.json({ success: false, error: 'Không tìm thấy key' });
    let expiry;
    if (new_expiry) expiry = new Date(new_expiry);
    else if (days) { expiry = new Date(); expiry.setDate(expiry.getDate() + parseInt(days)); }
    else return res.json({ success: false, error: 'Cần days hoặc new_expiry' });
    keyRecord.expires_at = expiry;
    await keyRecord.save();
    await Log.create({ action: 'key_extended_api', details: `Key ${keyRecord.key} gia hạn đến ${expiry}`, ip_address: req.ip, key_id: keyRecord.id });
    res.json({ success: true, key: keyRecord.key, new_expiry: expiry });
  } catch (e) { res.status(500).json({ success: false, error: 'Lỗi server' }); }
});

router.post('/create-key', async (req, res) => {
  try {
    const { tier, duration, prefix } = req.body;
    if (!tier || !duration) return res.json({ success: false, error: 'Thiếu tier hoặc duration' });
    let expires_at;
    if (duration === 'forever') expires_at = new Date('2099-12-31');
    else {
      const days = parseInt(duration);
      if (isNaN(days)) return res.json({ success: false, error: 'Duration không hợp lệ' });
      expires_at = new Date(); expires_at.setDate(expires_at.getDate() + days);
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'DPIC'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    const newKey = await Key.create({ key, tier, expires_at, created_by: 'api' });
    await Log.create({ action: 'key_created_api', details: `API tạo key ${key}`, ip_address: req.ip, key_id: newKey.id });
    res.json({ success: true, key: newKey.key, tier: newKey.tier, expires_at: newKey.expires_at });
  } catch (e) { res.status(500).json({ success: false, error: 'Lỗi server' }); }
});

module.exports = router;
