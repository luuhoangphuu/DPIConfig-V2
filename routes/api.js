const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Key, Log, KeyDevice } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');

// ==================== ROUTE TẠO KEY (GET) ====================
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
      created_by: 'auto-api-get'
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

// ==================== ROUTE TẠO KEY (POST) ====================
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
      created_by: 'auto-api-post'
    });

    await Log.create({
      action: 'auto_key_created',
      details: `API POST tạo key ${key} (${chosenTier}, ${days} ngày, max ${maxDev} TB)`,
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
  try {
    const { key, hwid, device_name } = req.body;
    if (!key || !hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu key hoặc hwid.');
    const keyRecord = await Key.findOne({ where: { key } });
    if (!keyRecord) return fail(res, 404, 'KEY_NOT_FOUND', 'Key không tồn tại.');
    if (!keyRecord.is_active) return fail(res, 403, 'KEY_DISABLED', 'Key đã bị admin khóa.');
    if (new Date(keyRecord.expires_at) < new Date()) {
      return fail(res, 410, 'LICENSE_EXPIRED', 'License đã hết hạn.', { expired_at: keyRecord.expires_at.toISOString() });
    }
    const totalDevices = await KeyDevice.count({ where: { key_id: keyRecord.id } });
    const existing = await KeyDevice.findOne({ where: { key_id: keyRecord.id, hwid } });
    if (existing) {
      if (!existing.is_active) return fail(res, 403, 'DEVICE_KICKED', 'Thiết bị này đã bị khóa khỏi key.');
      return ok(res, {
        tier: keyRecord.tier,
        expires_at: keyRecord.expires_at.toISOString(),
        remaining_days: calculateRemainingDays(keyRecord.expires_at),
        remaining_hours: calculateRemainingHours(keyRecord.expires_at),
        devices: totalDevices,
        max_devices: keyRecord.max_devices
      });
    }
    if (totalDevices >= keyRecord.max_devices) {
      await Log.create({ action: 'activate_blocked_limit', details: `Key ${key} đầy (${totalDevices}/${keyRecord.max_devices}), HWID ${hwid} bị từ chối`, ip_address: req.ip, key_id: keyRecord.id });
      return fail(res, 429, 'DEVICE_LIMIT_REACHED', `Key đã đạt giới hạn ${keyRecord.max_devices} thiết bị.`, { max_devices: keyRecord.max_devices, current_devices: totalDevices });
    }
    await KeyDevice.create({ key_id: keyRecord.id, hwid, device_name: device_name || null });
    const newCount = totalDevices + 1;
    await Log.create({ action: 'activate_success', details: `Key ${key} thêm thiết bị ${hwid} (${newCount}/${keyRecord.max_devices})`, ip_address: req.ip, key_id: keyRecord.id });
    return ok(res, {
      tier: keyRecord.tier,
      expires_at: keyRecord.expires_at.toISOString(),
      remaining_days: calculateRemainingDays(keyRecord.expires_at),
      remaining_hours: calculateRemainingHours(keyRecord.expires_at),
      devices: newCount,
      max_devices: keyRecord.max_devices
    });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ nội bộ.'); }
});

router.post('/check', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu hwid.');
    const device = await KeyDevice.findOne({ where: { hwid, is_active: true }, include: { model: Key, attributes: ['id', 'key', 'tier', 'expires_at', 'is_active'] } });
    if (!device || !device.Key) return fail(res, 404, 'LICENSE_NOT_FOUND', 'Không tìm thấy license.');
    const keyRecord = device.Key;
    if (!keyRecord.is_active) return fail(res, 403, 'LICENSE_DISABLED', 'License đã bị admin khóa.');
    if (new Date(keyRecord.expires_at) < new Date()) {
      return fail(res, 410, 'LICENSE_EXPIRED', 'License đã hết hạn.', { expired_at: keyRecord.expires_at.toISOString() });
    }
    await Log.create({ action: 'check', details: `HWID ${hwid} kiểm tra key ${keyRecord.key}`, ip_address: req.ip, key_id: keyRecord.id });
    return ok(res, {
      key: keyRecord.key,
      tier: keyRecord.tier,
      expires_at: keyRecord.expires_at.toISOString(),
      remaining_days: calculateRemainingDays(keyRecord.expires_at),
      remaining_hours: calculateRemainingHours(keyRecord.expires_at)
    });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ nội bộ.'); }
});

module.exports = router;
