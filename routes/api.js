const express = require('express');
const router = express.Router();
const { Key, Log, KeyDevice } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
router.use(apiLimiter);
router.use(apiAuth);

function ok(res, data) { return res.json({ success: true, data }); }
function fail(res, status, code, message, extra) { return res.status(status).json({ success: false, error: { code, message, ...extra } }); }

router.post('/activate', async (req, res) => {
  try {
    const { key, hwid, device_name } = req.body;
    if (!key || !hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu key hoặc hwid.');

    const keyRecord = await Key.findOne({ where: { key } });
    if (!keyRecord) return fail(res, 404, 'KEY_NOT_FOUND', 'Key không tồn tại.');
    if (!keyRecord.is_active) return fail(res, 403, 'KEY_DISABLED', 'Key đã bị admin khóa.');
    if (new Date(keyRecord.expires_at) < new Date()) return fail(res, 410, 'KEY_EXPIRED', 'Key đã hết hạn.', { expired_at: keyRecord.expires_at });

    const totalDevices = await KeyDevice.count({ where: { key_id: keyRecord.id } });
    const existing = await KeyDevice.findOne({ where: { key_id: keyRecord.id, hwid } });

    if (existing) {
      if (!existing.is_active) return fail(res, 403, 'DEVICE_KICKED', 'Thiết bị này đã bị khóa khỏi key. Liên hệ admin.');
      return ok(res, { tier: keyRecord.tier, expires_at: keyRecord.expires_at, remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / 86400000), devices: totalDevices, max_devices: keyRecord.max_devices });
    }

    if (totalDevices >= keyRecord.max_devices) {
      await Log.create({ action: 'activate_blocked_limit', details: `Key ${key} đầy (${totalDevices}/${keyRecord.max_devices}), HWID ${hwid} bị từ chối`, ip_address: req.ip, key_id: keyRecord.id });
      return fail(res, 429, 'DEVICE_LIMIT_REACHED', `Key đã đạt giới hạn ${keyRecord.max_devices} thiết bị. Liên hệ admin để mua key mới.`, { max_devices: keyRecord.max_devices, current_devices: totalDevices });
    }

    await KeyDevice.create({ key_id: keyRecord.id, hwid, device_name: device_name || null });
    const newCount = totalDevices + 1;
    await Log.create({ action: 'activate_success', details: `Key ${key} thêm thiết bị ${hwid} (${newCount}/${keyRecord.max_devices})`, ip_address: req.ip, key_id: keyRecord.id });
    return ok(res, { tier: keyRecord.tier, expires_at: keyRecord.expires_at, remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / 86400000), devices: newCount, max_devices: keyRecord.max_devices });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ nội bộ.'); }
});

router.post('/check', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu hwid.');

    const device = await KeyDevice.findOne({ where: { hwid, is_active: true }, include: { model: Key, attributes: ['id', 'key', 'tier', 'expires_at', 'is_active'] } });
    if (!device || !device.Key) return fail(res, 404, 'LICENSE_NOT_FOUND', 'Không tìm thấy license cho thiết bị này.');

    const keyRecord = device.Key;
    if (!keyRecord.is_active) return fail(res, 403, 'LICENSE_DISABLED', 'License đã bị admin khóa.');
    if (new Date(keyRecord.expires_at) < new Date()) return fail(res, 410, 'LICENSE_EXPIRED', 'License đã hết hạn.', { expired_at: keyRecord.expires_at });

    await Log.create({ action: 'check', details: `HWID ${hwid} kiểm tra key ${keyRecord.key}`, ip_address: req.ip, key_id: keyRecord.id });
    return ok(res, { key: keyRecord.key, tier: keyRecord.tier, expires_at: keyRecord.expires_at, remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / 86400000) });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ nội bộ.'); }
});

module.exports = router;
