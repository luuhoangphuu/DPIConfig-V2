const express = require('express');
const router = express.Router();
const { Key, Log, KeyDevice } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
router.use(apiLimiter);
router.use(apiAuth);

// Kích hoạt key (có kiểm tra giới hạn thiết bị)
router.post('/activate', async (req, res) => {
  try {
    const { key, hwid } = req.body;
    if (!key || !hwid) {
      return res.status(400).json({ success: false, error: { code: 'MISSING_PARAMETER', message: 'Thiếu key hoặc hwid.' } });
    }

    const keyRecord = await Key.findOne({ where: { key } });
    if (!keyRecord) return res.status(404).json({ success: false, error: { code: 'KEY_NOT_FOUND', message: 'Key không tồn tại.' } });
    if (!keyRecord.is_active) return res.status(403).json({ success: false, error: { code: 'KEY_DISABLED', message: 'Key đã bị admin khóa.' } });
    if (new Date(keyRecord.expires_at) < new Date()) return res.status(410).json({ success: false, error: { code: 'KEY_EXPIRED', message: 'Key đã hết hạn.', expired_at: keyRecord.expires_at } });

    // Kiểm tra giới hạn thiết bị
    const deviceCount = await KeyDevice.count({ where: { key_id: keyRecord.id } });
    if (deviceCount >= keyRecord.max_devices) {
      // Ghi log cảnh báo vượt giới hạn
      await Log.create({
        action: 'activate_blocked_limit',
        details: `Key ${key} đạt giới hạn ${keyRecord.max_devices} thiết bị. HWID ${hwid} bị từ chối.`,
        ip_address: req.ip,
        key_id: keyRecord.id
      });
      return res.status(429).json({ success: false, error: { code: 'DEVICE_LIMIT_REACHED', message: `Key đã đạt giới hạn ${keyRecord.max_devices} thiết bị.` } });
    }

    // Thêm thiết bị nếu chưa có
    const [device, created] = await KeyDevice.findOrCreate({
      where: { key_id: keyRecord.id, hwid },
      defaults: { key_id: keyRecord.id, hwid }
    });

    if (created) {
      await Log.create({
        action: 'activate_success',
        details: `Key ${key} thêm thiết bị ${hwid} (${deviceCount + 1}/${keyRecord.max_devices})`,
        ip_address: req.ip,
        key_id: keyRecord.id
      });
    }

    return res.json({
      success: true,
      data: {
        tier: keyRecord.tier,
        expires_at: keyRecord.expires_at,
        remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
        devices: deviceCount + (created ? 1 : 0),
        max_devices: keyRecord.max_devices
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Lỗi máy chủ nội bộ.' } });
  }
});

// Kiểm tra license (tìm theo HWID trong bảng key_devices)
router.post('/check', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, error: { code: 'MISSING_PARAMETER', message: 'Thiếu tham số hwid.' } });

    // Tìm thiết bị
    const device = await KeyDevice.findOne({ where: { hwid }, include: { model: Key, attributes: ['id', 'tier', 'expires_at', 'is_active'] } });
    if (!device || !device.Key) return res.status(404).json({ success: false, error: { code: 'LICENSE_NOT_FOUND', message: 'Không tìm thấy license cho thiết bị này.' } });

    const keyRecord = device.Key;
    if (!keyRecord.is_active) return res.status(403).json({ success: false, error: { code: 'LICENSE_DISABLED', message: 'License đã bị admin khóa.' } });
    if (new Date(keyRecord.expires_at) < new Date()) return res.status(410).json({ success: false, error: { code: 'LICENSE_EXPIRED', message: 'License đã hết hạn.', expired_at: keyRecord.expires_at } });

    await Log.create({ action: 'check', details: `HWID ${hwid} kiểm tra key ${keyRecord.key}`, ip_address: req.ip, key_id: keyRecord.id });

    return res.json({
      success: true,
      data: {
        tier: keyRecord.tier,
        expires_at: keyRecord.expires_at,
        remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / (1000 * 60 * 60 * 24))
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Lỗi máy chủ nội bộ.' } });
  }
});

module.exports = router;
