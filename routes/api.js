const express = require('express');
const router = express.Router();
const { Key, Log, KeyDevice } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
router.use(apiLimiter);
router.use(apiAuth);

// Kích hoạt key
router.post('/activate', async (req, res) => {
  try {
    const { key, hwid, device_name } = req.body;
    if (!key || !hwid) {
      return res.status(400).json({ success: false, error: { code: 'MISSING_PARAMETER', message: 'Thiếu key hoặc hwid.' } });
    }

    const keyRecord = await Key.findOne({ where: { key } });
    if (!keyRecord) return res.status(404).json({ success: false, error: { code: 'KEY_NOT_FOUND', message: 'Key không tồn tại.' } });
    if (!keyRecord.is_active) return res.status(403).json({ success: false, error: { code: 'KEY_DISABLED', message: 'Key đã bị admin khóa.' } });
    if (new Date(keyRecord.expires_at) < new Date()) return res.status(410).json({ success: false, error: { code: 'KEY_EXPIRED', message: 'Key đã hết hạn.', expired_at: keyRecord.expires_at } });

    // Đếm tổng số thiết bị (active + inactive) để kiểm tra giới hạn
    const totalDevices = await KeyDevice.count({ where: { key_id: keyRecord.id } });

    // Kiểm tra xem HWID này đã có trong key chưa (bất kể trạng thái)
    const existingDevice = await KeyDevice.findOne({ where: { key_id: keyRecord.id, hwid } });

    if (existingDevice) {
      if (existingDevice.is_active) {
        // Đã active rồi thì trả về thành công luôn
        return res.json({
          success: true,
          data: {
            tier: keyRecord.tier,
            expires_at: keyRecord.expires_at,
            remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
            devices: totalDevices,
            max_devices: keyRecord.max_devices
          }
        });
      } else {
        // Thiết bị đã bị khóa (kick) -> không cho tái kích hoạt
        return res.status(403).json({
          success: false,
          error: { code: 'DEVICE_KICKED', message: 'Thiết bị này đã bị khóa khỏi key. Vui lòng liên hệ admin.' }
        });
      }
    }

    // Nếu tổng thiết bị đã đạt giới hạn
    if (totalDevices >= keyRecord.max_devices) {
      await Log.create({
        action: 'activate_blocked_limit',
        details: `Key ${key} đạt giới hạn ${keyRecord.max_devices} thiết bị. HWID ${hwid} bị từ chối.`,
        ip_address: req.ip,
        key_id: keyRecord.id
      });
      return res.status(429).json({
        success: false,
        error: { code: 'DEVICE_LIMIT_REACHED', message: `Key đã đạt giới hạn ${keyRecord.max_devices} thiết bị.` }
      });
    }

    // Thêm thiết bị mới (mặc định is_active = true)
    await KeyDevice.create({ key_id: keyRecord.id, hwid, device_name: device_name || null });
    const newTotal = totalDevices + 1;

    await Log.create({
      action: 'activate_success',
      details: `Key ${key} thêm thiết bị ${hwid}` + (device_name ? ` (${device_name})` : '') + ` (${newTotal}/${keyRecord.max_devices})`,
      ip_address: req.ip,
      key_id: keyRecord.id
    });

    return res.json({
      success: true,
      data: {
        tier: keyRecord.tier,
        expires_at: keyRecord.expires_at,
        remaining_days: Math.ceil((new Date(keyRecord.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
        devices: newTotal,
        max_devices: keyRecord.max_devices
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Lỗi máy chủ nội bộ.' } });
  }
});

// Kiểm tra license (trả về chi tiết)
router.post('/check', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) {
      return res.status(400).json({ success: false, error: { code: 'MISSING_PARAMETER', message: 'Thiếu tham số hwid.' } });
    }

    // Tìm thiết bị ACTIVE (chỉ thiết bị đang hoạt động mới được check)
    const device = await KeyDevice.findOne({
      where: { hwid, is_active: true },
      include: { model: Key, attributes: ['id', 'key', 'tier', 'expires_at', 'is_active', 'max_devices'] }
    });

    if (!device || !device.Key) {
      return res.status(404).json({
        success: false,
        error: { code: 'LICENSE_NOT_FOUND', message: 'Không tìm thấy license cho thiết bị này.' }
      });
    }

    const keyRecord = device.Key;

    // Kiểm tra trạng thái key
    if (!keyRecord.is_active) {
      return res.status(403).json({
        success: false,
        error: { code: 'LICENSE_DISABLED', message: 'License đã bị admin khóa.' }
      });
    }

    if (new Date(keyRecord.expires_at) < new Date()) {
      return res.status(410).json({
        success: false,
        error: { code: 'LICENSE_EXPIRED', message: 'License đã hết hạn.', expired_at: keyRecord.expires_at }
      });
    }

    // Ghi log kiểm tra
    await Log.create({
      action: 'check',
      details: `HWID ${hwid} kiểm tra key ${keyRecord.key}`,
      ip_address: req.ip,
      key_id: keyRecord.id
    });

    // Tính thời gian còn lại
    const remainingDays = Math.ceil((new Date(keyRecord.expires_at) - new Date()) / (1000 * 60 * 60 * 24));

    return res.json({
      success: true,
      data: {
        key: keyRecord.key,               // key đang dùng
        tier: keyRecord.tier,             // VIP / Normal
        is_active: keyRecord.is_active,   // true
        expires_at: keyRecord.expires_at, // ngày hết hạn
        remaining_days: remainingDays,    // số ngày còn lại
        max_devices: keyRecord.max_devices // giới hạn thiết bị của key
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Lỗi máy chủ nội bộ.' } });
  }
});

module.exports = router;
