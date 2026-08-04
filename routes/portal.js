const express = require('express');
const router = express.Router();
const { Key, KeyDevice } = require('../models');

// Trang tra cứu (nhập HWID)
router.get('/', (req, res) => {
  res.render('portal/index', { result: null, error: null });
});

// Xử lý tra cứu
router.post('/lookup', async (req, res) => {
  const { hwid } = req.body;
  if (!hwid) return res.render('portal/index', { result: null, error: 'Vui lòng nhập HWID.' });

  try {
    const device = await KeyDevice.findOne({
      where: { hwid, is_active: true },
      include: { model: Key, attributes: ['id', 'key', 'tier', 'expires_at', 'is_active', 'max_devices'] }
    });

    if (!device || !device.Key) {
      return res.render('portal/index', { result: null, error: 'Không tìm thấy key cho thiết bị này.' });
    }

    const key = device.Key;
    const activeDevices = await KeyDevice.count({ where: { key_id: key.id, is_active: true } });
    const totalDevices = await KeyDevice.count({ where: { key_id: key.id } });
    const remainingDays = Math.ceil((new Date(key.expires_at) - new Date()) / (1000 * 60 * 60 * 24));

    const result = {
      key: key.key,
      tier: key.tier,
      expires_at: key.expires_at,
      is_active: key.is_active,
      max_devices: key.max_devices,
      active_devices: activeDevices,
      total_devices: totalDevices,
      remaining_days: remainingDays
    };

    res.render('portal/index', { result, error: null });
  } catch (err) {
    console.error(err);
    res.render('portal/index', { result: null, error: 'Lỗi máy chủ, thử lại sau.' });
  }
});

module.exports = router;
