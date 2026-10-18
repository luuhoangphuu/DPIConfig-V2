const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Op } = require('sequelize');
const { Key, Log, KeyDevice, AppVersion, Announcement } = require('../models');
const apiAuth = require('../middleware/apiAuth');
const apiLimiter = require('../middleware/rateLimiter');
const genKeyLimiter = require('../middleware/genKeyLimiter');
const publicApiAuth = require('../middleware/publicApiAuth');

// Hàm xóa key hết hạn (chạy mỗi lần có request)
async function cleanupExpiredKeys() {
  try {
    const now = new Date();
    const expiredKeys = await Key.findAll({ where: { expires_at: { [Op.lt]: now } } });
    for (const key of expiredKeys) {
      await KeyDevice.destroy({ where: { key_id: key.id } });
      await Log.destroy({ where: { key_id: key.id } });
      await key.destroy();
      await Log.create({
        action: 'key_expired_deleted',
        details: `Hệ thống tự động xóa key ${key.key} (hết hạn)`,
        ip_address: 'system'
      });
    }
  } catch (err) { console.error('Cleanup error:', err); }
}

// ==================== ROUTE TẠO KEY (GET & POST) ====================
router.get('/gen-key', genKeyLimiter, async (req, res) => {
  console.warn('[GEN-KEY] GET bị chặn, IP:', req.ip);
  return res.status(405).json({
    success: false,
    error: 'Phương thức GET không được hỗ trợ. Vui lòng dùng POST.',
    server_time: new Date().toISOString()
  });
});

router.post('/gen-key', genKeyLimiter, async (req, res) => {
  try {
    const { secret, tier, prefix, max_devices } = req.body;

    if (secret !== process.env.AUTO_KEY_SECRET) {
      console.warn('[GEN-KEY] Secret sai từ IP:', req.ip);
      return res.status(403).json({ success: false, error: 'Secret không hợp lệ.' });
    }

    const chosenTier = (tier && String(tier).toLowerCase() === 'normal') ? 'Normal' : 'VIP';
    const FIXED_HOURS = chosenTier === 'VIP' ? 2 : 8;
    const expires_at = new Date();
    expires_at.setHours(expires_at.getHours() + FIXED_HOURS);

    let maxDev = 1;
    if (max_devices) {
      maxDev = parseInt(max_devices) || 1;
      if (maxDev < 1) maxDev = 1;
      if (maxDev > 999) maxDev = 999;
    }

    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;

    await Key.create({
      key,
      tier: chosenTier,
      expires_at,
      max_devices: maxDev,
      created_by: 'auto-api'
    });

    const ua = (req.headers['user-agent'] || 'unknown').substring(0, 200);
    const referer = (req.headers['referer'] || req.headers['referrer'] || 'direct').substring(0, 200);
    const realIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;

    await Log.create({
      action: 'auto_key_created',
      details: `API tạo key ${key} | tier=${chosenTier} | ${FIXED_HOURS}h | IP=${realIp} | UA=${ua} | Ref=${referer}`,
      ip_address: realIp
    });

    return res.json({
      success: true,
      key,
      tier: chosenTier,
      expires_at: expires_at.toISOString(),
      duration_hours: FIXED_HOURS,
      max_devices: maxDev
    });
  } catch (err) {
    console.error('[GEN-KEY] Error:', err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});

// ==================== CÁC ROUTE CẦN X-API-KEY ====================
// ==================== CHECK APP VERSION (PRO) ====================
router.get('/version', async (req, res) => {
  try {
    // Nhận thêm: hwid (để rollout), channel (stable/beta), current_version
    const { hwid = '', channel = 'stable', current_version = '0' } = req.query;
    const currentCode = parseInt(current_version) || 0;

    const latest = await AppVersion.findOne({
      where: { 
        is_active: true,
        release_channel: channel
      },
      order: [['version_code', 'DESC']]
    });

    if (!latest) {
      return res.json({
        success: true,
        data: { has_update: false, update_enabled: false, server_time: new Date().toISOString() }
      });
    }

    // ===== ROLLOUT CHECK =====
    // Nếu rollout < 100, chỉ % user nhận được
    // Dùng hash của hwid để user luôn cùng nhóm (không random mỗi lần)
    let inRollout = true;
    if (latest.rollout_percentage < 100 && hwid) {
      const hash = hashString(hwid) % 100;
      inRollout = hash < latest.rollout_percentage;
    }

    // ===== GRACE PERIOD CHECK =====
    // Nếu app cũ < min_supported → force ngay
    // Nếu quá required_after → force
    // Ngược lại → chỉ thông báo (soft)
    const isBelowMin = currentCode < latest.min_supported_version;
    const pastRequired = latest.required_after && new Date() > latest.required_after;
    const forceNow = isBelowMin || pastRequired;
    
    // Tính thời gian còn lại trước khi bị force (nếu có required_after)
    let graceHours = null;
    if (latest.required_after && !pastRequired) {
      graceHours = Math.floor((new Date(latest.required_after) - new Date()) / 3600000);
    }

    return res.json({
      success: true,
      data: {
        has_update: latest.version_code > currentCode && inRollout,
        update_enabled: latest.update_enabled,
        force_update: forceNow,
        grace_hours: graceHours,
        
        version_code: latest.version_code,
        version_name: latest.version_name,
        download_url: latest.download_url,
        changelog: latest.changelog || '',
        release_channel: latest.release_channel,
        apk_checksum: latest.apk_checksum,
        apk_size: latest.apk_size,
        
        min_supported_version: latest.min_supported_version,
        required_after: latest.required_after ? latest.required_after.toISOString() : null,
        
        updated_at: latest.updatedAt.toISOString(),
        server_time: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Version check error:', err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});

// Helper: hash chuỗi thành số
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit int
  }
  return Math.abs(hash);
}


// ==================== THÔNG BÁO CHUNG (không cần X-API-Key) ====================
router.get('/announcement', async (req, res) => {
  try {
    const now = new Date();
    const { Op } = require('sequelize');
    const { Announcement } = require('../models');

    // Lấy thông báo ĐANG TRONG THỜI GIAN HIỆU LỰC
    const announcements = await Announcement.findAll({
      where: {
        is_enabled: true,
        [Op.and]: [
          // 1. Chưa có starts_at (hiện ngay) HOẶC đã đến giờ bắt đầu
          { [Op.or]: [
              { starts_at: null }, 
              { starts_at: { [Op.lte]: now } }
          ]},
          // 2. Chưa có expires_at (vĩnh viễn) HOẶC chưa hết hạn
          { [Op.or]: [
              { expires_at: null }, 
              { expires_at: { [Op.gte]: now } }
          ]}
        ]
      },
      order: [['priority', 'DESC'], ['createdAt', 'DESC']],
      limit: 10
    });

    return res.json({
      success: true,
      data: {
        announcements: announcements.map(a => ({
          id: a.id,
          title: a.title,
          message: a.message,
          type: a.type,
          is_dismissible: a.is_dismissible,
          priority: a.priority,
          starts_at: a.starts_at ? a.starts_at.toISOString() : null,
          expires_at: a.expires_at ? a.expires_at.toISOString() : null,
          created_at: a.createdAt.toISOString()
        })),
        server_time: now.toISOString()
      }
    });
  } catch (err) {
    console.error('Announcement error:', err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});


// ==================== THÔNG BÁO CHUNG (không cần X-API-Key) ====================


// ==================== APP BÁO CÁO ĐÃ UPDATE ====================
router.post('/version/report-install', async (req, res) => {
  try {
    const { version_code, hwid } = req.body;
    if (!version_code) return res.status(400).json({ success: false, error: 'Thiếu version_code' });
    
    const version = await AppVersion.findOne({ where: { version_code } });
    if (version) {
      version.install_count = (version.install_count || 0) + 1;
      await version.save();
      
      await Log.create({
        action: 'app_updated',
        details: `Thiết bị ${hwid || 'unknown'} đã cập nhật lên ${version.version_name}`,
        ip_address: req.ip
      });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Lỗi máy chủ' });
  }
});

router.use(apiLimiter);
router.use(apiAuth);

function ok(res, data) { return res.json({ success: true, data: { ...data, server_time: new Date().toISOString() } }); }
function fail(res, status, code, message, extra) {
  return res.status(status).json({ success: false, error: { code, message, ...extra }, server_time: new Date().toISOString() });
}
function calcHours(exp) { const d = new Date(exp) - new Date(); return d <= 0 ? 0 : Math.floor(d / 3600000); }
function calcDays(exp) { return Math.floor(calcHours(exp) / 24); }

// Check
router.post('/check', async (req, res) => {
  try {
    await cleanupExpiredKeys();
    const { hwid } = req.body || {};
    if (!hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu hwid.');
    const device = await KeyDevice.findOne({ where: { hwid, is_active: true }, include: { model: Key } });
    if (!device || !device.Key) return fail(res, 404, 'LICENSE_NOT_FOUND', 'Không tìm thấy license.');
    const k = device.Key;
    if (!k.is_active) return fail(res, 403, 'LICENSE_DISABLED', 'License đã bị admin khóa.');
    if (new Date(k.expires_at) < new Date()) return fail(res, 410, 'LICENSE_EXPIRED', 'License đã hết hạn.', { expired_at: k.expires_at.toISOString() });
    await Log.create({ action: 'check', details: `HWID ${hwid} check key ${k.key}`, ip_address: req.ip, key_id: k.id });
    return ok(res, {
      key: k.key, tier: k.tier, expires_at: k.expires_at.toISOString(),
      remaining_days: calcDays(k.expires_at), remaining_hours: calcHours(k.expires_at)
    });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ.'); }
});

// Activate
router.post('/activate', async (req, res) => {
  try {
    await cleanupExpiredKeys();
    const { key, hwid, device_name } = req.body || {};
    if (!key || !hwid) return fail(res, 400, 'MISSING_PARAMETER', 'Thiếu key hoặc hwid.');
    const k = await Key.findOne({ where: { key } });
    if (!k) return fail(res, 404, 'KEY_NOT_FOUND', 'Key không tồn tại.');
    if (!k.is_active) return fail(res, 403, 'KEY_DISABLED', 'Key đã bị admin khóa.');
    if (new Date(k.expires_at) < new Date()) return fail(res, 410, 'LICENSE_EXPIRED', 'Key đã hết hạn.');
    const total = await KeyDevice.count({ where: { key_id: k.id } });
    const existing = await KeyDevice.findOne({ where: { key_id: k.id, hwid } });
    if (existing) {
      if (!existing.is_active) return fail(res, 403, 'DEVICE_KICKED', 'Thiết bị này đã bị khóa.');
      return ok(res, {
        tier: k.tier, expires_at: k.expires_at.toISOString(),
        remaining_days: calcDays(k.expires_at), remaining_hours: calcHours(k.expires_at),
        devices: total, max_devices: k.max_devices
      });
    }
    if (total >= k.max_devices) {
      await Log.create({ action: 'activate_blocked_limit', details: `Key ${key} đầy`, ip_address: req.ip, key_id: k.id });
      return fail(res, 429, 'DEVICE_LIMIT_REACHED', `Key đã đạt giới hạn ${k.max_devices} TB.`, { max_devices: k.max_devices, current_devices: total });
    }
    await KeyDevice.create({ key_id: k.id, hwid, device_name: device_name || null });
    await Log.create({ action: 'activate_success', details: `Key ${key} gắn ${hwid}`, ip_address: req.ip, key_id: k.id });
    return ok(res, {
      tier: k.tier, expires_at: k.expires_at.toISOString(),
      remaining_days: calcDays(k.expires_at), remaining_hours: calcHours(k.expires_at),
      devices: total + 1, max_devices: k.max_devices
    });
  } catch (e) { console.error(e); return fail(res, 500, 'INTERNAL_ERROR', 'Lỗi máy chủ.'); }
});

module.exports = router;
