const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Op } = require('sequelize');
const ExpressBrute = require('express-brute');
const { Key, Log, KeyDevice } = require('../models');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';

const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store, {
  freeRetries: 5, minWait: 15*60*1000, maxWait: 15*60*1000,
  failCallback: (req, res, next, nextValidRequestDate) => res.status(429).send('Quá nhiều lần đăng nhập sai. Thử lại sau 15 phút.')
});

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.redirect('/admin/login');
}

router.get('/login', (req, res) => {
  if (req.session && req.session.admin) return res.redirect('/admin/dashboard');
  res.render('admin/login', { error: null });
});

router.post('/login', bruteforce.prevent, async (req, res) => {
  const { email, password } = req.body;
  const valid = email === ADMIN_EMAIL && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
  if (valid) { req.session.admin = { email }; return res.redirect('/admin/dashboard'); }
  res.render('admin/login', { error: 'Sai email hoặc mật khẩu' });
});

router.get('/logout', (req, res) => { req.session = null; res.redirect('/admin/login'); });

router.use(requireAdmin);

// Dashboard
router.get('/dashboard', async (req, res) => {
  const totalKeys = await Key.count();
  const activeKeys = await Key.count({ where: { is_active: true } });
  const expiredKeys = await Key.count({ where: { expires_at: { [Op.lt]: new Date() } } });
  const vipKeys = await Key.count({ where: { tier: 'VIP' } });
  const devicesActivated = await KeyDevice.count({ where: { is_active: true } });
  const recentLogs = await Log.findAll({ limit: 8, order: [['createdAt', 'DESC']], include: Key });
  res.render('admin/dashboard', { user: req.session.admin, totalKeys, activeKeys, expiredKeys, vipKeys, devicesActivated, recentLogs });
});

// Danh sách key
router.get('/keys', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 15;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  let where = {};
  if (search) where = { [Op.or]: [{ key: { [Op.iLike]: `%${search}%` } }] };
  const { count, rows: keys } = await Key.findAndCountAll({
    where, order: [['createdAt', 'DESC']],
    include: [{ model: KeyDevice, as: 'devices', attributes: ['id', 'hwid', 'device_name', 'is_active', 'createdAt'] }],
    limit, offset
  });
  res.render('admin/keys', { user: req.session.admin, keys, currentPage: page, totalPages: Math.ceil(count / limit), search });
});

// Tạo key
router.post('/keys/create', async (req, res) => {
  const { tier, duration, prefix, max_devices } = req.body;
  let maxDev = tier === 'VIP' ? 1 : 9;
  if (max_devices) maxDev = parseInt(max_devices) || maxDev;
  let expires_at;
  if (duration === 'forever') expires_at = new Date('2099-12-31');
  else { const days = parseInt(duration) || 30; expires_at = new Date(); expires_at.setDate(expires_at.getDate() + days); }
  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
  await Key.create({ key, tier, expires_at, max_devices: maxDev, created_by: req.session.admin.email });
  await Log.create({ action: 'key_created', details: `Admin tạo key ${key} max ${maxDev} thiết bị`, ip_address: req.ip });
  res.redirect('/admin/keys?created=1');
});

// Bật/tắt key
router.post('/keys/toggle/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) { key.is_active = !key.is_active; await key.save(); await Log.create({ action: key.is_active ? 'key_unlocked' : 'key_locked', details: `Key ${key.key}`, ip_address: req.ip, key_id: key.id }); }
  res.redirect('/admin/keys');
});

// Khóa/mở khóa từng thiết bị (kick)
router.post('/keys/toggle-device/:deviceId', requireAdmin, async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key, attributes: ['key'] } });
  if (device) {
    device.is_active = !device.is_active;
    await device.save();
    await Log.create({
      action: device.is_active ? 'device_unlocked' : 'device_kicked',
      details: `Thiết bị ${device.hwid}` + (device.device_name ? ` (${device.device_name})` : '') + ` của key ${device.Key.key} đã ${device.is_active ? 'mở khóa' : 'bị khóa'}`,
      ip_address: req.ip, key_id: device.key_id
    });
  }
  res.redirect('/admin/keys');
});

// Xóa vĩnh viễn thiết bị
router.post('/keys/unbind-device/:deviceId', requireAdmin, async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key, attributes: ['key'] } });
  if (device) {
    const keyKey = device.Key.key;
    await device.destroy();
    await Log.create({ action: 'device_deleted', details: `Xóa vĩnh viễn thiết bị ${device.hwid} khỏi key ${keyKey}`, ip_address: req.ip, key_id: device.key_id });
  }
  res.redirect('/admin/keys');
});

// Gỡ tất cả thiết bị (xóa toàn bộ)
router.post('/keys/unbind/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.destroy({ where: { key_id: key.id } });
    await Log.create({ action: 'hwid_unbound_all', details: `Gỡ tất cả thiết bị khỏi key ${key.key}`, ip_address: req.ip, key_id: key.id });
  }
  res.redirect('/admin/keys');
});

// Gia hạn key
router.post('/keys/extend/:id', async (req, res) => {
  const { new_expiry } = req.body;
  const key = await Key.findByPk(req.params.id);
  if (key && new_expiry) { key.expires_at = new Date(new_expiry); await key.save(); await Log.create({ action: 'key_extended', details: `Gia hạn key ${key.key} đến ${new_expiry}`, ip_address: req.ip, key_id: key.id }); }
  res.redirect('/admin/keys');
});

// Xóa key
router.post('/keys/delete/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) { await KeyDevice.destroy({ where: { key_id: key.id } }); await key.destroy(); await Log.create({ action: 'key_deleted', details: `Xoá key ${key.key}`, ip_address: req.ip }); }
  res.redirect('/admin/keys');
});

// API lấy danh sách thiết bị của key (cho modal)
router.get('/keys/devices/:id', requireAdmin, async (req, res) => {
  const key = await Key.findByPk(req.params.id, { include: [{ model: KeyDevice, as: 'devices', attributes: ['id', 'hwid', 'device_name', 'is_active', 'createdAt'] }] });
  if (!key) return res.json({ success: false });
  res.json({ success: true, devices: key.devices });
});

module.exports = router;
