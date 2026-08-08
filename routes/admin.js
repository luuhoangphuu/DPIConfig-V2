const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Op } = require('sequelize');
const ExpressBrute = require('express-brute');
const { Key, Log, KeyDevice } = require('../models');
const {
  notifyKeyCreated, notifyKeyToggled, notifyKeyDeleted,
  notifyKickAll, notifyDeleteAllDevices,
  notifyDeviceToggled, notifyDeviceDeleted
} = require('../utils/email');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';

const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store, {
  freeRetries: 5, minWait: 15*60*1000, maxWait: 15*60*1000,
  failCallback: (req, res, next, nextValidRequestDate) => res.status(429).send('Quá nhiều lần đăng nhập sai.')
});

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.redirect('/admin/login');
}

// AUTH
router.get('/login', (req, res) => {
  if (req.session && req.session.admin) return res.redirect('/admin/dashboard');
  res.render('admin/login', { error: null });
});

router.post('/login', bruteforce.prevent, async (req, res) => {
  const { email, password } = req.body;
  if (email === ADMIN_EMAIL && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    req.session.admin = { email };
    return res.redirect('/admin/dashboard');
  }
  res.render('admin/login', { error: 'Sai email hoặc mật khẩu' });
});

router.get('/logout', (req, res) => { req.session = null; res.redirect('/admin/login'); });
router.use(requireAdmin);

// DASHBOARD
router.get('/dashboard', async (req, res) => {
  const totalKeys = await Key.count();
  const activeKeys = await Key.count({ where: { is_active: true } });
  const expiredKeys = await Key.count({ where: { expires_at: { [Op.lt]: new Date() } } });
  const vipKeys = await Key.count({ where: { tier: 'VIP' } });
  const devicesActivated = await KeyDevice.count({ where: { is_active: true } });
  const recentLogs = await Log.findAll({ limit: 8, order: [['createdAt', 'DESC']], where: { action: { [Op.ne]: 'check' } }, include: Key }]'createdAt', 'DESC']], include: Key });
  res.render('admin/dashboard', { user: req.session.admin, totalKeys, activeKeys, expiredKeys, vipKeys, devicesActivated, recentLogs });
});

// KEY MANAGEMENT
router.get('/keys', async (req, res) => {
  const page = parseInt(req.query.page) || 1, limit = 15, offset = (page-1)*limit;
  const search = req.query.search || '';
  let where = {};
  if (search) where = { [Op.or]: [{ key: { [Op.iLike]: `%${search}%` } }] };
  const { count, rows: keys } = await Key.findAndCountAll({
    where, order: [['createdAt', 'DESC']],
    include: [{ model: KeyDevice, as: 'devices', required: false }],
    limit, offset
  });
  res.render('admin/keys', { user: req.session.admin, keys, currentPage: page, totalPages: Math.ceil(count/limit), search });
});

router.post('/keys/create', async (req, res) => {
  const { tier, duration, prefix, max_devices } = req.body;
  let maxDev = 1;
  if (max_devices) {
    maxDev = parseInt(max_devices) || maxDev;
    if (maxDev < 1) maxDev = 1;
    if (maxDev > 999) maxDev = 999;
  }

  let hours = 0;
  if (duration === '0.5') {
    hours = 12;
  } else if (duration === 'forever') {
    // vĩnh viễn
  } else {
    const dur = parseFloat(duration) || 30;
    let days = dur;
    if (days <= 0) days = 30;
    const hours = Math.round(days * 24);
    expires_at = new Date();
    expires_at.setHours(expires_at.getHours() + hours);
    if (days <= 0) days = 30;
    hours = days * 24;
  }

  let expires_at;
  if (duration === 'forever') {
    expires_at = new Date('2099-12-31');
  } else {
    expires_at = new Date();
    expires_at.setHours(expires_at.getHours() + hours);
  }

  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
  await Key.create({ key, tier, expires_at, max_devices: maxDev, created_by: req.session.admin.email });
  await Log.create({ action: 'key_created', details: `Admin tạo key ${key} max ${maxDev} TB`, ip_address: req.ip });
  notifyKeyCreated(key, maxDev);
  res.redirect('/admin/keys?created=1');
});

router.post('/keys/toggle/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    key.is_active = !key.is_active;
    await key.save();
    await Log.create({ action: key.is_active?'key_unlocked':'key_locked', details: `Key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyKeyToggled(key.key, key.is_active);
    res.redirect('/admin/keys?toggled=1');
  } else {
    res.redirect('/admin/keys?error=toggle_failed');
  }
});

router.post('/keys/kick-all/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.update({ is_active: false }, { where: { key_id: key.id } });
    await Log.create({ action: 'kick_all', details: `Khóa tất cả thiết bị của key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyKickAll(key.key);
    res.redirect('/admin/keys?kicked=1');
  } else {
    res.redirect('/admin/keys?error=kick_failed');
  }
});

router.post('/keys/delete-all-devices/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.destroy({ where: { key_id: key.id } });
    await Log.create({ action: 'delete_all_devices', details: `Xóa vĩnh viễn tất cả TB của key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyDeleteAllDevices(key.key);
    res.redirect('/admin/keys?deleted_all_devices=1');
  } else {
    res.redirect('/admin/keys?error=delete_all_failed');
  }
});

router.post('/keys/toggle-device/:deviceId', async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key, attributes: ['key'] } });
  if (device) {
    device.is_active = !device.is_active;
    await device.save();
    await Log.create({ action: device.is_active?'device_unlocked':'device_kicked', details: `TB ${device.hwid} của key ${device.Key.key} ${device.is_active?'mở':'bị khóa'}`, ip_address: req.ip, key_id: device.key_id });
    notifyDeviceToggled(device.Key.key, device.hwid, device.is_active);
    res.redirect('/admin/keys?device_toggled=1');
  } else {
    res.redirect('/admin/keys?error=device_toggle_failed');
  }
});

router.post('/keys/unbind-device/:deviceId', async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key, attributes: ['key'] } });
  if (device) {
    const keyKey = device.Key.key;
    await device.destroy();
    await Log.create({ action: 'device_deleted', details: `Xóa vĩnh viễn TB ${device.hwid} khỏi key ${keyKey}`, ip_address: req.ip, key_id: device.key_id });
    notifyDeviceDeleted(keyKey, device.hwid);
    res.redirect('/admin/keys?device_deleted=1');
  } else {
    res.redirect('/admin/keys?error=unbind_failed');
  }
});

router.post('/keys/extend/:id', async (req, res) => {
  const { new_expiry } = req.body;
  const key = await Key.findByPk(req.params.id);
  if (!key) return res.redirect('/admin/keys?error=extend_failed');
  if (!new_expiry) return res.redirect('/admin/keys?error=missing_date');
  try {
    const newDate = new Date(new_expiry);
    if (isNaN(newDate.getTime())) throw new Error('Invalid date');
    key.expires_at = newDate;
    await key.save();
    await Log.create({ action: 'key_extended', details: `Gia hạn key ${key.key} đến ${new_expiry}`, ip_address: req.ip, key_id: key.id });
    res.redirect('/admin/keys?extended=1');
  } catch (err) {
    console.error('Extend error:', err);
    res.redirect('/admin/keys?error=extend_failed');
  }
});

router.post('/keys/delete/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.destroy({ where: { key_id: key.id } });
    await key.destroy();
    await Log.create({ action: 'key_deleted', details: `Xoá key ${key.key}`, ip_address: req.ip });
    notifyKeyDeleted(key.key);
    res.redirect('/admin/keys?deleted=1');
  } else {
    res.redirect('/admin/keys?error=delete_failed');
  }
});

router.get('/keys/devices/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id, { include: [{ model: KeyDevice, as: 'devices', required: false }] });
  if (!key) return res.json({ success: false });
  res.json({ success: true, devices: key.devices || [] });
});

module.exports = router;
