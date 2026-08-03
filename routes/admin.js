const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Op } = require('sequelize');
const ExpressBrute = require('express-brute');
const { Key, Log } = require('../models');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';

const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store, {
  freeRetries: 5,
  minWait: 15*60*1000,
  maxWait: 15*60*1000,
  failCallback: function (req, res, next, nextValidRequestDate) {
    res.status(429).send('Quá nhiều lần đăng nhập sai. Hãy thử lại sau 15 phút.');
  }
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
  if (valid) {
    req.session.admin = { email };
    return res.redirect('/admin/dashboard');
  }
  res.render('admin/login', { error: 'Sai email hoặc mật khẩu' });
});

router.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/admin/login');
});

router.use(requireAdmin);

router.get('/dashboard', async (req, res) => {
  const totalKeys = await Key.count();
  const activeKeys = await Key.count({ where: { is_active: true } });
  const expiredKeys = await Key.count({ where: { expires_at: { [Op.lt]: new Date() } } });
  const vipKeys = await Key.count({ where: { tier: 'VIP' } });
  const devicesActivated = await Key.count({ where: { hwid: { [Op.ne]: null } } });
  const recentLogs = await Log.findAll({ limit: 8, order: [['createdAt', 'DESC']], include: Key });
  res.render('admin/dashboard', { user: req.session.admin, totalKeys, activeKeys, expiredKeys, vipKeys, devicesActivated, recentLogs });
});

router.get('/keys', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 15;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  let where = {};
  if (search) where = { [Op.or]: [{ key: { [Op.iLike]: `%${search}%` } }, { hwid: { [Op.iLike]: `%${search}%` } }] };
  const { count, rows: keys } = await Key.findAndCountAll({ where, order: [['createdAt', 'DESC']], limit, offset });
  res.render('admin/keys', { user: req.session.admin, keys, currentPage: page, totalPages: Math.ceil(count / limit), search });
});

router.post('/keys/create', async (req, res) => {
  const { tier, duration, prefix, hwid } = req.body; // Nhận thêm hwid từ form
  let expires_at;
  if (duration === 'forever') expires_at = new Date('2099-12-31');
  else {
    const days = parseInt(duration) || 30;
    expires_at = new Date(); expires_at.setDate(expires_at.getDate() + days);
  }
  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
  
  // Nếu admin nhập HWID, gán trực tiếp vào key
  await Key.create({ key, tier, expires_at, hwid: hwid || null, created_by: req.session.admin.email });
  await Log.create({ action: 'key_created', details: `Admin tạo key ${key}` + (hwid ? ` với HWID ${hwid}` : ''), ip_address: req.ip });
  res.redirect('/admin/keys?created=1');
});

router.post('/keys/toggle/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) { key.is_active = !key.is_active; await key.save(); await Log.create({ action: key.is_active ? 'key_unlocked' : 'key_locked', details: `Key ${key.key}`, ip_address: req.ip, key_id: key.id }); }
  res.redirect('/admin/keys');
});

router.post('/keys/unbind/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) { key.hwid = null; await key.save(); await Log.create({ action: 'hwid_unbound', details: `Gỡ HWID cho key ${key.key}`, ip_address: req.ip, key_id: key.id }); }
  res.redirect('/admin/keys');
});

router.post('/keys/extend/:id', async (req, res) => {
  const { new_expiry } = req.body;
  const key = await Key.findByPk(req.params.id);
  if (key && new_expiry) { key.expires_at = new Date(new_expiry); await key.save(); await Log.create({ action: 'key_extended', details: `Gia hạn key ${key.key} đến ${new_expiry}`, ip_address: req.ip, key_id: key.id }); }
  res.redirect('/admin/keys');
});

router.post('/keys/delete/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) { await key.destroy(); await Log.create({ action: 'key_deleted', details: `Xoá key ${key.key}`, ip_address: req.ip }); }
  res.redirect('/admin/keys');
});

module.exports = router;
