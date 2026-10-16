const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const ExpressBrute = require('express-brute');
const { Key, Log, KeyDevice, AppVersion, Announcement, Admin, Seller } = require('../models');
const {
  notifyKeyCreated, notifyKeyToggled, notifyKeyDeleted,
  notifyKickAll, notifyDeleteAllDevices,
  notifyDeviceToggled, notifyDeviceDeleted
} = require('../utils/email');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecret';

const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store, {
  freeRetries: 5, minWait: 15 * 60 * 1000, maxWait: 15 * 60 * 1000,
  failCallback: (req, res) => res.status(429).send('Quá nhiều lần thử. Đợi 15 phút.')
});

// ============ MIDDLEWARE ============
function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.redirect('/admin/login');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.email === process.env.ADMIN_EMAIL) {
      decoded.role = 'super';
      decoded.is_super = true;
    }
    if (!decoded.role) decoded.role = 'admin';
    req.admin = decoded;
    next();
  } catch (err) {
    res.clearCookie('admin_token');
    res.redirect('/admin/login');
  }
}

function requireSuperAdmin(req, res, next) {
  if (!req.admin) return res.redirect('/admin/login');
  if (req.admin.role !== 'super' && req.admin.is_super !== true) {
    return res.status(403).send(`
      <div style="font-family: system-ui; padding: 40px; background: #0a1e3f; color: #ffd700; min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center;">
        <div>
          <h1 style="font-size: 4rem; margin: 0;">🚫</h1>
          <h2>Không có quyền truy cập</h2>
          <p style="color: #8ba3c7;">Chỉ Super Admin mới được vào trang này.</p>
          <a href="/admin/dashboard" style="color: #4fc3f7; text-decoration: none;">← Về Dashboard</a>
        </div>
      </div>
    `);
  }
  next();
}

// ============ AUTH ============
router.get('/login', (req, res) => res.render('admin/login', { error: null }));

router.post('/login', bruteforce.prevent, async (req, res) => {
  const { email, password } = req.body;
  try {
    const dbAdmin = await Admin.findOne({ where: { email, is_active: true } });
    if (dbAdmin && bcrypt.compareSync(password, dbAdmin.password_hash)) {
      dbAdmin.last_login = new Date();
      await dbAdmin.save();
      const token = jwt.sign({
        id: dbAdmin.id, email, role: dbAdmin.role,
        name: dbAdmin.name, is_super: dbAdmin.role === 'super'
      }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('admin_token', token, {
        httpOnly: true, secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000
      });
      return res.redirect('/admin/dashboard');
    }
    if (email === ADMIN_EMAIL && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
      const token = jwt.sign({ email, role: 'super', name: 'Owner', is_super: true }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('admin_token', token, {
        httpOnly: true, secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000
      });
      return res.redirect('/admin/dashboard');
    }
    res.render('admin/login', { error: 'Sai email hoặc mật khẩu' });
  } catch (err) {
    console.error('Login error:', err);
    res.render('admin/login', { error: 'Lỗi hệ thống' });
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.clearCookie('seller_token');
  res.redirect('/admin/login');
});

router.get('/force-logout', (req, res) => {
  res.clearCookie('admin_token');
  res.clearCookie('seller_token');
  res.redirect('/admin/login');
});

router.get('/whoami', (req, res) => {
  const token = req.cookies.admin_token;
  if (!token) return res.json({ logged_in: false });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({
      logged_in: true, email: decoded.email, role: decoded.role,
      is_super: decoded.is_super, id: decoded.id,
      is_env_admin: decoded.email === process.env.ADMIN_EMAIL
    });
  } catch (e) {
    res.json({ logged_in: false, error: 'invalid_token' });
  }
});

router.use(requireAdmin);

// ============ DASHBOARD ============
router.get('/dashboard', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    const showAll = req.query.show === 'all';
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let keyWhere = {};
    if (!isSuper && req.admin.id) keyWhere.admin_id = req.admin.id;
    const where = { createdAt: { [Op.gte]: oneDayAgo } };
    if (!showAll) where.action = { [Op.ne]: 'check' };
    
    const totalKeys = await Key.count({ where: keyWhere });
    const activeKeys = await Key.count({ where: { ...keyWhere, is_active: true } });
    const expiredKeys = await Key.count({ where: { ...keyWhere, expires_at: { [Op.lt]: new Date() } } });
    const vipKeys = await Key.count({ where: { ...keyWhere, tier: 'VIP' } });
    const devicesActivated = await KeyDevice.count({ where: { is_active: true } });
    const recentLogs = await Log.findAll({ where, limit: 20, order: [['createdAt', 'DESC']], include: Key });
    
    let adminInfo = null;
    if (!isSuper && req.admin.id) adminInfo = await Admin.findByPk(req.admin.id);
    
    res.render('admin/dashboard', {
      user: req.admin, isSuper, adminInfo,
      totalKeys, activeKeys, expiredKeys, vipKeys, devicesActivated, recentLogs, showAll
    });
  } catch (err) {
    console.error('=== DASHBOARD ERROR ===');
    console.error('Message:', err.message);
    console.error('Stack:', err.stack);
    res.status(500).send(`
      <html><head><title>Dashboard Error</title>
      <style>body{font-family:monospace;padding:30px;background:#0a1e3f;color:#fff}h1{color:#ef5350}pre{background:#050d1f;padding:20px;border-radius:8px;overflow:auto;color:#81d4fa;max-height:60vh}</style>
      </head><body>
      <h1>⚠️ Lỗi tải Dashboard</h1>
      <p><strong style="color:#ef5350">${err.message}</strong></p>
      <pre>${err.stack}</pre>
      <p><a href="/admin/force-logout" style="color:#4fc3f7">Force logout</a> | <a href="/admin/login" style="color:#4fc3f7">Login lại</a></p>
      </body></html>
    `);
  }
});
  } catch (err) { console.error(err); res.status(500).send('Lỗi máy chủ'); }
});

// ============ KEYS ============
router.get('/keys', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    const page = parseInt(req.query.page) || 1, limit = 15, offset = (page - 1) * limit;
    const search = req.query.search || '';
    let where = {};
    if (!isSuper && req.admin.id) where.admin_id = req.admin.id;
    if (search) {
      where[Op.or] = [
        { key: { [Op.iLike]: `%${search}%` } },
        { hwid: { [Op.iLike]: `%${search}%` } }
      ];
    }
    const { count, rows: keys } = await Key.findAndCountAll({
      where, order: [['createdAt', 'DESC']],
      include: [{ model: KeyDevice, as: 'devices', required: false }],
      limit, offset
    });
    res.render('admin/keys', { user: req.admin, isSuper, keys, currentPage: page, totalPages: Math.ceil(count / limit), search });
  } catch (err) { console.error(err); res.status(500).send('Lỗi máy chủ'); }
});

router.post('/keys/create', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    const { tier, duration, prefix, max_devices } = req.body;
    let adminRecord = null;
    if (!isSuper && req.admin.id) {
      adminRecord = await Admin.findByPk(req.admin.id);
      if (!adminRecord) return res.redirect('/admin/login');
      if (adminRecord.quota_used >= adminRecord.quota) return res.redirect('/admin/keys?error=quota_exceeded');
    }
    let maxDev = 1;
    if (max_devices) {
      maxDev = parseInt(max_devices) || 1;
      if (maxDev < 1) maxDev = 1;
      if (maxDev > 999) maxDev = 999;
    }
    let expires_at;
    if (duration === 'forever') {
      expires_at = new Date('2099-12-31T23:59:59');
    } else {
      const dur = parseFloat(duration) || 30;
      let days = dur <= 0 ? 30 : dur;
      const hours = Math.round(days * 24);
      expires_at = new Date();
      expires_at.setHours(expires_at.getHours() + hours);
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    await Key.create({
      key, tier, expires_at, max_devices: maxDev,
      created_by: req.admin.email,
      admin_id: req.admin.id || null
    });
    if (adminRecord) {
      adminRecord.quota_used = (adminRecord.quota_used || 0) + 1;
      await adminRecord.save();
    }
    await Log.create({ action: 'key_created', details: `${req.admin.email} tạo key ${key}`, ip_address: req.ip });
    res.redirect('/admin/keys?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/keys?error=create_failed'); }
});

router.post('/keys/toggle/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    key.is_active = !key.is_active;
    await key.save();
    await Log.create({ action: key.is_active ? 'key_unlocked' : 'key_locked', details: `Key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyKeyToggled(key.key, key.is_active);
  }
  res.redirect('/admin/keys?toggled=1');
});

router.post('/keys/kick-all/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.update({ is_active: false }, { where: { key_id: key.id } });
    await Log.create({ action: 'kick_all', details: `Khóa tất cả TB của key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyKickAll(key.key);
  }
  res.redirect('/admin/keys?kicked=1');
});

router.post('/keys/delete-all-devices/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.destroy({ where: { key_id: key.id } });
    await Log.create({ action: 'delete_all_devices', details: `Xóa all TB của key ${key.key}`, ip_address: req.ip, key_id: key.id });
    notifyDeleteAllDevices(key.key);
  }
  res.redirect('/admin/keys?deleted_all_devices=1');
});

router.post('/keys/toggle-device/:deviceId', async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key } });
  if (device) {
    device.is_active = !device.is_active;
    await device.save();
    await Log.create({ action: device.is_active ? 'device_unlocked' : 'device_kicked', details: `TB ${device.hwid}`, ip_address: req.ip, key_id: device.key_id });
    notifyDeviceToggled(device.Key.key, device.hwid, device.is_active);
  }
  res.redirect('/admin/keys?device_toggled=1');
});

router.post('/keys/unbind-device/:deviceId', async (req, res) => {
  const device = await KeyDevice.findByPk(req.params.deviceId, { include: { model: Key } });
  if (device) {
    const keyKey = device.Key.key;
    await device.destroy();
    await Log.create({ action: 'device_deleted', details: `Xóa TB ${device.hwid}`, ip_address: req.ip, key_id: device.key_id });
    notifyDeviceDeleted(keyKey, device.hwid);
  }
  res.redirect('/admin/keys?device_deleted=1');
});

router.post('/keys/extend/:id', async (req, res) => {
  const { new_expiry } = req.body;
  const key = await Key.findByPk(req.params.id);
  if (key && new_expiry) {
    key.expires_at = new Date(new_expiry);
    await key.save();
    await Log.create({ action: 'key_extended', details: `Gia hạn key ${key.key}`, ip_address: req.ip, key_id: key.id });
  }
  res.redirect('/admin/keys?extended=1');
});

router.post('/keys/delete/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id);
  if (key) {
    await KeyDevice.destroy({ where: { key_id: key.id } });
    await key.destroy();
    await Log.create({ action: 'key_deleted', details: `Xoá key ${key.key}`, ip_address: req.ip });
    notifyKeyDeleted(key.key);
  }
  res.redirect('/admin/keys?deleted=1');
});

router.get('/keys/devices/:id', async (req, res) => {
  const key = await Key.findByPk(req.params.id, { include: [{ model: KeyDevice, as: 'devices', required: false }] });
  if (!key) return res.json({ success: false });
  res.json({ success: true, devices: key.devices || [] });
});

// ============ QUẢN LÝ ADMIN (SUPER ONLY) ============
router.get('/admins', requireSuperAdmin, async (req, res) => {
  try {
    const admins = await Admin.findAll({ order: [['createdAt', 'DESC']] });
    const adminsWithStats = await Promise.all(admins.map(async (a) => {
      const keyCount = await Key.count({ where: { admin_id: a.id } });
      return { ...a.toJSON(), keyCount };
    }));
    res.render('admin/admins', {
      user: req.admin,
      admins: adminsWithStats,
      envAdminEmail: process.env.ADMIN_EMAIL
    });
  } catch (err) { console.error(err); res.status(500).send('Lỗi tải trang'); }
});

router.post('/admins/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, role, quota, can_choose_tier, can_choose_duration, max_devices_default, notes } = req.body;
    if (!email || !password) return res.redirect('/admin/admins?error=missing');
    const existing = await Admin.findOne({ where: { email } });
    if (existing) return res.redirect('/admin/admins?error=email_exists');
    if (email === process.env.ADMIN_EMAIL) return res.redirect('/admin/admins?error=email_exists');
    const hash = bcrypt.hashSync(password, 10);
    await Admin.create({
      email, password_hash: hash, name: name || email,
      role: role || 'admin',
      quota: parseInt(quota) || 0,
      can_choose_tier: can_choose_tier === 'on',
      can_choose_duration: can_choose_duration === 'on',
      max_devices_default: parseInt(max_devices_default) || 1,
      notes: notes || null,
      created_by: req.admin.email
    });
    await Log.create({ action: 'admin_created', details: `${req.admin.email} tạo admin ${email}`, ip_address: req.ip });
    res.redirect('/admin/admins?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/admins?error=create_failed'); }
});

router.post('/admins/toggle/:id', requireSuperAdmin, async (req, res) => {
  const target = await Admin.findByPk(req.params.id);
  if (target) {
    if (target.email === req.admin.email) return res.redirect('/admin/admins?error=self_action');
    target.is_active = !target.is_active;
    await target.save();
  }
  res.redirect('/admin/admins?toggled=1');
});

router.post('/admins/add-quota/:id', requireSuperAdmin, async (req, res) => {
  const { amount } = req.body;
  const target = await Admin.findByPk(req.params.id);
  if (target && amount) {
    target.quota = (target.quota || 0) + parseInt(amount);
    await target.save();
  }
  res.redirect('/admin/admins?quota_added=1');
});

router.post('/admins/reset-quota/:id', requireSuperAdmin, async (req, res) => {
  const target = await Admin.findByPk(req.params.id);
  if (target) {
    target.quota_used = 0;
    await target.save();
  }
  res.redirect('/admin/admins?quota_reset=1');
});

router.post('/admins/change-role/:id', requireSuperAdmin, async (req, res) => {
  const { role } = req.body;
  const target = await Admin.findByPk(req.params.id);
  if (target && ['super', 'admin'].includes(role)) {
    if (target.email === req.admin.email) return res.redirect('/admin/admins?error=self_action');
    target.role = role;
    await target.save();
  }
  res.redirect('/admin/admins?role_changed=1');
});

router.post('/admins/delete/:id', requireSuperAdmin, async (req, res) => {
  const target = await Admin.findByPk(req.params.id);
  if (target) {
    if (target.email === req.admin.email) return res.redirect('/admin/admins?error=self_action');
    await Key.update({ admin_id: null }, { where: { admin_id: target.id } });
    await target.destroy();
  }
  res.redirect('/admin/admins?deleted=1');
});

// ============ QUẢN LÝ SELLER (SUPER ONLY) ============
router.get('/sellers', requireSuperAdmin, async (req, res) => {
  try {
    const sellers = await Seller.findAll({ order: [['createdAt', 'DESC']] });
    const sellerStats = await Promise.all(sellers.map(async (s) => {
      const keyCount = await Key.count({ where: { seller_id: s.id } });
      return { ...s.toJSON(), keyCount };
    }));
    res.render('admin/sellers', { user: req.admin, sellers: sellerStats });
  } catch (err) { console.error(err); res.status(500).send('Lỗi tải trang'); }
});

router.post('/sellers/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, phone, quota, can_choose_tier, can_choose_duration, max_devices_default, notes } = req.body;
    if (!email || !password || !name) return res.redirect('/admin/sellers?error=missing');
    const existing = await Seller.findOne({ where: { email } });
    if (existing) return res.redirect('/admin/sellers?error=email_exists');
    const hash = bcrypt.hashSync(password, 10);
    await Seller.create({
      email, password_hash: hash, name,
      phone: phone || null,
      quota: parseInt(quota) || 0,
      can_choose_tier: can_choose_tier === 'on',
      can_choose_duration: can_choose_duration === 'on',
      max_devices_default: parseInt(max_devices_default) || 1,
      notes: notes || null,
      created_by: req.admin.email
    });
    await Log.create({ action: 'seller_created', details: `${req.admin.email} tạo seller ${email}`, ip_address: req.ip });
    res.redirect('/admin/sellers?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/sellers?error=create_failed'); }
});

router.post('/sellers/toggle/:id', requireSuperAdmin, async (req, res) => {
  const seller = await Seller.findByPk(req.params.id);
  if (seller) { seller.is_active = !seller.is_active; await seller.save(); }
  res.redirect('/admin/sellers?toggled=1');
});

router.post('/sellers/add-quota/:id', requireSuperAdmin, async (req, res) => {
  const { amount } = req.body;
  const seller = await Seller.findByPk(req.params.id);
  if (seller && amount) {
    seller.quota = (seller.quota || 0) + parseInt(amount);
    await seller.save();
  }
  res.redirect('/admin/sellers?quota_added=1');
});

router.post('/sellers/reset-quota/:id', requireSuperAdmin, async (req, res) => {
  const seller = await Seller.findByPk(req.params.id);
  if (seller) { seller.quota_used = 0; await seller.save(); }
  res.redirect('/admin/sellers?quota_reset=1');
});

router.post('/sellers/delete/:id', requireSuperAdmin, async (req, res) => {
  const seller = await Seller.findByPk(req.params.id);
  if (seller) {
    await Key.update({ seller_id: null }, { where: { seller_id: seller.id } });
    await seller.destroy();
  }
  res.redirect('/admin/sellers?deleted=1');
});

// ============ VERSIONS ============
router.get('/versions', async (req, res) => {
  try {
    const versions = await AppVersion.findAll({ order: [['version_code', 'DESC']] });
    res.render('admin/versions', { user: req.admin, versions });
  } catch (err) { console.error(err); res.status(500).send('Lỗi tải trang'); }
});

router.post('/versions/create', async (req, res) => {
  try {
    const { version_code, version_name, download_url, changelog, is_required } = req.body;
    if (!version_code || !version_name || !download_url) return res.redirect('/admin/versions?error=missing');
    await AppVersion.update({ is_active: false }, { where: {} });
    await AppVersion.create({
      version_code: parseInt(version_code),
      version_name, download_url,
      changelog: changelog || '',
      is_required: is_required === 'on',
      is_active: true
    });
    res.redirect('/admin/versions?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/versions?error=create_failed'); }
});

router.post('/versions/activate/:id', async (req, res) => {
  await AppVersion.update({ is_active: false }, { where: {} });
  const v = await AppVersion.findByPk(req.params.id);
  if (v) { v.is_active = true; await v.save(); }
  res.redirect('/admin/versions?activated=1');
});

router.post('/versions/toggle-required/:id', async (req, res) => {
  const v = await AppVersion.findByPk(req.params.id);
  if (v) { v.is_required = !v.is_required; await v.save(); }
  res.redirect('/admin/versions?toggled=1');
});

router.post('/versions/toggle-update/:id', async (req, res) => {
  const v = await AppVersion.findByPk(req.params.id);
  if (v) { v.update_enabled = !v.update_enabled; await v.save(); }
  res.redirect('/admin/versions?toggled=1');
});

router.post('/versions/delete/:id', async (req, res) => {
  const v = await AppVersion.findByPk(req.params.id);
  if (v) await v.destroy();
  res.redirect('/admin/versions?deleted=1');
});

// ============ ANNOUNCEMENTS ============
router.get('/announcements', async (req, res) => {
  try {
    const announcements = await Announcement.findAll({ order: [['priority', 'DESC'], ['createdAt', 'DESC']] });
    res.render('admin/announcements', { user: req.admin, announcements });
  } catch (err) { console.error(err); res.status(500).send('Lỗi tải trang'); }
});

router.post('/announcements/create', async (req, res) => {
  try {
    const { title, message, type, priority, expires_at, is_dismissible } = req.body;
    if (!title || !message) return res.redirect('/admin/announcements?error=missing');
    await Announcement.create({
      title, message,
      type: type || 'info',
      priority: parseInt(priority) || 5,
      expires_at: expires_at ? new Date(expires_at) : null,
      is_dismissible: is_dismissible === 'on',
      created_by: req.admin.email
    });
    res.redirect('/admin/announcements?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/announcements?error=create_failed'); }
});

router.post('/announcements/toggle/:id', async (req, res) => {
  const a = await Announcement.findByPk(req.params.id);
  if (a) { a.is_enabled = !a.is_enabled; await a.save(); }
  res.redirect('/admin/announcements?toggled=1');
});

router.post('/announcements/delete/:id', async (req, res) => {
  const a = await Announcement.findByPk(req.params.id);
  if (a) await a.destroy();
  res.redirect('/admin/announcements?deleted=1');
});

module.exports = router;
