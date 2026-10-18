const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const { Key, Log, KeyDevice, AppVersion, Announcement, Admin, Seller } = require('../models');
const loginLimiter = require('../middleware/loginLimiter');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecret';

async function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.redirect('/yncuti/login');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const dbAdmin = await Admin.findByPk(decoded.id);
    
    // CHECK TOKEN PHIÊN ĐĂNG NHẬP
    if (!dbAdmin || (dbAdmin.session_token && dbAdmin.session_token !== decoded.session_token)) {
      res.clearCookie('admin_token');
      return res.redirect('/yncuti/login?error=session_expired');
    }
    
    if (decoded.email === process.env.ADMIN_EMAIL) { decoded.role = 'super'; decoded.is_super = true; }
    if (!decoded.role) decoded.role = 'admin';
    req.admin = decoded;
    next();
  } catch (err) { res.clearCookie('admin_token'); res.redirect('/yncuti/login'); }
}

function requireSuperAdmin(req, res, next) {
  if (!req.admin) return res.redirect('/yncuti/login');
  if (req.admin.role !== 'super' && req.admin.is_super !== true) {
    return res.status(403).send('Không có quyền');
  }
  next();
}

// ==================== RESET ADMIN ====================
router.get('/reset-admin', async (req, res) => {
  const { email, password } = req.query;
  if (!email || !password) {
    return res.send(`<html><body style="background:#0a1e3f;color:#fff;padding:50px;font-family:sans-serif"><h1>Reset Admin</h1><form method="GET"><input name="email" value="${ADMIN_EMAIL}" style="padding:10px"><input name="password" type="text" value="admin123" style="padding:10px"><button type="submit" style="padding:10px">Tạo/Đổi</button></form></body></html>`);
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const existing = await Admin.findOne({ where: { email } });
    if (existing) {
      existing.password_hash = hash; existing.role = 'super'; existing.is_active = true; await existing.save();
    } else {
      await Admin.create({ email, password_hash: hash, name: 'Super Admin', role: 'super', quota: 999999, is_active: true });
    }
    res.send(`<h1 style="color:#0a1e3f">Thành công! <a href="/yncuti/login">Đăng nhập</a></h1>`);
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

// ==================== LOGIN / LOGOUT ====================
router.get('/login', (req, res) => res.render('admin/login', { error: null }));

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    const dbAdmin = await Admin.findOne({ where: { email, is_active: true } });
    const isEnvAdmin = email === process.env.ADMIN_EMAIL;

    if (dbAdmin && bcrypt.compareSync(password, dbAdmin.password_hash)) {
      dbAdmin.last_login = new Date(); 
      dbAdmin.session_token = crypto.randomBytes(16).toString('hex');
      dbAdmin.last_login_ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
      await dbAdmin.save();
      const token = jwt.sign({ id: dbAdmin.id, email, role: isEnvAdmin ? 'super' : dbAdmin.role, name: dbAdmin.name, is_super: isEnvAdmin || dbAdmin.role === 'super', session_token: dbAdmin.session_token }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('admin_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
      return res.redirect('/yncuti/dashboard');
    }

    if (isEnvAdmin && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
      let envAdmin = dbAdmin;
      if (!envAdmin) {
        envAdmin = await Admin.create({ email, password_hash: ADMIN_PASSWORD_HASH, name: 'Super Admin', role: 'super', quota: 999999, is_active: true });
      }
      envAdmin.session_token = crypto.randomBytes(16).toString('hex');
      envAdmin.last_login_ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
      await envAdmin.save();
      const token = jwt.sign({ id: envAdmin.id, email, role: 'super', name: envAdmin.name, is_super: true, session_token: envAdmin.session_token }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('admin_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
      return res.redirect('/yncuti/dashboard');
    }
    res.render('admin/login', { error: 'Sai email hoặc mật khẩu' });
  } catch (err) { res.render('admin/login', { error: 'Lỗi hệ thống' }); }
});

router.get('/logout', (req, res) => { res.clearCookie('admin_token'); res.redirect('/yncuti/login'); });
router.get('/force-logout', (req, res) => { res.clearCookie('admin_token'); res.redirect('/yncuti/login'); });

router.use(requireAdmin);

// ==================== DASHBOARD ====================
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
    const devicesActivated = await KeyDevice.count({ where: { is_active: true } });
    const recentLogs = await Log.findAll({ where, limit: 20, order: [['createdAt', 'DESC']], include: Key });
    let adminInfo = null;
    if (!isSuper && req.admin.id) adminInfo = await Admin.findByPk(req.admin.id);
    res.render('admin/dashboard', { user: req.admin, isSuper, adminInfo, totalKeys, activeKeys, expiredKeys, devicesActivated, recentLogs, showAll });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

// ==================== KEYS ====================
router.get('/keys', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    const page = parseInt(req.query.page) || 1, limit = 15, offset = (page - 1) * limit;
    const search = req.query.search || '', tier = req.query.tier || '', status = req.query.status || '', sort = req.query.sort || 'newest';
    let where = {};
    if (!isSuper && req.admin.id) where.admin_id = req.admin.id;
    if (search) where[Op.or] = [{ key: { [Op.iLike]: `%${search}%` } }, { hwid: { [Op.iLike]: `%${search}%` } }];
    if (tier) where.tier = tier;
    if (status === 'active') where.is_active = true;
    if (status === 'disabled') where.is_active = false;
    if (status === 'expired') where.expires_at = { [Op.lt]: new Date() };
    
    const { count, rows: keys } = await Key.findAndCountAll({
      where, order: [['createdAt', 'DESC']], include: [{ model: KeyDevice, as: 'devices', required: false }], limit, offset
    });
    const activeKeys = await Key.count({ where: { ...(isSuper ? {} : { admin_id: req.admin.id }), is_active: true } });
    res.render('admin/keys', { user: req.admin, isSuper, keys, currentPage: page, totalPages: Math.ceil(count / limit), search, tier, status, sort, activeKeys });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/keys/create', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    const { tier, duration, prefix, max_devices } = req.body;
    let adminRecord = null;
    if (!isSuper && req.admin.id) {
      adminRecord = await Admin.findByPk(req.admin.id);
      if (!adminRecord) return res.redirect('/yncuti/login');
      if (adminRecord.quota_used >= adminRecord.quota) return res.redirect('/yncuti/keys?error=' + encodeURIComponent('Bạn đã hết quota.'));
    }
    let maxDev = parseInt(max_devices) || 1;
    if (maxDev > 999) maxDev = 999;

    let expires_at;
    if (duration === 'forever') expires_at = new Date('2099-12-31T23:59:59');
    else {
      const hours = Math.round((parseFloat(duration) || 30) * 24);
      expires_at = new Date(); expires_at.setHours(expires_at.getHours() + hours);
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    
    await Key.create({ key, tier: tier || 'Normal', expires_at, max_devices: maxDev, created_by: req.admin.email, admin_id: req.admin.id || null });
    if (adminRecord) { adminRecord.quota_used = (adminRecord.quota_used || 0) + 1; await adminRecord.save(); }
    await Log.create({ action: 'key_created', details: `${req.admin.email} tạo key ${key}`, ip_address: req.ip });
    
    res.redirect('/yncuti/keys?created=1');
  } catch (err) { res.redirect('/yncuti/keys?error=' + encodeURIComponent(err.message)); }
});

router.post('/keys/toggle/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) { k.is_active = !k.is_active; await k.save(); } res.redirect('/yncuti/keys?toggled=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/kick-all/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) await KeyDevice.update({ is_active: false }, { where: { key_id: k.id } }); res.redirect('/yncuti/keys?kicked=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/delete-all-devices/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) await KeyDevice.destroy({ where: { key_id: k.id } }); res.redirect('/yncuti/keys?deleted_all_devices=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/toggle-device/:deviceId', async (req, res) => {
  try { const d = await KeyDevice.findByPk(req.params.deviceId); if (d) { d.is_active = !d.is_active; await d.save(); } res.redirect('/yncuti/keys?device_toggled=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/unbind-device/:deviceId', async (req, res) => {
  try { const d = await KeyDevice.findByPk(req.params.deviceId); if (d) await d.destroy(); res.redirect('/yncuti/keys?device_deleted=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/extend/:id', async (req, res) => {
  try { const { new_expiry } = req.body; const k = await Key.findByPk(req.params.id); if (k && new_expiry) { k.expires_at = new Date(new_expiry); await k.save(); } res.redirect('/yncuti/keys?extended=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.post('/keys/delete/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) { await KeyDevice.destroy({ where: { key_id: k.id } }); await k.destroy(); } res.redirect('/yncuti/keys?deleted=1'); } catch (err) { res.redirect('/yncuti/keys'); }
});

router.get('/keys/devices/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id, { include: [{ model: KeyDevice, as: 'devices', required: false }] }); if (!k) return res.json({ success: false }); res.json({ success: true, devices: k.devices || [] }); } catch (err) { res.status(500).json({ success: false }); }
});

// ==================== QUẢN TRỊ VIÊN ====================
router.get('/admins', requireSuperAdmin, async (req, res) => {
  try {
    const admins = await Admin.findAll({ order: [['createdAt', 'DESC']] });
    res.render('admin/admins', { user: req.admin, isSuper: true, admins, currentPage: 'admins', success: req.query.success || null, error: req.query.error || null });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/admins/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, role, quota, can_choose_tier, can_choose_duration, max_devices_default } = req.body;
    if (!email || !password) return res.redirect('/yncuti/admins?error=missing');
    const dup = await Admin.findOne({ where: { email } });
    if (dup) return res.redirect('/yncuti/admins?error=email_exists');
    await Admin.create({ email, password_hash: bcrypt.hashSync(password, 10), name: name || 'Admin', role: role || 'admin', quota: parseInt(quota) || 0, quota_used: 0, can_choose_tier: can_choose_tier === 'on', can_choose_duration: can_choose_duration === 'on', max_devices_default: parseInt(max_devices_default) || 1, is_active: true, created_by: req.admin.email });
    res.redirect('/yncuti/admins?success=created');
  } catch (err) { res.redirect('/yncuti/admins?error=' + encodeURIComponent(err.message)); }
});

router.post('/admins/update/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Admin.findByPk(req.params.id);
    if (!a) return res.redirect('/yncuti/admins?error=not_found');
    const { name, role, quota, can_choose_tier, can_choose_duration, max_devices_default, is_active, new_password } = req.body;
    a.name = name; a.role = role; a.quota = parseInt(quota) || 0;
    a.can_choose_tier = can_choose_tier === 'on'; a.can_choose_duration = can_choose_duration === 'on';
    a.max_devices_default = parseInt(max_devices_default) || 1; a.is_active = is_active === 'on';
    if (new_password) a.password_hash = bcrypt.hashSync(new_password, 10);
    await a.save();
    res.redirect('/yncuti/admins?success=updated');
  } catch (err) { res.redirect('/yncuti/admins?error=1'); }
});

router.post('/admins/toggle/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Admin.findByPk(req.params.id);
    if (a && a.email !== process.env.ADMIN_EMAIL) {
      a.is_active = !a.is_active;
      await a.save();
    }
    res.redirect('/yncuti/admins?success=updated');
  } catch (err) { res.redirect('/yncuti/admins?error=1'); }
});

router.post('/admins/reset-password/:id', requireSuperAdmin, async (req, res) => {
  try {
    const { new_password } = req.body;
    const a = await Admin.findByPk(req.params.id);
    if (a && new_password) {
      a.password_hash = bcrypt.hashSync(new_password, 10);
      await a.save();
    }
    res.redirect('/yncuti/admins?success=updated');
  } catch (err) { res.redirect('/yncuti/admins?error=1'); }
});

router.post('/admins/toggle-role/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Admin.findByPk(req.params.id);
    if (a && a.email !== process.env.ADMIN_EMAIL) {
      a.role = a.role === 'super' ? 'admin' : 'super';
      await a.save();
    }
    res.redirect('/yncuti/admins?success=updated');
  } catch (err) { res.redirect('/yncuti/admins?error=1'); }
});

router.post('/admins/delete/:id', requireSuperAdmin, async (req, res) => {
  try { const a = await Admin.findByPk(req.params.id); if (a && a.email !== process.env.ADMIN_EMAIL) await a.destroy(); res.redirect('/yncuti/admins?success=deleted'); } catch (err) { res.redirect('/yncuti/admins?error=1'); }
});

// ==================== NGƯỜI BÁN ====================
router.get('/sellers', requireSuperAdmin, async (req, res) => {
  try {
    const sellers = await Seller.findAll({ order: [['createdAt', 'DESC']] });
    res.render('admin/sellers', { user: req.admin, isSuper: true, sellers, currentPage: 'sellers', success: req.query.success || null, error: req.query.error || null });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/sellers/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, phone, quota, can_choose_tier, can_choose_duration, default_tier, max_devices_default } = req.body;
    const dup = await Seller.findOne({ where: { email } });
    if (dup) return res.redirect('/yncuti/sellers?error=email_exists');
    await Seller.create({ email, password_hash: bcrypt.hashSync(password, 10), name: name || 'Seller', phone, quota: parseInt(quota) || 0, quota_used: 0, can_choose_tier: can_choose_tier === 'on', can_choose_duration: can_choose_duration === 'on', default_tier: default_tier || 'Normal', max_devices_default: parseInt(max_devices_default) || 1, is_active: true, created_by: req.admin.email });
    res.redirect('/yncuti/sellers?success=created');
  } catch (err) { res.redirect('/yncuti/sellers?error=1'); }
});

router.post('/sellers/update/:id', requireSuperAdmin, async (req, res) => {
  try {
    const s = await Seller.findByPk(req.params.id);
    if (!s) return res.redirect('/yncuti/sellers');
    const { name, phone, quota, can_choose_tier, can_choose_duration, default_tier, max_devices_default, is_active, new_password } = req.body;
    s.name = name; s.phone = phone; s.quota = parseInt(quota) || 0;
    s.can_choose_tier = can_choose_tier === 'on'; s.can_choose_duration = can_choose_duration === 'on';
    s.default_tier = default_tier; s.max_devices_default = parseInt(max_devices_default) || 1;
    s.is_active = is_active === 'on';
    if (new_password) s.password_hash = bcrypt.hashSync(new_password, 10);
    await s.save();
    res.redirect('/yncuti/sellers?success=updated');
  } catch (err) { res.redirect('/yncuti/sellers?error=1'); }
});

router.post('/sellers/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await Seller.destroy({ where: { id: req.params.id } }); res.redirect('/yncuti/sellers?success=deleted'); } catch (err) { res.redirect('/yncuti/sellers?error=1'); }
});

// ==================== PHIÊN BẢN APP ====================
router.get('/versions', requireSuperAdmin, async (req, res) => {
  try {
    const versions = await AppVersion.findAll({ order: [['version_code', 'DESC']] });
    res.render('admin/versions', { user: req.admin, isSuper: true, versions, currentPage: 'versions', success: req.query.success || null, error: req.query.error || null });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/versions/create', requireSuperAdmin, async (req, res) => {
  try {
    const { version_code, version_name, download_url, changelog, is_required, min_supported_version, release_channel } = req.body;
    await AppVersion.create({ version_code: parseInt(version_code), version_name, download_url, changelog, is_required: is_required === 'on', min_supported_version: parseInt(min_supported_version) || 0, release_channel: release_channel || 'stable', is_active: true, update_enabled: true });
    res.redirect('/yncuti/versions?success=created');
  } catch (err) { res.redirect('/yncuti/versions?error=1'); }
});

router.post('/versions/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await AppVersion.destroy({ where: { id: req.params.id } }); res.redirect('/yncuti/versions?success=deleted'); } catch (err) { res.redirect('/yncuti/versions?error=1'); }
});

// ==================== THÔNG BÁO ====================
router.get('/announcements', requireSuperAdmin, async (req, res) => {
  try {
    const announcements = await Announcement.findAll({ order: [['priority', 'DESC'], ['createdAt', 'DESC']] });
    res.render('admin/announcements', { user: req.admin, isSuper: true, announcements, currentPage: 'announcements', success: req.query.success || null, error: req.query.error || null });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/announcements/create', requireSuperAdmin, async (req, res) => {
  try {
    const { title, message, type, priority, is_dismissible, end_days, end_hours } = req.body;
    
    // Chỉ tính thời gian kết thúc
    const calcDate = (days, hours) => {
      const dDays = parseInt(days) || 0;
      const dHours = parseInt(hours) || 0;
      if (dDays === 0 && dHours === 0) return null; 
      const d = new Date();
      d.setDate(d.getDate() + dDays);
      d.setHours(d.getHours() + dHours);
      return d;
    };

    await Announcement.create({ 
      title, 
      message, 
      type: type || 'info', 
      priority: parseInt(priority) || 5, 
      is_dismissible: is_dismissible === 'on', 
      is_enabled: true, 
      starts_at: new Date(), // 🔥 Hiệu lực NGAY LẬP TỨC
      expires_at: calcDate(end_days, end_hours),
      created_by: req.admin.email 
    });
    res.redirect('/yncuti/announcements?success=created');
  } catch (err) { res.redirect('/yncuti/announcements?error=1'); }
});

router.post('/announcements/toggle/:id', requireSuperAdmin, async (req, res) => {
  try { const a = await Announcement.findByPk(req.params.id); if (a) { a.is_enabled = !a.is_enabled; await a.save(); } res.redirect('/yncuti/announcements?success=toggled'); } catch (err) { res.redirect('/yncuti/announcements?error=1'); }
});

router.post('/announcements/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await Announcement.destroy({ where: { id: req.params.id } }); res.redirect('/yncuti/announcements?success=deleted'); } catch (err) { res.redirect('/yncuti/announcements?error=1'); }
});

// ==================== PROFILE ====================
router.get('/profile', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    let adminInfo = null;
    if (req.admin.id) adminInfo = await Admin.findByPk(req.admin.id);
    else adminInfo = await Admin.findOne({ where: { email: req.admin.email } });
    res.render('admin/profile', { user: req.admin, isSuper, adminInfo, currentPage: 'profile', success: req.query.success || null, error: req.query.error || null });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/profile/change-password', async (req, res) => {
  try {
    const { old_password, new_password, confirm_password } = req.body;
    if (!old_password || !new_password || !confirm_password) return res.redirect('/yncuti/profile?error=missing');
    if (new_password !== confirm_password) return res.redirect('/yncuti/profile?error=password_mismatch');
    if (new_password.length < 6) return res.redirect('/yncuti/profile?error=too_short');
    const admin = await Admin.findOne({ where: { email: req.admin.email } });
    if (!admin) return res.redirect('/yncuti/profile?error=not_found');
    if (!bcrypt.compareSync(old_password, admin.password_hash)) return res.redirect('/yncuti/profile?error=wrong_password');
    admin.password_hash = bcrypt.hashSync(new_password, 10);
    admin.session_token = null; // Bắt buộc đăng nhập lại trên mọi thiết bị
    await admin.save();
    res.redirect('/yncuti/profile?success=password_changed');
  } catch (err) { res.redirect('/yncuti/profile?error=system'); }
});

module.exports = router;
