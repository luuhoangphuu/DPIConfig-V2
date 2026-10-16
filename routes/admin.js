const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const { Key, Log, KeyDevice, AppVersion, Announcement, Admin, Seller } = require('../models');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecret';

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.redirect('/admin/login');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
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
    return res.status(403).send('Không có quyền');
  }
  next();
}

// ============================================
// RESET ADMIN - TẠO / ĐỔI MẬT KHẨU NGAY
// ============================================
router.get('/reset-admin', async (req, res) => {
  const { email, password } = req.query;
  
  // Không có tham số → hiện form
  if (!email || !password) {
    return res.send(`
      <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Reset Admin</title>
      <style>
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;font-family:'Segoe UI',sans-serif;
          background:url('/images/starry-night.jpg') center/cover fixed;
          display:flex;align-items:center;justify-content:center;padding:20px;color:#fff}
        body::before{content:'';position:fixed;inset:0;background:rgba(5,13,31,0.75);z-index:-1}
        .card{max-width:480px;width:100%;background:rgba(10,30,63,0.9);
          backdrop-filter:blur(30px);border:2px solid rgba(255,215,0,0.4);
          border-radius:24px;padding:40px;box-shadow:0 20px 60px rgba(0,0,0,0.6)}
        h1{font-size:1.8rem;color:#ffd700;text-align:center;margin:0 0 8px}
        p.sub{text-align:center;color:#81d4fa;margin:0 0 24px;font-size:0.9rem}
        label{color:#ffd700;font-weight:700;font-size:0.8rem;letter-spacing:1px;
          text-transform:uppercase;display:block;margin-bottom:8px}
        input{width:100%;padding:14px;margin-bottom:16px;background:rgba(5,13,31,0.7);
          border:1.5px solid rgba(79,195,247,0.3);color:#fff;border-radius:12px;font-size:1rem}
        input:focus{outline:none;border-color:#ffd700}
        button{width:100%;padding:16px;background:linear-gradient(135deg,#ffd700,#f59e0b);
          color:#0a1e3f;border:none;border-radius:12px;font-weight:800;font-size:1.1rem;
          cursor:pointer}
        .info{background:rgba(255,215,0,0.1);border-left:3px solid #ffd700;
          padding:14px;border-radius:8px;font-size:0.85rem;color:#8ba3c7;margin-top:20px}
      </style></head><body>
      <div class="card">
        <h1>🔑 Reset Admin</h1>
        <p class="sub">Tạo hoặc đổi mật khẩu tài khoản admin</p>
        <form method="GET" action="/admin/reset-admin">
          <label>Email admin</label>
          <input type="email" name="email" value="${ADMIN_EMAIL}" required>
          <label>Mật khẩu mới</label>
          <input type="text" name="password" value="duy123456" required minlength="6">
          <button type="submit">✅ Tạo / Đổi mật khẩu</button>
        </form>
        <div class="info">
          Bấm nút → tài khoản được tạo (hoặc đổi mật khẩu).<br>
          Sau đó vào <b>/admin/login</b> đăng nhập bằng email + mật khẩu vừa nhập.
        </div>
      </div></body></html>
    `);
  }
  
  // Có đủ email + password → tạo/update admin
  try {
    const hash = bcrypt.hashSync(password, 10);
    const existing = await Admin.findOne({ where: { email } });
    
    if (existing) {
      existing.password_hash = hash;
      existing.role = 'super';
      existing.is_active = true;
      await existing.save();
    } else {
      await Admin.create({
        email,
        password_hash: hash,
        name: 'Super Admin',
        role: 'super',
        quota: 999999,
        quota_used: 0,
        can_choose_tier: true,
        can_choose_duration: true,
        max_devices_default: 999,
        is_active: true,
        created_by: 'reset-admin'
      });
    }
    
    res.send(`
      <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Thành công</title>
      <style>
        body{margin:0;min-height:100vh;font-family:'Segoe UI',sans-serif;
          background:url('/images/starry-night.jpg') center/cover fixed;
          display:flex;align-items:center;justify-content:center;padding:20px;color:#fff}
        body::before{content:'';position:fixed;inset:0;background:rgba(5,13,31,0.75);z-index:-1}
        .card{max-width:480px;width:100%;background:rgba(10,30,63,0.9);
          backdrop-filter:blur(30px);border:2px solid #81c784;
          border-radius:24px;padding:40px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.6)}
        h1{color:#81c784;font-size:1.8rem;margin:0 0 20px}
        .creds{background:#050d1f;padding:20px;border-radius:12px;
          margin:20px 0;text-align:left;font-family:monospace;color:#4fc3f7;font-size:0.95rem;line-height:1.8}
        .creds b{color:#ffd700}
        a{display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#ffd700,#f59e0b);
          color:#0a1e3f;text-decoration:none;border-radius:12px;font-weight:800}
      </style></head><body>
      <div class="card">
        <h1>🎉 Thành công!</h1>
        <div class="creds">
          📧 Email: <b>${email}</b><br>
          🔑 Password: <b>${password}</b><br>
          👑 Role: <b>SUPER ADMIN</b>
        </div>
        <a href="/admin/login">→ Đăng nhập ngay</a>
      </div></body></html>
    `);
  } catch (err) {
    res.status(500).send('Lỗi: ' + err.message);
  }
});

// ==================== LOGIN ====================
router.get('/login', (req, res) => res.render('admin/login', { error: null }));

router.post('/login', async (req, res) => {
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
  res.redirect('/admin/login');
});

router.get('/force-logout', (req, res) => {
  res.clearCookie('admin_token');
  res.redirect('/admin/login');
});

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
    console.error(err);
    res.status(500).send('Lỗi: ' + err.message);
  }
});

// ==================== KEYS ====================
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
  } catch (err) { console.error(err); res.status(500).send('Lỗi: ' + err.message); }
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
    if (duration === 'forever') expires_at = new Date('2099-12-31T23:59:59');
    else {
      const dur = parseFloat(duration) || 30;
      const days = dur <= 0 ? 30 : dur;
      const hours = Math.round(days * 24);
      expires_at = new Date();
      expires_at.setHours(expires_at.getHours() + hours);
    }
    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
    await Key.create({ key, tier, expires_at, max_devices: maxDev, created_by: req.admin.email, admin_id: req.admin.id || null });
    if (adminRecord) { adminRecord.quota_used = (adminRecord.quota_used || 0) + 1; await adminRecord.save(); }
    await Log.create({ action: 'key_created', details: `${req.admin.email} tạo key ${key}`, ip_address: req.ip });
    res.redirect('/admin/keys?created=1');
  } catch (err) { console.error(err); res.redirect('/admin/keys?error=create_failed'); }
});

router.post('/keys/toggle/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) { k.is_active = !k.is_active; await k.save(); } res.redirect('/admin/keys?toggled=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/kick-all/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) await KeyDevice.update({ is_active: false }, { where: { key_id: k.id } }); res.redirect('/admin/keys?kicked=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/delete-all-devices/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) await KeyDevice.destroy({ where: { key_id: k.id } }); res.redirect('/admin/keys?deleted_all_devices=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/toggle-device/:deviceId', async (req, res) => {
  try { const d = await KeyDevice.findByPk(req.params.deviceId); if (d) { d.is_active = !d.is_active; await d.save(); } res.redirect('/admin/keys?device_toggled=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/unbind-device/:deviceId', async (req, res) => {
  try { const d = await KeyDevice.findByPk(req.params.deviceId); if (d) await d.destroy(); res.redirect('/admin/keys?device_deleted=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/extend/:id', async (req, res) => {
  try { const { new_expiry } = req.body; const k = await Key.findByPk(req.params.id); if (k && new_expiry) { k.expires_at = new Date(new_expiry); await k.save(); } res.redirect('/admin/keys?extended=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.post('/keys/delete/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id); if (k) { await KeyDevice.destroy({ where: { key_id: k.id } }); await k.destroy(); } res.redirect('/admin/keys?deleted=1'); } catch (err) { res.redirect('/admin/keys'); }
});

router.get('/keys/devices/:id', async (req, res) => {
  try { const k = await Key.findByPk(req.params.id, { include: [{ model: KeyDevice, as: 'devices', required: false }] }); if (!k) return res.json({ success: false }); res.json({ success: true, devices: k.devices || [] }); } catch (err) { res.status(500).json({ success: false }); }
});


// ============================================
// QUẢN TRỊ VIÊN (chỉ Super Admin)
// ============================================
router.get('/admins', requireSuperAdmin, async (req, res) => {
  try {
    const admins = await Admin.findAll({ order: [['createdAt', 'DESC']] });
    res.render('admin/admins', {
      user: req.admin, isSuper: true, admins, currentPage: 'admins',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/admins/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, role, quota, can_choose_tier, can_choose_duration, max_devices_default } = req.body;
    if (!email || !password) return res.redirect('/admin/admins?error=missing');
    const dup = await Admin.findOne({ where: { email } });
    if (dup) return res.redirect('/admin/admins?error=email_exists');
    await Admin.create({
      email, password_hash: bcrypt.hashSync(password, 10),
      name: name || 'Admin', role: role || 'admin',
      quota: parseInt(quota) || 0, quota_used: 0,
      can_choose_tier: can_choose_tier === 'on',
      can_choose_duration: can_choose_duration === 'on',
      max_devices_default: parseInt(max_devices_default) || 1,
      is_active: true, created_by: req.admin.email
    });
    await Log.create({ action: 'admin_created', details: `${req.admin.email} tạo admin ${email}`, ip_address: req.ip });
    res.redirect('/admin/admins?success=created');
  } catch (err) { res.redirect('/admin/admins?error=' + encodeURIComponent(err.message)); }
});

router.post('/admins/update/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Admin.findByPk(req.params.id);
    if (!a) return res.redirect('/admin/admins?error=not_found');
    const { name, role, quota, can_choose_tier, can_choose_duration, max_devices_default, is_active, new_password } = req.body;
    a.name = name; a.role = role;
    a.quota = parseInt(quota) || 0;
    a.can_choose_tier = can_choose_tier === 'on';
    a.can_choose_duration = can_choose_duration === 'on';
    a.max_devices_default = parseInt(max_devices_default) || 1;
    a.is_active = is_active === 'on';
    if (new_password) a.password_hash = bcrypt.hashSync(new_password, 10);
    await a.save();
    res.redirect('/admin/admins?success=updated');
  } catch (err) { res.redirect('/admin/admins?error=1'); }
});

router.post('/admins/delete/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Admin.findByPk(req.params.id);
    if (a && a.email !== process.env.ADMIN_EMAIL) await a.destroy();
    res.redirect('/admin/admins?success=deleted');
  } catch (err) { res.redirect('/admin/admins?error=1'); }
});

// ============================================
// NGƯỜI BÁN - SELLERS (chỉ Super Admin)
// ============================================
router.get('/sellers', requireSuperAdmin, async (req, res) => {
  try {
    const sellers = await Seller.findAll({ order: [['createdAt', 'DESC']] });
    res.render('admin/sellers', {
      user: req.admin, isSuper: true, sellers, currentPage: 'sellers',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/sellers/create', requireSuperAdmin, async (req, res) => {
  try {
    // 🔒 TRIM tất cả input để tránh khoảng trắng thừa
    const email = (req.body.email || '').trim().toLowerCase();
    const password = (req.body.password || '').trim();
    const name = (req.body.name || '').trim();
    const phone = (req.body.phone || '').trim();
    const { quota, can_choose_tier, can_choose_duration, default_tier, max_devices_default } = req.body;
    
    // 🔍 LOG để debug
    console.log('🎬 CREATE SELLER:', { 
      email, 
      password_len: password.length, 
      name,
      has_leading_space: req.body.password !== password  // true nếu có space bị cắt
    });
    
    // ✅ VALIDATE
    if (!email) return res.redirect('/admin/sellers?error=' + encodeURIComponent('Thiếu email'));
    if (!password || password.length < 6) {
      return res.redirect('/admin/sellers?error=' + encodeURIComponent('Mật khẩu phải >= 6 ký tự'));
    }
    
    // Check trùng
    const dup = await Seller.findOne({ where: { email } });
    if (dup) {
      return res.redirect('/admin/sellers?error=' + encodeURIComponent('Email đã tồn tại: ' + email));
    }
    
    // Tạo seller
    const hash = bcrypt.hashSync(password, 10);
    const seller = await Seller.create({
      email, 
      password_hash: hash,
      name: name || 'Seller', 
      phone: phone || null,
      quota: parseInt(quota) || 0, 
      quota_used: 0,
      can_choose_tier: can_choose_tier === 'on',
      can_choose_duration: can_choose_duration === 'on',
      default_tier: default_tier || 'Normal',
      max_devices_default: parseInt(max_devices_default) || 1,
      is_active: true, 
      created_by: req.admin.email
    });
    
    // 🧪 VERIFY ngay sau khi tạo
    const verify = bcrypt.compareSync(password, seller.password_hash);
    console.log('🧪 Verify login:', verify ? '✅ PASS' : '❌ FAIL');
    console.log('✅ Seller created ID:', seller.id);
    
    res.redirect('/admin/sellers?success=created');
  } catch (err) {
    console.error('❌ CREATE SELLER ERROR:', err);
    res.redirect('/admin/sellers?error=' + encodeURIComponent(err.message));
  }
});
router.post('/sellers/update/:id', requireSuperAdmin, async (req, res) => {
  try {
    const s = await Seller.findByPk(req.params.id);
    if (!s) return res.redirect('/admin/sellers');
    const { name, phone, quota, can_choose_tier, can_choose_duration, default_tier, max_devices_default, is_active, new_password } = req.body;
    s.name = name; s.phone = phone;
    s.quota = parseInt(quota) || 0;
    s.can_choose_tier = can_choose_tier === 'on';
    s.can_choose_duration = can_choose_duration === 'on';
    s.default_tier = default_tier; s.max_devices_default = parseInt(max_devices_default) || 1;
    s.is_active = is_active === 'on';
    if (new_password) s.password_hash = bcrypt.hashSync(new_password, 10);
    await s.save();
    res.redirect('/admin/sellers?success=updated');
  } catch (err) { res.redirect('/admin/sellers?error=1'); }
});

router.post('/sellers/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await Seller.destroy({ where: { id: req.params.id } }); res.redirect('/admin/sellers?success=deleted'); }
  catch (err) { res.redirect('/admin/sellers?error=1'); }
});

// ============================================
// PHIÊN BẢN APP - VERSIONS (chỉ Super Admin)
// ============================================
router.get('/versions', requireSuperAdmin, async (req, res) => {
  try {
    const versions = await AppVersion.findAll({ order: [['version_code', 'DESC']] });
    res.render('admin/versions', {
      user: req.admin, isSuper: true, versions, currentPage: 'versions',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/versions/create', requireSuperAdmin, async (req, res) => {
  try {
    const { version_code, version_name, download_url, changelog, is_required, min_supported_version, release_channel } = req.body;
    await AppVersion.create({
      version_code: parseInt(version_code), version_name, download_url, changelog,
      is_required: is_required === 'on',
      min_supported_version: parseInt(min_supported_version) || 0,
      release_channel: release_channel || 'stable',
      is_active: true, update_enabled: true
    });
    res.redirect('/admin/versions?success=created');
  } catch (err) { res.redirect('/admin/versions?error=1'); }
});

router.post('/versions/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await AppVersion.destroy({ where: { id: req.params.id } }); res.redirect('/admin/versions?success=deleted'); }
  catch (err) { res.redirect('/admin/versions?error=1'); }
});

// ============================================
// THÔNG BÁO - ANNOUNCEMENTS (API cho app)
// ============================================
router.get('/announcements', requireSuperAdmin, async (req, res) => {
  try {
    const announcements = await Announcement.findAll({ order: [['priority', 'DESC'], ['createdAt', 'DESC']] });
    res.render('admin/announcements', {
      user: req.admin, isSuper: true, announcements, currentPage: 'announcements',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/announcements/create', requireSuperAdmin, async (req, res) => {
  try {
    const { title, message, type, priority, is_dismissible } = req.body;
    await Announcement.create({
      title, message, type: type || 'info',
      priority: parseInt(priority) || 5,
      is_dismissible: is_dismissible === 'on',
      is_enabled: true, created_by: req.admin.email
    });
    await Log.create({ action: 'announcement_created', details: `${req.admin.email} tạo thông báo: ${title}`, ip_address: req.ip });
    res.redirect('/admin/announcements?success=created');
  } catch (err) { res.redirect('/admin/announcements?error=1'); }
});

router.post('/announcements/toggle/:id', requireSuperAdmin, async (req, res) => {
  try {
    const a = await Announcement.findByPk(req.params.id);
    if (a) { a.is_enabled = !a.is_enabled; await a.save(); }
    res.redirect('/admin/announcements?success=toggled');
  } catch (err) { res.redirect('/admin/announcements?error=1'); }
});

router.post('/announcements/delete/:id', requireSuperAdmin, async (req, res) => {
  try { await Announcement.destroy({ where: { id: req.params.id } }); res.redirect('/admin/announcements?success=deleted'); }
  catch (err) { res.redirect('/admin/announcements?error=1'); }
});

// ============================================
// TÀI KHOẢN - PROFILE (mọi admin)
// ============================================
router.get('/profile', async (req, res) => {
  try {
    const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
    let adminInfo = null;
    if (req.admin.id) adminInfo = await Admin.findByPk(req.admin.id);
    res.render('admin/profile', {
      user: req.admin, isSuper, adminInfo, currentPage: 'profile',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/profile/change-password', async (req, res) => {
  try {
    const { old_password, new_password, confirm_password } = req.body;
    if (!old_password || !new_password || !confirm_password) return res.redirect('/admin/profile?error=missing');
    if (new_password !== confirm_password) return res.redirect('/admin/profile?error=password_mismatch');
    if (new_password.length < 6) return res.redirect('/admin/profile?error=too_short');
    const admin = await Admin.findByPk(req.admin.id);
    if (!admin) return res.redirect('/admin/profile?error=not_found');
    if (!bcrypt.compareSync(old_password, admin.password_hash)) return res.redirect('/admin/profile?error=wrong_password');
    admin.password_hash = bcrypt.hashSync(new_password, 10);
    await admin.save();
    res.redirect('/admin/profile?success=password_changed');
  } catch (err) { res.redirect('/admin/profile?error=system'); }
});

module.exports = router;
