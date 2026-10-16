const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const ExpressBrute = require('express-brute');
const { requireSuperAdmin } = require('../middleware/roleCheck');
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

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.redirect('/admin/login');
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.redirect('/admin/login'); }
}

router.get('/login', (req, res) => res.render('admin/login', { error: null }));

router.post('/login', bruteforce.prevent, async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // 1. Check trong DB trước
    const dbAdmin = await Admin.findOne({ where: { email, is_active: true } });
    if (dbAdmin && bcrypt.compareSync(password, dbAdmin.password_hash)) {
      dbAdmin.last_login = new Date();
      await dbAdmin.save();
      
      const token = jwt.sign({ 
        id: dbAdmin.id,
        email, 
        role: dbAdmin.role,
        name: dbAdmin.name,
        is_super: dbAdmin.role === 'super'
      }, JWT_SECRET, { expiresIn: '7d' });
      
      res.cookie('admin_token', token, {
        httpOnly: true, secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000
      });
      return res.redirect('/admin/dashboard');
    }
    
    // 2. Fallback: env owner (luôn là super)
    if (email === ADMIN_EMAIL && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
      const token = jwt.sign({ 
        email, 
        role: 'super', 
        name: 'Owner',
        is_super: true
      }, JWT_SECRET, { expiresIn: '7d' });
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
});,
      totalKeys, activeKeys, expiredKeys, vipKeys, devicesActivated, recentLogs,
      showAll
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Lỗi máy chủ');
  }
});

// KEYS
router.get('/keys', async (req, res) => {
  const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
  const page = parseInt(req.query.page) || 1, limit = 15, offset = (page - 1) * limit;
  const search = req.query.search || '';
  
  let where = {};
  // Admin thường chỉ thấy key mình tạo
  if (!isSuper && req.admin.id) {
    where.admin_id = req.admin.id;
  }
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
});
});

router.post('/keys/create', async (req, res) => {
  const isSuper = req.admin.role === 'super' || req.admin.is_super === true;
  const { tier, duration, prefix, max_devices } = req.body;
  
  try {
    // Admin thường: check quota
    let adminRecord = null;
    if (!isSuper && req.admin.id) {
      adminRecord = await Admin.findByPk(req.admin.id);
      if (!adminRecord) return res.redirect('/admin/login');
      
      if (adminRecord.quota_used >= adminRecord.quota) {
        return res.redirect('/admin/keys?error=quota_exceeded');
      }
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
      key, tier, expires_at,
      max_devices: maxDev,
      created_by: req.admin.email,
      admin_id: req.admin.id || null
    });
    
    // Tăng quota_used
    if (adminRecord) {
      adminRecord.quota_used = (adminRecord.quota_used || 0) + 1;
      await adminRecord.save();
    }
    
    await Log.create({ action: 'key_created', details: `${req.admin.email} tạo key ${key}`, ip_address: req.ip });
    res.redirect('/admin/keys?created=1');
  } catch (err) {
    console.error(err);
    res.redirect('/admin/keys?error=create_failed');
  }
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


// Toggle bật/tắt thông báo update cho app
router.post('/versions/toggle-update/:id', async (req, res) => {
  try {
    const v = await AppVersion.findByPk(req.params.id);
    if (v) {
      v.update_enabled = !v.update_enabled;
      await v.save();
      await Log.create({
        action: v.update_enabled ? 'version_update_enabled' : 'version_update_disabled',
        details: `${v.update_enabled ? 'Bật' : 'Tắt'} thông báo update cho ${v.version_name}`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/versions?toggled=1');
  } catch (err) {
    console.error(err);
    res.redirect('/admin/versions?error=toggle_failed');
  }
});

// ==================== QUẢN LÝ THÔNG BÁO CHUNG ====================
router.get('/announcements', async (req, res) => {
  try {
    const announcements = await Announcement.findAll({ order: [['priority', 'DESC'], ['createdAt', 'DESC']] });
    res.render('admin/announcements', { user: req.admin, announcements });
  } catch (err) {
    console.error('Announcements page error:', err);
    res.status(500).send(`
      <div style="font-family: monospace; padding: 40px; background: #0a1e3f; color: #ffd700; min-height: 100vh;">
        <h2>⚠️ Lỗi tải trang Thông báo</h2>
        <p style="color: #ef5350;">${err.message}</p>
        <pre style="background: #050d1f; padding: 20px; border-radius: 8px; overflow: auto; color: #81d4fa;">${err.stack}</pre>
        <p><a href="/admin/dashboard" style="color: #4fc3f7;">← Về Dashboard</a></p>
      </div>
    `);
  }
});

router.post('/announcements/create', async (req, res) => {
  try {
    const { title, message, type, priority, expires_at, is_dismissible } = req.body;
    if (!title || !message) return res.redirect('/admin/announcements?error=missing_fields');

    await Announcement.create({
      title,
      message,
      type: type || 'info',
      priority: parseInt(priority) || 5,
      expires_at: expires_at ? new Date(expires_at) : null,
      is_dismissible: is_dismissible === 'on',
      created_by: req.admin.email
    });
    await Log.create({ action: 'announcement_created', details: `Tạo thông báo: ${title}`, ip_address: req.ip });
    res.redirect('/admin/announcements?created=1');
  } catch (err) {
    console.error(err);
    res.redirect('/admin/announcements?error=create_failed');
  }
});

router.post('/announcements/toggle/:id', async (req, res) => {
  const a = await Announcement.findByPk(req.params.id);
  if (a) {
    a.is_enabled = !a.is_enabled;
    await a.save();
    await Log.create({
      action: a.is_enabled ? 'announcement_enabled' : 'announcement_disabled',
      details: `${a.is_enabled ? 'Bật' : 'Tắt'} thông báo: ${a.title}`,
      ip_address: req.ip
    });
  }
  res.redirect('/admin/announcements?toggled=1');
});

router.post('/announcements/delete/:id', async (req, res) => {
  const a = await Announcement.findByPk(req.params.id);
  if (a) {
    const title = a.title;
    await a.destroy();
    await Log.create({ action: 'announcement_deleted', details: `Xóa thông báo: ${title}`, ip_address: req.ip });
  }
  res.redirect('/admin/announcements?deleted=1');
});


// ==================== QUẢN LÝ ADMIN (chỉ SUPER ADMIN) ====================

router.get('/admins', requireSuperAdmin, async (req, res) => {
  try {
    const admins = await Admin.findAll({ order: [['createdAt', 'DESC']] });
    
    // Đếm key mỗi admin đã tạo
    const adminsWithStats = await Promise.all(admins.map(async (a) => {
      const keyCount = await Key.count({ where: { admin_id: a.id } });
      return { ...a.toJSON(), keyCount };
    }));
    
    res.render('admin/admins', { 
      user: req.admin, 
      admins: adminsWithStats,
      envAdminEmail: process.env.ADMIN_EMAIL 
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Lỗi tải trang');
  }
});

router.post('/admins/create', requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, name, role, quota, can_choose_tier, can_choose_duration, max_devices_default, notes } = req.body;
    if (!email || !password) return res.redirect('/admin/admins?error=missing');
    
    // Check email trùng
    const existing = await Admin.findOne({ where: { email } });
    if (existing) return res.redirect('/admin/admins?error=email_exists');
    
    // Không cho tạo trùng email admin chính
    if (email === process.env.ADMIN_EMAIL) {
      return res.redirect('/admin/admins?error=email_exists');
    }
    
    const hash = bcrypt.hashSync(password, 10);
    const newAdmin = await Admin.create({
      email,
      password_hash: hash,
      name: name || email,
      role: role || 'admin',   // super hoặc admin
      quota: parseInt(quota) || 0,
      can_choose_tier: can_choose_tier === 'on',
      can_choose_duration: can_choose_duration === 'on',
      max_devices_default: parseInt(max_devices_default) || 1,
      notes: notes || null,
      created_by: req.admin.email
    });
    
    await Log.create({
      action: 'admin_created',
      details: `${req.admin.email} tạo tài khoản ${role || 'admin'}: ${email} (quota: ${quota})`,
      ip_address: req.ip
    });
    
    res.redirect('/admin/admins?created=1');
  } catch (err) {
    console.error(err);
    res.redirect('/admin/admins?error=create_failed');
  }
});

router.post('/admins/toggle/:id', requireSuperAdmin, async (req, res) => {
  try {
    const target = await Admin.findByPk(req.params.id);
    if (target) {
      if (target.email === req.admin.email) {
        return res.redirect('/admin/admins?error=self_action');
      }
      target.is_active = !target.is_active;
      await target.save();
      await Log.create({
        action: target.is_active ? 'admin_enabled' : 'admin_disabled',
        details: `${target.is_active ? 'Mở khóa' : 'Khóa'} admin ${target.email}`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/admins?toggled=1');
  } catch (err) {
    res.redirect('/admin/admins?error=toggle_failed');
  }
});

router.post('/admins/add-quota/:id', requireSuperAdmin, async (req, res) => {
  try {
    const { amount } = req.body;
    const target = await Admin.findByPk(req.params.id);
    if (target && amount) {
      target.quota = (target.quota || 0) + parseInt(amount);
      await target.save();
      await Log.create({
        action: 'admin_quota_added',
        details: `Thêm ${amount} quota cho admin ${target.email} (tổng: ${target.quota})`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/admins?quota_added=1');
  } catch (err) {
    res.redirect('/admin/admins?error=quota_failed');
  }
});

router.post('/admins/reset-quota/:id', requireSuperAdmin, async (req, res) => {
  try {
    const target = await Admin.findByPk(req.params.id);
    if (target) {
      target.quota_used = 0;
      await target.save();
      await Log.create({
        action: 'admin_quota_reset',
        details: `Reset quota_used cho admin ${target.email}`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/admins?quota_reset=1');
  } catch (err) {
    res.redirect('/admin/admins?error=reset_failed');
  }
});

router.post('/admins/change-role/:id', requireSuperAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const target = await Admin.findByPk(req.params.id);
    if (target && ['super', 'admin'].includes(role)) {
      if (target.email === req.admin.email) {
        return res.redirect('/admin/admins?error=self_action');
      }
      target.role = role;
      await target.save();
      await Log.create({
        action: 'admin_role_changed',
        details: `Đổi role của ${target.email} thành ${role}`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/admins?role_changed=1');
  } catch (err) {
    res.redirect('/admin/admins?error=role_failed');
  }
});

router.post('/admins/delete/:id', requireSuperAdmin, async (req, res) => {
  try {
    const target = await Admin.findByPk(req.params.id);
    if (target) {
      if (target.email === req.admin.email) {
        return res.redirect('/admin/admins?error=self_action');
      }
      const email = target.email;
      // Xóa key cũ của admin, hoặc set null để giữ key
      await Key.update({ admin_id: null }, { where: { admin_id: target.id } });
      await target.destroy();
      await Log.create({
        action: 'admin_deleted',
        details: `Xóa admin ${email}`,
        ip_address: req.ip
      });
    }
    res.redirect('/admin/admins?deleted=1');
  } catch (err) {
    res.redirect('/admin/admins?error=delete_failed');
  }
});

module.exports = router;
