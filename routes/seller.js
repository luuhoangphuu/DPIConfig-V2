const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const { Key, Log, KeyDevice, Seller } = require('../models');
const sellerAuth = require('../middleware/sellerAuth');
const loginLimiter = require('../middleware/loginLimiter');

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecret';

router.get('/login', (req, res) => {
  if (req.cookies.seller_token) return res.redirect('/seller/dashboard');
  res.render('seller/login', { error: null });
});

router.post('/login', loginLimiter, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = (req.body.password || '').trim();
  console.log('🔐 SELLER LOGIN:', { email, password_len: password.length });
  try {
    const seller = await Seller.findOne({ where: { email, is_active: true } });
    if (!seller || !bcrypt.compareSync(password, seller.password_hash)) {
      return res.render('seller/login', { error: 'Sai email hoặc mật khẩu' });
    }
    seller.last_login = new Date();
    seller.session_token = crypto.randomBytes(16).toString('hex');
    seller.last_login_ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
    await seller.save();
    const token = jwt.sign(
      { id: seller.id, email: seller.email, name: seller.name, session_token: seller.session_token, type: 'seller' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.cookie('seller_token', token, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.redirect('/seller/dashboard');
  } catch (err) {
    console.error(err);
    res.render('seller/login', { error: 'Lỗi hệ thống' });
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('seller_token');
  res.redirect('/seller/login');
});

router.use(sellerAuth);

router.get('/dashboard', async (req, res) => {
  try {
    const seller = await Seller.findByPk(req.seller.id);
    if (!seller || !seller.is_active) {
      res.clearCookie('seller_token');
      return res.redirect('/seller/login');
    }
    const totalKeys = await Key.count({ where: { seller_id: seller.id } });
    const activeKeys = await Key.count({ where: { seller_id: seller.id, is_active: true } });
    const expiredKeys = await Key.count({
      where: { seller_id: seller.id, expires_at: { [Op.lt]: new Date() } }
    });
    res.render('seller/dashboard', { seller, totalKeys, activeKeys, expiredKeys });
  } catch (err) { console.error(err); res.status(500).send('Lỗi máy chủ'); }
});

router.get('/keys', async (req, res) => {
  try {
    const seller = await Seller.findByPk(req.seller.id);
    const page = parseInt(req.query.page) || 1;
    const limit = 15;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    let where = { seller_id: seller.id };
    if (search) {
      where = {
        seller_id: seller.id,
        [Op.or]: [
          { key: { [Op.iLike]: `%${search}%` } },
          { hwid: { [Op.iLike]: `%${search}%` } }
        ]
      };
    }
    const { count, rows: keys } = await Key.findAndCountAll({
      where, order: [['createdAt', 'DESC']],
      include: [{ model: KeyDevice, as: 'devices', required: false }],
      limit, offset
    });
    res.render('seller/keys', {
      seller, keys,
      currentPage: page,
      totalPages: Math.ceil(count / limit),
      search
    });
  } catch (err) { console.error(err); res.status(500).send('Lỗi máy chủ'); }
});

router.post('/keys/create', async (req, res) => {
  try {
    const seller = await Seller.findByPk(req.seller.id);
    if (!seller || !seller.is_active) return res.redirect('/seller/login');
    if (seller.quota_used >= seller.quota) return res.redirect('/seller/keys?error=' + encodeURIComponent('Bạn đã hết quota.'));

    const { tier, duration, prefix } = req.body;
    const chosenTier = seller.can_choose_tier ? (tier === 'VIP' ? 'VIP' : 'Normal') : seller.default_tier;
    const dur = seller.can_choose_duration ? (duration || 30) : 30;
    
    let expires_at;
    if (dur === 'forever') expires_at = new Date('2099-12-31T23:59:59');
    else {
      const days = parseFloat(dur) <= 0 ? 30 : parseFloat(dur);
      const hours = Math.round(days * 24);
      expires_at = new Date(); expires_at.setHours(expires_at.getHours() + hours);
    }

    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `ZwicApex-${randomPart.match(/.{1,4}/g).join('-')}`; // Ép cứng tiền tố ZwicApex

    await Key.create({
      key, tier: chosenTier, expires_at, max_devices: seller.max_devices_default, created_by: seller.email, seller_id: seller.id
    });
    
    // 🔥 CẬP NHẬT QUOTA
    seller.quota_used = (seller.quota_used || 0) + 1;
    await seller.save();
    
    await Log.create({ action: 'seller_key_created', details: `Seller ${seller.email} tạo key ${key}`, ip_address: req.ip });
    res.redirect('/seller/keys?created=1');
  } catch (err) { 
    console.error(err);
    res.redirect('/seller/keys?error=' + encodeURIComponent(err.message)); 
  }
});

router.post('/keys/toggle/:id', async (req, res) => {
  try {
    const key = await Key.findOne({ where: { id: req.params.id, seller_id: req.seller.id } });
    if (key) { key.is_active = !key.is_active; await key.save(); }
    res.redirect('/seller/keys?toggled=1');
  } catch (err) { res.redirect('/seller/keys'); }
});

router.get('/keys/devices/:id', async (req, res) => {
  try {
    const key = await Key.findOne({
      where: { id: req.params.id, seller_id: req.seller.id },
      include: [{ model: KeyDevice, as: 'devices', required: false }]
    });
    if (!key) return res.json({ success: false });
    res.json({ success: true, devices: key.devices || [] });
  } catch (err) { res.status(500).json({ success: false }); }
});


// ==================== PROFILE SELLER ====================
router.get('/profile', async (req, res) => {
  try {
    const seller = await Seller.findByPk(req.seller.id);
    if (!seller) return res.redirect('/seller/login');
    res.render('seller/profile', {
      user: seller, seller, currentPage: 'profile',
      success: req.query.success || null, error: req.query.error || null
    });
  } catch (err) { res.status(500).send('Lỗi: ' + err.message); }
});

router.post('/profile/change-password', async (req, res) => {
  try {
    const { old_password, new_password, confirm_password } = req.body;
    if (!old_password || !new_password || !confirm_password) return res.redirect('/seller/profile?error=missing');
    if (new_password !== confirm_password) return res.redirect('/seller/profile?error=password_mismatch');
    if (new_password.length < 6) return res.redirect('/seller/profile?error=too_short');
    
    const seller = await Seller.findByPk(req.seller.id);
    if (!seller) return res.redirect('/seller/login');
    if (!bcrypt.compareSync(old_password, seller.password_hash)) return res.redirect('/seller/profile?error=wrong_password');
    
    seller.password_hash = bcrypt.hashSync(new_password, 10);
    await seller.save();
    
    res.redirect('/seller/profile?success=updated');
  } catch (err) { res.redirect('/seller/profile?error=system'); }
});

module.exports = router;
