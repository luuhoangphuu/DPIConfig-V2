process.env.TZ = 'Asia/Ho_Chi_Minh';
const pg = require('pg');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const sequelize = require('../config/database');
const apiRoutes = require('../routes/api');
const adminRoutes = require('../routes/admin');
const botBlocker = require('../middleware/botBlocker');
const csrfProtection = require('../middleware/csrfProtection');
const sellerRoutes = require('../routes/seller');
require('../models');

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(csrfProtection);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));


// ================= BẢO MẬT TOÀN DIỆN =================
// 1. Chặn Bot dò quét
app.use(botBlocker);

// 2. Bảo vệ Header (Chống XSS, Clickjacking, MIME Sniffing)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.removeHeader('X-Powered-By'); // Giấu công nghệ
  next();
});
// ======================================================


// ==================== API BẢO MẬT CAO (TÁCH RIÊNG KHỎI /api) ====================
const ycutieAuth = require('../middleware/yncutieAuth');
const genKeyLimiter = require('../middleware/genKeyLimiter');
const crypto = require('crypto');
const { Key, Log } = require('../models');

app.post('/yncutie', genKeyLimiter, ycutieAuth, async (req, res) => {
  try {
    const { tier, prefix } = req.body;
    const chosenTier = (tier && String(tier).toLowerCase() === 'vip') ? 'VIP' : 'Normal';
    const FIXED_HOURS = chosenTier === 'VIP' ? 2 : 8;
    
    const expires_at = new Date();
    expires_at.setHours(expires_at.getHours() + FIXED_HOURS);

    const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
    const key = `${prefix || 'ZwicApex'}-${randomPart.match(/.{1,4}/g).join('-')}`;

    await Key.create({ key, tier: chosenTier, expires_at, max_devices: 1, created_by: 'api-secure' });

    await Log.create({
      action: 'api_key_created',
      details: `API bảo mật tạo key ${key} | tier=${chosenTier} | IP=${req.ip}`,
      ip_address: req.ip
    });

    return res.json({ success: true, key, tier: chosenTier, expires_at: expires_at.toISOString() });
  } catch (err) {
    console.error('[YNCUTIE API] Error:', err);
    return res.status(500).json({ success: false, error: 'Lỗi máy chủ.' });
  }
});
// ==============================================================================

app.use('/api', apiRoutes);
// Inject env vars cho tất cả EJS views
app.use((req, res, next) => {
  res.locals.envAdminEmail = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
  res.locals.envJwtSecret = process.env.JWT_SECRET || '';
  next();
});

app.use('/admin', adminRoutes);
app.use('/seller', sellerRoutes);

// BLOCK OLD ADMIN
app.use('/admin', (req, res) => res.status(404).send('Not Found')); 
app.use('/yncuti', adminRoutes);

app.get('/', (req, res) => res.redirect('/seller/login'));

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  console.error('=== ERROR ===', err.message);
  res.status(500).send(`
    <html><body style="font-family:monospace;padding:30px;background:#0a1e3f;color:#fff">
    <h1 style="color:#ef5350">⚠️ Lỗi</h1>
    <p>Path: <b style="color:#ffd700">${req.path}</b></p>
    <p>Message: <b style="color:#ef5350">${err.message}</b></p>
    <pre style="background:#050d1f;padding:20px;border-radius:8px;overflow:auto;color:#81d4fa">${err.stack || ''}</pre>
    <p><a href="/admin/force-logout" style="color:#4fc3f7">Force logout</a></p>
    </body></html>
  `);
});

// ============ INIT DB + SERVER ============
async function initApp() {
  try {
    await sequelize.authenticate();
    console.log('DB connected.');

    // ALTER TABLE thủ công trước khi sync
    await sequelize.query(`ALTER TABLE "keys" ADD COLUMN IF NOT EXISTS "admin_id" INTEGER;`);
    await sequelize.query(`ALTER TABLE "keys" ADD COLUMN IF NOT EXISTS "seller_id" INTEGER;`);
    console.log('Columns ensured.');

    // Đảm bảo cột starts_at tồn tại trong DB
    await sequelize.query('ALTER TABLE "announcements" ADD COLUMN IF NOT EXISTS "starts_at" TIMESTAMP WITH TIME ZONE;');
    
    await sequelize.sync({ alter: true });

    // SYNC ADMIN ENV VÀO DB (Để không bị lỗi foreign key)
    const bcrypt = require('bcryptjs');
    const { Admin } = require('../models');
    const envEmail = process.env.ADMIN_EMAIL || 'admin@dpiconfig.com';
    const envPassHash = process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync('admin123', 10);
    const existing = await Admin.findOne({ where: { email: envEmail } });
    if (!existing) {
      await Admin.create({ email: envEmail, password_hash: envPassHash, name: 'Super Owner', role: 'super', quota: 999999, is_active: true });
      console.log('✅ Đã đồng bộ tài khoản ENV vào DB');
    } else if (existing.role !== 'super') {
      existing.role = 'super'; await existing.save();
    }
  
    console.log('Models synced.');

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log('Server on port', PORT));
  } catch (err) {
    console.error('Init error:', err);
    // Vẫn export app để Vercel không crash — lỗi sẽ hiện khi có request
  }
}
initApp();

module.exports = app;
