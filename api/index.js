const pg = require('pg');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const sequelize = require('../config/database');
const apiRoutes = require('../routes/api');
const adminRoutes = require('../routes/admin');
const sellerRoutes = require('../routes/seller');
require('../models');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', apiRoutes);
app.use('/admin', adminRoutes);
app.use('/seller', sellerRoutes);
app.get('/', (req, res) => res.redirect('/admin/dashboard'));

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

    await sequelize.sync({ alter: true });
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
