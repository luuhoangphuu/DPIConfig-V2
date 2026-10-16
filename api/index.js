const pg = require('pg');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const sequelize = require('../config/database');
const apiRoutes = require('../routes/api');
const adminRoutes = require('../routes/admin');
// Import models để đảm bảo sequelize biết về chúng
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
app.get('/', (req, res) => res.redirect('/admin/dashboard'));

// ============ KHỞI TẠO DATABASE ============
let dbReady = false;
const dbInitPromise = (async () => {
  try {
    await sequelize.authenticate();
    console.log('DB connected.');
    await sequelize.sync({ alter: true });
    console.log('Models synced - all tables created.');
    dbReady = true;
  } catch (err) {
    console.error('DB init error:', err);
  }
})();

// Middleware chờ DB sẵn sàng trước khi xử lý request
app.use(async (req, res, next) => {
  if (!dbReady) {
    try {
      await dbInitPromise;
    } catch (e) {
      console.error('DB wait error:', e);
    }
  }
  next();
});


// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  console.error('=== ERROR ===');
  console.error('Path:', req.path);
  console.error('Message:', err.message);
  console.error('Stack:', err.stack);
  
  res.status(500).send(`
    <html>
      <head>
        <title>Lỗi - Chi tiết</title>
        <style>
          body { font-family: monospace; padding: 30px; background: #0a1e3f; color: #fff; }
          h1 { color: #ef5350; }
          pre { background: #050d1f; padding: 20px; border-radius: 8px; overflow: auto; color: #81d4fa; }
          .path { color: #ffd700; }
          a { color: #4fc3f7; }
        </style>
      </head>
      <body>
        <h1>⚠️ Lỗi máy chủ</h1>
        <p>Path: <span class="path">${req.path}</span></p>
        <p>Message: <strong style="color: #ef5350;">${err.message}</strong></p>
        <pre>${err.stack || 'No stack trace'}</pre>
        <p><a href="/admin/dashboard">← Về Dashboard</a></p>
      </body>
    </html>
  `);
});

module.exports = app;
