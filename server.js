require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const sequelize = require('./config/database');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');

const app = express();
app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieSession({
  name: 'dpiconfig_session',
  secret: process.env.SESSION_SECRET || 'defaultSecret',
  maxAge: 30 * 24 * 60 * 60 * 1000,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax'
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');
  next();
});

app.use('/api', apiRoutes);
app.use('/admin', adminRoutes);
app.get('/', (req, res) => res.redirect('/admin/dashboard'));

const PORT = process.env.PORT || 3000;

async function start() {
  try {
    await sequelize.authenticate();
    console.log('Database connected.');

    // Thêm cột is_active nếu chưa có (cho bảng key_devices)
    try {
      await sequelize.query(`
        ALTER TABLE key_devices 
        ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
      `);
      console.log('Column is_active ensured on key_devices.');
    } catch (alterError) {
      console.warn('Failed to add column is_active (may already exist):', alterError.message);
    }

    // Đồng bộ model (sẽ không xóa dữ liệu)
    await sequelize.sync({ alter: true });
    console.log('Models synced (alter).');

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup error:', err);
  }
}

start();
