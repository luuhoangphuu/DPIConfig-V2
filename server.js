require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const { DataTypes } = require('sequelize');
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

    const queryInterface = sequelize.getQueryInterface();
    const tableInfo = await queryInterface.describeTable('key_devices');

    // Thêm cột device_name nếu chưa có
    if (!tableInfo.device_name) {
      await queryInterface.addColumn('key_devices', 'device_name', {
        type: DataTypes.STRING(255),
        allowNull: true,
      });
      console.log('Added column device_name to key_devices.');
    } else {
      console.log('Column device_name already exists.');
    }

    // Thêm cột is_active nếu chưa có
    if (!tableInfo.is_active) {
      await queryInterface.addColumn('key_devices', 'is_active', {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
      });
      console.log('Added column is_active to key_devices.');
    } else {
      console.log('Column is_active already exists.');
    }

    // Đồng bộ model (sẽ thêm các ràng buộc, index nếu cần)
    await sequelize.sync({ alter: true });
    console.log('Models synced (alter).');

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup error:', err);
  }
}

start();
