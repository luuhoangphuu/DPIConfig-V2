// Đặt múi giờ Việt Nam ngay từ đầu
process.env.TZ = 'Asia/Ho_Chi_Minh';

require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const nodeCron = require('node-cron');
const sequelize = require('./config/database');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const { Key, Log, KeyDevice } = require('./models');
const { notifyKeyExpiringSoon } = require('./utils/email');
const { Op } = require('sequelize');

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
    console.log('DB connected.');

    await sequelize.query(`ALTER TABLE key_devices ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);`);
    await sequelize.query(`ALTER TABLE key_devices ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;`);
    await sequelize.sync({ alter: true });
    console.log('Models synced.');

    // ==================== CRON JOB: XÓA LOG CHECK CŨ (MỖI 30 PHÚT) ====================
    nodeCron.schedule('*/30 * * * *', async () => {
      try {
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const deleted = await Log.destroy({
          where: { action: 'check', createdAt: { [Op.lt]: oneDayAgo } }
        });
        if (deleted > 0) console.log(`Deleted ${deleted} old check logs`);
      } catch (err) {
        console.error('Cleanup check logs error:', err);
      }
    }, { timezone: 'Asia/Ho_Chi_Minh' });

    // ==================== CRON JOB: CẢNH BÁO KEY SẮP HẾT HẠN (9H SÁNG HÀNG NGÀY) ====================
    nodeCron.schedule('0 9 * * *', async () => {
      console.log('Checking expiring keys...');
      try {
        const threeDaysFromNow = new Date();
        threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);
        const expiringKeys = await Key.findAll({
          where: {
            is_active: true,
            expires_at: { [Op.lte]: threeDaysFromNow, [Op.gt]: new Date() }
          }
        });
        for (const key of expiringKeys) {
          const daysLeft = Math.ceil((new Date(key.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
          await notifyKeyExpiringSoon(key.key, daysLeft);
        }
      } catch (err) {
        console.error('Cron warning expiring keys error:', err);
      }
    }, { timezone: 'Asia/Ho_Chi_Minh' });

    // ==================== CRON JOB: TỰ ĐỘNG XÓA KEY HẾT HẠN (MỖI 3 PHÚT) ====================
    nodeCron.schedule('*/3 * * * *', async () => {
      try {
        const now = new Date();
        // Lấy tất cả key có expires_at < now (chắc chắn đã hết hạn)
        const expiredKeys = await Key.findAll({
          where: {
            expires_at: { [Op.lt]: now }
          }
        });

        for (const key of expiredKeys) {
          // Xóa tất cả thiết bị liên quan
          const deletedDevices = await KeyDevice.destroy({ where: { key_id: key.id } });
          // Xóa key
          await key.destroy();
          // Ghi log
          await Log.create({
            action: 'key_expired_deleted',
            details: `Hệ thống tự động xóa key ${key.key} (đã hết hạn, ${deletedDevices} thiết bị bị xóa)`,
            ip_address: 'system'
          });
          console.log(`Deleted expired key ${key.key}`);
        }
      } catch (err) {
        console.error('Cron delete expired keys error:', err);
      }
    }, { timezone: 'Asia/Ho_Chi_Minh' });

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup error:', err);
  }
}

start();
