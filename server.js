require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const cron = require('node-cron');
const sequelize = require('./config/database');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const portalRoutes = require('./routes/portal');
const { Key } = require('./models');
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
app.use('/portal', portalRoutes);
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

    // Cron job: kiểm tra key sắp hết hạn mỗi ngày lúc 9h sáng (UTC)
    cron.schedule('0 9 * * *', async () => {
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
        console.error('Cron error:', err);
      }
    });

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Startup error:', err);
  }
}

start();
