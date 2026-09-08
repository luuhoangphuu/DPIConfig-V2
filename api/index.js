const pg = require('pg');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const sequelize = require('../config/database');
const apiRoutes = require('../routes/api');
const adminRoutes = require('../routes/admin');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Routes
app.use('/api', apiRoutes);
app.use('/admin', adminRoutes);
app.get('/', (req, res) => res.redirect('/admin/dashboard'));

// Khởi tạo database
sequelize.authenticate()
  .then(() => {
    console.log('Database connected.');
    return sequelize.sync({ alter: true });
  })
  .then(() => console.log('Models synced.'))
  .catch(err => console.error('DB error:', err));

module.exports = app;
