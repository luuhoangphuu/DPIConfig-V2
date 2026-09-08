const { Sequelize } = require('sequelize');
const { neon } = require('@neondatabase/serverless');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectModule: neon, // Dùng driver Neon thay vì pg
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  }
});

module.exports = sequelize;
