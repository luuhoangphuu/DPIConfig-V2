const { Sequelize } = require('sequelize');
const pg = require('pg'); // Bắt buộc load pg để Sequelize nhận diện
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectModule: pg, // Chỉ định rõ module pg
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  }
});

module.exports = sequelize;
