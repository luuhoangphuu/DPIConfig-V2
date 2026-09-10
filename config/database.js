const { Sequelize } = require('sequelize');
const pg = require('pg');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectModule: pg,
  dialectOptions: {
    ssl: { require: true, rejectUnauthorized: false }
  }
});

module.exports = sequelize;
