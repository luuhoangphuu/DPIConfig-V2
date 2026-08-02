const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const Log = sequelize.define('Log', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  action: { type: DataTypes.STRING(50), allowNull: false },
  details: { type: DataTypes.TEXT, allowNull: true },
  ip_address: { type: DataTypes.STRING(45), allowNull: true },
  key_id: { type: DataTypes.INTEGER, allowNull: true, references: { model: 'keys', key: 'id' } }
}, { timestamps: true, tableName: 'logs' });
module.exports = Log;
