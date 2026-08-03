const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Key = sequelize.define('Key', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  key: { type: DataTypes.STRING(50), unique: true, allowNull: false },
  tier: { type: DataTypes.ENUM('VIP', 'Normal'), allowNull: false },
  expires_at: { type: DataTypes.DATE, allowNull: false },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  max_devices: { type: DataTypes.INTEGER, defaultValue: 1, allowNull: false }, // số thiết bị tối đa
  created_by: { type: DataTypes.STRING, allowNull: true }
}, { timestamps: true, tableName: 'keys' });

module.exports = Key;
