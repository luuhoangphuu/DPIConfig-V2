const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Seller = sequelize.define('Seller', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING(100), unique: true, allowNull: false },
  password_hash: { type: DataTypes.STRING(100), allowNull: false },
  name: { type: DataTypes.STRING(100), allowNull: false },
  phone: { type: DataTypes.STRING(20), allowNull: true },
  quota: { type: DataTypes.INTEGER, defaultValue: 0 },
  quota_used: { type: DataTypes.INTEGER, defaultValue: 0 },
  can_choose_tier: { type: DataTypes.BOOLEAN, defaultValue: true },
  can_choose_duration: { type: DataTypes.BOOLEAN, defaultValue: true },
  default_tier: { type: DataTypes.ENUM('VIP', 'Normal'), defaultValue: 'Normal' },
  max_devices_default: { type: DataTypes.INTEGER, defaultValue: 1 },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  notes: { type: DataTypes.TEXT, allowNull: true },
  last_login: { type: DataTypes.DATE, allowNull: true },
  created_by: { type: DataTypes.STRING, allowNull: true }
}, { timestamps: true, tableName: 'sellers' });

module.exports = Seller;
