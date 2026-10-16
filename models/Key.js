const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Key = sequelize.define('Key', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  key: { type: DataTypes.STRING(50), unique: true, allowNull: false },
  tier: { type: DataTypes.ENUM('VIP', 'Normal'), allowNull: false },
  expires_at: { type: DataTypes.DATE, allowNull: false },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  max_devices: { type: DataTypes.INTEGER, defaultValue: 1 },
  created_by: { type: DataTypes.STRING, allowNull: true },   // email người tạo
  admin_id: { type: DataTypes.INTEGER, allowNull: true },     // ID admin (nếu tạo từ web)
  seller_id: { type: DataTypes.INTEGER, allowNull: true }     // ID seller (nếu tạo từ seller)
}, { timestamps: true, tableName: 'keys' });

module.exports = Key;
