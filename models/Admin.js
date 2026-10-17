const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Admin = sequelize.define('Admin', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING(100), unique: true, allowNull: false },
  password_hash: { type: DataTypes.STRING(100), allowNull: false },
  name: { type: DataTypes.STRING(100), allowNull: true },
  
  // role: super = tối cao, admin = thường
  role: { 
    type: DataTypes.ENUM('super', 'admin'), 
    defaultValue: 'admin' 
  },
  
  // Quota: số key được tạo
  quota: { type: DataTypes.INTEGER, defaultValue: 0 },
  quota_used: { type: DataTypes.INTEGER, defaultValue: 0 },
  
  // Quyền hạn cho admin thường
  can_choose_tier: { type: DataTypes.BOOLEAN, defaultValue: true },
  can_choose_duration: { type: DataTypes.BOOLEAN, defaultValue: true },
  max_devices_default: { type: DataTypes.INTEGER, defaultValue: 1 },
  
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  last_login: { type: DataTypes.DATE, allowNull: true },
  session_token: { type: DataTypes.STRING(64), allowNull: true },
  last_login_ip: { type: DataTypes.STRING(45), allowNull: true },
  notes: { type: DataTypes.TEXT, allowNull: true },
  created_by: { type: DataTypes.STRING, allowNull: true }
}, { timestamps: true, tableName: 'admins' });

module.exports = Admin;
