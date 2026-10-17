const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Announcement = sequelize.define('Announcement', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING(200), allowNull: false },
  message: { type: DataTypes.TEXT, allowNull: false },
  type: { type: DataTypes.ENUM('info', 'success', 'warning', 'error'), defaultValue: 'info' },
  // Nút khóa/bật
  is_enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
  // Cho phép user đóng hay không
  is_dismissible: { type: DataTypes.BOOLEAN, defaultValue: true },
  // Ưu tiên 1-10, cao hơn = hiện trước
  priority: { type: DataTypes.INTEGER, defaultValue: 5 },
  // Ngày hết hạn (null = không hết hạn)
  starts_at: { type: DataTypes.DATE, allowNull: true },
  expires_at: { type: DataTypes.DATE, allowNull: true },
  created_by: { type: DataTypes.STRING, allowNull: true }
}, { timestamps: true, tableName: 'announcements' });

module.exports = Announcement;
