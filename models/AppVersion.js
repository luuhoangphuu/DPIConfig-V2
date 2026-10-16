const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const AppVersion = sequelize.define('AppVersion', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  version_code: { type: DataTypes.INTEGER, allowNull: false, unique: true },
  version_name: { type: DataTypes.STRING(20), allowNull: false },
  download_url: { type: DataTypes.STRING(500), allowNull: false },
  changelog: { type: DataTypes.TEXT, allowNull: true },
  is_required: { type: DataTypes.BOOLEAN, defaultValue: false },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  // Nút khóa/bật thông báo update
  update_enabled: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { timestamps: true, tableName: 'app_versions' });

module.exports = AppVersion;
