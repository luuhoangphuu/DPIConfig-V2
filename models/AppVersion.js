const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const AppVersion = sequelize.define('AppVersion', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  version_code: { type: DataTypes.INTEGER, allowNull: false, unique: true },
  version_name: { type: DataTypes.STRING(20), allowNull: false },
  download_url: { type: DataTypes.STRING(500), allowNull: false },
  changelog: { type: DataTypes.TEXT, allowNull: true },
  
  // ===== CORE =====
  is_required: { type: DataTypes.BOOLEAN, defaultValue: false },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  update_enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
  
  // ===== PRO FIELDS =====
  // Version tối thiểu còn dùng được. App < số này → force update ngay
  min_supported_version: { type: DataTypes.INTEGER, defaultValue: 0 },
  
  // Sau thời điểm này (nếu app chưa update) → bắt buộc
  required_after: { type: DataTypes.DATE, allowNull: true },
  
  // Rollout: 0-100. App chỉ thấy update nếu hash(deviceId) % 100 < rollout
  rollout_percentage: { type: DataTypes.INTEGER, defaultValue: 100 },
  
  // Kênh phát hành
  release_channel: { 
    type: DataTypes.ENUM('stable', 'beta', 'internal'), 
    defaultValue: 'stable' 
  },
  
  // SHA-256 checksum của file APK (để app verify)
  apk_checksum: { type: DataTypes.STRING(64), allowNull: true },
  
  // Dung lượng APK (bytes) - để hiện "12 MB"
  apk_size: { type: DataTypes.BIGINT, allowNull: true },
  
  // Số user đã cài (analytics)
  install_count: { type: DataTypes.INTEGER, defaultValue: 0 }
  
}, { timestamps: true, tableName: 'app_versions' });

module.exports = AppVersion;
