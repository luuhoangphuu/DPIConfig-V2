const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const KeyDevice = sequelize.define('KeyDevice', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  key_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: { model: 'keys', key: 'id' }
  },
  hwid: {
    type: DataTypes.STRING(255),
    allowNull: false
  }
}, {
  timestamps: true,
  tableName: 'key_devices',
  indexes: [{ unique: true, fields: ['key_id', 'hwid'] }] // mỗi HWID chỉ được thêm 1 lần cho 1 key
});

module.exports = KeyDevice;
