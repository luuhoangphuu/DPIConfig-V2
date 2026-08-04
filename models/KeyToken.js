const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const KeyToken = sequelize.define('KeyToken', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  token: { type: DataTypes.STRING(64), unique: true, allowNull: false },
  key: { type: DataTypes.STRING(50), allowNull: false },
  used: { type: DataTypes.BOOLEAN, defaultValue: false },
  created_by: { type: DataTypes.STRING, allowNull: true }
}, { timestamps: true, tableName: 'key_tokens' });

module.exports = KeyToken;
