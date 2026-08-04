const Key = require('./Key');
const Log = require('./Log');
const KeyDevice = require('./KeyDevice');

Key.hasMany(Log, { foreignKey: 'key_id' });
Log.belongsTo(Key, { foreignKey: 'key_id' });

Key.hasMany(KeyDevice, { foreignKey: 'key_id', as: 'devices' });
KeyDevice.belongsTo(Key, { foreignKey: 'key_id' });

module.exports = { Key, Log, KeyDevice };
