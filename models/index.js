const Key = require('./Key');
const Log = require('./Log');
Key.hasMany(Log, { foreignKey: 'key_id' });
Log.belongsTo(Key, { foreignKey: 'key_id' });
module.exports = { Key, Log };
