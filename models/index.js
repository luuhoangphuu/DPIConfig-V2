const Key = require('./Key');
const Log = require('./Log');
const KeyDevice = require('./KeyDevice');
const AppVersion = require('./AppVersion');
const Announcement = require('./Announcement');
const Admin = require('./Admin');
const Seller = require('./Seller');

Key.hasMany(Log, { foreignKey: 'key_id' });
Log.belongsTo(Key, { foreignKey: 'key_id' });

Key.hasMany(KeyDevice, { foreignKey: 'key_id', as: 'devices' });
KeyDevice.belongsTo(Key, { foreignKey: 'key_id' });

Seller.hasMany(Key, { foreignKey: 'seller_id', as: 'keys' });
Key.belongsTo(Seller, { foreignKey: 'seller_id', as: 'seller' });

Admin.hasMany(Key, { foreignKey: 'admin_id', as: 'keys' });
Key.belongsTo(Admin, { foreignKey: 'admin_id', as: 'admin' });

module.exports = { Key, Log, KeyDevice, AppVersion, Announcement, Admin, Seller };
