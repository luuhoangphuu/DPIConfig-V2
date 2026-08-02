const bcrypt = require('bcryptjs');
require('dotenv').config();
const password = process.env.ADMIN_PASSWORD || 'admin123';
console.log('ADMIN_PASSWORD_HASH=', bcrypt.hashSync(password, 10));
