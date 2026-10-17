const rateLimit = require('express-rate-limit');
module.exports = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 5, // 5 lần thử
  message: 'Bạn đã thử đăng nhập sai quá nhiều lần. Vui lòng quay lại sau 15 phút.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
  }
});
