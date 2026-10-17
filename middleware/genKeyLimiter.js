const rateLimit = require('express-rate-limit');

module.exports = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: 'Quá nhiều yêu cầu. Vui lòng thử lại sau 5 phút.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
    return req.ip;
  }
});
