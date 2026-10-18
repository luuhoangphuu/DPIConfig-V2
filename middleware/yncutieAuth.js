module.exports = function yncutieAuth(req, res, next) {
  const clientKey = req.headers['x-api-key'];
  const serverKey = process.env.PUBLIC_API_KEY || 'ync_8f9a2b4c6d1e3f5a7b9c0d2e4f6a8b1c';

  if (clientKey !== serverKey) {
    console.warn('[API SECURITY] Chặn IP truy cập sai X-API-Key:', req.ip);
    return res.status(401).json({ success: false, error: 'Mã X-API-Key không hợp lệ.' });
  }

  const origin = req.headers.origin || req.headers.referer || '';
  const allowedOrigins = ['https://dpi-config.vercel.app', 'http://localhost:3000'];
  const isAllowed = allowedOrigins.some(allowed => origin.startsWith(allowed)) || origin === '';
  
  if (!isAllowed && origin !== '') {
    console.warn('[API SECURITY] Chặn domain lạ:', origin);
    return res.status(403).json({ success: false, error: 'Tên miền không được phép gọi API.' });
  }

  next();
};
