module.exports = function csrfProtection(req, res, next) {
  // Chỉ kiểm tra các request thay đổi dữ liệu (POST, PUT, DELETE)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const origin = req.headers.origin || req.headers.referer || '';
  const host = req.headers.host || '';

  // Cho phép request nếu Origin trùng với Host hiện tại (hoặc test local)
  if (origin && (origin.includes(host) || origin.includes('localhost'))) {
    return next();
  }
  
  // Chặn nếu request không có Origin (do trình duyệt ẩn) hoặc sai Origin
  if (!origin) {
     // Bỏ qua cho API (vì API dùng token chứ không dùng cookie session)
     if (req.path.startsWith('/api/')) return next();
  }

  console.warn('[CSRF BLOCKED] Từ IP:', req.ip, '| Origin:', origin);
  return res.status(403).send('Truy cập bị từ chối: Lỗi bảo mật CSRF.');
};
