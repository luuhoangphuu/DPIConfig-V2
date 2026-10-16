// Chỉ SUPER ADMIN mới được truy cập
function requireSuperAdmin(req, res, next) {
  if (!req.admin) return res.redirect('/admin/login');
  if (req.admin.role !== 'super') {
    return res.status(403).send(`
      <div style="font-family: system-ui; padding: 40px; background: #0a1e3f; color: #ffd700; min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center;">
        <div>
          <h1 style="font-size: 4rem; margin: 0;">🚫</h1>
          <h2>Không có quyền truy cập</h2>
          <p style="color: #8ba3c7;">Chỉ Super Admin mới được vào trang này.</p>
          <a href="/admin/dashboard" style="color: #4fc3f7; text-decoration: none;">← Về Dashboard</a>
        </div>
      </div>
    `);
  }
  next();
}

module.exports = { requireSuperAdmin };
