const jwt = require('jsonwebtoken');

function sellerAuth(req, res, next) {
  const token = req.cookies.seller_token;
  if (!token) return res.redirect('/seller/login');
  try {
    req.seller = jwt.verify(token, process.env.JWT_SECRET || 'defaultSecret');
    next();
  } catch {
    res.clearCookie('seller_token');
    res.redirect('/seller/login');
  }
}

module.exports = sellerAuth;
