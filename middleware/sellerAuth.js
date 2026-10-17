const jwt = require('jsonwebtoken');
const { Seller } = require('../models');

module.exports = async function sellerAuth(req, res, next) {
  const token = req.cookies.seller_token;
  if (!token) return res.redirect('/seller/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'defaultSecret');
    const dbSeller = await Seller.findByPk(decoded.id);
    
    // CHECK TOKEN PHIÊN
    if (!dbSeller || (dbSeller.session_token && dbSeller.session_token !== decoded.session_token)) {
      res.clearCookie('seller_token');
      return res.redirect('/seller/login?error=session_expired');
    }
    
    req.seller = decoded;
    next();
  } catch {
    res.clearCookie('seller_token');
    res.redirect('/seller/login');
  }
};