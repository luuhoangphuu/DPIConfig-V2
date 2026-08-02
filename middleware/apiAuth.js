module.exports = function apiAuth(req, res, next) {
  if (req.headers['x-api-key'] !== process.env.API_SECRET) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  next();
};
