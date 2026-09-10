module.exports = function apiAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.API_SECRET) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  next();
};
