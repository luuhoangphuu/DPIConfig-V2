module.exports = function botBlocker(req, res, next) {
  const ua = req.headers['user-agent'] || '';
  
  // 1. Chặn nếu không có User-Agent (Bot nguy hiểm thường giả không có UA)
  if (!ua) {
    return res.status(403).send('Access Denied');
  }

  // 2. Chặn các tool quét phổ biến (có thể thêm bớt tùy ý)
  const badBots = ['curl', 'wget', 'python-requests', 'go-http-client', 'postmanruntime', 'insomnia', 'zgrab', 'nmap', 'sqlmap'];
  const uaLower = ua.toLowerCase();
  if (badBots.some(bot => uaLower.includes(bot))) {
    return res.status(403).send('Access Denied');
  }

  next();
};
