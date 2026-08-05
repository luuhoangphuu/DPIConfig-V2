// Chèn lại toàn bộ route /keys/create với giới hạn 1-999
router.post('/keys/create', async (req, res) => {
  const { tier, duration, prefix, max_devices } = req.body;
  let maxDev = tier === 'VIP' ? 1 : 9; // mặc định
  if (max_devices) {
    maxDev = parseInt(max_devices) || maxDev;
    if (maxDev < 1) maxDev = 1;
    if (maxDev > 999) maxDev = 999;
  }
  let expires_at;
  if (duration === 'forever') expires_at = new Date('2099-12-31');
  else {
    const days = parseInt(duration) || 30;
    expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + days);
  }
  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const key = `${prefix || 'HoangPhu'}-${randomPart.match(/.{1,4}/g).join('-')}`;
  await Key.create({ key, tier, expires_at, max_devices: maxDev, created_by: req.session.admin.email });
  await Log.create({ action: 'key_created', details: `Admin tạo key ${key} max ${maxDev} TB`, ip_address: req.ip });
  notifyKeyCreated(key, maxDev);
  res.redirect('/admin/keys?created=1');
});
