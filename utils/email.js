const nodemailer = require('nodemailer');
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = EMAIL_USER && EMAIL_PASS ? nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
}) : null;

async function sendEmail(subject, html) {
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: `"DPIConfig Bot" <${EMAIL_USER}>`,
      to: EMAIL_USER,
      subject,
      html
    });
  } catch (e) { console.error('Email error:', e.message); }
}

module.exports = {
  notifyKeyCreated: (key, max) => sendEmail('🔑 Key mới', `<p>Key: <code>${key}</code></p><p>Giới hạn: ${max} TB</p>`),
  notifyKeyToggled: (key, active) => sendEmail(active ? '🔓 Key mở' : '🔒 Key khóa', `<p>Key: <code>${key}</code></p>`),
  notifyKeyDeleted: (key) => sendEmail('🗑 Key xóa', `<p>Key: <code>${key}</code></p>`),
  notifyKickAll: (key) => sendEmail('⛔ Kick all', `<p>Key: <code>${key}</code></p>`),
  notifyDeleteAllDevices: (key) => sendEmail('💣 Xóa all TB', `<p>Key: <code>${key}</code></p>`),
  notifyDeviceToggled: (key, hwid, active) => sendEmail(active ? '🔓 TB mở' : '🔒 TB khóa', `<p>Key: <code>${key}</code></p><p>HWID: <code>${hwid}</code></p>`),
  notifyDeviceDeleted: (key, hwid) => sendEmail('❌ TB xóa', `<p>Key: <code>${key}</code></p><p>HWID: <code>${hwid}</code></p>`),
  notifyKeyExpiringSoon: (key, days) => sendEmail('⏳ Key sắp hết hạn', `<p>Key: <code>${key}</code></p><p>Còn ${days} ngày</p>`)
};
