const nodemailer = require('nodemailer');

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

async function sendEmail(subject, htmlContent) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.warn('Email not configured, skipping notification.');
    return;
  }
  try {
    await transporter.sendMail({
      from: `"DPIConfig Bot" <${EMAIL_USER}>`,
      to: EMAIL_USER, // gửi cho chính admin
      subject: subject,
      html: htmlContent
    });
    console.log('Email sent:', subject);
  } catch (err) {
    console.error('Failed to send email:', err.message);
  }
}

// Các hàm thông báo
function notifyKeyCreated(key, maxDevices) {
  sendEmail('🔑 Key mới được tạo', `<p>Key: <code>${key}</code></p><p>Giới hạn: ${maxDevices} thiết bị</p>`);
}

function notifyKeyToggled(key, active) {
  sendEmail(`${active ? '🔓 Key được mở khóa' : '🔒 Key bị khóa'}`, `<p>Key: <code>${key}</code></p>`);
}

function notifyKeyDeleted(key) {
  sendEmail('🗑 Key bị xóa', `<p>Key: <code>${key}</code></p>`);
}

function notifyKickAll(key) {
  sendEmail('⛔ Tất cả thiết bị của key bị khóa', `<p>Key: <code>${key}</code></p>`);
}

function notifyDeleteAllDevices(key) {
  sendEmail('💣 Tất cả thiết bị của key bị xóa vĩnh viễn', `<p>Key: <code>${key}</code></p>`);
}

function notifyDeviceToggled(key, hwid, active) {
  sendEmail(`${active ? '🔓 Thiết bị được mở khóa' : '🔒 Thiết bị bị khóa'}`, `<p>Key: <code>${key}</code></p><p>HWID: <code>${hwid}</code></p>`);
}

function notifyDeviceDeleted(key, hwid) {
  sendEmail('❌ Thiết bị bị xóa', `<p>Key: <code>${key}</code></p><p>HWID: <code>${hwid}</code></p>`);
}

function notifyKeyExpiringSoon(key, daysLeft) {
  sendEmail('⏳ Key sắp hết hạn', `<p>Key: <code>${key}</code></p><p>Còn <b>${daysLeft} ngày</b></p>`);
}

module.exports = {
  notifyKeyCreated,
  notifyKeyToggled,
  notifyKeyDeleted,
  notifyKickAll,
  notifyDeleteAllDevices,
  notifyDeviceToggled,
  notifyDeviceDeleted,
  notifyKeyExpiringSoon
};
