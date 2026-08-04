const axios = require('axios');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.warn('Telegram not configured, skipping notification.');
    return;
  }
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: text,
      parse_mode: 'HTML'
    });
    console.log('Telegram notification sent:', text);
  } catch (err) {
    console.error('Failed to send Telegram message:', err.message);
  }
}

// Các hàm tiện ích
function notifyKeyCreated(key, maxDevices) {
  sendTelegramMessage(`🔑 <b>Key mới được tạo</b>\nKey: <code>${key}</code>\nGiới hạn: ${maxDevices} thiết bị`);
}

function notifyKeyToggled(key, active) {
  sendTelegramMessage(`${active ? '🔓' : '🔒'} <b>Key ${active ? 'được mở khóa' : 'bị khóa'}</b>\nKey: <code>${key}</code>`);
}

function notifyKeyDeleted(key) {
  sendTelegramMessage(`🗑 <b>Key bị xóa</b>\nKey: <code>${key}</code>`);
}

function notifyKickAll(key) {
  sendTelegramMessage(`⛔ <b>Tất cả thiết bị của key bị khóa</b>\nKey: <code>${key}</code>`);
}

function notifyDeleteAllDevices(key) {
  sendTelegramMessage(`💣 <b>Tất cả thiết bị của key bị xóa vĩnh viễn</b>\nKey: <code>${key}</code>`);
}

function notifyDeviceToggled(key, hwid, active) {
  sendTelegramMessage(`${active ? '🔓' : '🔒'} <b>Thiết bị ${active ? 'được mở khóa' : 'bị khóa'}</b>\nKey: <code>${key}</code>\nHWID: <code>${hwid}</code>`);
}

function notifyDeviceDeleted(key, hwid) {
  sendTelegramMessage(`❌ <b>Thiết bị bị xóa</b>\nKey: <code>${key}</code>\nHWID: <code>${hwid}</code>`);
}

function notifyKeyExpiringSoon(key, daysLeft) {
  sendTelegramMessage(`⏳ <b>Key sắp hết hạn</b>\nKey: <code>${key}</code>\nCòn <b>${daysLeft} ngày</b>`);
}

module.exports = {
  sendTelegramMessage,
  notifyKeyCreated,
  notifyKeyToggled,
  notifyKeyDeleted,
  notifyKickAll,
  notifyDeleteAllDevices,
  notifyDeviceToggled,
  notifyDeviceDeleted,
  notifyKeyExpiringSoon
};
