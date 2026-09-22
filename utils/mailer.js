const nodemailer = require('nodemailer');

let transporter = null;
if (process.env.SMTP_HOST) {
  const port = Number(process.env.SMTP_PORT || 587);
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendResetEmail(to, link) {
  if (!transporter) {
    // Development fallback: no SMTP configured, so print the link instead of emailing it.
    console.log(`\n[DEV] Password reset link for ${to}:\n${link}\n`);
    return;
  }
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to,
    subject: 'Reset your DROPKIT password',
    text: `Use this link to set a new password (valid for 30 minutes):\n${link}\n\nIf you did not ask for this, ignore this email.`,
    html: `<p>Use this link to set a new password (valid for 30 minutes):</p><p><a href="${link}">${link}</a></p><p>If you did not ask for this, ignore this email.</p>`,
  });
}

module.exports = { sendResetEmail };
