const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { sendResetEmail } = require('../utils/mailer');

const router = express.Router();
const googleClient = new OAuth2Client();

const WEEK = 7 * 24 * 60 * 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /^[6-9]\d{9}$/;
const MIN_PASSWORD = 8;
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

router.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 40,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  })
);

const bad = (res, field, error, status = 400) => res.status(status).json({ error, field });
const publicUser = (u) => ({ id: u._id, name: u.name, email: u.email, avatar: u.avatar || null, role: u.role });

function startSession(res, user) {
  const token = jwt.sign({ id: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: WEEK,
  });
}

router.post('/register', async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const phone = String(req.body.phone || '').trim();
    const password = String(req.body.password || '');

    if (name.length < 2 || name.length > 80) return bad(res, 'name', 'Enter your full name.');
    if (!EMAIL_RE.test(email)) return bad(res, 'email', 'Enter a valid email like you@email.com.');
    if (!PHONE_RE.test(phone)) return bad(res, 'phone', 'Enter a 10-digit Indian mobile number starting with 6 to 9.');
    if (password.length < MIN_PASSWORD) return bad(res, 'password', `Password needs at least ${MIN_PASSWORD} characters.`);

    if (await User.findOne({ email })) {
      return bad(res, 'email', 'This email already has an account. Sign in instead.', 409);
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, phone, passwordHash });
    startSession(res, user);
    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    if (err && err.code === 11000) return bad(res, 'email', 'This email already has an account. Sign in instead.', 409);
    next(err);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!EMAIL_RE.test(email)) return bad(res, 'email', 'Enter a valid email like you@email.com.');
    if (!password) return bad(res, 'password', 'Enter your password.');

    const user = await User.findOne({ email }).select('+passwordHash');
    const ok = await bcrypt.compare(password, user && user.passwordHash ? user.passwordHash : DUMMY_HASH);

    if (user && !user.passwordHash) {
      return bad(res, 'email', 'This account uses Google. Tap "Continue with Google" to sign in.', 401);
    }
    if (!user || !ok) return bad(res, 'password', 'Wrong email or password.', 401);

    startSession(res, user);
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

router.post('/google', async (req, res, next) => {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) return bad(res, null, 'Google sign-in is not configured on this server.', 503);

    const credential = String(req.body.credential || '');
    if (!credential) return bad(res, null, 'Missing Google credential.');

    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: clientId });
      payload = ticket.getPayload();
    } catch (e) {
      return bad(res, null, 'Google sign-in failed. Please try again.', 401);
    }
    if (!payload || !payload.email || !payload.email_verified) {
      return bad(res, null, 'Your Google email is not verified.', 401);
    }

    const email = payload.email.toLowerCase();
    let user = await User.findOne({ $or: [{ googleId: payload.sub }, { email }] });
    if (!user) {
      user = await User.create({
        name: payload.name || email.split('@')[0],
        email,
        googleId: payload.sub,
        avatar: payload.picture,
      });
    } else if (!user.googleId) {
      user.googleId = payload.sub;
      if (!user.avatar && payload.picture) user.avatar = payload.picture;
      await user.save();
    }
    startSession(res, user);
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

router.post('/forgot', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return bad(res, 'email', 'Enter a valid email like you@email.com.');

    const user = await User.findOne({ email }).select('+passwordHash');
    if (user && user.passwordHash) {
      const token = crypto.randomBytes(32).toString('hex');
      user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
      user.resetTokenExpires = new Date(Date.now() + 30 * 60 * 1000);
      await user.save();
      const base = process.env.APP_URL || `http://localhost:${process.env.PORT || 5000}`;
      try {
        await sendResetEmail(email, `${base}/?reset=${token}`);
      } catch (e) {
        console.error('Could not send reset email:', e.message);
      }
    }
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/reset', async (req, res, next) => {
  try {
    const token = String(req.body.token || '');
    const password = String(req.body.password || '');
    if (password.length < MIN_PASSWORD) return bad(res, 'password', `Password needs at least ${MIN_PASSWORD} characters.`);

    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ resetTokenHash: hash, resetTokenExpires: { $gt: new Date() } }).select(
      '+resetTokenHash +resetTokenExpires'
    );
    if (!user) return bad(res, null, 'This reset link is invalid or has expired. Request a new one.', 400);

    user.passwordHash = await bcrypt.hash(password, 12);
    user.resetTokenHash = undefined;
    user.resetTokenExpires = undefined;
    await user.save();
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.get('/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

router.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
  res.json({ ok: true });
});

module.exports = router;
