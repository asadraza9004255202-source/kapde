require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth.js');

const { MONGODB_URI, JWT_SECRET, GOOGLE_CLIENT_ID, PORT = 5000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET. Copy server/.env.example to server/.env and fill it in.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1); // needed behind Render / Railway / Nginx so secure cookies and rate limits work

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://accounts.google.com/gsi/client'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://accounts.google.com/gsi/style'],
        fontSrc: ['https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        frameSrc: ['https://accounts.google.com/gsi/'],
        connectSrc: ["'self'", 'https://accounts.google.com/gsi/'],
      },
    },
    // Google's sign-in popup needs this relaxed value
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// The frontend asks for this so the Client ID is never hard-coded in the HTML
app.get('/api/config', (req, res) => res.json({ googleClientId: GOOGLE_CLIENT_ID || null }));
app.use('/api/auth', authRoutes);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Serve the website itself from the same server (no CORS needed)
app.use(express.static(path.join(__dirname, '..', 'client')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our side. Please try again.' });
});

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    app.listen(PORT, () => console.log(`DROPKIT running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Could not connect to MongoDB:', err.message);
    process.exit(1);
  });

module.exports = app;
