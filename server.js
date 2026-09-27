require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth.js');
const Record = require('./models/Record'); // Record model for admin panel data

const { MONGODB_URI, JWT_SECRET, GOOGLE_CLIENT_ID, PORT = 5000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

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
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Config & Auth Routes
app.get('/api/config', (req, res) => res.json({ googleClientId: GOOGLE_CLIENT_ID || null }));
app.use('/api/auth', authRoutes);

// --- ADMIN PANEL API ROUTES (Database Sync for all users) ---
app.get('/api/users', async (req, res, next) => {
  try {
    const records = await Record.find().sort({ _id: -1 });
    res.json(records);
  } catch (err) {
    next(err);
  }
});

app.post('/api/users', async (req, res, next) => {
  try {
    const { name, age, number } = req.body;
    if (!name || !age || !number) {
      return res.status(400).json({ error: 'All fields are required.' });
    }
    const newRecord = await Record.create({ name, age, number });
    res.status(201).json(newRecord);
  } catch (err) {
    next(err);
  }
});
// -------------------------------------------------------------

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Serve Homepage Root URL
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve static files from same directory
app.use(express.static(path.join(__dirname)));

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
