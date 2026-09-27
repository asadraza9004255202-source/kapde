const mongoose = require('mongoose');

const recordSchema = new mongoose.Schema({
    name: { type: String, required: true },
    age: { type: String, required: true },
    number: { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Record', recordSchema);
