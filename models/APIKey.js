const mongoose = require('mongoose');

const apiKeySchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  serverKey: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'locked', 'suspended'],
    default: 'active'
  },
  usageCount: {
    type: Number,
    default: 0
  },
  lastUsed: {
    type: Date
  },
  createdBy: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date
  },
  rateLimit: {
    type: Number,
    default: 1000
  },
  allowedOrigins: [{
    type: String
  }]
});

module.exports = mongoose.model('APIKey', apiKeySchema);
