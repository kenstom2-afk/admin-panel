const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const mongoose = require('mongoose');

// Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'API Key Management System is running',
    timestamp: new Date().toISOString()
  });
});

// API Key routes
const APIKey = require('./models/APIKey');

// Create API Key
app.post('/api/keys', async (req, res) => {
  try {
    const { name, description } = req.body;
    
    // Generate keys
    const generateKey = () => `ak_${require('crypto').randomBytes(24).toString('hex')}`;
    const generateServerKey = () => `sk_${require('crypto').randomBytes(32).toString('hex')}`;
    
    const apiKey = generateKey();
    const serverKey = generateServerKey();
    
    // Hash server key
    const bcrypt = require('bcryptjs');
    const hashedServerKey = await bcrypt.hash(serverKey, 10);
    
    const newKey = new APIKey({
      key: apiKey,
      name,
      description,
      serverKey: hashedServerKey,
      status: 'active',
      createdBy: 'admin',
      rateLimit: 1000
    });
    
    await newKey.save();
    
    res.status(201).json({
      message: 'API key created successfully',
      key: {
        id: newKey._id,
        apiKey,
        serverKey, // Only shown once
        name: newKey.name,
        status: newKey.status,
        createdAt: newKey.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating key', error: error.message });
  }
});

// Get all keys
app.get('/api/keys', async (req, res) => {
  try {
    const keys = await APIKey.find().sort({ createdAt: -1 }).select('-serverKey');
    res.json(keys);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching keys', error: error.message });
  }
});

// Delete key
app.delete('/api/keys/:id', async (req, res) => {
  try {
    await APIKey.findByIdAndDelete(req.params.id);
    res.json({ message: 'Key deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting key', error: error.message });
  }
});

// Lock key
app.post('/api/keys/:id/lock', async (req, res) => {
  try {
    const key = await APIKey.findById(req.params.id);
    if (!key) {
      return res.status(404).json({ message: 'Key not found' });
    }
    
    key.status = 'locked';
    await key.save();
    
    res.json({ message: 'Key locked successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error locking key', error: error.message });
  }
});

// Unlock key
app.post('/api/keys/:id/unlock', async (req, res) => {
  try {
    const key = await APIKey.findById(req.params.id);
    if (!key) {
      return res.status(404).json({ message: 'Key not found' });
    }
    
    key.status = 'active';
    await key.save();
    
    res.json({ message: 'Key unlocked successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error unlocking key', error: error.message });
  }
});

// Reset server key
app.post('/api/keys/:id/reset', async (req, res) => {
  try {
    const key = await APIKey.findById(req.params.id);
    if (!key) {
      return res.status(404).json({ message: 'Key not found' });
    }
    
    const generateServerKey = () => `sk_${require('crypto').randomBytes(32).toString('hex')}`;
    const newServerKey = generateServerKey();
    
    const bcrypt = require('bcryptjs');
    key.serverKey = await bcrypt.hash(newServerKey, 10);
    await key.save();
    
    res.json({
      message: 'Server key reset successfully',
      serverKey: newServerKey
    });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting key', error: error.message });
  }
});

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Simple auth for demo
    if (username === 'admin' && password === 'Admin@123') {
      const jwt = require('jsonwebtoken');
      const token = jwt.sign(
        { id: 'admin', username: 'admin', role: 'admin' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '24h' }
      );
      
      res.json({
        token,
        user: {
          id: 'admin',
          username: 'admin',
          role: 'admin'
        }
      });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Connect to MongoDB and start server
const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/api_keys';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
  
  // Create admin user if not exists
  const User = require('./models/User');
  const initAdmin = async () => {
    const bcrypt = require('bcryptjs');
    const adminExists = await User.findOne({ username: 'admin' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@123', 10);
      const admin = new User({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        email: 'admin@example.com'
      });
      await admin.save();
      console.log('Admin user created');
    }
  };
  
  initAdmin();
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV}`);
  });
})
.catch((error) => {
  console.error('MongoDB connection error:', error);
});
