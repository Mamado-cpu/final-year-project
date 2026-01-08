const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('../models/User');
const Collector = require('../models/Collector');
const Booking = require('../models/Booking');
const Report = require('../models/Report');

const adminController = {
  // Admin creates a collector (creates both User and Collector records)
  createCollector: async (req, res) => {
    try {
      console.log('Admin create collector payload:', req.body);
      const { email, password, fullName, phone, vehicleNumber, vehicleType, username: reqUsername } = req.body;
      if (!reqUsername || !email || !password || !fullName) {
        return res.status(400).json({ message: 'Missing required fields: username, email, password, fullName are required' });
      }

      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ message: 'Email already registered' });

      // Use provided username if present, otherwise derive from email
      let { username: requestedUsername } = req.body;
      let username;
      if (requestedUsername) {
        requestedUsername = String(requestedUsername).replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
        const existsU = await User.findOne({ username: requestedUsername });
        if (existsU) return res.status(400).json({ message: 'Username already taken' });
        username = requestedUsername;
      } else {
        // derive a username from the email local-part and ensure uniqueness
        let baseUsername = String(email).split('@')[0].replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase() || `collector${Date.now()}`;
        username = baseUsername;
        let counter = 0;
        while (await User.findOne({ username })) {
          counter += 1;
          username = `${baseUsername}${counter}`;
          if (counter > 50) break;
        }
      }

      console.log('Resolved username to use for new user:', username, 'requestedUsername:', requestedUsername);

      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(password, salt);

      const user = new User({
        username: username,
        email,
        password: hashed,
        fullName,
        phone: phone || '',
        roles: ['collector']
      });

      console.log('About to save user object:', { username: user.username, email: user.email, fullName: user.fullName, roles: user.roles });

      try {
        await user.save();
      } catch (saveErr) {
        console.error('Error saving new user:', saveErr && saveErr.stack ? saveErr.stack : saveErr);
        // give a clearer error to the client
        return res.status(500).json({ message: 'Server error', error: saveErr.message || String(saveErr) });
      }
      // Ensure roles explicitly set to collector (avoid schema coercion)
      try {
        await User.findByIdAndUpdate(user._id, { roles: ['collector'] });
        const reloaded = await User.findById(user._id).select('-password');
        console.log('Created user (after enforce roles):', reloaded);
      } catch (e) {
        console.error('Failed to enforce collector role on created user:', e && e.message ? e.message : e);
      }
      let collector;
      try {
        collector = new Collector({
          userId: user._id,
          fullName: fullName || user.fullName || '',
          username: user.username,
          email: user.email,
          phone: phone || user.phone || '',
          vehicleNumber,
          vehicleType: vehicleType || '',
          isAvailable: true
        });

        await collector.save();
      } catch (err) {
        console.error('Collector save error:', err && err.stack ? err.stack : err);
        // If duplicate collector (unique userId) return conflict
        if (err && err.name === 'MongoServerError' && err.code === 11000) {
          return res.status(409).json({ message: 'Collector already exists for this user' });
        }
        // Remove created user to avoid orphaned user if collector creation fails
        try { await User.findByIdAndDelete(user._id); } catch (e) { console.error('Failed to cleanup user after collector save failure', e); }
        return res.status(500).json({ message: 'Failed to create collector', error: err.message || String(err) });
      }

      const created = await Collector.findById(collector._id).populate('userId', 'fullName email phone username roles');

      // Also include the user object explicitly for convenience
      const userObj = created.userId ? {
        id: created.userId._id,
        username: created.userId.username,
        email: created.userId.email,
        fullName: created.userId.fullName,
        phone: created.userId.phone,
        roles: created.userId.roles
      } : null;

      res.status(201).json({ collector: created, user: userObj });
    } catch (error) {
      console.error('Admin create collector error:', error && error.stack ? error.stack : error);
      res.status(500).json({ message: 'Server error', error: error.message || String(error) });
    }
  },

  // Admin deletes a collector (removes collector and associated user)
  deleteCollector: async (req, res) => {
    try {
      const { userId } = req.params;
      if (!userId) return res.status(400).json({ message: 'userId required' });

      // Remove collector record
      await Collector.findOneAndDelete({ userId });
      // Optionally remove user - careful in production
      await User.findByIdAndDelete(userId);

      res.json({ message: 'Collector deleted' });
    } catch (error) {
      console.error('Admin delete collector error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
  ,
  // Get users (optionally filter by role)
  getUsers: async (req, res) => {
    try {
      const role = req.query.role;
      const filter = {};
      if (role) filter.roles = role;
      const users = await User.find(filter).select('-password');
      res.json(users);
    } catch (error) {
      console.error('Admin get users error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  },

  deleteUser: async (req, res) => {
    try {
      const { userId } = req.params;
      if (!userId) return res.status(400).json({ message: 'userId required' });

      // Find user first to check if exists and get role
      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      
      // Don't allow deleting other admins
      if (user.roles.includes('admin')) {
        return res.status(403).json({ message: 'Cannot delete admin users' });
      }

      // Start transaction to ensure all related data is cleaned up
      const session = await mongoose.startSession();
      try {
        await session.withTransaction(async () => {
          // Delete user
          await User.findByIdAndDelete(userId).session(session);

          // If was collector, delete collector profile and unassign from tasks
          if (user.roles.includes('collector')) {
            const collector = await Collector.findOne({ userId }).session(session);
            if (collector) {
              // Remove collector assignments from bookings and reports
              await Booking.updateMany(
                { collectorId: collector._id },
                { $set: { collectorId: null, status: 'pending', assignedAt: null } }
              ).session(session);
              await Report.updateMany(
                { collectorId: collector._id },
                { $set: { collectorId: null, status: 'pending', assignedAt: null } }
              ).session(session);
              await Collector.findByIdAndDelete(collector._id).session(session);
            }
          }

          // If was resident, delete their bookings and reports
          if (user.roles.includes('resident')) {
            await Booking.deleteMany({ userId }).session(session);
            await Report.deleteMany({ userId }).session(session);
          }
        });

        res.json({ 
          message: 'User and related data deleted successfully',
          deletedUserId: userId
        });
      } finally {
        session.endSession();
      }
    } catch (error) {
      console.error('Admin delete user error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
};

module.exports = adminController;
