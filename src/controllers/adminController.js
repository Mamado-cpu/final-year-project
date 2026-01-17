const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/User');
const Collector = require('../models/Collector');
const Booking = require('../models/Booking');
const Report = require('../models/Report');
const { sendVerificationEmail } = require('../services/emailService');

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

const adminController = {
  // Admin creates a collector (sends verification email, user created after verification)
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
      const hashedPassword = await bcrypt.hash(password, salt);
      const code = generateCode();
      const hashedCode = await bcrypt.hash(code, 10);

      // Prepare user data (don't save yet)
      const userData = {
        username,
        email,
        password: hashedPassword,
        fullName,
        phone: phone || '',
        roles: ['collector'],
        twoFactorEnabled: false,
        twoFactorMethod: 'email',
        isVerified: false, // Will be set to true after verification
        vehicleNumber: vehicleNumber || undefined,
        vehicleType: vehicleType || undefined
      };

      // Send verification email
      try {
        const subject = 'Verify Your Email';
        const html = `<p>Your verification code is: <strong>${code}</strong></p>`;
        await sendVerificationEmail(email, subject, html);
      } catch (e) {
        console.error('Failed to send verification email for new collector:', e && e.message ? e.message : e);
        return res.status(500).json({ message: 'Failed to send verification email' });
      }

      // Create temp token with user data and verification code
      const tempToken = jwt.sign({ 
        twoFactor: true, 
        userData,
        verificationCode: hashedCode,
        expires: Date.now() + 5 * 60 * 1000 // 5 minutes
      }, process.env.JWT_SECRET, { expiresIn: '10m' });

      // Save the user to the database with isVerified: false
      const user = new User({ ...userData, isVerified: false });
      await user.save();

      res.status(200).json({ 
        twoFactorRequired: true, 
        tempToken, 
        twoFactorMethod: 'email',
        message: 'Collector verification email sent. User will be created after verification.' 
      });
    } catch (error) {
      console.error('Admin create collector error:', error && error.stack ? error.stack : error);
      res.status(500).json({ message: 'Server error', error: error.message || String(error) });
    }
  },

  verifyCollector: async (req, res) => {
    try {
      const { tempToken, code } = req.body;
      const tokenData = jwt.verify(tempToken, process.env.JWT_SECRET);

      if (!tokenData || !tokenData.userData || !tokenData.verificationCode) {
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      const user = await User.findOneAndUpdate(
        { email: tokenData.userData.email },
        { $set: { isVerified: true } },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({ message: 'User not found for verification' });
      }

      const isCodeValid = await bcrypt.compare(code, tokenData.verificationCode);
      if (!isCodeValid) {
        return res.status(400).json({ message: 'Invalid verification code' });
      }

      user.isVerified = true;
      await user.save();

      res.status(201).json({ message: 'Collector successfully verified and created' });
    } catch (error) {
      console.error('Collector verification error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
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
      res.set('Cache-Control', 'no-cache');
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
  ,
  // Get admin statistics about bookings/tasks
  getStats: async (req, res) => {
    try {
      const totalBookings = await Booking.countDocuments();
      const totalCompleted = await Booking.countDocuments({ status: 'completed' });

      // Completed today
      const startOfToday = new Date();
      startOfToday.setHours(0,0,0,0);
      const completedToday = await Booking.countDocuments({ status: 'completed', completedAt: { $gte: startOfToday } });

      // Report stats
      const totalReports = await Report.countDocuments();
      const totalClearedReports = await Report.countDocuments({ status: 'cleared' });

      // Completed by collector (top 10)
      const byCollector = await Booking.aggregate([
        { $match: { status: 'completed', collectorId: { $ne: null } } },
        { $group: { _id: '$collectorId', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ]);

      // Populate collector details
      const collectorsStats = await Promise.all(byCollector.map(async (row) => {
        const collector = await Collector.findById(row._id).populate('userId', 'fullName email');
        return {
          collectorId: row._id,
          name: collector?.userId?.fullName || collector?.username || null,
          vehicleNumber: collector?.vehicleNumber || null,
          count: row.count
        };
      }));

      // Completed by day (last N days) for bookings
      const days = parseInt(req.query.days || '14', 10) || 14;
      const since = new Date(Date.now() - (days * 24 * 60 * 60 * 1000));
      const byDayBookings = await Booking.aggregate([
        { $match: { status: 'completed', completedAt: { $gte: since } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$completedAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ]);

      // Cleared by day for reports
      const byDayReports = await Report.aggregate([
        { $match: { status: 'cleared', clearedAt: { $gte: since } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$clearedAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ]);

      // Combine for bar graph
      const combinedByDay = {};
      byDayBookings.forEach(item => {
        combinedByDay[item._id] = { date: item._id, bookings: item.count, reports: 0 };
      });
      byDayReports.forEach(item => {
        if (combinedByDay[item._id]) {
          combinedByDay[item._id].reports = item.count;
        } else {
          combinedByDay[item._id] = { date: item._id, bookings: 0, reports: item.count };
        }
      });
      const byDayCombined = Object.values(combinedByDay).sort((a, b) => a.date.localeCompare(b.date));

      res.json({ 
        totalBookings, 
        totalCompleted, 
        completedToday, 
        totalReports, 
        totalClearedReports,
        collectorsStats, 
        byDayBookings, 
        byDayReports,
        byDayCombined 
      });
    } catch (error) {
      console.error('Admin getStats error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
};

module.exports = adminController;
