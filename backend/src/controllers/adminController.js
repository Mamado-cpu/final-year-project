const bcrypt = require('bcryptjs');
const User = require('../models/User');
const Collector = require('../models/Collector');

const adminController = {
  // Admin creates a collector (creates both User and Collector records)
  createCollector: async (req, res) => {
    try {
      const { email, password, fullName, phone, vehicleNumber, vehicleType } = req.body;
      if (!email || !password || !fullName || !vehicleNumber) {
        return res.status(400).json({ message: 'Missing required fields' });
      }

      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ message: 'Email already registered' });

      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(password, salt);

      const user = new User({
        email,
        password: hashed,
        fullName,
        phone: phone || '',
        roles: ['collector']
      });

      await user.save();

      const collector = new Collector({
        userId: user._id,
        vehicleNumber,
        vehicleType: vehicleType || '',
        isAvailable: true
      });

      await collector.save();

      const created = await Collector.findById(collector._id).populate('userId', 'fullName email phone');

      res.status(201).json({ collector: created });
    } catch (error) {
      console.error('Admin create collector error:', error);
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
