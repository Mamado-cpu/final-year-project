const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
require('dotenv').config({ path: '../.env' });

// Import the User model
const User = require('../src/models/User');

async function createAdminUser() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Check if admin already exists (by email or username)
        const existingAdmin = await User.findOne({ $or: [{ email: 'admin@smartwaste.com' }, { username: 'admin' }] });
        if (existingAdmin) {
            console.log('Admin user already exists');
            process.exit(0);
        }

        // Create admin user
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('Admin@123', salt);

        const adminUser = new User({
            username: 'admin',
            email: 'admin@smartwaste.com',
            password: hashedPassword,
            fullName: 'System Administrator',
            phone: '+2201234567',
            roles: ['admin']
        });

        await adminUser.save();
        console.log('Admin user created successfully');
        
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

createAdminUser();