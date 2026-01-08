const bcrypt = require('bcryptjs');
const User = require('../models/User');

async function ensureAdmin() {
    try {
        const existing = await User.findOne({ roles: 'admin' });
        if (existing) {
            console.log('Admin account already exists:', existing.email || existing.username);
            return;
        }

        const username = process.env.ADMIN_USERNAME || 'admin';
        const email = process.env.ADMIN_EMAIL || 'admin@smartwaste.com';
        const password = process.env.ADMIN_PASSWORD || 'Admin@123';

        const salt = await bcrypt.genSalt(10);
        const hashed = await bcrypt.hash(password, salt);

        const admin = new User({
            username,
            email,
            password: hashed,
            fullName: 'System Administrator',
            phone: process.env.ADMIN_PHONE || '+2201234567',
            roles: ['admin']
        });

        await admin.save();
        console.log('Created admin account:', email, 'username:', username);
    } catch (e) {
        console.error('Failed to ensure admin account:', e && e.message ? e.message : e);
    }
}

module.exports = ensureAdmin;
