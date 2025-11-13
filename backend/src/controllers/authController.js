// Use bcryptjs which is already listed in package.json and works cross-platform
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authController = {
    register: async (req, res) => {
        try {
            console.log('Register request body:', req.body); // Debug log
            const { email, password, fullName, phone, role } = req.body;
            
            if (!email || !password) {
                return res.status(400).json({ message: 'Email and password are required' });
            }

            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already registered' });
            }

            // Hash password and create local user
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password, salt);

            const user = new User({
                email,
                password: hashed,
                fullName: fullName || '',
                roles: [role || 'resident'],
                phone: phone || ''
            });

            await user.save();
            console.log('User created:', { id: user._id, email: user.email }); // Debug log

            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
            
            res.status(201).json({
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    fullName: user.fullName,
                    roles: user.roles
                },
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    login: async (req, res) => {
        try {
            const { email, password } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            const isMatch = await bcrypt.compare(password, user.password || '');
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

            res.json({
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    fullName: user.fullName,
                    roles: user.roles
                },
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
    // Get current authenticated user
    me: async (req, res) => {
        try {
            const user = await User.findById(req.user._id).select('-password');
            if (!user) return res.status(404).json({ message: 'User not found' });
            res.json(user);
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
};

module.exports = authController;