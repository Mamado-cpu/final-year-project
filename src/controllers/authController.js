const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Collector = require('../models/Collector');
const { sendOtp } = require('../utils/twoFactor');

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

const authController = {
    register: async (req, res) => {
        try {
            const { 
                email, 
                password, 
                fullName, 
                phone, 
                role, 
                username, 
                twoFactorEnabled, 
                twoFactorMethod 
            } = req.body;

            if (!username || !password) {
                return res.status(400).json({ message: 'Username and password are required' });
            }
            if (!email && !phone) {
                return res.status(400).json({ message: 'Provide either email or phone' });
            }

            const existingUsername = await User.findOne({ username });
            if (existingUsername) return res.status(400).json({ message: 'Username already taken' });
            if (email) {
                const existingEmail = await User.findOne({ email });
                if (existingEmail) return res.status(400).json({ message: 'Email already registered' });
            }
            if (phone) {
                const existingPhone = await User.findOne({ phone });
                if (existingPhone) return res.status(400).json({ message: 'Phone already registered' });
            }

            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password, salt);
                  

            const allowedRoles = ['resident', 'collector', 'admin'];
            const finalRole = allowedRoles.includes(role) ? role : 'resident';

            const user = new User({
                username,
                email: email || undefined,
                password: hashed,
                fullName: fullName || '',
                roles: [finalRole],
                phone: phone || undefined,
                twoFactorEnabled: !!twoFactorEnabled,
                twoFactorMethod: twoFactorMethod || (email ? 'email' : (phone ? 'phone' : undefined))
            });

            await user.save();
            console.log('REGISTER ROLE:', finalRole);
            console.log('DB ROLES:', user.roles);

            // If registering as collector, create collector profile (vehicle fields optional)
            if (finalRole === 'collector') {
                const Collector = require('../models/Collector');
                try {
                    const collector = new Collector({
                        userId: user._id,
                        fullName: fullName || user.fullName || '',
                        username: username || user.username || '',
                        email: email || user.email || undefined,
                        phone: phone || user.phone || undefined,
                        vehicleNumber: req.body.vehicleNumber || undefined,
                        vehicleType: req.body.vehicleType || undefined,
                        isAvailable: true
                    });
                    await collector.save();
                } catch (err) {
                    console.error('Failed to create collector profile during registration:', err && err.stack ? err.stack : err);
                    // cleanup user
                    try { await User.findByIdAndDelete(user._id); } catch (e) { console.error('Cleanup failed', e); }
                    return res.status(500).json({ message: 'Failed to create collector profile', error: err.message || String(err) });
                }
            }
                // If registering as collector ensure roles include collector and create profile handled elsewhere
                try {
                    if (finalRole === 'collector') {
                        if (!user.roles || !user.roles.includes('collector')) {
                            user.roles = Array.from(new Set([...(user.roles || []), 'collector']));
                            await User.findByIdAndUpdate(user._id, { roles: user.roles });
                            console.log('Registered user roles enforced to include collector:', user._id.toString());
                        }
                    }
                } catch (e) {
                    console.error('Failed to enforce collector role during registration:', e && e.message ? e.message : e);
                }
            // If user enabled two-factor, don't issue full token yet — send OTP and return a temp token
            if (user.twoFactorEnabled) {
                const code = generateCode();
                const hashedCode = await bcrypt.hash(code, 10);
                user.twoFactorCode = hashedCode;
                user.twoFactorExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
                user.twoFactorLastSent = Date.now();
                await user.save();

                try {
                    const method = user.twoFactorMethod || (user.email ? 'email' : (user.phone ? 'phone' : 'email'));
                    await sendOtp(user, code, method);
                } catch (e) {
                    console.error('Failed to send OTP during registration:', e && e.message ? e.message : e);
                }

                const tempToken = jwt.sign({ twoFactor: true, userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });
                return res.status(200).json({ twoFactorRequired: true, tempToken, twoFactorMethod: user.twoFactorMethod });
            }

            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

            res.status(201).json({
                token,
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    fullName: user.fullName,
                    isApproved: user.isApproved,
                    roles: user.roles
                }
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
    verify2fa: async (req, res) => {
        try {
            const { tempToken, code } = req.body;
            const authHeader = req.headers.authorization;
            const token = tempToken || (authHeader && authHeader.split(' ')[1]);
            if (!token) return res.status(400).json({ message: 'tempToken is required' });

            let payload;
            try {
                payload = jwt.verify(token, process.env.JWT_SECRET);
            } catch (e) {
                return res.status(401).json({ message: 'Invalid or expired temp token' });
            }
            if (!payload || !payload.twoFactor || !payload.userId) return res.status(401).json({ message: 'Invalid temp token' });

            const user = await User.findById(payload.userId);
            if (!user) return res.status(404).json({ message: 'User not found' });
            if (!user.twoFactorCode || !user.twoFactorExpires) return res.status(400).json({ message: 'No pending 2FA' });
            if (Date.now() > user.twoFactorExpires) return res.status(410).json({ message: '2FA code expired' });

            const matches = await bcrypt.compare(code, user.twoFactorCode || '');
            if (!matches) return res.status(401).json({ message: 'Invalid code' });

            // clear 2FA and issue full token
            user.twoFactorCode = undefined;
            user.twoFactorExpires = undefined;
            await user.save();

            const fullToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.json({ token: fullToken, user: { id: user._id, username: user.username, email: user.email, roles: user.roles } });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Resend 2FA code (uses tempToken to identify user). Enforces cooldown.
    resend2fa: async (req, res) => {
        try {
            const { tempToken } = req.body;
            const authHeader = req.headers.authorization;
            const token = tempToken || (authHeader && authHeader.split(' ')[1]);
            if (!token) return res.status(400).json({ message: 'tempToken is required' });

            let payload;
            try {
                payload = jwt.verify(token, process.env.JWT_SECRET);
            } catch (e) {
                return res.status(401).json({ message: 'Invalid or expired temp token' });
            }
            if (!payload || !payload.twoFactor || !payload.userId) return res.status(401).json({ message: 'Invalid temp token' });

            const user = await User.findById(payload.userId);
            if (!user) return res.status(404).json({ message: 'User not found' });
            if (!user.twoFactorEnabled) return res.status(400).json({ message: '2FA not enabled for user' });

            const COOLDOWN_MS = 60 * 1000; // 60 seconds
            const last = user.twoFactorLastSent || 0;
            const since = Date.now() - last;
            if (last && since < COOLDOWN_MS) {
                const wait = Math.ceil((COOLDOWN_MS - since) / 1000);
                return res.status(429).json({ message: 'Too many requests', retryAfter: wait });
            }

            // generate new code and send
            const code = generateCode();
            const hashedCode = await bcrypt.hash(code, 10);
            user.twoFactorCode = hashedCode;
            user.twoFactorExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
            user.twoFactorLastSent = Date.now();
            await user.save();

            try {
                const method = user.twoFactorMethod || (user.email ? 'email' : (user.phone ? 'phone' : 'email'));
                await sendOtp(user, code, method);
            } catch (e) {
                console.error('Failed to resend OTP:', e && e.message ? e.message : e);
            }

            // extend temp token validity a bit by issuing a fresh temp token
            const newTemp = jwt.sign({ twoFactor: true, userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });
            return res.json({ ok: true, twoFactorRequired: true, tempToken: newTemp, twoFactorMethod: user.twoFactorMethod });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    login: async (req, res) => {
        try {
            const { email, username, password } = req.body;

            if (!password) return res.status(400).json({ message: 'Password is required' });

            const identifier = email || username || '<none>';
            console.log('Login attempt for identifier:', identifier);

            let user = null;
            if (email) user = await User.findOne({ email });
            else if (username) user = await User.findOne({ username });
            else return res.status(400).json({ message: 'Provide email or username' });

            console.log('Login lookup result:', user ? user._id.toString() : 'not found');
            console.log('Login user roles:', user ? user.roles : null);

            if (!user) return res.status(401).json({ message: 'Invalid credentials' });

            const isMatch = await bcrypt.compare(password, user.password || '');
            if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

            // Ensure roles reflect collector profile if present
            try {
                const collectorProfile = await Collector.findOne({ userId: user._id });
                if (collectorProfile && (!user.roles || !user.roles.includes('collector'))) {
                    user.roles = Array.from(new Set([...(user.roles || []), 'collector']));
                    await user.save();
                    console.log('Synchronized user roles to include collector for', user._id.toString());
                }
            } catch (e) {
                console.error('Failed to synchronize collector role:', e && e.message ? e.message : e);
            }

            const isResidentOrCollector = user.roles && (user.roles.includes('resident') || user.roles.includes('collector'));

            if (isResidentOrCollector && user.twoFactorEnabled) {
                // generate code, save hashed
                const code = generateCode();
                const hashedCode = await bcrypt.hash(code, 10);
                user.twoFactorCode = hashedCode;
                user.twoFactorExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
                user.twoFactorLastSent = Date.now();
                await user.save();

                // send code (prefer email when available)
                try {
                    const method = user.twoFactorMethod || (user.email ? 'email' : (user.phone ? 'phone' : 'email'));
                    await sendOtp(user, code, method);
                } catch (e) {
                    console.error('Failed to send OTP:', e.message || e);
                }

                const tempToken = jwt.sign({ twoFactor: true, userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });
                return res.status(200).json({ twoFactorRequired: true, tempToken, twoFactorMethod: user.twoFactorMethod });
            }

            // No 2FA -> issue normal token
            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.json({
                token,
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    fullName: user.fullName,
                    roles: user.roles
                }
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
    // Get current authenticated user
    me: async (req, res) => {
        try {
                const user = await User.findById(req.user._id).select('-password');
                // If user has a collector profile but roles missing collector, sync it
                try {
                    const collectorProfile = await Collector.findOne({ userId: user._id });
                    if (collectorProfile && (!user.roles || !user.roles.includes('collector'))) {
                        user.roles = Array.from(new Set([...(user.roles || []), 'collector']));
                        await User.findByIdAndUpdate(user._id, { roles: user.roles });
                        console.log('Synchronized roles for /auth/me to include collector for', user._id.toString());
                    }
                } catch (e) {
                    console.error('Failed to sync roles in /auth/me:', e && e.message ? e.message : e);
                }
            if (!user) return res.status(404).json({ message: 'User not found' });
            res.json(user);
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
};

module.exports = authController;