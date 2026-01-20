const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Collector = require('../models/Collector');
const { sendVerificationEmail } = require('../services/emailService');

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
                twoFactorMethod,
                vehicleNumber,
                vehicleType
            } = req.body;

            // Log incoming request data for debugging
            console.log('Register request body:', req.body);

            // Log validation failures
            if (!username || !password) {
                console.error('Validation failed: Username and password are required');
                return res.status(400).json({ message: 'Username and password are required' });
            }
            if (!email) {
                console.error('Validation failed: Email is required');
                return res.status(400).json({ message: 'Email is required for verification' });
            }

            // Check for existing users
            const existingUsername = await User.findOne({ username });
            if (existingUsername) return res.status(400).json({ message: 'Username already taken' });
            const existingEmail = await User.findOne({ email });
            if (existingEmail) return res.status(400).json({ message: 'Email already registered' });

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const code = generateCode();
            const hashedCode = await bcrypt.hash(code, 10);

            const allowedRoles = ['resident', 'collector', 'admin'];
            const finalRole = allowedRoles.includes(role) ? role : 'resident';

            // Prepare user data (don't save yet)
            const userData = {
                username,
                email,
                password: hashedPassword,
                fullName: fullName || '',
                roles: [finalRole],
                phone: phone || undefined,
                twoFactorEnabled: !!twoFactorEnabled,
                twoFactorMethod: 'email',
                isVerified: false, // Will be set to true after verification
                vehicleNumber: vehicleNumber || undefined,
                vehicleType: vehicleType || undefined
            };

            // Allow collectors to register independently
            if (role === 'collector') {
                userData.isVerified = true; // Automatically verify collectors for now
            }

            // Send verification email
            try {
                const subject = 'Verify Your Email';
                const html = `<p>Your verification code is: <strong>${code}</strong></p>`;
                await sendVerificationEmail(email, subject, html);
            } catch (e) {
                console.error('Failed to send verification email during registration:', e && e.message ? e.message : e);
                return res.status(500).json({ message: 'Failed to send verification email' });
            }

            // Create temp token with user data and verification code
            const tempToken = jwt.sign({ 
                twoFactor: true, 
                userData,
                verificationCode: hashedCode,
                expires: Date.now() + 5 * 60 * 1000 // 5 minutes
            }, process.env.JWT_SECRET, { expiresIn: '10m' });

            return res.status(200).json({ twoFactorRequired: true, tempToken, twoFactorMethod: 'email' });
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
            if (!payload || !payload.twoFactor) return res.status(401).json({ message: 'Invalid temp token' });

            // Check if it's old format (userId) or new format (userData)
            if (payload.userId) {
                // Old format: user exists, just verify
                const user = await User.findById(payload.userId);
                if (!user) return res.status(404).json({ message: 'User not found' });
                if (!user.twoFactorCode || !user.twoFactorExpires) return res.status(400).json({ message: 'No pending 2FA' });
                if (Date.now() > user.twoFactorExpires) return res.status(410).json({ message: '2FA code expired' });

                const matches = await bcrypt.compare(code, user.twoFactorCode || '');
                if (!matches) return res.status(401).json({ message: 'Invalid code' });

                // clear 2FA and issue full token
                user.twoFactorCode = undefined;
                user.twoFactorExpires = undefined;
                user.isVerified = true;
                await user.save();

                const fullToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
                res.json({ token: fullToken, user: { id: user._id, username: user.username, email: user.email, roles: user.roles } });
            } else if (payload.userData && payload.verificationCode) {
                // New format: create user after verification
                if (Date.now() > payload.expires) return res.status(410).json({ message: 'Verification code expired' });

                const matches = await bcrypt.compare(code, payload.verificationCode);
                if (!matches) return res.status(401).json({ message: 'Invalid code' });

                // Create the user
                const user = new User(payload.userData);
                await user.save();

                // Set verified after creation
                user.isVerified = true;
                await user.save();

                // If registering as collector, create collector profile
                if (user.roles.includes('collector')) {
                    const Collector = require('../models/Collector');
                    try {
                        const collector = new Collector({
                            userId: user._id,
                            fullName: user.fullName,
                            username: user.username,
                            email: user.email,
                            phone: user.phone,
                            vehicleNumber: payload.userData.vehicleNumber,
                            vehicleType: payload.userData.vehicleType,
                            isAvailable: true
                        });
                        await collector.save();
                    } catch (err) {
                        console.error('Failed to create collector profile:', err);
                        // Cleanup user
                        try { await User.findByIdAndDelete(user._id); } catch (e) { console.error('Cleanup failed', e); }
                        return res.status(500).json({ message: 'Failed to create collector profile' });
                    }
                }

                const fullToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
                let redirectTo = '/';
                if (user.roles.includes('admin')) redirectTo = '/admin';
                else if (user.roles.includes('collector')) redirectTo = '/collector';
                else if (user.roles.includes('resident')) redirectTo = '/resident';
                res.json({ token: fullToken, user: { id: user._id, username: user.username, email: user.email, roles: user.roles }, redirectTo });
            } else {
                return res.status(401).json({ message: 'Invalid temp token' });
            }
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
            if (!payload || !payload.twoFactor) return res.status(401).json({ message: 'Invalid temp token' });

            let userEmail = '';
            let userId = null;

            if (payload.userId) {
                // Old format
                const user = await User.findById(payload.userId);
                if (!user) return res.status(404).json({ message: 'User not found' });
                userEmail = user.email;
                userId = user._id;
            } else if (payload.userData) {
                // New format
                userEmail = payload.userData.email;
            } else {
                return res.status(401).json({ message: 'Invalid temp token' });
            }

            // Enforce cooldown (only for existing users)
            if (userId) {
                const user = await User.findById(userId);
                const COOLDOWN_MS = 60 * 1000; // 60 seconds
                const last = user.twoFactorLastSent || 0;
                const since = Date.now() - last;
                if (last && since < COOLDOWN_MS) {
                    const wait = Math.ceil((COOLDOWN_MS - since) / 1000);
                    return res.status(429).json({ message: 'Too many requests', retryAfter: wait });
                }
                user.twoFactorLastSent = Date.now();
                await user.save();
            }

            // generate new code
            const code = generateCode();
            const hashedCode = await bcrypt.hash(code, 10);

            // Send verification email
            try {
                const subject = 'Verify Your Email';
                const html = `<p>Your verification code is: <strong>${code}</strong></p>`;
                await sendVerificationEmail(userEmail, subject, html);
            } catch (e) {
                console.error('Failed to resend verification email:', e && e.message ? e.message : e);
                return res.status(500).json({ message: 'Failed to send verification email' });
            }

            // For new format, create new temp token with updated code
            let newTempToken = tempToken;
            if (payload.userData) {
                newTempToken = jwt.sign({ 
                    twoFactor: true, 
                    userData: payload.userData,
                    verificationCode: hashedCode,
                    expires: Date.now() + 5 * 60 * 1000
                }, process.env.JWT_SECRET, { expiresIn: '10m' });
            }

            return res.json({ ok: true, twoFactorRequired: true, tempToken: newTempToken, twoFactorMethod: 'email' });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    login: async (req, res) => {
        try {
        const { email, password, role } = req.body;

        // role MUST come from roleHint
        if (!email || !password || !role) {
            return res.status(400).json({
            message: 'Missing login data',
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Account not verified' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // 🔒 ROLE COMES FROM PAGE, NOT USER INPUT
        if (!user.roles.includes(role)) {
            return res.status(403).json({
            message: 'Access denied. Role mismatch.',
            });
        }

        // 🔐 2FA only for resident & collector
        if (
            (role === 'resident' || role === 'collector') &&
            user.twoFactorEnabled
        ) {
            const code = generateCode();
            user.twoFactorCode = await bcrypt.hash(code, 10);
            user.twoFactorExpires = Date.now() + 5 * 60 * 1000;
            await user.save();

            await sendOtp(user, code, 'email');

            const tempToken = jwt.sign(
            { userId: user._id, role },
            process.env.JWT_SECRET,
            { expiresIn: '10m' }
            );

            return res.json({
            twoFactorRequired: true,
            tempToken,
            });
        }

        // ✅ LOGIN SUCCESS
        const token = jwt.sign(
            { userId: user._id, role }, // ACTIVE ROLE
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        return res.json({
            token,
            user: {
            id: user._id,
            email: user.email,
            fullName: user.fullName,
            roles: user.roles,
            role, // 👈 ACTIVE ROLE FROM URL
            },
        });
        } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
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
            res.json({
                ...user.toObject(),
                
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
};

module.exports = authController;