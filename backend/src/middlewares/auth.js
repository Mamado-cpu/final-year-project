const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        // Check Authorization header first, then query param for SSE or EventSource clients
        let token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) token = req.query?.token || req.query?.auth_token || null;
        if (!token) return res.status(401).json({ message: 'Authentication required' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded || !decoded.userId) return res.status(401).json({ message: 'Invalid token' });

        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ message: 'User not found' });

        req.user = user;
        next();
    } catch (err) {
        console.error('Auth error:', err && err.message ? err.message : err);
        res.status(401).json({ message: 'Invalid token' });
    }
};

const checkRole = (requiredRole) => {
    return (req, res, next) => {
        const roles = req.user?.roles || [];
        if (!roles.includes(requiredRole)) return res.status(403).json({ message: 'Access denied' });
        next();
    };
};

const checkAnyRole = (allowedRoles) => {
    return (req, res, next) => {
        const roles = req.user?.roles || [];
        if (!roles.some(role => allowedRoles.includes(role))) return res.status(403).json({ message: 'Access denied' });
        next();
    };
};

module.exports = { auth, checkRole, checkAnyRole };