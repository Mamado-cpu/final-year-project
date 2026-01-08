const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
require('dotenv').config();

// Import configurations
const connectDB = require('./src/config/database');

// Import routes
const authRoutes = require('./src/routes/authRoutes');
const bookingRoutes = require('./src/routes/bookingRoutes');
const reportRoutes = require('./src/routes/reportRoutes');
const locationRoutes = require('./src/routes/locationRoutes');
const adminRoutes = require('./src/routes/adminRoutes');

// Initialize express app
const app = express();

// Connect to MongoDB
connectDB();
// Ensure admin account exists (creates one if missing)
const ensureAdmin = require('./src/utils/ensureAdmin');
ensureAdmin();

// Firebase has been removed from server runtime - using MongoDB for realtime/location data now

// Middleware
const corsOptions = {
    origin: function(origin, callback) {
        const allowedOrigins = [
            'http://localhost:5173',
            'http://localhost:3000',
            'http://localhost:8082'
        ];
        // Allow requests with no origin (mobile apps, curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            return callback(null, true);
        }
        // In development, be permissive
        if (process.env.NODE_ENV !== 'production') {
            return callback(null, true);
        }
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(morgan('dev'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/locations', locationRoutes);
app.use('/api/admin', adminRoutes);

// SSE endpoint for real-time location updates
// Real-time streams are exposed via `locationRoutes` (router -> /api/locations/stream)
app.use('/api/locations/stream', locationRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Handle server shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});