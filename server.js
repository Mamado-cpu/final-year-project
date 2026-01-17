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

// Wrap http server so Socket.io can attach
const http = require('http');
const server = http.createServer(app);
let io;
try {
    const { Server } = require('socket.io');
    io = new Server(server, {
        cors: {
            origin: [
                'http://localhost:5173',
                'http://localhost:3000',
                'http://localhost:8082',
                'https://final-year-project-front-end-ges4.vercel.app'
            ],
            methods: ['GET', 'POST']
        }
    });
    app.set('io', io);
    console.log('Socket.io enabled');
} catch (e) {
    console.warn('Socket.io not available:', e.message);
}

// Connect to MongoDB
connectDB();

// Firebase has been removed from server runtime - using MongoDB for realtime/location data now

// Middleware
const corsOptions = {
    origin: function(origin, callback) {
        const allowedOrigins = [
            'http://localhost:5173',
            'http://localhost:3000',
            'http://localhost:8082',
            'https://final-year-project-front-end-ges4.vercel.app'        ];
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

// // SSE endpoint for real-time location updates
// // Real-time streams are exposed via `locationRoutes` (router -> /api/locations/stream)
// app.use('/api/locations/stream', locationRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start server with retry on EADDRINUSE
const DEFAULT_PORT = parseInt(process.env.PORT || '5000', 10);
const MAX_RETRIES = 10;

const startServer = (port, attempt = 0) => {
    const s = server.listen(port);
    s.on('listening', () => console.log(`Server running on port ${port}`));
    s.on('error', (err) => {
        if (err && err.code === 'EADDRINUSE' && attempt < MAX_RETRIES) {
            const next = port + 1;
            console.warn(`Port ${port} in use, trying ${next} (attempt ${attempt + 1}/${MAX_RETRIES})`);
            // try next port
            startServer(next, attempt + 1);
        } else {
            console.error('Failed to start server:', err);
            process.exit(1);
        }
    });
};

startServer(DEFAULT_PORT);

if (io) {
    io.on('connection', (socket) => {
        const qs = socket.handshake.query || {};
        const userRole = qs.role || 'guest';
        const id = qs.id || null;
        if (userRole === 'collector' && id) socket.join(`collector:${id}`);
        if (userRole === 'resident') socket.join('residents');
        if (userRole === 'admin') socket.join('admins');

        socket.on('collector:location', (payload) => {
            try {
                // Broadcast to residents and admins
                io.to('residents').emit('collector:update', payload);
                io.to('admins').emit('collector:update', payload);
                if (payload && payload.collectorId) io.to(`collector:${payload.collectorId}`).emit('collector:self', payload);
            } catch (e) { console.error('Socket emit error', e); }
        });

        socket.on('disconnect', () => {});
    });
}

// Handle server shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});