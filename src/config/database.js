const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('MongoDB connected successfully');
        try {
            console.log('MongoDB connection info:', {
                name: mongoose.connection.name,
                host: mongoose.connection.host,
                port: mongoose.connection.port,
                readyState: mongoose.connection.readyState
            });
        } catch (e) {
            console.log('MongoDB connection info not available:', e && e.message ? e.message : e);
        }
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

module.exports = connectDB;