const Collector = require('../models/Collector');
const User = require('../models/User');
const Task = require('../models/Task');
const nodemailer = require('nodemailer');
const haversine = require('haversine-distance');

const gpsController = {
    updateLocation: async (req, res) => {
        try {
            const { lat, lng } = req.body;
            if (!lat || !lng) {
                return res.status(400).json({ message: 'Latitude and longitude are required' });
            }

            // Update collector's location
            const collector = await Collector.findByIdAndUpdate(req.user._id, {
                locationLat: lat,
                locationLng: lng,
                lastUpdated: new Date(),
            }, { new: true });

            if (!collector) {
                return res.status(404).json({ message: 'Collector not found' });
            }

            // Set collector to active mode when sharing location
            collector.isActive = true;
            await collector.save();

            // Check proximity to residents
            const residents = await User.find({ roles: 'resident', locationLat: { $ne: null }, locationLng: { $ne: null } });
            for (const resident of residents) {
                const residentLocation = { lat: resident.locationLat, lng: resident.locationLng };
                const collectorLocation = { lat, lng };
                const distance = haversine(residentLocation, collectorLocation);

                // If within 500 meters, send notification
                if (distance <= 500) {
                    const transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: process.env.EMAIL_USER,
                            pass: process.env.EMAIL_PASS,
                        },
                    });

                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: resident.email,
                        subject: 'Collector Nearby Notification',
                        text: `A collector is nearby your location. Please check.`,
                    };

                    await transporter.sendMail(mailOptions);
                }
            }

            res.status(200).json({ message: 'Location updated successfully' });
        } catch (error) {
            console.error('Error updating location:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    getAllCollectors: async (req, res) => {
        try {
            const collectors = await Collector.find({ locationLat: { $ne: null }, locationLng: { $ne: null } });
            res.status(200).json(collectors);
        } catch (error) {
            console.error('Error fetching collectors:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    deactivateCollector: async (req, res) => {
        try {
            const collector = await Collector.findByIdAndUpdate(req.user._id, {
                isActive: false,
            }, { new: true });

            if (!collector) {
                return res.status(404).json({ message: 'Collector not found' });
            }

            res.status(200).json({ message: 'Collector deactivated successfully' });
        } catch (error) {
            console.error('Error deactivating collector:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    getCollectorLocations: async (req, res) => {
        try {
            const collectors = await Collector.find({}, 'locationLat locationLng isActive');
            res.status(200).json(collectors);
        } catch (error) {
            console.error('Error fetching collector locations:', error);
            res.status(500).json({ message: 'Failed to fetch collector locations' });
        }
    },

    getTaskLocations: async (req, res) => {
        try {
            const { collectorId } = req.params;
            const tasks = await Task.find({ assignedCollector: collectorId }, 'locationLat locationLng');

            // Emit real-time updates for task locations
            const io = req.app.get('io');
            if (io) {
                io.to(`collector:${collectorId}`).emit('tasks:update', tasks);
            }

            res.status(200).json(tasks);
        } catch (error) {
            console.error('Error fetching task locations:', error);
            res.status(500).json({ message: 'Failed to fetch task locations' });
        }
    },

    getUserLocation: async (req, res) => {
        try {
            const user = await User.findById(req.user._id, 'locationLat locationLng');
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            res.status(200).json({ locationLat: user.locationLat, locationLng: user.locationLng });
        } catch (error) {
            console.error('Error fetching user location:', error);
            res.status(500).json({ message: 'Failed to fetch user location' });
        }
    },
};

module.exports = gpsController;