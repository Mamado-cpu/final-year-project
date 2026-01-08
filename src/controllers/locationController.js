const locationService = require('../services/locationService');
const Collector = require('../models/Collector');
const User = require('../models/User');

const locationController = {
    // Update collector's real-time location
    updateLocation: async (req, res) => {
        try {
            const { latitude, longitude, timestamp } = req.body;
            const userId = req.user._id;
            
            // Get collector info from MongoDB
            const collector = await Collector.findOne({ userId })
                .populate('userId', 'fullName phone email');

            if (!collector) {
                return res.status(404).json({ message: 'Collector not found' });
            }

            // Update collector location in MongoDB (centralized in service)
            await locationService.updateCollectorLocation(collector._id.toString(), {
                latitude,
                longitude,
                timestamp: timestamp || new Date().toISOString(),
                collectorInfo: {
                    name: collector.userId.fullName,
                    phone: collector.userId.phone,
                    email: collector.userId.email,
                    vehicleNumber: collector.vehicleNumber,
                    vehicleType: collector.vehicleType
                },
                isOnline: true
            });

            res.json({ message: 'Location updated successfully' });
        } catch (error) {
            console.error('Location update error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get a specific collector's location
    getCollectorLocation: async (req, res) => {
        try {
            const { collectorId } = req.params;
            
            // Get location from MongoDB (realtime data provided by locationService)
            const collector = await Collector.findById(collectorId)
                .populate('userId', 'fullName phone email');
                
            const realtimeLocation = await locationService.getCollectorLocation(collectorId);
            
            if (!collector) {
                return res.status(404).json({ message: 'Collector not found' });
            }

            const response = {
                collectorId: collector._id,
                name: collector.userId.fullName,
                phone: collector.userId.phone,
                email: collector.userId.email,
                vehicleNumber: collector.vehicleNumber,
                vehicleType: collector.vehicleType,
                isAvailable: collector.isAvailable,
                lastKnownLocation: {
                    latitude: collector.currentLat,
                    longitude: collector.currentLng,
                    timestamp: collector.lastLocationUpdate
                },
                realtimeLocation // From MongoDB via locationService
            };

            res.json(response);
        } catch (error) {
            console.error('Get collector location error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get collector profile for the currently authenticated collector
    getOwnCollector: async (req, res) => {
        try {
            const userId = req.user._id;
            const collector = await Collector.findOne({ userId }).populate('userId', 'fullName email phone username');
            if (!collector) return res.status(404).json({ message: 'Collector profile not found' });
            res.json(collector);
        } catch (error) {
            console.error('Get own collector error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Update collector profile for the currently authenticated collector
    updateOwnCollector: async (req, res) => {
        try {
            const userId = req.user._id;
            let collector = await Collector.findOne({ userId });
            const { vehicleNumber, vehicleType, phone, fullName, locationAddress } = req.body;
            console.log('updateOwnCollector payload for user', userId.toString(), { vehicleNumber, vehicleType, phone, fullName, locationAddress });

            // If collector profile doesn't exist, create one so collectors can save profile from dashboard
            if (!collector) {
                collector = new Collector({
                    userId,
                    vehicleNumber: (typeof vehicleNumber === 'string' && vehicleNumber.trim()) ? vehicleNumber.trim() : undefined,
                    vehicleType: (typeof vehicleType === 'string' && vehicleType.trim()) ? vehicleType.trim() : undefined,
                    isAvailable: true
                });
                try {
                    await collector.save();
                } catch (createErr) {
                    console.error('Failed to create collector profile in updateOwnCollector:', createErr);
                    return res.status(500).json({ message: 'Failed to create collector profile', error: createErr.message });
                }
            } else {
                if (vehicleNumber !== undefined) collector.vehicleNumber = (typeof vehicleNumber === 'string' && vehicleNumber.trim()) ? vehicleNumber.trim() : undefined;
                if (vehicleType !== undefined) collector.vehicleType = (typeof vehicleType === 'string' && vehicleType.trim()) ? vehicleType.trim() : undefined;
                await collector.save();
            }

            // Also allow updating some fields on the linked User document
            const updateUser = {};
            if (phone !== undefined) updateUser.phone = phone;
            if (fullName !== undefined) updateUser.fullName = fullName;
            if (locationAddress !== undefined) updateUser.locationAddress = locationAddress;
            if (Object.keys(updateUser).length > 0) {
                await User.findByIdAndUpdate(req.user._id, updateUser);
            }

            const reloaded = await Collector.findById(collector._id).populate('userId', 'fullName email phone username');
            console.log('updateOwnCollector result for user', userId.toString(), { collectorId: reloaded._id.toString(), vehicleNumber: reloaded.vehicleNumber });
            res.json(reloaded);
        } catch (error) {
            console.error('Update own collector error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get all active collectors' locations
    getAllCollectorLocations: async (req, res) => {
        try {
            const locations = await locationService.getAllCollectorLocations();
            const activeLocations = {};

            // Filter out stale locations (older than 15 minutes)
            if (locations) {
                const fifteenMinutesAgo = Date.now() - (15 * 60 * 1000);
                Object.entries(locations).forEach(([id, data]) => {
                    const ts = data.timestamp ? new Date(data.timestamp).getTime() : 0;
                    if (ts > fifteenMinutesAgo) {
                        activeLocations[id] = data;
                    }
                });
            }

            res.json(activeLocations);
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Mark collector as offline
    goOffline: async (req, res) => {
        try {
            const collectorId = req.user._id;
            await locationService.removeCollectorLocation(collectorId.toString());
            res.json({ message: 'Successfully marked as offline' });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Admin endpoint to get all collector locations with detailed info
    getAllCollectorLocationsAdmin: async (req, res) => {
        try {
            // Get all collectors from MongoDB
            const collectors = await Collector.find()
                .populate('userId', 'fullName phone email');
            
            // Get real-time locations from MongoDB
            const realtimeLocations = await locationService.getAllCollectorLocations();
            
            // Combine MongoDB data
            const detailedLocations = collectors.map(collector => ({
                collectorId: collector._id,
                userId: collector.userId?._id,
                name: collector.userId.fullName,
                phone: collector.userId.phone,
                email: collector.userId.email,
                vehicleNumber: collector.vehicleNumber,
                vehicleType: collector.vehicleType,
                isAvailable: collector.isAvailable,
                lastKnownLocation: {
                    latitude: collector.currentLat,
                    longitude: collector.currentLng,
                    timestamp: collector.lastLocationUpdate
                },
                realtimeLocation: realtimeLocations?.[collector._id.toString()]
            }));

            res.json(detailedLocations);
        } catch (error) {
            console.error('Get all collectors location error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Stream real-time location updates using SSE (polling MongoDB)
    streamLocations: (req, res) => {
        try {
            // Set headers for SSE
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');

            // Send initial message
            res.write('data: ' + JSON.stringify({ message: 'Connected to location stream' }) + '\n\n');

            // Poll MongoDB every 3 seconds for active locations
            const interval = setInterval(async () => {
                try {
                    const locations = await locationService.getAllCollectorLocations();
                    const fifteenMinutesAgo = Date.now() - (15 * 60 * 1000);
                    const activeLocations = {};
                    Object.entries(locations || {}).forEach(([id, data]) => {
                        const ts = data.timestamp ? new Date(data.timestamp).getTime() : 0;
                        if (ts > fifteenMinutesAgo) {
                            activeLocations[id] = data;
                        }
                    });
                    res.write('data: ' + JSON.stringify(activeLocations) + '\n\n');
                } catch (err) {
                    console.error('Error polling locations for SSE:', err);
                }
            }, 3000);

            // Clean up when client disconnects
            req.on('close', () => {
                clearInterval(interval);
            });
        } catch (error) {
            console.error('SSE Error:', error);
            res.status(500).end();
        }
    }
};

module.exports = locationController;