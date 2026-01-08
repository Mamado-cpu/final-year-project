const Collector = require('../models/Collector');

const locationService = {
    // Update collector's location in MongoDB
    updateCollectorLocation: async (collectorId, locationData) => {
        const collector = await Collector.findById(collectorId);
        if (!collector) throw new Error('Collector not found');

        collector.currentLat = locationData.latitude;
        collector.currentLng = locationData.longitude;
        collector.lastLocationUpdate = locationData.timestamp ? new Date(locationData.timestamp) : new Date();
        collector.isAvailable = locationData.isOnline !== undefined ? locationData.isOnline : true;

        // Update vehicle info if provided
        if (locationData.collectorInfo) {
            collector.vehicleNumber = locationData.collectorInfo.vehicleNumber || collector.vehicleNumber;
            collector.vehicleType = locationData.collectorInfo.vehicleType || collector.vehicleType;
        }

        await collector.save();
        return collector;
    },

    // Get a single collector's location from MongoDB
    getCollectorLocation: async (collectorId) => {
        const collector = await Collector.findById(collectorId).populate('userId', 'fullName phone email');
        if (!collector) return null;
        return {
            latitude: collector.currentLat,
            longitude: collector.currentLng,
            timestamp: collector.lastLocationUpdate,
            isOnline: collector.isAvailable,
            collectorInfo: {
                vehicleNumber: collector.vehicleNumber,
                vehicleType: collector.vehicleType
            }
        };
    },

    // Get all active collectors' locations (filter by recent updates)
    getAllCollectorLocations: async () => {
        const fifteenMinutesAgo = new Date(Date.now() - (15 * 60 * 1000));
        const collectors = await Collector.find({ lastLocationUpdate: { $gte: fifteenMinutesAgo }, isAvailable: true }).populate('userId', 'fullName phone email');
        const locations = {};
        collectors.forEach(c => {
            locations[c._id.toString()] = {
                latitude: c.currentLat,
                longitude: c.currentLng,
                timestamp: c.lastLocationUpdate,
                isOnline: c.isAvailable,
                collectorInfo: {
                    name: c.userId?.fullName,
                    phone: c.userId?.phone,
                    email: c.userId?.email,
                    vehicleNumber: c.vehicleNumber,
                    vehicleType: c.vehicleType
                }
            };
        });
        return locations;
    },

    // Remove collector's location / mark offline
    removeCollectorLocation: async (collectorId) => {
        const collector = await Collector.findById(collectorId);
        if (!collector) return;
        collector.isAvailable = false;
        collector.currentLat = null;
        collector.currentLng = null;
        collector.lastLocationUpdate = null;
        await collector.save();
    }
};

module.exports = locationService;