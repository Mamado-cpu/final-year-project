const Booking = require('../models/Booking');
const Collector = require('../models/Collector');
const User = require('../models/User');

const bookingController = {
    // Resident creates a booking
    createBooking: async (req, res) => {
        try {
            const { locationAddress, locationLat, locationLng, notes, serviceType, serviceDetails } = req.body;
            if (!locationAddress || locationLat === undefined || locationLng === undefined) {
                return res.status(400).json({ message: 'Missing booking location information' });
            }

            const lat = Number(locationLat);
            const lng = Number(locationLng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ message: 'Invalid latitude or longitude' });
            }

            // validate serviceType
            const allowed = ['sewage', 'garbage'];
            const type = serviceType && allowed.includes(serviceType) ? serviceType : 'garbage';

            // validate service-specific details
            const details = serviceDetails || {};
            if (type === 'garbage') {
                const bags = (details.bags !== undefined) ? Number(details.bags) : (req.body.bags !== undefined ? Number(req.body.bags) : undefined);
                if (!Number.isFinite(bags) || bags <= 0) {
                    return res.status(400).json({ message: 'For garbage collection, provide a positive `bags` count in serviceDetails or as `bags` field' });
                }
                details.bags = bags;
            }
            if (type === 'sewage') {
                const vol = details.tankVolume !== undefined ? Number(details.tankVolume) : (req.body.tankVolume !== undefined ? Number(req.body.tankVolume) : undefined);
                if (!Number.isFinite(vol) || vol <= 0) {
                    return res.status(400).json({ message: 'For sewage disposal, provide a positive `tankVolume` (liters) in serviceDetails or as `tankVolume` field' });
                }
                details.tankVolume = vol;
            }

            const booking = new Booking({
                userId: req.user._id,
                collectorId: null,
                locationAddress,
                locationLat: lat,
                locationLng: lng,
                notes: notes || '',
                serviceType: type,
                serviceDetails: details || {}
            });

            await booking.save();

            // Update user's saved location on booking submit
            try {
                await User.findByIdAndUpdate(req.user._id, {
                    locationAddress,
                    locationLat: lat,
                    locationLng: lng
                });
            } catch (e) {
                console.error('Failed to update user location after booking:', e);
            }

            res.status(201).json(booking);
        } catch (error) {
            console.error('Create booking error:', error && error.stack ? error.stack : error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get bookings for the logged-in resident
    getResidentBookings: async (req, res) => {
        try {
            const bookings = await Booking.find({ userId: req.user._id })
                .populate('collectorId', 'vehicleNumber vehicleType')
                .sort({ createdAt: -1 });
            res.json(bookings);
        } catch (error) {
            console.error('Get resident bookings error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get bookings assigned to the logged-in collector
    getCollectorBookings: async (req, res) => {
        try {
            // Find collector document for this user
            const collector = await Collector.findOne({ userId: req.user._id });
            if (!collector) return res.status(404).json({ message: 'Collector profile not found' });

            const bookings = await Booking.find({ collectorId: collector._id })
                .populate('userId', 'fullName email phone')
                .sort({ createdAt: -1 });
            res.json(bookings);
        } catch (error) {
            console.error('Get collector bookings error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Update booking status (admin or collector)
    updateBookingStatus: async (req, res) => {
        try {
            const { status, collectorId } = req.body;
            const booking = await Booking.findById(req.params.id);

            if (!booking) {
                return res.status(404).json({ message: 'Booking not found' });
            }

            // If caller is a collector, ensure they are assigned to this booking
            if (req.user.roles && req.user.roles.includes('collector')) {
                const Collector = require('../models/Collector');
                const collector = await Collector.findOne({ userId: req.user._id });
                if (!collector) return res.status(404).json({ message: 'Collector profile not found' });
                if (!booking.collectorId || booking.collectorId.toString() !== collector._id.toString()) {
                    return res.status(403).json({ message: 'Not assigned to this booking' });
                }
            }

            booking.status = status;

            if (status === 'assigned') {
                if (collectorId) {
                    booking.collectorId = collectorId;
                } else if (req.user && req.user.roles && req.user.roles.includes('collector')) {
                    // Collector self-assign: find collector doc
                    const collector = await Collector.findOne({ userId: req.user._id });
                    if (collector) booking.collectorId = collector._id;
                }
                booking.assignedAt = new Date();
            }

            if (status === 'in_progress') booking.startedAt = new Date();
            if (status === 'completed') booking.completedAt = new Date();

            await booking.save();
            const populated = await Booking.findById(booking._id).populate('userId', 'fullName email phone').populate('collectorId', 'vehicleNumber vehicleType');
            res.json(populated);
        } catch (error) {
            console.error('Update booking status error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Admin: get all bookings
    getAllBookings: async (req, res) => {
        try {
            console.log('Getting all bookings for admin...', {
                adminId: req.user._id,
                adminEmail: req.user.email,
                roles: req.user.roles
            });

            // First check if we can find any bookings at all
            const count = await Booking.countDocuments();
            console.log('Total bookings in database:', count);

            // allow admin to filter by serviceType (e.g., ?serviceType=garbage)
            const filter = {};
            if (req.query && req.query.serviceType) {
                const st = String(req.query.serviceType);
                if (['sewage', 'garbage'].includes(st)) filter.serviceType = st;
            }

            const bookings = await Booking.find(filter)
                .populate('userId', 'fullName email phone')
                .populate('collectorId', 'vehicleNumber vehicleType')
                .sort({ createdAt: -1 });

            console.log('Found bookings:', {
                count: bookings.length,
                sampleBooking: bookings[0] ? {
                    id: bookings[0]._id,
                    address: bookings[0].locationAddress,
                    userId: bookings[0].userId,
                    status: bookings[0].status
                } : null
            });

            res.json(bookings);
        } catch (error) {
            console.error('Get all bookings error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
};

module.exports = bookingController;