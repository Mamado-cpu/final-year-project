const Report = require('../models/Report');

const reportController = {
    // Resident creates a report
    createReport: async (req, res) => {
        try {
            const { locationAddress, locationLat, locationLng, description, photoUrl } = req.body;
            if (!locationAddress || locationLat === undefined || locationLng === undefined || !description) {
                return res.status(400).json({ message: 'Missing report fields' });
            }

            const lat = Number(locationLat);
            const lng = Number(locationLng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ message: 'Invalid latitude or longitude' });
            }

            const report = new Report({
                userId: req.user._id,
                locationAddress,
                locationLat: lat,
                locationLng: lng,
                description,
                photoUrl: photoUrl || null,
            });

            await report.save();

            // Update user's saved location on report submit
            try {
                const User = require('../models/User');
                await User.findByIdAndUpdate(req.user._id, {
                    locationAddress,
                    locationLat: lat,
                    locationLng: lng
                });
            } catch (e) {
                console.error('Failed to update user location after report:', e);
            }

            res.status(201).json(report);
        } catch (error) {
            console.error('Create report error:', error && error.stack ? error.stack : error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get reports for the logged-in resident
    getUserReports: async (req, res) => {
        try {
            const reports = await Report.find({ userId: req.user._id }).sort({ createdAt: -1 });
            res.json(reports);
        } catch (error) {
            console.error('Get user reports error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Admin: get all reports
    getAllReports: async (req, res) => {
        try {
            const reports = await Report.find()
                .populate('userId', 'fullName email')
                .sort({ createdAt: -1 });
            res.json(reports);
        } catch (error) {
            console.error('Get all reports error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Get reports assigned to the logged-in collector
    getCollectorReports: async (req, res) => {
        try {
            const Collector = require('../models/Collector');
            const collector = await Collector.findOne({ userId: req.user._id });
            if (!collector) return res.status(404).json({ message: 'Collector profile not found' });

            const reports = await Report.find({ collectorId: collector._id }).sort({ createdAt: -1 });
            res.json(reports);
        } catch (error) {
            console.error('Get collector reports error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },

    // Update report status (admin)
    updateReportStatus: async (req, res) => {
        try {
            const { status, collectorId } = req.body;
            const report = await Report.findById(req.params.id);
            if (!report) return res.status(404).json({ message: 'Report not found' });

            // If caller is collector, ensure they are assigned to this report
            if (req.user.roles && req.user.roles.includes('collector')) {
                const Collector = require('../models/Collector');
                const collector = await Collector.findOne({ userId: req.user._id });
                if (!collector) return res.status(404).json({ message: 'Collector profile not found' });
                if (!report.collectorId || report.collectorId.toString() !== collector._id.toString()) {
                    return res.status(403).json({ message: 'Not assigned to this report' });
                }
            }

            const update = { status };
            if (collectorId && req.user.roles && req.user.roles.includes('admin')) {
                update.collectorId = collectorId;
                update.assignedAt = new Date();
            }

            if (status === 'in_progress') update.startedAt = new Date();
            if (status === 'cleared') update.clearedAt = new Date();

            const updated = await Report.findByIdAndUpdate(req.params.id, update, { new: true });
            res.json(updated);
        } catch (error) {
            console.error('Update report status error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
};

module.exports = reportController;