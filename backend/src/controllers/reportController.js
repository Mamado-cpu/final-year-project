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

    // Update report status (admin)
    updateReportStatus: async (req, res) => {
        try {
            const { status, collectorId } = req.body;
            const update = { status };
            if (collectorId) {
                update.collectorId = collectorId;
                update.assignedAt = new Date();
            }

            const report = await Report.findByIdAndUpdate(req.params.id, update, { new: true });
            if (!report) return res.status(404).json({ message: 'Report not found' });
            res.json(report);
        } catch (error) {
            console.error('Update report status error:', error);
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    },
};

module.exports = reportController;