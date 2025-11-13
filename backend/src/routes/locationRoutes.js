const express = require('express');
const router = express.Router();
const locationController = require('../controllers/locationController');
const { auth, checkRole, checkAnyRole } = require('../middlewares/auth');

// Regular endpoints
router.post('/update', auth, checkRole('collector'), locationController.updateLocation);
router.get('/collector/:collectorId', auth, locationController.getCollectorLocation);
router.get('/collectors', auth, locationController.getAllCollectorLocations);

// SSE endpoint for real-time location updates
router.get('/stream', auth, checkAnyRole(['resident', 'admin']), locationController.streamLocations);

// Admin-only endpoints
router.get('/admin/collectors', auth, checkRole('admin'), locationController.getAllCollectorLocationsAdmin);

module.exports = router;