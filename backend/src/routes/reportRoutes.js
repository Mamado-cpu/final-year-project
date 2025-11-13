const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { auth, checkRole } = require('../middlewares/auth');

// Ensure we pass a single role string to checkRole (middleware expects a string)
router.post('/', auth, checkRole('resident'), reportController.createReport);
router.get('/user', auth, checkRole('resident'), reportController.getUserReports);
router.get('/all', auth, checkRole('admin'), reportController.getAllReports);
router.put('/:id/status', auth, checkRole('admin'), reportController.updateReportStatus);

module.exports = router;