const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { auth, checkRole, checkAnyRole } = require('../middlewares/auth');

// Ensure we pass a single role string to checkRole (middleware expects a string)
router.post('/', auth, checkRole('resident'), reportController.createReport);
router.get('/user', auth, checkRole('resident'), reportController.getUserReports);
router.get('/collector', auth, checkRole('collector'), reportController.getCollectorReports);
router.get('/all', auth, checkRole('admin'), reportController.getAllReports);
// Let the controller perform fine-grained authorization (admin vs assigned collector)
router.put('/:id/status', auth, reportController.updateReportStatus);

module.exports = router;