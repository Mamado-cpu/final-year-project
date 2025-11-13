const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { auth, checkRole } = require('../middlewares/auth');

// Admin: create a collector
router.post('/collectors', auth, checkRole('admin'), adminController.createCollector);

// Admin: delete a collector by userId
router.delete('/collectors/:userId', auth, checkRole('admin'), adminController.deleteCollector);

// Admin: list users (optional role filter) and delete users
router.get('/users', auth, checkRole('admin'), adminController.getUsers);
router.delete('/users/:userId', auth, checkRole('admin'), adminController.deleteUser);

module.exports = router;
