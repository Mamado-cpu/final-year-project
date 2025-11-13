const express = require('express');
const router = express.Router();
const bookingController = require('../controllers/bookingController');
const { auth, checkRole, checkAnyRole } = require('../middlewares/auth');

router.post('/', auth, checkRole('resident'), bookingController.createBooking);
router.get('/resident', auth, checkRole('resident'), bookingController.getResidentBookings);
router.get('/collector', auth, checkRole('collector'), bookingController.getCollectorBookings);
router.put('/:id/status', auth, checkAnyRole(['admin', 'collector']), bookingController.updateBookingStatus);
router.get('/all', auth, checkRole('admin'), bookingController.getAllBookings);

module.exports = router;