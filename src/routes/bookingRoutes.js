const express = require('express');
const router = express.Router();
const bookingController = require('../controllers/bookingController');
const { auth, checkRole, checkAnyRole } = require('../middlewares/auth');

router.post('/', auth, checkRole('resident'), bookingController.createBooking);
router.get('/resident', auth, checkRole('resident'), bookingController.getResidentBookings);
router.get('/collector', auth, checkRole('collector'), bookingController.getCollectorBookings);
// Let the controller perform fine-grained authorization (admin vs assigned collector)
router.put('/:id/status', auth, bookingController.updateBookingStatus);
router.get('/all', auth, checkRole('admin'), bookingController.getAllBookings);

module.exports = router;