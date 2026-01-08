const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { auth } = require('../middlewares/auth');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/verify-2fa', authController.verify2fa);
router.post('/resend-2fa', authController.resend2fa);
router.get('/me', auth, authController.me);

module.exports = router;