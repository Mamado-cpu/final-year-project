const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendVerificationEmail } = require('../services/emailService');

const passwordController = {
  requestPasswordReset: async (req, res) => {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedCode = await bcrypt.hash(verificationCode, 10);

      user.resetCode = hashedCode;
      user.resetCodeExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
      await user.save();

      const subject = 'Password Reset Verification Code';
      const html = `<p>Your password reset verification code is: <strong>${verificationCode}</strong></p>`;

      await sendVerificationEmail(email, subject, html);

      res.status(200).json({ message: 'Verification code sent to your email' });
    } catch (error) {
      console.error('Error in requestPasswordReset:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  },

  verifyResetCode: async (req, res) => {
    try {
      const { email, code } = req.body;
      const user = await User.findOne({ email });
      if (!user || !user.resetCode || !user.resetCodeExpires) {
        return res.status(400).json({ message: 'Invalid or expired reset code' });
      }

      const isCodeValid = await bcrypt.compare(code, user.resetCode);
      if (!isCodeValid || user.resetCodeExpires < Date.now()) {
        return res.status(400).json({ message: 'Invalid or expired reset code' });
      }

      // Generate a short-lived JWT reset token
      const resetToken = jwt.sign(
        { userId: user._id, purpose: 'password_reset' },
        process.env.JWT_SECRET,
        { expiresIn: '10m' }
      );

      res.status(200).json({ message: 'Reset code verified successfully', resetToken });
    } catch (error) {
      console.error('Error in verifyResetCode:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  },

  resetPassword: async (req, res) => {
    try {
      const { resetToken, newPassword } = req.body;

      // Verify the JWT reset token
      let payload;
      try {
        payload = jwt.verify(resetToken, process.env.JWT_SECRET);
      } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired reset token' });
      }

      if (payload.purpose !== 'password_reset') {
        return res.status(403).json({ message: 'Invalid token purpose' });
      }

      const user = await User.findById(payload.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      user.resetCode = undefined;
      user.resetCodeExpires = undefined;
      await user.save();

      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      console.error('Error in resetPassword:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  },
};

module.exports = passwordController;