const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
let twilioClient = null;

// Create a transporter if SMTP settings are provided via env.
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        }
    });
}

// Optional Twilio client: used if TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM set
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM) {
    try {
        const twilio = require('twilio');
        twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    } catch (e) {
        console.warn('Twilio module is not available or failed to initialize:', e && e.message ? e.message : e);
        twilioClient = null;
    }
}

async function sendOtp(user, code, method = 'email') {
    // method: 'email' | 'phone'
    if (method === 'email') {
        if (!transporter) {
            console.log('No SMTP transporter configured. OTP for', user.email, 'is', code);
            // fallback to Twilio if available
            if (user.phone && twilioClient) {
                try {
                    await twilioClient.messages.create({
                        body: `Your verification code is: ${code}`,
                        from: process.env.TWILIO_FROM,
                        to: user.phone
                    });
                    return;
                } catch (e) {
                    console.error('Failed to send OTP via Twilio fallback:', e && e.message ? e.message : e);
                }
            }
            // final fallback: log
            if (user.phone) console.log(`Fallback SMS OTP to ${user.phone}: ${code}`);
            return;
        }
        const mailOptions = {
            from: process.env.SMTP_FROM || 'no-reply@example.com',
            to: user.email,
            subject: 'Your 2FA code',
            text: `Your verification code is: ${code}. It expires in 5 minutes.`
        };
        await transporter.sendMail(mailOptions);
        return;
    }

    // Phone method: try Twilio first, else log.
    if (method === 'phone') {
        if (twilioClient) {
            try {
                await twilioClient.messages.create({
                    body: `Your verification code is: ${code}`,
                    from: process.env.TWILIO_FROM,
                    to: user.phone
                });
                return;
            } catch (e) {
                console.error('Failed to send SMS via Twilio:', e && e.message ? e.message : e);
            }
        }
        // Fallback: log
        console.log(`Sending SMS OTP to ${user.phone}: ${code}`);
        return;
    }
}

module.exports = {
    sendOtp
};
