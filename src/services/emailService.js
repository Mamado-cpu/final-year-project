const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Create a reusable transporter object using SendGrid
const transporter = nodemailer.createTransport({
    host: 'smtp.sendgrid.net',
    port: 587,
    secure: false, // Use TLS
    auth: {
        user: 'apikey', // This is the fixed username for SendGrid
        pass: process.env.SENDGRID_API_KEY, // Use the API key as the password
    },
});

/**
 * Send a verification email
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} html - HTML content for the email
 */
const sendVerificationEmail = async (to, subject, html) => {
    try {
        const mailOptions = {
            from: 'smartwaste374@gmail.com', // Verified sender email
            to,
            subject,
            html,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully:', {
            response: info.response,
            messageId: info.messageId,
            accepted: info.accepted,
            rejected: info.rejected,
        });
    } catch (error) {
        console.error('Error sending email:', {
            message: error.message,
            stack: error.stack,
            code: error.code,
            response: error.response,
        });
        throw error;
    }
};

module.exports = { sendVerificationEmail };