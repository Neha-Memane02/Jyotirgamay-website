require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const app = express();

// CORS configuration
const corsOptions = {
    origin: [
        'http://127.0.0.1:5500',     // Local development
        'https://www.jyotirgamay.com', // Production domain
        'http://localhost:3000',      // Additional local development port
        'http://127.0.0.1:3000'       // Another local development option
    ],
    methods: ['GET', 'POST', 'OPTIONS'], // Added OPTIONS
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true // Allow credentials (cookies, authorization headers)
};

// Apply CORS middleware
app.use(cors(corsOptions));
// Handle preflight requests
app.options('*', cors(corsOptions));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging middleware for debugging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// OTP storage
const otpStore = new Map();
const OTP_EXPIRY_TIME = 5 * 60 * 1000; // 5 minutes

// Email transporter
const transporter = nodemailer.createTransport({
    host: 'webmail.jyotirgamay.online',
    port: 25,
    secure: false, // No SSL
    auth: {
        user: process.env.EMAIL, // Your email address
        pass: process.env.EMAIL_PASSWORD, // Your email password
    },
    // Added error handling for transporter
    tls: {
        rejectUnauthorized: false // Use only if you have certificate issues
    }
});

// Verify transporter connection
transporter.verify((error) => {
    if (error) {
        console.error('SMTP Connection Error:', error);
    } else {
        console.log('SMTP Server is ready');
    }
});

// Email validation with more robust regex
function isValidEmail(email) {
    // Updated to be more flexible while still restricting to specific domain
    const emailRegex = /^[a-zA-Z0-9._%+-]+@jyotirgamay\.online$/i;
    return emailRegex.test(email);
}

// OTP Request Endpoint
app.post('/request-otp', async (req, res) => {
    try {
        const { email } = req.body;
        
        // Comprehensive email validation
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: 'Invalid email domain' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        
        // Store OTP with more detailed tracking
        otpStore.set(email, { 
            otp, 
            expiresAt: Date.now() + OTP_EXPIRY_TIME,
            attempts: 0 // Optional: track OTP request attempts
        });

        // Prepare mail options
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}. It is valid for 5 minutes.`,
            html: `<p>Your OTP code is <strong>${otp}</strong>. It will expire in 5 minutes.</p>`
        };

        // Send email
        await transporter.sendMail(mailOptions);
        
        res.status(200).json({ 
            message: 'OTP sent successfully',
            expiresIn: OTP_EXPIRY_TIME / 1000 // Send expiry time in seconds
        });

    } catch (error) {
        console.error('OTP Send Error:', error);
        res.status(500).json({ 
            message: 'Error sending OTP', 
            details: error.message 
        });
    }
});

// OTP Verification Endpoint
app.post('/verify-otp', (req, res) => {
    try {
        const { email, otp } = req.body;
        
        // Validate input
        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }

        const storedData = otpStore.get(email);

        // Check if OTP exists
        if (!storedData) {
            return res.status(400).json({ message: 'OTP expired or invalid' });
        }

        // Check OTP expiration
        if (Date.now() > storedData.expiresAt) {
            otpStore.delete(email);
            return res.status(400).json({ message: 'OTP expired' });
        }

        // Verify OTP
        if (storedData.otp === parseInt(otp)) {
            otpStore.delete(email);
            res.status(200).json({ message: 'OTP verified successfully' });
        } else {
            res.status(400).json({ message: 'Invalid OTP' });
        }

    } catch (error) {
        console.error('OTP Verify Error:', error);
        res.status(500).json({ 
            message: 'Error verifying OTP', 
            details: error.message 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString() 
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        message: 'Something went wrong!', 
        error: process.env.NODE_ENV === 'production' ? {} : err.message 
    });
});

// Server start
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
    console.log(`Server running on ${HOST}:${PORT}`);
});

module.exports = app; 