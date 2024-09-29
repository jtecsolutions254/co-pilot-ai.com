const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // Add nodemailer for sending emails
const crypto = require('crypto'); // For generating tokens

// Initialize the app
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/uoe_chatbot', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: { type: String }, // Field for reset token
    resetPasswordExpires: { type: Date }   // Field for token expiry
});

const User = mongoose.model('User', userSchema);

// Define a root route
app.get('/', (req, res) => {
    console.log('Root route accessed');  // Logging the request
    res.json({ message: 'Welcome to the Chatbot API' });  // Send response as JSON
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });

        await newUser.save();
        res.status(201).json({ success: true, message: 'Account successfully created' });  // Send response as JSON
    } catch (error) {
        res.status(400).json({ success: false, message: 'Error creating user: ' + error.message });  // Send response as JSON
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Email not found please create account' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, 'mySuperSecretKey123', { expiresIn: '1h' });
        res.json({ success: true, token });  // Send response as JSON
    } catch (error) {
        res.status(500).json({ success: false, message: 'Internal Server Error' });  // Send response as JSON
    }
});

// Password Reset Request Route
app.post('/reset_password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Email not found' });
        }

        // Generate reset token
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        // Setup email transporter
        const transporter = nodemailer.createTransport({
            service: 'Gmail', // Replace with your email provider
            auth: {
                user: 'josephkiseko3@gmail.com', // Your email
                pass: 'Eddy008#', // Your email password
            },
        });

        const mailOptions = {
            to: user.email,
            from: 'josephkiseko3@gmail.com',
            subject: 'Password Reset Request',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            http://localhost:3000/reset_password/${token}\n\n
            If you did not request this, please ignore this email.\n`,
        };

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Password reset link sent to your email.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error sending email: ' + error.message });
    }
});

// Password Reset Confirm Route
app.post('/reset_password/:token', async (req, res) => {
    const { password } = req.body;
    const token = req.params.token;

    try {
        const user = await User.findOne({ 
            resetPasswordToken: token, 
            resetPasswordExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Password reset token is invalid or has expired.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined; // Clear the reset token
        user.resetPasswordExpires = undefined; // Clear the expiry date

        await user.save();
        res.json({ success: true, message: 'Password has been successfully reset.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error resetting password: ' + error.message });
    }
});



// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ success: false, message: 'Something broke!' });  // Send response as JSON
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
