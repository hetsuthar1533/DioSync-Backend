const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const OTP_SECRET = 'otp_secret234'; // Separate secret key for OTP
const app = express()

const SECRET_KEY = 'your_jwt_secret';
const REFRESH_SECRET_KEY = 'i_am_refresh';
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    Headers: ['Content-Type', 'Authorization'],
}));
// Token generation function
const generateTokens = (user) => {
    const accessToken = jwt.sign({ id: user.user_id }, SECRET_KEY, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.user_id }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
    return { accessToken, refreshToken };
};

// Signup function
const Signup = async (req, res) => {
    const { username, email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', err });
        if (results.length > 0) return res.status(400).json({ message: 'User already exists' });

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).json({ message: 'Error hashing password', err });

            db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], (err, results) => {
                if (err) return res.status(500).json({ message: 'Database error', err });

                const { accessToken, refreshToken } = generateTokens({ user_id: results.insertId });
                res.status(201).json({ accessToken, refreshToken });
            });
        });
    });
};

// Login function
const Login = async (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', err });
        if (results.length === 0) return res.status(400).json({ message: 'Invalid credentials' });

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ message: 'Error comparing passwords', err });
            if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

            const { accessToken, refreshToken } = generateTokens(user);

            db.query('UPDATE users SET refresh_token = ? WHERE user_id = ?', [refreshToken, user.user_id], (err) => {
                if (err) return res.status(500).json({ message: 'Database error', err });
                res.status(200).json({ accessToken, refreshToken, user_type: 'admin', is_temp_pwd_changed: true });
            });
        });
    });
};

// Middleware to verify token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ message: 'No token provided' });

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(500).json({ message: 'Failed to authenticate token' });
        req.userId = decoded.id;
        next();
    });
};
let blacklist = [];

// Logout function
const Logout = (req, res) => {
    console.log("hi this is logout");

    const authHeader = req.headers['authorization'];
    console.log("hi this is logout",authHeader);

    
    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

    blacklist.push(token);
    console.log('blacklist', blacklist)
    res.status(200).json({ message: 'Logged out successfully' });
};

// Refresh token function
const RefreshToken = (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(403).json({ message: 'Refresh token not provided' });

    jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        const userId = decoded.id;
        const sql = 'SELECT * FROM users WHERE user_id = ? AND refresh_token = ?';
        db.query(sql, [userId, refreshToken], (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error', err });
            if (results.length === 0) return res.status(403).json({ message: 'Invalid refresh token' });

            const user = results[0];
            const accessToken = jwt.sign({ id: user.user_id }, SECRET_KEY, { expiresIn: '1h' });
            res.status(200).json({ accessToken });
        });
    });
};




// SMTP configuration for nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'hetsuthar1533@gmail.com',
        pass: 'jbjw ownf kprg nzrg',
    },
});

// Controller functions


const sendForgotPasswordEmail = (req, res) => {
    const { email } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', err });
        if (results.length === 0) return res.status(400).json({ message: 'Email not found' });

        const user = results[0];
        const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP

        const token = jwt.sign({ email, otp }, OTP_SECRET, { expiresIn: '15m' });

        const mailOptions = {
            from: 'hetsuthar1533@gmail.com',
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) return res.status(500).json({ message: 'Email sending failed', error });
            res.status(200).json({ token, message: 'OTP sent to email' });
        });
    });
};

const verifyOTP = (req, res) => {
    const { token, otp } = req.body;
    jwt.verify(token, OTP_SECRET, (err, decoded) => {
        if (err) return res.status(400).json({ message: 'Invalid or expired OTP' });

        if (decoded.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

        res.status(200).json({ message: 'OTP verified', email: decoded.email });
    });
};

const addNewPassword = (req, res) => {
    const { email, newPassword } = req.body;
    const sql = 'UPDATE users SET password = ? WHERE email = ?';

    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error hashing password', err });

        db.query(sql, [hash, email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error', err });

            res.status(200).json({ message: 'Password updated successfully' });
        });
    });
};

const changePassword = (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', err });
        if (results.length === 0) return res.status(400).json({ message: 'Email not found' });

        const user = results[0];

        bcrypt.compare(oldPassword, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ message: 'Error comparing passwords', err });
            if (!isMatch) return res.status(400).json({ message: 'Incorrect old password' });

            bcrypt.hash(newPassword, 10, (err, hash) => {
                if (err) return res.status(500).json({ message: 'Error hashing password', err });

                db.query('UPDATE users SET password = ? WHERE email = ?', [hash, email], (err) => {
                    if (err) return res.status(500).json({ message: 'Database error', err });

                    res.status(200).json({ message: 'Password updated successfully' });
                });
            });
        });
    });
};

const resetPassword = (req, res) => {
    const { email, newPassword } = req.body;

    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error hashing password', err });

        const sql = 'UPDATE users SET password = ? WHERE email = ?';
        db.query(sql, [hash, email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error', err });

            res.status(200).json({ message: 'Password reset successfully' });
        });
    });
};

module.exports = { Signup, Login, Logout, RefreshToken, verifyToken, sendForgotPasswordEmail, verifyOTP, addNewPassword, changePassword, resetPassword };

// module.exports = { Signup, Login, Logout, RefreshToken, verifyToken };
