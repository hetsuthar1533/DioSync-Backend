const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const express = require('express');
const cors = require('cors'); 
const app=express()

const SECRET_KEY = 'your_jwt_secret';
const REFRESH_SECRET_KEY = 'i_am_refresh';
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
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
let blacklist = [];
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

// Logout function
const Logout = (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

    blacklist.push(token);
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

module.exports = { Signup, Login, Logout, RefreshToken, verifyToken };
