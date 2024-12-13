// const express = require('express');
const express = require('express');

// const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const cors = require('cors')
const app = express()

app.use(cors({
    origin: 'http://localhost:3000', // Replace with your frontend's URL
    methods: ['GET', 'POST'], // Specify allowed methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
}));
const Signup = (req, res) => {
    const { username, email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?'
    // Check if user already exists
    db.query(sql, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database error', err });
        }
        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ message: 'Error hashing password', err });
            }

            // Insert the new user into the database
            db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], (err, results) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error', err });
                }

                // Generate a JWT token
                const token = jwt.sign({ id: results.insertId }, 'your_jwt_secret', { expiresIn: '1h' });

                res.status(201).json({ token },);
            });
        });
    });
};

const Login = (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?'
    // Check if user exists
    db.query(sql, [email], (err, results) => { 
        if (err) {
            return res.status(500).json({ message: 'Database error', err });
        }
        if (results.length === 0) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const user = results[0];
        console.log(user)

        // Compare passwords
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ message: 'Error comparing passwords', err });
            }
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            // Generate a JWT token
            const token = jwt.sign({ id: user.id }, 'your_jwt_secret', { expiresIn: '1h' });
            
            res.status(200).json({ token,user_type:['admin'],is_temp_pwd_changed: true });
        });
    });
};

module.exports = { Signup, Login };