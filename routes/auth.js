// const express = require('express')
// const router = express.Router()
// const jwt = require('jsonwebtoken')
// const bcrypt = require('bcrypt')
// const jwtSecret = "MyNameisHetsuthar"

// routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db'); // Import the database connection
const { Signup, Login,Logout,verifyToken,RefreshToken } = require('../controllers/Authcontrollers');
// Signup route
 router.post('/signup', Signup); 
// Login route
router.post('/login', Login);
// Logout 
router.post('/logout', verifyToken, Logout);
//
router.post('/token/refresh', RefreshToken);
module.exports = router;







