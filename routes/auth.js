const express = require('express');
const router = express.Router();
const { Signup, Login, Logout, RefreshToken, verifyToken, sendForgotPasswordEmail, verifyOTP, addNewPassword, changePassword, resetPassword } = require('../controllers/Authcontrollers');

// Existing routes
router.post('/signup', Signup);
router.post('/login', Login);
router.post('/logout', verifyToken, Logout);
router.post('/token/refresh', RefreshToken);

// New routes for password management
router.post('/forget-password/send-mail', sendForgotPasswordEmail);
router.post('/forget-password/verify-code', verifyOTP);
router.post('/forget-password/change-password', addNewPassword);
router.post('/login/change-password', changePassword);
router.post('/reset-password', resetPassword);






module.exports = router;
