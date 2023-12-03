const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const userMiddleware = require('../middleware/user');
const authMiddleware = require('../middleware/auth');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', userMiddleware, authController.logout)
router.put('/password', authMiddleware, authController.passwordReset)

module.exports = router;
