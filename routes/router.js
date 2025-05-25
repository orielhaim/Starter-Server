const express = require('express');
const expressValidator = require('express-validator');
const verifyToken = require('../middleware/verifyToken');
const router = express.Router();

// User endpoint
router.get('/user/me', verifyToken({
  userData: 'full'
}), require('./user/me'));
router.post('/user/register',
  expressValidator.body('email').isEmail().withMessage('Invalid email'),
  expressValidator.body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  expressValidator.body('name').isLength({ min: 3 }).withMessage('Name must be at least 3 characters long'),
  require('./user/register')
);

// Admin endpoint
router.get('/admin/users', verifyToken({
  requiredPermissions: ['readUsers']
}), require('./admin/getUsers'));

module.exports = router;