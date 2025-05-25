const express = require('express');
const expressValidator = require('express-validator');
const verifyToken = require('../middleware/verifyToken');
const router = express.Router();

// User endpoints
router.get('/user/me', verifyToken({
  userData: 'full'
}), require('./user/me'));

router.post('/user/register',
  expressValidator.body('email').isEmail().withMessage('Invalid email'),
  expressValidator.body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  expressValidator.body('name').isLength({ min: 3 }).withMessage('Name must be at least 3 characters long'),
  require('./user/register')
);

router.post('/user/login',
  expressValidator.body('email').isEmail().withMessage('Invalid email'),
  expressValidator.body('password').notEmpty().withMessage('Password is required'),
  expressValidator.body('twoFactorToken').optional().isLength({ min: 6, max: 6 }).withMessage('Two-factor token must be 6 digits'),
  expressValidator.body('backupCode').optional().isLength({ min: 8, max: 8 }).withMessage('Backup code must be 8 characters'),
  require('./user/login')
);

router.post('/user/refresh', require('./user/refresh'));

router.post('/user/logout', require('./user/logout'));

router.post('/user/enable-2fa', verifyToken({
  userData: 'full'
}), require('./user/enable2fa'));

router.post('/user/verify-2fa', verifyToken({
  userData: 'full'
}),
  expressValidator.body('token').isLength({ min: 6, max: 6 }).withMessage('Token must be 6 digits'),
  require('./user/verify2fa')
);

router.post('/user/disable-2fa', verifyToken({
  userData: 'full'
}),
  expressValidator.body('token').optional().isLength({ min: 6, max: 6 }).withMessage('Token must be 6 digits'),
  expressValidator.body('backupCode').optional().isLength({ min: 8, max: 8 }).withMessage('Backup code must be 8 characters'),
  require('./user/disable2fa')
);

router.get('/user/sessions', verifyToken({
  userData: 'minimal'
}), require('./user/sessions'));

router.post('/user/revoke-session', verifyToken({
  userData: 'minimal'
}),
  expressValidator.body('sessionId').notEmpty().withMessage('Session ID is required'),
  require('./user/revokeSession')
);

// Admin endpoints
router.get('/admin/users', verifyToken({
  requiredPermissions: ['readUsers']
}), require('./admin/getUsers'));

router.get('/admin/user/:userId', verifyToken({
  requiredPermissions: ['readUsers']
}),
  expressValidator.param('userId').isInt().withMessage('User ID must be an integer'),
  require('./admin/getUser')
);

router.post('/admin/banUser', verifyToken({
  requiredPermissions: ['readUsers']
}),
  expressValidator.body('userId').isInt().withMessage('User ID must be an integer'),
  expressValidator.body('duration').isInt().withMessage('Duration must be an integer'),
  expressValidator.body('reason').optional().isString().withMessage('Reason must be a string'),
  require('./admin/banUser')
);

module.exports = router;