const express = require('express');
const expressValidator = require('express-validator');
const verifyToken = require('../middleware/verifyToken');
const twoFactor = require('../utils/twoFactor');
const turnstile = require('../middleware/turnstile');
const router = express.Router();

// Auth endpoints
router.get('/auth/me', verifyToken({
  userData: 'full'
}), require('./auth/me'));

router.post('/auth/register',
  expressValidator.body('email').isEmail().withMessage('Invalid email'),
  expressValidator.body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  expressValidator.body('name').isLength({ min: 3 }).withMessage('Name must be at least 3 characters long'),
  require('./auth/register')
);

router.post('/auth/login',
  expressValidator.body('email').isEmail().withMessage('Invalid email'),
  expressValidator.body('password').notEmpty().withMessage('Password is required'),
  expressValidator.body('twoFactorToken').optional().isLength({ min: 6, max: 6 }).withMessage('Two-factor token must be 6 digits'),
  expressValidator.body('backupCode').optional().isLength({ min: 8, max: 8 }).withMessage('Backup code must be 8 characters'),
  twoFactor.mw,
  require('./auth/login')
);

router.post('/auth/refresh', require('./auth/refresh'));

router.post('/auth/logout', require('./auth/logout'));

// User endpoints
router.post('/user/update', verifyToken({
  userData: 'full'
}),
  expressValidator.body('name').optional().isLength({ min: 3, max: 50 }).withMessage('Name must be between 3 and 50 characters long'),
  twoFactor.mw,
  require('./user/update')
);

router.post('/user/change-password', verifyToken({
  userData: 'full'
}),
  expressValidator.body('currentPassword').notEmpty().withMessage('Current password is required'),
  expressValidator.body('newPassword').isLength({ min: 8, max: 128 }).withMessage('New password must be between 8 and 128 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).withMessage('New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  twoFactor.mw,
  require('./user/changePassword')
);

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
  requiredPermissions: ['readUsers', 'banUser']
}),
  expressValidator.body('userId').isInt().withMessage('User ID must be an integer'),
  expressValidator.body('duration').isInt().withMessage('Duration must be an integer'),
  expressValidator.body('reason').optional().isString().withMessage('Reason must be a string'),
  require('./admin/banUser')
);

module.exports = router;