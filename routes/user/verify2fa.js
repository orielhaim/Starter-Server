const { validationResult } = require('express-validator');
const db = require('../../db');
const logger = require('../../utils/logger');
const twoFactor = require('../../utils/twoFactor');

module.exports = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const { token } = req.body;
    const userId = req.user.id;
    const userEmail = req.user.email;

    // Check if user has a 2FA secret (from setup process)
    if (!req.user.two_factor_secret) {
      logger.warn('2FA verify attempt: no secret found', {
        userId,
        email: userEmail,
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Two-factor authentication setup not initiated'
      });
    }

    // Check if 2FA is already enabled
    if (req.user.two_factor === 'true') {
      logger.warn('2FA verify attempt: already enabled', {
        userId,
        email: userEmail,
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Two-factor authentication is already enabled'
      });
    }

    // Verify the token
    const isValid = twoFactor.verifyToken(token, req.user.two_factor_secret);

    if (!isValid) {
      logger.warn('2FA verify failed: invalid token', {
        userId,
        email: userEmail,
        tokenLength: token?.length,
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Invalid verification code'
      });
    }

    // Activate 2FA
    db.prepare(`
      UPDATE users 
      SET two_factor = 'true', updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(userId);

    logger.info('2FA enabled successfully', {
      userId,
      email: userEmail,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication enabled successfully'
    });

  } catch (error) {
    logger.error('2FA verify failed: Unexpected error', {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id,
      ip: req.clientIp
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}; 