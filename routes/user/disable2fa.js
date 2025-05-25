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

    const { token, backupCode } = req.body;
    const userId = req.user.id;
    const userEmail = req.user.email;

    // Check if 2FA is enabled
    if (req.user.two_factor !== 'true' || !req.user.two_factor_secret) {
      logger.warn('2FA disable attempt: not enabled', {
        userId,
        email: userEmail,
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Two-factor authentication is not enabled'
      });
    }

    // Parse user's register data to get backup codes
    let registerData = {};
    try {
      registerData = JSON.parse(req.user.register_data || '{}');
    } catch (error) {
      logger.warn('Failed to parse user register data during 2FA disable', {
        userId,
        error: error.message
      });
    }

    let twoFactorValid = false;

    // Check if backup code is provided
    if (backupCode && registerData.backupCodes) {
      const backupResult = twoFactor.verifyBackupCode(backupCode, registerData.backupCodes);
      
      if (backupResult.verified) {
        twoFactorValid = true;
        
        // Update user's backup codes
        registerData.backupCodes = backupResult.remainingCodes;

        logger.info('2FA disable with backup code', {
          userId,
          email: userEmail,
          backupCodesRemaining: backupResult.remainingCodes.length,
          ip: req.clientIp
        });
      }
    }
    // Check if 2FA token is provided
    else if (token) {
      twoFactorValid = twoFactor.verifyToken(token, req.user.two_factor_secret);
      
      if (twoFactorValid) {
        logger.info('2FA disable with token', {
          userId,
          email: userEmail,
          ip: req.clientIp
        });
      }
    }

    if (!twoFactorValid) {
      logger.warn('2FA disable failed: invalid verification', { 
        userId,
        email: userEmail,
        hasToken: !!token,
        hasBackupCode: !!backupCode,
        ip: req.clientIp 
      });
      
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid two-factor authentication code'
      });
    }

    // Disable 2FA and clear secret
    db.prepare(`
      UPDATE users 
      SET two_factor = 'false', two_factor_secret = NULL, register_data = ?, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(JSON.stringify(registerData), userId);

    logger.info('2FA disabled successfully', {
      userId,
      email: userEmail,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication disabled successfully'
    });

  } catch (error) {
    logger.error('2FA disable failed: Unexpected error', {
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