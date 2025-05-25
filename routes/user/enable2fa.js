const db = require('../../db');
const logger = require('../../utils/logger');
const twoFactor = require('../../utils/twoFactor');

module.exports = async (req, res) => {
  try {
    const userId = req.user.id;
    const userEmail = req.user.email;

    // Check if 2FA is already enabled
    if (req.user.two_factor === 'true' && req.user.two_factor_secret) {
      logger.warn('2FA enable attempt: already enabled', {
        userId,
        email: userEmail,
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Two-factor authentication is already enabled'
      });
    }

    // Generate 2FA secret and QR code
    const twoFactorData = await twoFactor.generateSecret(userEmail);

    // Store the secret temporarily (not activated until verified)
    db.prepare(`
      UPDATE users 
      SET two_factor_secret = ?, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(twoFactorData.secret, userId);

    // Parse existing register data
    let registerData = {};
    try {
      registerData = JSON.parse(req.user.register_data || '{}');
    } catch (error) {
      logger.warn('Failed to parse user register data during 2FA setup', {
        userId,
        error: error.message
      });
    }

    // Store backup codes in register data (but don't activate 2FA yet)
    registerData.backupCodes = twoFactorData.backupCodes;

    db.prepare(`
      UPDATE users 
      SET register_data = ?, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(JSON.stringify(registerData), userId);

    logger.info('2FA setup initiated', {
      userId,
      email: userEmail,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication setup initiated',
      qrCode: twoFactorData.qrCode,
      manualEntryKey: twoFactorData.manualEntryKey,
      backupCodes: twoFactorData.backupCodes
    });

  } catch (error) {
    logger.error('2FA enable failed: Unexpected error', {
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