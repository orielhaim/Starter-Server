const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const logger = require('./logger');

/**
 * Generate a new 2FA secret for a user
 * @param {string} userEmail - User's email address
 * @param {string} serviceName - Name of the service (default: from env)
 * @returns {Object} Object containing secret, qr code URL, and backup codes
 */
const generateSecret = async (userEmail, serviceName = process.env.APP_NAME || 'Starter Server') => {
  try {
    const secret = speakeasy.generateSecret({
      name: userEmail,
      issuer: serviceName.replaceAll('{{user_email}}', userEmail),
      length: 32
    });

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    // Generate backup codes
    const backupCodes = generateBackupCodes();

    logger.info('2FA secret generated', {
      userEmail,
      secretLength: secret.base32.length
    });

    return {
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      backupCodes
    };
  } catch (error) {
    logger.error('Failed to generate 2FA secret', {
      error: error.message,
      userEmail,
      stack: error.stack
    });
    throw error;
  }
};

/**
 * Verify a 2FA token
 * @param {string} token - The 6-digit token from user's authenticator
 * @param {string} secret - User's 2FA secret
 * @param {number} window - Time window for verification (default: 2)
 * @returns {boolean} True if token is valid
 */
const verifyToken = (token, secret, window = 2) => {
  try {
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window
    });

    logger.info('2FA token verification', {
      verified,
      tokenLength: token?.length
    });

    return verified;
  } catch (error) {
    logger.error('Failed to verify 2FA token', {
      error: error.message,
      tokenLength: token?.length,
      stack: error.stack
    });
    return false;
  }
};

/**
 * Generate backup codes for 2FA
 * @param {number} count - Number of backup codes to generate (default: 10)
 * @returns {Array<string>} Array of backup codes
 */
const generateBackupCodes = (count = 10) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    // Generate 8-character alphanumeric codes
    const code = Math.random().toString(36).substr(2, 4).toUpperCase() + 
                 Math.random().toString(36).substr(2, 4).toUpperCase();
    codes.push(code);
  }
  return codes;
};

/**
 * Verify a backup code
 * @param {string} code - The backup code to verify
 * @param {Array<string>} validCodes - Array of valid backup codes
 * @returns {Object} Object containing verification result and remaining codes
 */
const verifyBackupCode = (code, validCodes) => {
  try {
    const codeIndex = validCodes.indexOf(code.toUpperCase());
    
    if (codeIndex === -1) {
      return {
        verified: false,
        remainingCodes: validCodes
      };
    }

    // Remove used code
    const remainingCodes = validCodes.filter((_, index) => index !== codeIndex);

    logger.info('Backup code used', {
      codesRemaining: remainingCodes.length
    });

    return {
      verified: true,
      remainingCodes
    };
  } catch (error) {
    logger.error('Failed to verify backup code', {
      error: error.message,
      stack: error.stack
    });
    return {
      verified: false,
      remainingCodes: validCodes
    };
  }
};

module.exports = {
  generateSecret,
  verifyToken,
  generateBackupCodes,
  verifyBackupCode
}; 