const { validationResult } = require('express-validator');
const validator = require('validator');
const bcrypt = require('bcrypt');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const crypto = require('crypto');
const db = require('../../db');
const logger = require('../../utils/logger');


// Rate limiter for password updates (more restrictive)
const passwordUpdateRateLimiter = new RateLimiterMemory({
  points: 3,
  duration: 900,
  blockDuration: 1800,
});

// Validate password strength
const validatePasswordStrength = (password) => {
  const checks = {
    length: password.length >= 8 && password.length <= 128,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /\d/.test(password),
    special: /[@$!%*?&]/.test(password),
    noCommon: !['password', '12345678', 'qwerty123', 'password123'].includes(password.toLowerCase()),
    noSequential: !/123456|abcdef|qwerty/i.test(password)
  };

  const score = Object.values(checks).filter(Boolean).length;
  return {
    isValid: score >= 6,
    score,
    checks,
    strength: score < 4 ? 'weak' : score < 6 ? 'medium' : 'strong'
  };
};

// Generate audit trail entry for password changes
const createPasswordAuditEntry = (userId, ip, userAgent, success = true) => {
  return {
    userId,
    action: 'password_update',
    success,
    ip,
    userAgent: userAgent?.browser?.name || 'Unknown',
    timestamp: new Date().toISOString(),
    changeId: crypto.randomUUID()
  };
};

module.exports = async (req, res) => {
  const startTime = Date.now();

  try {
    // Rate limiting check for password updates
    try {
      await passwordUpdateRateLimiter.consume(req.user.id);
    } catch (rateLimiterRes) {
      logger.security('Password update rate limit exceeded', {
        userId: req.user.id,
        ip: req.clientIp,
        remainingPoints: rateLimiterRes.remainingPoints,
        msBeforeNext: rateLimiterRes.msBeforeNext
      });

      return res.status(429).json({
        success: false,
        error: 'Too many password update attempts. Please try again later.',
        retryAfter: Math.round(rateLimiterRes.msBeforeNext / 1000)
      });
    }

    // Validate request format
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Password update validation failed', {
        userId: req.user?.id,
        errors: errors.array(),
        ip: req.clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;
    const userData = req.user;
    const clientIp = req.clientIp;
    const userAgent = req.userAgent?.getResult();

    // Verify current password
    if (!currentPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current password is required',
        field: 'currentPassword'
      });
    }

    const passwordValid = await bcrypt.compare(currentPassword, userData.password);
    if (!passwordValid) {
      logger.security('Password update failed: invalid current password', {
        userId: userData.id,
        ip: clientIp
      });

      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    // Validate new password
    if (!newPassword) {
      return res.status(400).json({
        success: false,
        error: 'New password is required',
        field: 'newPassword'
      });
    }

    // Check if new password is different from current
    const isSamePassword = await bcrypt.compare(newPassword, userData.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        error: 'New password must be different from current password'
      });
    }

    // Validate password strength
    const passwordStrength = validatePasswordStrength(newPassword);
    if (!passwordStrength.isValid) {
      logger.warn('Password update failed: weak password', {
        userId: userData.id,
        strength: passwordStrength.strength,
        score: passwordStrength.score,
        ip: clientIp
      });

      return res.status(400).json({
        success: false,
        error: 'Password does not meet security requirements',
        requirements: {
          minLength: 8,
          maxLength: 128,
          requiresLowercase: true,
          requiresUppercase: true,
          requiresNumber: true,
          requiresSpecialChar: true,
          noCommonPasswords: true,
          noSequentialChars: true
        },
        strength: passwordStrength,
        field: 'newPassword'
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password in database with transaction
    const result = await new Promise((resolve, reject) => {
      db.transaction(() => {
        try {
          const updateResult = db.prepare(`
            UPDATE users 
            SET password = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
          `).run(hashedPassword, userData.id);

          if (updateResult.changes === 0) {
            throw new Error('No rows updated');
          }

          // Invalidate all other sessions except current one
          const sessionInvalidateResult = db.prepare(`
            UPDATE sessions 
            SET active = 'false', revoked_at = CURRENT_TIMESTAMP 
            WHERE user_id = ? AND session_id != ?
          `).run(userData.id, userData.sessionId);

          resolve({
            success: true,
            changesCount: updateResult.changes,
            sessionsInvalidated: sessionInvalidateResult.changes
          });
        } catch (error) {
          reject(error);
        }
      })();
    });

    // Log successful password update
    const processingTime = Date.now() - startTime;

    logger.info('Password updated successfully', {
      userId: userData.id,
      sessionsInvalidated: result.sessionsInvalidated,
      processingTime,
      ip: clientIp,
      userAgent: userAgent?.browser?.name
    });

    // Create audit entry
    const auditEntry = createPasswordAuditEntry(userData.id, clientIp, userAgent, true);
    logger.info('Password change audit', auditEntry);

    return res.status(200).json({
      success: true,
      message: 'Password updated successfully',
      metadata: {
        processingTime,
        sessionsInvalidated: result.sessionsInvalidated,
        auditTrail: true,
        passwordStrength: passwordStrength.strength
      }
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;

    // Create failed audit entry
    const auditEntry = createPasswordAuditEntry(
      req.user?.id,
      req.clientIp,
      req.userAgent?.getResult(),
      false
    );
    logger.error('Password update failed', {
      ...auditEntry,
      error: error.message,
      stack: error.stack,
      processingTime
    });

    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      requestId: req.requestId
    });
  }
}; 