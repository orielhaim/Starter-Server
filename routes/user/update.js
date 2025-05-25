const { validationResult } = require('express-validator');
const validator = require('validator');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const db = require('../../db');
const logger = require('../../utils/logger');
const crypto = require('crypto');

// Define updatable fields with their validation rules and security constraints
const UPDATABLE_FIELDS = {
  name: {
    validator: (value) => validator.isLength(value, { min: 3, max: 50 }) && validator.isAlphanumeric(value, 'en-US', { ignore: ' -_.' }),
    sanitizer: (value) => validator.escape(validator.trim(value)),
    sensitive: false,
    requiresReauth: false
  }
};

const updateRateLimiter = new RateLimiterMemory({
  points: 10,
  duration: 60,
  blockDuration: 60,
});

const createAuditEntry = (userId, field, oldValue, newValue, ip, userAgent) => {
  return {
    userId,
    field,
    oldValue: UPDATABLE_FIELDS[field].sensitive ? '[REDACTED]' : oldValue,
    newValue: UPDATABLE_FIELDS[field].sensitive ? '[REDACTED]' : newValue,
    ip,
    userAgent: userAgent?.browser?.name || 'Unknown',
    timestamp: new Date().toISOString(),
    changeId: crypto.randomUUID()
  };
};

module.exports = async (req, res) => {
  const startTime = Date.now();

  try {
    // Rate limiting check
    try {
      await updateRateLimiter.consume(req.user.id);
    } catch (rateLimiterRes) {
      logger.warn('Rate limit exceeded for user update', {
        userId: req.user.id,
        ip: req.clientIp,
        remainingPoints: rateLimiterRes.remainingPoints,
        msBeforeNext: rateLimiterRes.msBeforeNext
      });

      return res.status(429).json({
        success: false,
        error: 'Too many update attempts. Please try again later.',
        retryAfter: Math.round(rateLimiterRes.msBeforeNext / 1000)
      });
    }

    // Validate request format
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('User update validation failed', {
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

    const userData = req.user;
    const requestBody = req.body;
    const clientIp = req.clientIp;
    const userAgent = req.userAgent?.getResult();

    // Extract and validate fields to update
    const updates = {};
    const auditEntries = [];

    // Process each field in the request
    for (const [fieldName, newValue] of Object.entries(requestBody)) {
      // Skip if field is not updatable
      if (!UPDATABLE_FIELDS[fieldName]) {
        logger.warn('Attempt to update non-updatable field', {
          userId: userData.id,
          field: fieldName,
          ip: clientIp
        });
        continue;
      }

      const fieldConfig = UPDATABLE_FIELDS[fieldName];
      const currentValue = userData[fieldName];

      // Skip if value hasn't changed
      if (newValue === currentValue) {
        continue;
      }

      // Validate field value
      if (!fieldConfig.validator(newValue)) {
        return res.status(400).json({
          success: false,
          error: `Invalid ${fieldName} format`,
          field: fieldName
        });
      }

      // Sanitize and prepare value
      let processedValue = fieldConfig.sanitizer(newValue);

      updates[fieldName] = processedValue;

      // Create audit entry
      auditEntries.push(createAuditEntry(
        userData.id,
        fieldName,
        currentValue,
        newValue,
        clientIp,
        userAgent
      ));
    }

    // Check if any valid updates were provided
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No valid updates provided'
      });
    }

    // Perform database update in transaction
    const result = await new Promise((resolve, reject) => {
      db.transaction(() => {
        try {
          // Build dynamic SQL query
          const setClause = Object.keys(updates).map(field => `${field} = ?`).join(', ');
          const values = [...Object.values(updates), userData.id];

          const updateQuery = `
            UPDATE users 
            SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
          `;

          const updateResult = db.prepare(updateQuery).run(...values);

          if (updateResult.changes === 0) {
            throw new Error('No rows updated');
          }

          // Get updated user data
          const updatedUser = db.prepare(`
            SELECT id, name, email, role, two_factor, updated_at, created_at
            FROM users 
            WHERE id = ?
          `).get(userData.id);

          resolve({
            success: true,
            updatedUser,
            changesCount: updateResult.changes
          });
        } catch (error) {
          reject(error);
        }
      })();
    });

    // Log successful update
    const processingTime = Date.now() - startTime;

    logger.info('User profile updated successfully', {
      userId: userData.id,
      updatedFields: Object.keys(updates),
      auditEntries: auditEntries.length,
      processingTime,
      ip: clientIp,
      userAgent: userAgent?.browser?.name
    });

    // Log audit entries
    auditEntries.forEach(entry => {
      logger.info('User field updated', entry);
    });

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      updatedFields: Object.keys(updates),
      user: result.updatedUser,
      metadata: {
        processingTime,
        auditTrail: auditEntries.length > 0
      }
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;

    logger.error('User update failed', {
      userId: req.user?.id,
      error: error.message,
      stack: error.stack,
      processingTime,
      ip: req.clientIp
    });

    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      requestId: req.requestId
    });
  }
};