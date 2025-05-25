const jwt = require('jsonwebtoken');
const db = require('../db');
const logger = require('../logger');
const UAParser = require('ua-parser-js');
const { isbot } = require('isbot');
const fs = require('fs-extra');
const path = require('path');
const _ = require('lodash');

let rolesConfig = {};
try {
  const rolesPath = path.join(__dirname, '..', 'config', 'roles.json');
  const configExists = fs.pathExistsSync(rolesPath);

  if (configExists) {
    rolesConfig = fs.readJsonSync(rolesPath);
    logger.info('Roles configuration loaded successfully', {
      roles: Object.keys(rolesConfig),
      totalRoles: Object.keys(rolesConfig).length
    });
  } else {
    logger.warn('Roles configuration file not found, creating default', { path: rolesPath });

    fs.ensureDirSync(path.dirname(rolesPath));
    fs.writeJsonSync(rolesPath, {}, { spaces: 2 });
    rolesConfig = {};
  }
} catch (error) {
  logger.error('Failed to load roles configuration', { error: error.message });
  rolesConfig = {};
}

/**
 * Get permissions for a role from the roles configuration
 * @param {string} role - Role name
 * @returns {Array<string>} Array of permissions
 */
const getRolePermissions = (role) => {
  if (!role || _.isEmpty(rolesConfig)) {
    return [];
  }

  const roleConfig = _.get(rolesConfig, role);
  if (!roleConfig) {
    logger.warn('Role not found in configuration', { role, availableRoles: Object.keys(rolesConfig) });
    return [];
  }

  return _.get(roleConfig, 'permissions', []);
};

/**
 * Token verification middleware with configurable options
 * @param {Object} options - Configuration options
 * @param {boolean} options.requireUser - Whether the user must exist in database (default: true)
 * @param {Array<string>} options.permissions - Required permissions (use ['*'] for any permission)
 * @param {boolean} options.strictMode - Enable strict security mode (default: true)
 * @returns {Function} Express middleware function
 */
const verifyToken = (options = {}) => {
  const {
    requireUser = true,
    permissions = [],
    strictMode = true
  } = options;

  return async (req, res, next) => {
    try {
      // Parse user agent
      const userAgent = req.get('User-Agent') || '';
      const parser = new UAParser(userAgent);
      const uaResult = parser.getResult();

      // Bot protection if enabled
      if (process.env.BOT_PROTECT === 'true') {
        if (isbot(userAgent)) {
          logger.warn('Bot access attempt blocked', {
            ip: req.clientIp,
            userAgent: userAgent,
            path: req.path,
            browser: uaResult.browser.name,
            os: uaResult.os.name
          });
          return res.status(403).json({
            message: 'Bot access not allowed',
            code: 'BOT_BLOCKED'
          });
        }
      }

      // Extract token from Authorization header
      const authHeader = req.headers['authorization'];

      if (!authHeader) {
        logger.warn('Missing authorization header', {
          ip: req.clientIp,
          userAgent: userAgent,
          path: req.path,
          browser: uaResult.browser.name,
          os: uaResult.os.name
        });
        return res.status(401).json({
          message: 'Access denied. No token provided.',
          code: 'NO_TOKEN'
        });
      }

      // Validate Bearer token format
      const tokenParts = authHeader.split(' ');
      if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        logger.warn('Invalid token format', {
          ip: req.clientIp,
          authHeader: authHeader.substring(0, 20) + '...',
          path: req.path
        });
        return res.status(401).json({
          message: 'Invalid token format. Use Bearer <token>',
          code: 'INVALID_FORMAT'
        });
      }

      const token = tokenParts[1];

      // Verify JWT token
      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET, {
          algorithms: [process.env.JWT_ALGORITHM || 'HS256'], // Restrict to specific algorithm
          maxAge: strictMode ? '24h' : '7d', // Token expiration based on strict mode
          clockTolerance: 30 // Allow 30 seconds clock skew
        });
      } catch (jwtError) {
        logger.warn('JWT verification failed', {
          error: jwtError.message,
          ip: req.clientIp,
          path: req.path,
          tokenPrefix: token.substring(0, 10) + '...'
        });

        if (jwtError.name === 'TokenExpiredError') {
          return res.status(401).json({
            message: 'Token has expired',
            code: 'TOKEN_EXPIRED'
          });
        } else if (jwtError.name === 'JsonWebTokenError') {
          return res.status(401).json({
            message: 'Invalid token',
            code: 'INVALID_TOKEN'
          });
        } else {
          return res.status(401).json({
            message: 'Token verification failed',
            code: 'VERIFICATION_FAILED'
          });
        }
      }

      // Validate required token fields
      if (!decoded.userId || (strictMode && !decoded.iat)) {
        logger.warn('Token missing required fields', {
          userId: !!decoded.userId,
          iat: !!decoded.iat,
          ip: req.clientIp,
          path: req.path
        });
        return res.status(401).json({
          message: 'Invalid token structure',
          code: 'INVALID_STRUCTURE'
        });
      }

      // Check if user exists in database (if required)
      let user = null;
      if (requireUser) {
        try {
          // Use better-sqlite3 API with the correct schema
          const userQuery = db.prepare('SELECT id, name, email, role, ban, ban_reason, two_factor, register_data, updated_at, created_at FROM users WHERE id = ? AND ban = 0');
          user = userQuery.get(decoded.userId);

          if (!user) {
            logger.warn('User not found or banned', {
              userId: decoded.userId,
              ip: req.clientIp,
              path: req.path,
              browser: uaResult.browser.name,
              os: uaResult.os.name
            });
            return res.status(401).json({
              message: 'User not found or account suspended',
              code: 'USER_NOT_FOUND'
            });
          }

          // Parse register_data if it exists
          if (user.register_data) {
            try {
              user.register_data = JSON.parse(user.register_data);
            } catch (parseError) {
              logger.warn('Failed to parse user register_data', {
                userId: user.id,
                error: parseError.message
              });
              user.register_data = {};
            }
          }

          // Update user activity in strict mode
          if (strictMode) {
            const updateQuery = db.prepare('UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?');
            updateQuery.run(user.id);

            // Create or update session record
            const sessionData = {
              user_id: user.id,
              ip: req.ip,
              user_agent: userAgent,
              last_activity: new Date().toISOString()
            };

            const insertSessionQuery = db.prepare(`
              INSERT INTO sessions (user_id, ip, user_agent, last_activity) 
              VALUES (?, ?, ?, ?)
            `);
            insertSessionQuery.run(sessionData.user_id, sessionData.ip, sessionData.user_agent, sessionData.last_activity);
          }
        } catch (dbError) {
          logger.error('Database error during user verification', {
            error: dbError.message,
            userId: decoded.userId,
            ip: req.ip,
            path: req.path,
            browser: uaResult.browser.name,
            os: uaResult.os.name
          });
          return res.status(500).json({
            message: 'Internal server error',
            code: 'DATABASE_ERROR'
          });
        }
      }

      // Get user permissions from role and direct permissions using lodash
      let userPermissions = [];
      if (user) {
        // Get permissions from role
        const rolePermissions = getRolePermissions(user.role);

        // Get direct permissions from register_data or token
        const directPermissions = _.get(user, 'register_data.permissions', []);
        const tokenPermissions = _.get(decoded, 'permissions', []);

        // Combine and deduplicate permissions using lodash
        userPermissions = _.uniq([
          ..._.castArray(rolePermissions),
          ..._.castArray(directPermissions),
          ..._.castArray(tokenPermissions)
        ]);

        // Filter out empty values
        userPermissions = _.compact(userPermissions);
      } else {
        // Fallback to token permissions if user not required
        userPermissions = _.castArray(_.get(decoded, 'permissions', []));
      }

      // Check permissions if specified using lodash
      if (!_.isEmpty(permissions)) {
        // Wildcard permission allows everything
        if (!_.includes(permissions, '*')) {
          // Check if user has any of the required permissions using lodash intersection
          const hasWildcard = _.includes(userPermissions, '*');
          const hasRequiredPermission = !_.isEmpty(_.intersection(permissions, userPermissions));

          if (!hasWildcard && !hasRequiredPermission) {
            const missingPermissions = _.difference(permissions, userPermissions);

            logger.warn('Insufficient permissions', {
              userId: decoded.userId,
              requiredPermissions: permissions,
              userPermissions: userPermissions,
              missingPermissions: missingPermissions,
              userRole: _.get(user, 'role'),
              ip: req.ip,
              path: req.path,
              browser: uaResult.browser.name,
              os: uaResult.os.name
            });
            return res.status(403).json({
              message: 'Insufficient permissions',
              code: 'INSUFFICIENT_PERMISSIONS',
              required: permissions,
              missing: missingPermissions
            });
          }
        }
      }

      // Attach comprehensive user information to request object using lodash
      req.user = _.merge({
        id: decoded.userId,
        email: _.get(user, 'email', _.get(decoded, 'email')),
        name: _.get(user, 'name', _.get(decoded, 'name')),
        role: _.get(user, 'role', _.get(decoded, 'role', 'user')),
        permissions: userPermissions,
        isBanned: _.get(user, 'ban', 0) === 1,
        banReason: _.get(user, 'ban_reason'),
        twoFactorEnabled: _.get(user, 'two_factor') === 'true',
        registerData: _.get(user, 'register_data', {}),
        accountCreated: _.get(user, 'created_at'),
        lastUpdated: _.get(user, 'updated_at'),
        token: {
          iat: decoded.iat,
          exp: decoded.exp,
          algorithm: 'HS256'
        }
      }, {
        device: {
          browser: _.pick(uaResult.browser, ['name', 'version', 'major']),
          os: _.pick(uaResult.os, ['name', 'version']),
          device: _.merge(
            _.pick(uaResult.device, ['type', 'vendor', 'model']),
            { type: _.get(uaResult.device, 'type', 'desktop') }
          ),
          engine: _.pick(uaResult.engine, ['name', 'version']),
          cpu: _.pick(uaResult.cpu, ['architecture']),
          userAgent: userAgent,
          isBot: isbot(userAgent),
          isMobile: _.includes(['mobile', 'tablet'], _.get(uaResult.device, 'type')),
          isDesktop: _.get(uaResult.device, 'type', 'desktop') === 'desktop'
        },
        request: {
          ip: req.ip,
          path: req.path,
          method: req.method,
          timestamp: new Date().toISOString()
        }
      });

      // Add security headers for strict mode
      if (strictMode) {
        res.set({
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block'
        });
      }

      logger.info('Token verification successful', _.pick(req.user, [
        'id', 'email', 'role', 'permissions', 'isBanned', 'twoFactorEnabled'
      ]), {
        device: _.pick(req.user.device, ['browser.name', 'os.name', 'device.type', 'isBot', 'isMobile']),
        request: _.pick(req.user.request, ['ip', 'path', 'method']),
        sessionInfo: {
          tokenExpiry: new Date(decoded.exp * 1000).toISOString(),
          strictMode: strictMode,
          requireUser: requireUser
        }
      });

      next();
    } catch (error) {
      logger.error('Unexpected error in token verification', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        path: req.path
      });
      return res.status(500).json({
        message: 'Internal server error',
        code: 'INTERNAL_ERROR'
      });
    }
  };
};

module.exports = verifyToken;