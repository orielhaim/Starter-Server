const jwt = require('jsonwebtoken');
const db = require('../db');
const logger = require('../utils/logger');
const { isbot } = require('isbot');
const fs = require('fs-extra');
const path = require('path');
const _ = require('lodash');

// Cache for roles configuration to improve performance
let rolesConfigurationCache = {};
let lastConfigLoadTime = 0;
const CONFIG_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Load roles configuration with caching for better performance
 * @returns {Object} Roles configuration object
 */
const loadRolesConfiguration = () => {
  const currentTime = Date.now();

  // Return cached config if still valid
  if (currentTime - lastConfigLoadTime < CONFIG_CACHE_TTL && !_.isEmpty(rolesConfigurationCache)) {
    return rolesConfigurationCache;
  }

  try {
    const rolesConfigurationPath = path.join(__dirname, '..', 'config', 'roles.json');
    const configurationFileExists = fs.pathExistsSync(rolesConfigurationPath);

    if (configurationFileExists) {
      rolesConfigurationCache = fs.readJsonSync(rolesConfigurationPath);
      lastConfigLoadTime = currentTime;

      logger.info('Roles configuration loaded successfully', {
        availableRoles: Object.keys(rolesConfigurationCache),
        totalRolesCount: Object.keys(rolesConfigurationCache).length,
        cacheUpdated: true
      });
    } else {
      logger.warn('Roles configuration file not found, creating default configuration', {
        configPath: rolesConfigurationPath
      });

      fs.ensureDirSync(path.dirname(rolesConfigurationPath));
      fs.writeJsonSync(rolesConfigurationPath, {}, { spaces: 2 });
      rolesConfigurationCache = {};
      lastConfigLoadTime = currentTime;
    }
  } catch (configurationError) {
    logger.error('Failed to load roles configuration', {
      errorMessage: configurationError.message,
      errorStack: configurationError.stack
    });
    rolesConfigurationCache = {};
  }

  return rolesConfigurationCache;
};

/**
 * Get permissions for a specific role from the roles configuration
 * @param {string} userRole - The user's role name
 * @returns {Array<string>} Array of permissions for the role
 */
const getUserRolePermissions = (userRole) => {
  if (!userRole || typeof userRole !== 'string') {
    logger.debug('Invalid role provided', { providedRole: userRole });
    return [];
  }

  const currentRolesConfiguration = loadRolesConfiguration();

  if (_.isEmpty(currentRolesConfiguration)) {
    logger.warn('No roles configuration available');
    return [];
  }

  const roleConfiguration = _.get(currentRolesConfiguration, userRole);
  if (!roleConfiguration) {
    logger.warn('Role not found in configuration', {
      requestedRole: userRole,
      availableRoles: Object.keys(currentRolesConfiguration)
    });
    return [];
  }

  const rolePermissions = _.get(roleConfiguration, 'permissions', []);
  return _.isArray(rolePermissions) ? _.compact(rolePermissions) : [];
};

/**
 * Check if user has required permissions
 * @param {Array<string>} userPermissionsList - User's permissions
 * @param {Array<string>} requiredPermissionsList - Required permissions
 * @returns {Object} Permission check result
 */
const validateUserPermissions = (userPermissionsList, requiredPermissionsList) => {
  if (_.isEmpty(requiredPermissionsList)) {
    return { hasAccess: true, missingPermissions: [] };
  }

  if (_.isEmpty(userPermissionsList)) {
    return { hasAccess: false, missingPermissions: requiredPermissionsList };
  }

  // Check for wildcard permission
  if (_.includes(userPermissionsList, '*')) {
    return { hasAccess: true, missingPermissions: [] };
  }

  // Check for intersection of required and user permissions
  const matchingPermissions = _.intersection(requiredPermissionsList, userPermissionsList);
  const hasRequiredAccess = !_.isEmpty(matchingPermissions);
  const missingPermissions = _.difference(requiredPermissionsList, userPermissionsList);

  return {
    hasAccess: hasRequiredAccess,
    missingPermissions: missingPermissions
  };
};

/**
 * Enhanced token verification middleware with configurable security options
 * @param {Object} middlewareOptions - Configuration options for the middleware
 * @param {boolean} middlewareOptions.requireUserExists - Whether the user must exist in database (default: true)
 * @param {Array<string>} middlewareOptions.requiredPermissions - Required permissions array
 * @param {boolean} middlewareOptions.strictSecurity - Enable strict security mode (default: true)
 * @param {string} middlewareOptions.userData - User data to be added to the request object (default: "regular") ["regular", "minimal", "full"]
 * @param {boolean} middlewareOptions.botProtection - Enable bot protection (default: from env)
 * @returns {Function} Express middleware function
 */
const verifyToken = (middlewareOptions = {}) => {
  const {
    requireUserExists = true,
    requiredPermissions = [],
    strictSecurity = true,
    userData = "regular",
    botProtection = process.env.BOT_PROTECT === 'true'
  } = middlewareOptions;

  return async (req, res, next) => {
    const requestStartTime = Date.now();
    const clientIpAddress = req.clientIp || req.ip;
    const requestPath = req.path;
    const requestMethod = req.method;

    try {
      // Parse user agent information
      const rawUserAgentString = req.get('User-Agent') || '';
      const parsedUserAgentData = req.userAgent?.getResult() || {};

      // Bot protection validation
      if (botProtection && isbot(rawUserAgentString)) {
        logger.warn('Bot access attempt blocked by security policy', {
          clientIp: clientIpAddress,
          userAgent: rawUserAgentString,
          requestPath: requestPath,
          requestMethod: requestMethod,
          browserName: parsedUserAgentData.browser.name,
          operatingSystem: parsedUserAgentData.os.name
        });

        return res.status(403).json({
          message: 'Bot access not permitted',
          code: 'BOT_ACCESS_BLOCKED',
          timestamp: new Date().toISOString()
        });
      }

      // Extract session token from cookies
      const sessionTokenFromCookie = req.cookies['session_token']?.trim();

      if (!sessionTokenFromCookie) {
        logger.warn('Authentication failed: missing session token', {
          clientIp: clientIpAddress,
          userAgent: rawUserAgentString,
          requestPath: requestPath,
          requestMethod: requestMethod,
          browserName: parsedUserAgentData.browser.name,
          operatingSystem: parsedUserAgentData.os.name
        });

        return res.status(401).json({
          message: 'Access denied. Authentication token required.',
          code: 'MISSING_AUTH_TOKEN',
          timestamp: new Date().toISOString()
        });
      }

      // JWT token verification with enhanced security
      let decodedTokenPayload;
      try {
        const jwtVerificationOptions = {
          algorithms: [process.env.JWT_ALGORITHM || 'HS256'],
          maxAge: strictSecurity ? '24h' : '7d',
          clockTolerance: 30, // 30 seconds clock skew tolerance
          issuer: process.env.JWT_ISSUER,
          audience: process.env.JWT_AUDIENCE
        };

        decodedTokenPayload = jwt.verify(sessionTokenFromCookie, process.env.JWT_SECRET, jwtVerificationOptions);
      } catch (jwtVerificationError) {
        const tokenPreview = sessionTokenFromCookie.substring(0, 10) + '...';

        logger.warn('JWT token verification failed', {
          errorType: jwtVerificationError.name,
          errorMessage: jwtVerificationError.message,
          clientIp: clientIpAddress,
          requestPath: requestPath,
          tokenPreview: tokenPreview
        });

        let errorResponse = {
          message: 'Authentication failed',
          code: 'AUTH_VERIFICATION_FAILED',
          timestamp: new Date().toISOString()
        };

        if (jwtVerificationError.name === 'TokenExpiredError') {
          errorResponse.message = 'Authentication token has expired';
          errorResponse.code = 'TOKEN_EXPIRED';
        } else if (jwtVerificationError.name === 'JsonWebTokenError') {
          errorResponse.message = 'Invalid authentication token';
          errorResponse.code = 'INVALID_TOKEN_FORMAT';
        }

        return res.status(401).json(errorResponse);
      }

      // Validate essential token payload fields
      if (!decodedTokenPayload.userId || (strictSecurity && !decodedTokenPayload.iat)) {
        logger.warn('Token payload validation failed', {
          hasUserId: !!decodedTokenPayload.userId,
          hasIssuedAt: !!decodedTokenPayload.iat,
          strictModeEnabled: strictSecurity,
          clientIp: clientIpAddress,
          requestPath: requestPath
        });

        return res.status(401).json({
          message: 'Invalid token structure',
          code: 'MALFORMED_TOKEN_PAYLOAD',
          timestamp: new Date().toISOString()
        });
      }

      let authenticatedUser = null;

      // Database user verification (if required)
      if (requireUserExists) {
        try {
          let userDataQuery = {}

          if (userData === "regular") {
            userDataQuery = db.prepare(`
              SELECT id, name, email, role, ban, two_factor, created_at
              FROM users 
              WHERE id = ?
            `);
          } else if (userData === "minimal") {
            userDataQuery = db.prepare(`
              SELECT id, role, ban, two_factor
              FROM users 
              WHERE id = ?
            `);
          } else if (userData === "full") {
            userDataQuery = db.prepare(`
              SELECT *
              FROM users 
              WHERE id = ?
            `);
          }

          authenticatedUser = userDataQuery.get(decodedTokenPayload.userId);

          if (!authenticatedUser) {
            logger.warn('User authentication failed: user not found in database', {
              requestedUserId: decodedTokenPayload.userId,
              clientIp: clientIpAddress,
              requestPath: requestPath,
              browserName: parsedUserAgentData.browser.name,
              operatingSystem: parsedUserAgentData.os.name
            });

            return res.status(401).json({
              message: 'User account not found',
              code: 'USER_NOT_FOUND',
              timestamp: new Date().toISOString()
            });
          }

          // Check user ban status
          const currentTimestamp = Date.now() / 1000;
          const userBanExpiration = authenticatedUser.ban || 0;

          if (userBanExpiration !== 0 && userBanExpiration > currentTimestamp) {
            const banExpirationDate = new Date(userBanExpiration * 1000);

            logger.warn('Access denied: user account is banned', {
              userId: authenticatedUser.id,
              banExpiration: banExpirationDate.toISOString(),
              banReason: authenticatedUser.ban_reason,
              clientIp: clientIpAddress,
              requestPath: requestPath
            });

            return res.status(403).json({
              message: 'Account access suspended',
              code: 'USER_ACCOUNT_BANNED',
              banExpiration: banExpirationDate.toISOString(),
              timestamp: new Date().toISOString()
            });
          }

          // Parse user registration data safely
          if (authenticatedUser.register_data) {
            try {
              authenticatedUser.register_data = JSON.parse(authenticatedUser.register_data);
            } catch (jsonParsingError) {
              logger.warn('Failed to parse user registration data', {
                userId: authenticatedUser.id,
                parsingError: jsonParsingError.message
              });
              authenticatedUser.register_data = {};
            }
          } else {
            authenticatedUser.register_data = {};
          }

          // Get user role permissions
          const userRolePermissions = getUserRolePermissions(authenticatedUser.role);
          authenticatedUser.permissions = userRolePermissions;

          // Validate user permissions against requirements
          if (!_.isEmpty(requiredPermissions)) {
            const permissionValidationResult = validateUserPermissions(userRolePermissions, requiredPermissions);

            if (!permissionValidationResult.hasAccess) {
              logger.warn('Access denied: insufficient user permissions', {
                userId: authenticatedUser.id,
                userRole: authenticatedUser.role,
                requiredPermissions: requiredPermissions,
                userPermissions: userRolePermissions,
                missingPermissions: permissionValidationResult.missingPermissions,
                clientIp: clientIpAddress,
                requestPath: requestPath
              });

              return res.status(403).json({
                message: 'Insufficient permissions for this operation',
                code: 'INSUFFICIENT_PERMISSIONS',
                required: requiredPermissions,
                missing: permissionValidationResult.missingPermissions,
                timestamp: new Date().toISOString()
              });
            }
          }

          // Attach user data to request object
          req.user = authenticatedUser;

        } catch (databaseQueryError) {
          logger.error('Database error during user authentication', {
            errorMessage: databaseQueryError.message,
            errorStack: databaseQueryError.stack,
            userId: decodedTokenPayload.userId,
            clientIp: clientIpAddress,
            requestPath: requestPath
          });

          return res.status(500).json({
            message: 'Internal authentication error',
            code: 'DATABASE_QUERY_FAILED',
            timestamp: new Date().toISOString()
          });
        }
      }

      // Log successful authentication
      const processingTimeMs = Date.now() - requestStartTime;

      logger.info('Token verification completed successfully', {
        userId: authenticatedUser?.id,
        userEmail: authenticatedUser?.email,
        userRole: authenticatedUser?.role,
        permissionsCount: authenticatedUser?.permissions?.length || 0,
        clientIp: clientIpAddress,
        requestPath: requestPath,
        requestMethod: requestMethod,
        browserName: parsedUserAgentData.browser.name,
        operatingSystem: parsedUserAgentData.os.name,
        processingTimeMs: processingTimeMs,
        strictModeEnabled: strictSecurity,
        botProtectionEnabled: botProtection,
        timestamp: new Date().toISOString()
      });

      next();

    } catch (unexpectedError) {
      const processingTimeMs = Date.now() - requestStartTime;

      logger.error('Unexpected error during token verification', {
        errorMessage: unexpectedError.message,
        errorStack: unexpectedError.stack,
        clientIp: clientIpAddress,
        requestPath: requestPath,
        requestMethod: requestMethod,
        processingTimeMs: processingTimeMs
      });

      return res.status(500).json({
        message: 'Internal server error during authentication',
        code: 'INTERNAL_AUTH_ERROR',
        timestamp: new Date().toISOString()
      });
    }
  };
};

module.exports = verifyToken;