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
 * Get data about roles from the roles configuration
 * @param {string} role - The role name
 * @returns {Object} Data about the role
 */
const getRole = (role) => {
  const currentRolesConfiguration = loadRolesConfiguration();
  if (_.isEmpty(currentRolesConfiguration)) {
    logger.warn('No roles configuration available');
    return {};
  }
  const roleConfiguration = currentRolesConfiguration[role];
  if (_.isEmpty(roleConfiguration)) {
    logger.warn('Role not found in configuration', {
      requestedRole: role,
      availableRoles: Object.keys(currentRolesConfiguration)
    });
    return {};
  }
  return roleConfiguration;
};

/**
 * Get permissions for a specific role from the roles configuration
 * @param {string} userRole - The user's role name
 * @returns {Array<string>} Array of permissions for the role
 */
const getPermissions = (userRole) => {
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

module.exports = {
  getRole,
  getPermissions
};