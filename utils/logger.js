const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// Configuration
const LOG_CONFIG = {
    logDir: process.env.LOG_DIR || path.join(__dirname, '..', 'logs'),
    maxSize: process.env.LOG_MAX_SIZE || '20m',
    maxFiles: process.env.LOG_MAX_FILES || '14d',
    datePattern: 'YYYY-MM-DD',
    auditFile: 'audit.json',
    encryptLogs: process.env.ENCRYPT_LOGS === 'true',
    encryptionKey: process.env.LOG_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    sensitiveFields: ['password', 'token', 'secret', 'key', 'authorization', 'cookie', 'session'],
    environment: process.env.NODE_ENV || 'development'
};

// Ensure log directory exists with proper permissions
const initializeLogDirectory = () => {
    try {
        if (!fs.existsSync(LOG_CONFIG.logDir)) {
            fs.mkdirSync(LOG_CONFIG.logDir, { recursive: true, mode: 0o750 });
        }
        
        // Set restrictive permissions on log directory (owner read/write/execute only)
        if (process.platform !== 'win32') {
            fs.chmodSync(LOG_CONFIG.logDir, 0o750);
        }
    } catch (error) {
        console.error('Failed to initialize log directory:', error.message);
        process.exit(1);
    }
};

// Security: Sanitize sensitive data from logs
const sanitizeData = (data) => {
    if (typeof data !== 'object' || data === null) {
        return data;
    }
    
    const sanitized = Array.isArray(data) ? [] : {};
    
    for (const [key, value] of Object.entries(data)) {
        const lowerKey = key.toLowerCase();
        const isSensitive = LOG_CONFIG.sensitiveFields.some(field => 
            lowerKey.includes(field.toLowerCase())
        );
        
        if (isSensitive) {
            sanitized[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeData(value);
        } else {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
};

// Custom format for structured logging with security
const createSecureFormat = () => {
    return winston.format.combine(
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss.SSS'
        }),
        winston.format.errors({ stack: true }),
        winston.format.printf((info) => {
            const baseLog = {
                timestamp: info.timestamp,
                level: info.level.toUpperCase(),
                message: info.message,
                service: process.env.SERVICE_NAME || 'application',
                version: process.env.APP_VERSION || '1.0.0',
                environment: LOG_CONFIG.environment,
                hostname: os.hostname(),
                pid: process.pid,
                requestId: info.requestId || null,
                userId: info.userId || null,
                ip: info.ip || null,
                userAgent: info.userAgent || null
            };

            // Add stack trace for errors
            if (info.stack) {
                baseLog.stack = info.stack;
            }

            // Add metadata if present
            if (info.metadata) {
                baseLog.metadata = sanitizeData(info.metadata);
            }

            // Add performance metrics if present
            if (info.duration) {
                baseLog.duration = info.duration;
            }

            // Add correlation ID for distributed tracing
            if (info.correlationId) {
                baseLog.correlationId = info.correlationId;
            }

            return JSON.stringify(baseLog);
        })
    );
};

// Create transport configurations
const createTransports = () => {
    const transports = [];

    // Console transport for development
    if (LOG_CONFIG.environment === 'development') {
        transports.push(
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            })
        );
    }

    // Error log with rotation
    transports.push(
        new DailyRotateFile({
            filename: path.join(LOG_CONFIG.logDir, 'error-%DATE%.log'),
            datePattern: LOG_CONFIG.datePattern,
            level: 'error',
            maxSize: LOG_CONFIG.maxSize,
            maxFiles: LOG_CONFIG.maxFiles,
            auditFile: path.join(LOG_CONFIG.logDir, 'error-' + LOG_CONFIG.auditFile),
            format: createSecureFormat(),
            handleExceptions: true,
            handleRejections: true
        })
    );

    // Combined log with rotation
    transports.push(
        new DailyRotateFile({
            filename: path.join(LOG_CONFIG.logDir, 'combined-%DATE%.log'),
            datePattern: LOG_CONFIG.datePattern,
            maxSize: LOG_CONFIG.maxSize,
            maxFiles: LOG_CONFIG.maxFiles,
            auditFile: path.join(LOG_CONFIG.logDir, 'combined-' + LOG_CONFIG.auditFile),
            format: createSecureFormat()
        })
    );

    // Security audit log
    transports.push(
        new DailyRotateFile({
            filename: path.join(LOG_CONFIG.logDir, 'security-%DATE%.log'),
            datePattern: LOG_CONFIG.datePattern,
            level: 'warn',
            maxSize: LOG_CONFIG.maxSize,
            maxFiles: '30d', // Keep security logs longer
            auditFile: path.join(LOG_CONFIG.logDir, 'security-' + LOG_CONFIG.auditFile),
            format: createSecureFormat()
        })
    );

    // Performance log
    transports.push(
        new DailyRotateFile({
            filename: path.join(LOG_CONFIG.logDir, 'performance-%DATE%.log'),
            datePattern: LOG_CONFIG.datePattern,
            maxSize: LOG_CONFIG.maxSize,
            maxFiles: LOG_CONFIG.maxFiles,
            auditFile: path.join(LOG_CONFIG.logDir, 'performance-' + LOG_CONFIG.auditFile),
            format: createSecureFormat(),
            level: 'info'
        })
    );

    return transports;
};

// Initialize log directory
initializeLogDirectory();

// Create the main logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    transports: createTransports(),
    exitOnError: false,
    silent: process.env.NODE_ENV === 'test'
});

// Enhanced logging methods with security and context
const Logger = {
    // Standard logging methods
    error: (message, metadata = {}) => {
        logger.error(message, { metadata: sanitizeData(metadata) });
    },

    warn: (message, metadata = {}) => {
        logger.warn(message, { metadata: sanitizeData(metadata) });
    },

    info: (message, metadata = {}) => {
        logger.info(message, { metadata: sanitizeData(metadata) });
    },

    debug: (message, metadata = {}) => {
        logger.debug(message, { metadata: sanitizeData(metadata) });
    },

    // Security-specific logging
    security: (event, details = {}) => {
        logger.warn(`SECURITY_EVENT: ${event}`, {
            metadata: sanitizeData(details),
            securityEvent: true
        });
    },

    // Performance logging
    performance: (operation, duration, metadata = {}) => {
        logger.info(`PERFORMANCE: ${operation}`, {
            duration,
            metadata: sanitizeData(metadata),
            performanceMetric: true
        });
    },

    // Request logging with context
    request: (req, res, duration) => {
        const logData = {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            requestId: req.id,
            userId: req.user?.id,
            correlationId: req.headers['x-correlation-id']
        };

        if (res.statusCode >= 400) {
            logger.error('HTTP Request Error', { metadata: logData });
        } else {
            logger.info('HTTP Request', { metadata: logData });
        }
    },

    // Database operation logging
    database: (operation, table, duration, metadata = {}) => {
        logger.info(`DB_OPERATION: ${operation} on ${table}`, {
            duration,
            metadata: sanitizeData(metadata),
            databaseOperation: true
        });
    },

    // Authentication events
    auth: (event, userId, metadata = {}) => {
        logger.info(`AUTH_EVENT: ${event}`, {
            userId,
            metadata: sanitizeData(metadata),
            authEvent: true
        });
    },

    // Business logic events
    business: (event, metadata = {}) => {
        logger.info(`BUSINESS_EVENT: ${event}`, {
            metadata: sanitizeData(metadata),
            businessEvent: true
        });
    },

    // System health monitoring
    health: (component, status, metadata = {}) => {
        const level = status === 'healthy' ? 'info' : 'warn';
        logger[level](`HEALTH_CHECK: ${component} is ${status}`, {
            metadata: sanitizeData(metadata),
            healthCheck: true
        });
    },

    // Audit trail for compliance
    audit: (action, actor, target, metadata = {}) => {
        logger.info(`AUDIT: ${actor} performed ${action} on ${target}`, {
            metadata: sanitizeData(metadata),
            auditTrail: true,
            actor,
            action,
            target
        });
    }
};

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
        metadata: {
            error: error.message,
            stack: error.stack
        }
    });
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection', {
        metadata: {
            reason: reason?.message || reason,
            stack: reason?.stack
        }
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    logger.end();
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, shutting down gracefully');
    logger.end();
});

module.exports = Logger;