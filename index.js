const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const requestIp = require('request-ip');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const compression = require('compression');
const hpp = require('hpp');
const { doubleCsrf } = require('csrf-csrf');
const UAParser = require('ua-parser-js');
const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');
require('dotenv').config();
const logger = require('./utils/logger');
const db = require('./db');

const app = express();

// Trust proxy for accurate IP addresses behind reverse proxies
app.set('trust proxy', process.env.TRUST_PROXY || 1);

// Security: Generate nonce for CSP
app.use((req, res, next) => {
  try {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    req.userAgent = new UAParser(req.headers['user-agent']);
    next();
  } catch (error) {
    logger.error('Error generating nonce', {
      error: error.message,
      stack: error.stack
    });
    next(error);
  }
});

// Security: Comprehensive Helmet configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
    reportOnly: process.env.NODE_ENV === 'development'
  },
  crossOriginEmbedderPolicy: { policy: "require-corp" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: "no-referrer" },
  xssFilter: true
}));

// Security: CORS configuration with strict settings
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS ?
      process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) :
      ['http://localhost:3000', 'http://localhost:3001'];

    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      logger.security('CORS violation attempt', {
        origin,
        allowedOrigins,
        ip: requestIp.getClientIp(req)
      });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400, // 24 hours
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-API-Key',
    'X-Request-ID'
  ],
  exposedHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining']
};

app.use(cors(corsOptions));

// Security: Rate limiting with different tiers
const createRateLimit = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    keyGenerator: (req) => {
      return req.ip + ':' + (req.userAgent || '');
    },
    handler: (req, res) => {
      // Log rate limit exceeded
      logger.security('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.userAgent,
        path: req.path,
        method: req.method
      });

      res.status(429).json({
        error: message,
        retryAfter: Math.round(windowMs / 1000),
        requestId: req.requestId
      });
    }
  });
};

// Global rate limiting
app.use(createRateLimit(
  10 * 60 * 1000, // 10 minutes
  1000, // limit each IP to 1000 requests per windowMs
  'Too many requests from this IP, please try again later.'
));

// Speed limiting (progressive delay)
app.use(slowDown({
  windowMs: 10 * 60 * 1000, // 10 minutes
  delayAfter: 500, // allow 500 requests per windowMs without delay
  delayMs: (used, req) => (used - 500) * 500, // progressive delay calculation for v2
  maxDelayMs: 20000, // max delay of 20 seconds
  skipSuccessfulRequests: true
}));

// Security: Compression with security considerations
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    // Don't compress responses that may contain sensitive data
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// CSRF temporarily disabled to isolate path-to-regexp error
const {
  generateToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'your-secret-key',
  cookieName: 'csrf_token',
  cookieOptions: {
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: false,
  },
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

// CSRF token endpoint (no protection needed)
app.get('/csrf-token', (req, res) => {
  const token = generateToken(req, res);
  res.json({ csrfToken: token });
});

app.use(cookieParser(process.env.COOKIE_SECRET || crypto.randomBytes(64).toString('hex'), {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));

// Apply CSRF protection globally
app.use(doubleCsrfProtection);

app.use(express.json({
  limit: process.env.JSON_LIMIT || '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({
  extended: true,
  limit: process.env.URL_ENCODED_LIMIT || '10mb',
  parameterLimit: 100
}));

app.use(requestIp.mw());

app.use(hpp({
  whitelist: ['tags', 'categories']
}));

// Security: Request logging and monitoring
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  // Log request details
  logger.info('Incoming request', {
    requestId,
    method: req.method,
    url: req.url,
    ip: req.clientIp,
    userAgent: req.userAgent?.getResult(),
    referer: req.headers.referer,
    contentLength: req.headers['content-length']
  });

  // Monitor response
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logLevel = res.statusCode >= 400 ? 'warn' : 'info';

    logger[logLevel]('Request completed', {
      requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      ip: req.clientIp,
      userAgent: req.userAgent?.getResult()
    });

    // Log slow requests
    if (duration > 5000) {
      logger.warn('Slow request detected', {
        requestId,
        method: req.method,
        url: req.url,
        duration,
        ip: req.clientIp
      });
    }
  });

  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint (before other routes)
app.get('/health', (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  };

  res.status(200).json(healthCheck);
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Server is running securely',
    version: process.env.APP_VERSION || '1.0.0',
    timestamp: new Date().toISOString(),
    requestId: req.requestId
  });
});

// API routes
app.use('/api', require('./routes/router'));

app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();

  logger.error('Unhandled error', {
    errorId,
    message: err.message,
    stack: err.stack,
    requestId: req.requestId,
    method: req.method,
    url: req.url,
    ip: req.clientIp,
    userAgent: req.userAgent?.getResult()
  });

  const isDevelopment = process.env.NODE_ENV === 'development';

  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal server error',
    errorId,
    requestId: req.requestId,
    ...(isDevelopment && { stack: err.stack })
  });
});

const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully`);
  db.close();

  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', {
    reason: reason.toString(),
    promise: promise.toString()
  });
  db.close();
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', {
    message: err.message,
    stack: err.stack
  });
  db.close();
  process.exit(1);
});

const PORT = process.env.PORT;

if (!PORT) {
  logger.error('[FATAL] PORT is not set');
  process.exit(1);
}

app.listen(PORT, () => {
  logger.info(`Server started successfully`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    pid: process.pid
  });
});