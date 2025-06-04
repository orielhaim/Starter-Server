const axios = require('axios');

/**
 * Cloudflare Turnstile validation middleware
 * Validates Turnstile tokens from client requests
 */
async function validateTurnstile(req, res, next) {
  try {
    const token = req.body?.['cf-turnstile-response'] ||
      req.query?.['cf-turnstile-response'] ||
      req.headers?.['cf-turnstile-response'];

    if (!token) {
      return res.status(400).json({
        error: 'Turnstile token is required',
        code: 'TURNSTILE_TOKEN_MISSING'
      });
    }

    const clientIP = req.clientIp;

    if (!clientIP) throw new Error('Client IP address are not available');

    const verificationData = {
      secret: process.env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: clientIP
    };

    const response = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      verificationData,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 10000,
        transformRequest: [(data) => {
          return Object.keys(data)
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`)
            .join('&');
        }]
      }
    );

    const result = response.data;

    if (!result.success) {
      return res.status(403).json({
        error: 'Turnstile verification failed',
        code: 'TURNSTILE_VERIFICATION_FAILED',
        details: result['error-codes'] || []
      });
    }

    req.turnstile = {
      success: true,
      challenge_ts: result.challenge_ts,
      hostname: result.hostname,
      action: result.action,
      cdata: result.cdata
    };

    next();

  } catch (error) {
    console.error('Turnstile validation error:', error.message);

    return res.status(500).json({
      error: 'Turnstile validation error',
      code: 'TURNSTILE_INTERNAL_ERROR'
    });
  }
}

module.exports = validateTurnstile;