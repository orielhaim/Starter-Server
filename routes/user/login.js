const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const db = require('../../db');
const logger = require('../../utils/logger');
const generateToken = require('../../utils/generateToken');

module.exports = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Get user from database
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
      logger.warn('Login failed: User not found', {
        email,
        ip: req.clientIp
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Check if user is banned
    const currentTimestamp = Date.now() / 1000;
    const userBanExpiration = user.ban || 0;

    if (userBanExpiration !== 0 && userBanExpiration > currentTimestamp) {
      const banExpirationDate = new Date(userBanExpiration * 1000);

      logger.warn('Login failed: User is banned', {
        userId: user.id,
        email,
        banExpiration: banExpirationDate.toISOString(),
        ip: req.clientIp
      });

      return res.status(403).json({
        success: false,
        error: 'Account is suspended',
        banExpiration: banExpirationDate.toISOString()
      });
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      logger.warn('Login failed: Invalid password', {
        userId: user.id,
        email,
        ip: req.clientIp
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Generate session data
    const sessionData = {
      ip: req.clientIp || null,
      userAgent: req.userAgent?.getResult() || {}
    };

    // Generate tokens
    const tokens = generateToken(user.id, sessionData);

    if (!tokens) {
      logger.error('Login failed: Token generation failed', {
        userId: user.id,
        email,
        ip: req.clientIp
      });
      return res.status(500).json({
        success: false,
        error: 'Failed to create session'
      });
    }

    // Set secure cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour for session token
    };

    const refreshCookieOptions = {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days for refresh token
    };

    res.cookie('session_token', tokens.session_token, cookieOptions);
    res.cookie('refresh_token', tokens.refresh_token, refreshCookieOptions);

    // Update user's last activity
    db.prepare('UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(user.id);

    // Prepare user data for response (exclude sensitive fields)
    const userData = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      two_factor: user.two_factor,
      created_at: user.created_at
    };

    logger.info('Login successful', {
      userId: user.id,
      email,
      sessionId: tokens.session_id,
      twoFactorUsed: user.two_factor === 'true' ? true : false,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      user: userData,
      sessionId: tokens.session_id
    });

  } catch (error) {
    logger.error('Login failed: Unexpected error', {
      error: error.message,
      stack: error.stack,
      email: req.body?.email,
      ip: req.clientIp
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}; 