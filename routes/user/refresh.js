const jwt = require('jsonwebtoken');
const db = require('../../db');
const logger = require('../../utils/logger');
const generateToken = require('../../utils/generateToken');

module.exports = async (req, res) => {
  try {
    // Get refresh token from cookies
    const refreshToken = req.cookies['refresh_token']?.trim();

    if (!refreshToken) {
      logger.warn('Refresh failed: Missing refresh token', {
        ip: req.clientIp
      });
      return res.status(401).json({
        success: false,
        error: 'Refresh token required'
      });
    }

    // Verify refresh token
    let decodedToken;
    try {
      const jwtVerificationOptions = {
        algorithms: [process.env.JWT_ALGORITHM || 'HS256'],
        clockTolerance: 30,
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      };

      decodedToken = jwt.verify(refreshToken, process.env.JWT_SECRET, jwtVerificationOptions);
    } catch (jwtError) {
      logger.warn('Refresh failed: Invalid refresh token', {
        errorType: jwtError.name,
        errorMessage: jwtError.message,
        ip: req.clientIp
      });

      // Clear invalid cookies
      res.clearCookie('session_token');
      res.clearCookie('refresh_token');

      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }

    // Validate token payload
    if (!decodedToken.userId || !decodedToken.sessionId || decodedToken.type !== 'refresh') {
      logger.warn('Refresh failed: Invalid token payload', {
        hasUserId: !!decodedToken.userId,
        hasSessionId: !!decodedToken.sessionId,
        tokenType: decodedToken.type,
        ip: req.clientIp
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid token structure'
      });
    }

    // Check if session exists and is active
    const session = db.prepare(`
      SELECT * FROM sessions 
      WHERE session_id = ? AND user_id = ? AND active = 'true'
    `).get(decodedToken.sessionId, decodedToken.userId);

    if (!session) {
      logger.warn('Refresh failed: Session not found or inactive', {
        userId: decodedToken.userId,
        sessionId: decodedToken.sessionId,
        ip: req.clientIp
      });

      // Clear cookies for invalid session
      res.clearCookie('session_token');
      res.clearCookie('refresh_token');

      return res.status(401).json({
        success: false,
        error: 'Session expired or invalid'
      });
    }

    // Get user data
    const user = db.prepare(`
      SELECT id, name, email, role, ban, two_factor, created_at
      FROM users 
      WHERE id = ?
    `).get(decodedToken.userId);

    if (!user) {
      logger.warn('Refresh failed: User not found', {
        userId: decodedToken.userId,
        sessionId: decodedToken.sessionId,
        ip: req.clientIp
      });

      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check if user is banned
    const currentTimestamp = Date.now() / 1000;
    const userBanExpiration = user.ban || 0;

    if (userBanExpiration !== 0 && userBanExpiration > currentTimestamp) {
      const banExpirationDate = new Date(userBanExpiration * 1000);
      
      logger.warn('Refresh failed: User is banned', {
        userId: user.id,
        banExpiration: banExpirationDate.toISOString(),
        ip: req.clientIp
      });

      // Revoke session
      db.prepare(`
        UPDATE sessions 
        SET active = 'false', revoked_at = CURRENT_TIMESTAMP 
        WHERE session_id = ?
      `).run(decodedToken.sessionId);

      // Clear cookies
      res.clearCookie('session_token');
      res.clearCookie('refresh_token');

      return res.status(403).json({
        success: false,
        error: 'Account is suspended',
        banExpiration: banExpirationDate.toISOString()
      });
    }

    // Generate new session token (keep same session ID)
    const newSessionToken = jwt.sign(
      { 
        userId: user.id, 
        sessionId: decodedToken.sessionId,
        type: 'session'
      }, 
      process.env.JWT_SECRET, 
      { 
        expiresIn: '1h',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      }
    );

    // Update session last activity
    db.prepare(`
      UPDATE sessions 
      SET last_activity = CURRENT_TIMESTAMP 
      WHERE session_id = ?
    `).run(decodedToken.sessionId);

    // Set new session token cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour
    };

    res.cookie('session_token', newSessionToken, cookieOptions);

    logger.info('Token refresh successful', {
      userId: user.id,
      sessionId: decodedToken.sessionId,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        two_factor: user.two_factor,
        created_at: user.created_at
      }
    });

  } catch (error) {
    logger.error('Refresh failed: Unexpected error', {
      error: error.message,
      stack: error.stack,
      ip: req.clientIp
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}; 