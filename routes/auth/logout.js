const jwt = require('jsonwebtoken');
const db = require('../../db');
const logger = require('../../utils/logger');

module.exports = async (req, res) => {
  try {
    const sessionToken = req.cookies['session_token']?.trim();
    const refreshToken = req.cookies['refresh_token']?.trim();

    let sessionId = null;
    let userId = null;

    // Try to get session info from either token
    if (sessionToken) {
      try {
        const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
        sessionId = decoded.sessionId;
        userId = decoded.userId;
      } catch (error) {
        // Token might be expired, try refresh token
      }
    }

    if (!sessionId && refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        sessionId = decoded.sessionId;
        userId = decoded.userId;
      } catch (error) {
        // Both tokens are invalid
      }
    }

    // Revoke session in database if we have session info
    if (sessionId && userId) {
      try {
        db.prepare(`
          UPDATE sessions 
          SET active = 'false', revoked_at = CURRENT_TIMESTAMP 
          WHERE session_id = ? AND user_id = ?
        `).run(sessionId, userId);

        logger.info('Session revoked during logout', {
          userId,
          sessionId,
          ip: req.clientIp
        });
      } catch (dbError) {
        logger.error('Failed to revoke session in database', {
          error: dbError.message,
          userId,
          sessionId,
          ip: req.clientIp
        });
      }
    }

    // Clear cookies regardless of token validity
    res.clearCookie('session_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    logger.info('Logout successful', {
      userId,
      sessionId,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    logger.error('Logout failed: Unexpected error', {
      error: error.message,
      stack: error.stack,
      ip: req.clientIp
    });

    // Still clear cookies even if there's an error
    res.clearCookie('session_token');
    res.clearCookie('refresh_token');

    res.status(500).json({
      success: false,
      error: 'Internal server error during logout'
    });
  }
}; 