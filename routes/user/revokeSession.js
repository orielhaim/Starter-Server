const { validationResult } = require('express-validator');
const db = require('../../db');
const logger = require('../../utils/logger');

module.exports = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const { sessionId } = req.body;
    const userId = req.user.id;

    // Check if session exists and belongs to the user
    const session = db.prepare(`
      SELECT * FROM sessions 
      WHERE session_id = ? AND user_id = ? AND active = 'true'
    `).get(sessionId, userId);

    if (!session) {
      logger.warn('Session revoke failed: session not found', {
        userId,
        requestedSessionId: sessionId,
        ip: req.clientIp
      });

      return res.status(404).json({
        success: false,
        error: 'Session not found or already revoked'
      });
    }

    // Revoke the session
    db.prepare(`
      UPDATE sessions 
      SET active = 'false', revoked_at = CURRENT_TIMESTAMP 
      WHERE session_id = ? AND user_id = ?
    `).run(sessionId, userId);

    logger.info('Session revoked successfully', {
      userId,
      revokedSessionId: sessionId,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      message: 'Session revoked successfully'
    });

  } catch (error) {
    logger.error('Session revoke failed: Unexpected error', {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id,
      ip: req.clientIp
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}; 