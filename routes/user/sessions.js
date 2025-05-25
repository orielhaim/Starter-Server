const db = require('../../db');
const logger = require('../../utils/logger');

module.exports = async (req, res) => {
  try {
    const userId = req.user.id;

    // Get all active sessions for the user
    const sessions = db.prepare(`
      SELECT 
        session_id,
        ip,
        user_agent,
        last_activity,
        created_at
      FROM sessions 
      WHERE user_id = ? AND active = 'true'
      ORDER BY last_activity DESC
    `).all(userId);

    // Parse user agent data for each session
    const sessionsWithParsedData = sessions.map(session => {
      let userAgentData = {};
      try {
        userAgentData = JSON.parse(session.user_agent || '{}');
      } catch (error) {
        logger.warn('Failed to parse user agent data for session', {
          userId,
          sessionId: session.session_id,
          error: error.message
        });
      }

      return {
        sessionId: session.session_id,
        ip: session.ip,
        browser: userAgentData.browser?.name || 'Unknown',
        os: userAgentData.os?.name || 'Unknown',
        device: userAgentData.device?.type || 'desktop',
        lastActivity: session.last_activity,
        createdAt: session.created_at,
        isCurrent: session.session_id === req.user.sessionId // This would need to be added to req.user
      };
    });

    logger.info('Sessions retrieved', {
      userId,
      sessionCount: sessionsWithParsedData.length,
      ip: req.clientIp
    });

    res.status(200).json({
      success: true,
      sessions: sessionsWithParsedData,
      totalSessions: sessionsWithParsedData.length
    });

  } catch (error) {
    logger.error('Get sessions failed: Unexpected error', {
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