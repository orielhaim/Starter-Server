const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const logger = require('./logger');
const db = require('../db');

/**
 * Generate session and refresh tokens for a user
 * @param {number} userId - User ID
 * @param {Object} sessionData - Additional session data (ip, userAgent, etc.)
 * @returns {Object|null} Object containing session_token, refresh_token, and session_id
 */
module.exports = (userId, sessionData = {}) => {
  try {
    const sessionId = uuidv4();
    
    // Create session tokens
    const session_token = jwt.sign(
      { 
        userId, 
        sessionId,
        type: 'session'
      }, 
      process.env.JWT_SECRET, 
      { 
        expiresIn: '1h',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      }
    );
    
    const refresh_token = jwt.sign(
      { 
        userId, 
        sessionId,
        type: 'refresh'
      }, 
      process.env.JWT_SECRET, 
      { 
        expiresIn: '7d',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      }
    );

    // Store session in database
    const sessionInsert = db.prepare(`
      INSERT INTO sessions (user_id, session_id, ip, user_agent)
      VALUES (?, ?, ?, ?)
    `);

    sessionInsert.run(
      userId,
      sessionId,
      sessionData.ip || null,
      JSON.stringify(sessionData.userAgent)
    );

    logger.info('Tokens generated successfully', {
      userId,
      sessionId,
      ip: sessionData.ip
    });

    return { 
      session_token, 
      refresh_token, 
      session_id: sessionId 
    };
  } catch (error) {
    logger.error('Generate token failed', { 
      error: error.message,
      userId,
      stack: error.stack
    });
    return null;
  }
};