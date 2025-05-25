const { validationResult } = require('express-validator');
const db = require('../../db');
const logger = require('../../utils/logger');

module.exports = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: errors.array()
      });
    }

    const userId = req.params.userId;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }
    const user_sessions = db.prepare('SELECT * FROM sessions WHERE user_id = ?').all(userId);

    res.json({
      success: true,
      user: user,
      sessions: user_sessions
    });
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};