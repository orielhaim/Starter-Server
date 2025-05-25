const { validationResult } = require('express-validator');
const db = require('../../db');
const logger = require('../../utils/logger');
const roler = require('../../utils/roler');

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

    const { userId, duration, reason } = req.body;

    const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const currentTime = Date.now() / 1000;
    if (duration !== 0 || duration < currentTime) {
      return res.status(400).json({
        success: false,
        message: 'Duration must be greater than current time or 0'
      });
    }

    const ban = await db.prepare('UPDATE users SET ban = ?, ban_reason = ? WHERE id = ?').run(duration, reason, userId);

    res.json({
      success: true,
      message: 'User banned successfully'
    });
    logger.info(`User ${userId} banned by ${req.user.id} for ${duration} seconds`);
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};