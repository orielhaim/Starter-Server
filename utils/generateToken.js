const jwt = require('jsonwebtoken');

module.exports = (userId) => {
  try {
    const session_token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refresh_token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
    return { session_token, refresh_token };
  } catch (error) {
    logger.error('Generate token failed', { error: error.message });
    return null;
  }
};