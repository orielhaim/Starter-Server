const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const db = require('../../db');
const logger = require('../../utils/logger');
const generateToken = require('../../utils/generateToken');

module.exports = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    const { email, password, name } = req.body;

    db.transaction(async (tx) => {
      // check if user already exists
      const user = await tx.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (user) {
        logger.info('Register failed, User already exists', { user });
        return res.status(400).json({ success: false, error: 'User already exists' });
      }

      const registerData = {
        ip: req.clientIp || null,
        userAgent: req.userAgent?.getResult() || {}
      };

      // create user
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await tx.prepare('INSERT INTO users (email, password, name, register_data) VALUES (?, ?, ?, ?)').run(email, hashedPassword, name, registerData);
      res.status(201).json({ success: true, user: newUser });
      logger.info('Register success, User created successfully', { user: newUser });
    }).catch((err) => {
      logger.error('Register failed, Failed to create user', { error: err.message });
      res.status(500).json({ success: false, error: 'Failed to create user' });
    });
  } catch (error) {
    logger.error('Register failed, Failed to create user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to create user' });
  }
};