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
        logger.info('Register failed, User already exists', { email });
        return res.status(400).json({ success: false, error: 'User already exists' });
      }

      const registerData = {
        ip: req.clientIp || null,
        userAgent: req.userAgent?.getResult() || {}
      };

      // create user with default 'user' role
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await tx.prepare('INSERT INTO users (email, password, name, role, register_data) VALUES (?, ?, ?, ?, ?)').run(email, hashedPassword, name, 'user', JSON.stringify(registerData));
      
      // Generate tokens for the new user
      const sessionData = {
        ip: req.clientIp || null,
        userAgent: req.userAgent?.getResult() || {}
      };

      const tokens = generateToken(newUser.lastInsertRowid, sessionData);
      
      if (tokens) {
        // Set secure cookies
        const cookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000 // 1 hour for session token
        };

        const refreshCookieOptions = {
          ...cookieOptions,
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days for refresh token
          path: '/api/auth/refresh'
        };

        res.cookie('session_token', tokens.session_token, cookieOptions);
        res.cookie('refresh_token', tokens.refresh_token, refreshCookieOptions);
      }

      res.status(201).json({ 
        success: true, 
        user: {
          id: newUser.lastInsertRowid,
          email,
          name,
          role: 'user'
        },
        sessionId: tokens?.session_id
      });
      logger.info('Register success, User created successfully', { 
        userId: newUser.lastInsertRowid,
        email,
        sessionId: tokens?.session_id
      });
    }).catch((err) => {
      logger.error('Register failed, Failed to create user', { error: err.message });
      res.status(500).json({ success: false, error: 'Failed to create user' });
    });
  } catch (error) {
    logger.error('Register failed, Failed to create user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to create user' });
  }
}; 