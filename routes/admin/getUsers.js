const db = require('../../db');

module.exports = (req, res) => {
  try {
    const users = db.prepare('SELECT * FROM users').all();
    res.send(users);
  } catch (error) {
    res.status(500).send({
      error: 'Failed to get users'
    });
  }
};