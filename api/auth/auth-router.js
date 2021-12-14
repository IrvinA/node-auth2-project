const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require('../secrets');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { BCRYPT_ROUNDS } = require('../../config');
const Users = require('../users/users-model');

router.post('/register', validateRoleName, (req, res, next) => {
  const { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  Users.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch(next);
});

router.post('/login', checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password,  req.user.password)) {
    const token = buildToken(req.user)
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token,
    })
  } else {
    next({ status: 401, message: 'Invalid credentials'})
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name,
  };
  const options = {
    exp: '1d',
    iat: Date.now(),
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
