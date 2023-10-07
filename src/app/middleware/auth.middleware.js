const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token)
    return res.status(401).json({
      success: false,
      message: 'Access Token not found',
    });

  try {
    const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN);
    req.body.userId = decodeToken.userId;
    next();
  } catch (error) {
    console.log(error);
    return res.status(403).json({
      success: false,
      message: 'Invalid token',
    });
  }
};

module.exports = verifyToken;
