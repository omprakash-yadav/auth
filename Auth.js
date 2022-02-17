var bcrypt = require("bcryptjs");
var JWT = require("jsonwebtoken");
var JWTD = require("jwt-decode");
var secrat = "eirjnskj%$#@12344959";
var saltRound = 10;

//incrpting the password
var hashPassword = async (pwd) => {
  let salt = await bcrypt.genSalt(saltRound);
  let hash = await bcrypt.hash(pwd, salt);
  console.log(salt);
  console.log(hash);
  return hash;
};

//comparing the password
let hashCompare = async (pwd, hash) => {
  let result = await bcrypt.compare(pwd, hash);
  return result;
};
//seson time token
let createToken = async (email, firstname, role) => {
  let token = await JWT.sign(
    {
      email,
      firstname,
      role,
    },
    secrat,
    {
      expiresIn: "1m", //session expire time
    }
  );
  return token;
};

//verify the token
let verifyToken = async (req, res, next) => {
  let decodeData = JWTD(req.headers.token);
  if (new Date() / 1000 < decodeData.exp) {
    next();
  } else {
    res.json({
      statusCode: 401,
      message: "Tokken Expired",
    });
  }
};

//verefy admin role
let verefyAdminRole = async (req, res, next) => {
  let decodeData = JWTD(req.headers.token);
  if (decodeData.role === 1) {
    next();
  } else {
    res.json({
      statusCode: 401,
      message: "only Admine can access this site:",
    });
  }
};

module.exports = {
  hashPassword,
  hashCompare,
  createToken,
  verifyToken,
  verefyAdminRole,
};
