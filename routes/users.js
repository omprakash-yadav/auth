var express = require("express");
var router = express.Router();
var { mongodb, MongoClient, dbUrl } = require("../dbSchima");
var {
  hashPassword,
  hashCompare,
  createToken,
  verifyToken,
  verefyAdminRole,
} = require("../Auth");
//signup request
router.post("/signup", async (req, res) => {
  const client = await MongoClient.connect(dbUrl);
  try {
    let db = await client.db("B31WD");
    let user = await db.collection("users").find({ email: req.body.email });
    if (user.length > 0) {
      res.json({
        statusCode: 400,
        message: "User Already Exists",
      });
    } else {
      let hashedPassword = await hashPassword(req.body.password);
      req.body.password = hashedPassword;
      let user = await db.collection("users").insertOne(req.body);
      res.json({
        statusCode: 200,
        message: "User SignUp Successfull",
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      statusCode: 500,
      message: "Internal Server Error",
    });
  } finally {
    client.close();
  }
});

//login request
router.post("/login", async (req, res) => {
  const client = await MongoClient.connect(dbUrl);
  try {
    let db = await client.db("B31WD");
    let user = await db.collection("users").findOne({ email: req.body.email });
    if (user) {
      let compare = await hashCompare(req.body.password, user.password);
      if (compare) {
        let token = await createToken(user.email, user.firstName, user.role);
        res.json({
          statusCode: 200,
          role: user.role,
          email: user.email,
          firstName: user.firstName,
          token,
        });
      } else {
        res.json({
          statusCode: 400,
          message: "Invalid Password",
        });
      }
    } else {
      res.json({
        statusCode: 404,
        message: "User Not Found",
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      statusCode: 500,
      message: "Internal Server Error",
    });
  } finally {
    client.close();
  }
});
//verefy request

router.post("/auth", verifyToken, /*verefyAdminRole,*/ async (req, res) => {
  // When uncoment the verefyAdminRole Then only access the dashbord portel who have admin(rol=1)
  res.json({
    statusCode: 200,
    message: req.body.purpose,
  });
});

module.exports = router;
