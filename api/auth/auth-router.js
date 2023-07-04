const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi, checkPayload } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const userModel = require("../users/users-model");

router.post("/register",  checkPayload, rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    let hashedPassword = bcryptjs.hashSync(req.body.password);
    let user_model = { username: req.body.username, password: hashedPassword, role_name: req.body.role_name };
    const registered = await userModel.ekle(user_model);
    res.status(201).json(registered);
  } catch (error) {
    next(error);
  }
});


router.post("/login", checkPayload, usernameVarmi, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
 const { username, password } = req.body;
 const [user] = await userModel.goreBul({username: username});
 if(user && bcryptjs.compareSync(password, user.password)) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '24h'});
  res.json({message: `${user.username} geri geldi!`, token: token})
 } else {
  next({ status: 401, message: 'Gecersiz kriter'})
 }
});

module.exports = router;
