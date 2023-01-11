const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

//function to generate token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// register a user
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //check if not empty
  if (!name || !email || !password) {
    res.status(400);
    throw new Error(`Please fill in all required fields`);
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 up");
  }

  //check if user email already exist
  const userExist = await User.findOne({ email });

  if (userExist) {
    res.status(400);
    throw new Error("Email is already used");
  }

  //create new user
  const user = await User.create({
    name,
    email,
    password,
  });

  //generate the token
  const token = generateToken(user._id);

  //send http-only cookie
  res.cookie("token", token, {
    path: "/",
    HttpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    SameSite: "none",
    Secure: true,
  });

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error(`Invalid user data`);
  }
});

//login a user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  //add validation
  if (!email || !password) {
    res.status(400);
    throw new Error(`Please add email and password`);
  }

  //check if user exist
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error(`User not found Please sign up`);
  }

  //check if the password is correct after user exist
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  //generate the token
  const token = generateToken(user._id);

  //send http-only cookie
  res.cookie("token", token, {
    path: "/",
    HttpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    SameSite: "none",
    Secure: false,
  });

  if (user && passwordIsCorrect) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error(`Invalid credential`);
  }
});

//logout a user
const logout = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    HttpOnly: true,
    expires: new Date(0), // expires right away
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({
    message: "Logout successfully",
  });
});

//get user data
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
    });
  } else {
    res.status(400);
    throw new Error(`User not found`);
  }
});

//get user login status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  //verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

//update user
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, photo, phone, bio } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      photo: updatedUser.photo,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
    });
  } else {
    res.status(404);
    throw new Error(`User not found`);
  }
});

//update the password
const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  const { oldPassword, password } = req.body;

  if (!user) {
    res.status(400);
    throw new Error(`User not found, Please Signup`);
  }

  //validate
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error(`Please add old and new password`);
  }

  //check if the oldpassword and password matches correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  //save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).send(`Password change successfully`);
  } else {
    res.status(400);
    throw new Error(`Old password is incorect`);
  }
});

//forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error(`user does not exist`);
  }

  //delete token if it exist in database
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // create a reset token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  //hash token before saving to db

  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //save token to the database
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), //30mins
  }).save();

  //construct reeset url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  //reset email
  const message = `
  <h2>Hello ${user.name}</h2>
  <p>Please use the url below to reset your password</p>
  <p>This link is valid for only 30 minutes.</p>

  <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

  <p>Regards...</p>
  <p>mern inventory team</p>
  `;
  const subject = `Password reset request`;
  const sendTo = user.email;
  const sentFrom = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, sendTo, sentFrom);
    res
      .status(200)
      .json({ success: true, message: "Reset email sent to inbox or spam" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

//reset password
const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  //hash token then compare to the one in the database
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //find token in database
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(500);
    throw new Error(`Invalid or expired token`);
  }

  //find the user
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: "Password reset successfully, Please login",
  });
});

module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
