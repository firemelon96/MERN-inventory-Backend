const asynchandler = require("express-async-Handler");
const User = require("../models/userModel");
const sendEmail = require("../utils/sendEmail");

const contactUs = asynchandler(async (req, res) => {
  const { subject, message } = req.body;
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error(`User not found`);
  }

  if (!subject || !message) {
    res.status(400);
    throw new Error(`Please add subject and message`);
  }

  const replyTo = user.email;
  const sentFrom = process.env.EMAIL_USER;
  const sendTo = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, sendTo, sentFrom, replyTo);
    res.status(200).json({ success: true, message: "Email sent successfully" });
  } catch (error) {
    res.status(500);
    throw new Error(`Email not sent`);
  }
});

module.exports = { contactUs };
