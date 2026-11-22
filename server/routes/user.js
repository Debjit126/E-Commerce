const { User } = require("../models/user");
const { ImageUpload } = require("../models/imageUpload");
const { sendEmail } = require("../utils/emailService");

const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { signToken, requireAuth, requireAdmin, selfOrAdmin } = require("../middleware/auth");
const { verifyFirebaseIdToken } = require("../utils/firebaseAuth");
const { generateOtp } = require("../utils/otp");

const MONGO_ID = "[a-fA-F0-9]{24}";
const MIN_PASSWORD_LENGTH = 8;

const multer = require("multer");
const fs = require("fs");

const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.cloudinary_Config_Cloud_Name,
  api_key: process.env.cloudinary_Config_api_key,
  api_secret: process.env.cloudinary_Config_api_secret,
  secure: true,
});

var imagesArr = [];

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads");
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}_${file.originalname}`);
    //imagesArr.push(`${Date.now()}_${file.originalname}`)
  },
});

const upload = multer({ storage: storage });

router.post(`/upload`, requireAuth, upload.array("images"), async (req, res) => {
  imagesArr = [];

  try {
    for (let i = 0; i < req?.files?.length; i++) {
      const options = {
        use_filename: true,
        unique_filename: false,
        overwrite: false,
      };

      const img = await cloudinary.uploader.upload(req.files[i].path, options);
      imagesArr.push(img.secure_url);
      fs.unlinkSync(`uploads/${req.files[i].filename}`);
    }

    let imagesUploaded = new ImageUpload({
      images: imagesArr,
    });

    imagesUploaded = await imagesUploaded.save();
    return res.status(200).json(imagesArr);
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      msg: "Image upload failed: " + (error && error.message ? error.message : "unknown error"),
    });
  }
});

router.post(`/signup`, async (req, res) => {
  const { name, phone, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ status: "FAILED", msg: "Name, email and password are required" });
  }
  if (String(password).length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ status: "FAILED", msg: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  try {
    // Generate verification code
    const verifyCode = generateOtp();
    let user;

    // If the user exists but is not verified, update the existing user

    const existingUser = await User.findOne({ email: email });
    const existingUserByPh = await User.findOne({ phone: phone });

    if (existingUser) {
      res.json({
        status: "FAILED",
        msg: "User already exist with this email!",
      });
      return;
    }

    if (existingUserByPh) {
      res.json({
        status: "FAILED",
        msg: "User already exist with this phone number!",
      });
      return;
    }

    if (existingUser) {
      const hashPassword = await bcrypt.hash(password, 10);
      existingUser.password = hashPassword;
      existingUser.otp = verifyCode;
      existingUser.otpExpires = Date.now() + 600000; // 10 minutes
      await existingUser.save();
      user = existingUser;
    } else {
      // Create a new user
      const hashPassword = await bcrypt.hash(password, 10);

      user = new User({
        name,
        email,
        phone,
        password: hashPassword,
        isAdmin: false, // admins are created with `npm run make-admin`, never via signup
        otp: verifyCode,
        otpExpires: Date.now() + 600000, // 10 minutes
      });

      await user.save();
    }

    // Send verification email
    const resp = sendEmailFun(
      email,
      "Verify Email",
      "",
      "Your OTP is " + verifyCode
    );

    // No token is issued here: the account cannot sign in until the email is verified.
    return res.status(200).json({
      success: true,
      message: "User registered successfully! Please verify your email.",
    });
  } catch (error) {
    console.log(error);
    res.json({ status: "FAILED", msg: "something went wrong" });
    return;
  }
});

router.post(`/verifyAccount/resendOtp`, async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email: email });

    // Same response whether or not the account exists, so emails cannot be enumerated.
    if (existingUser) {
      const verifyCode = generateOtp();
      existingUser.otp = verifyCode;
      existingUser.otpExpires = Date.now() + 600000; // 10 minutes
      await existingUser.save();
      sendEmailFun(email, "Verify Email", "", "Your OTP is " + verifyCode);
    }

    return res.status(200).json({ success: true, message: "OTP SEND", otp: null });
  } catch (error) {
    console.log(error);
    return res.json({ status: "FAILED", msg: "something went wrong" });
  }
});

// Retired: this endpoint let the caller choose the OTP and then verify with it.
// OTPs are now generated, stored and emailed by /verifyAccount/resendOtp.
router.put(`/verifyAccount/emailVerify/:id`, (req, res) => {
  res.status(410).json({ success: false, message: "Use /verifyAccount/resendOtp" });
});

const sendEmailFun = async (to, subject, text, html) => {
  const result = await sendEmail(to, subject, text, html);
  if (result.success) {
    return true;
    //res.status(200).json({ message: 'Email sent successfully', messageId: result.messageId });
  } else {
    return false;
    // res.status(500).json({ message: 'Failed to send email', error: result.error });
  }
};

router.post("/verifyemail", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    const isCodeValid = !!user.otp && !!otp && String(user.otp) === String(otp);
    const isNotExpired = user.otpExpires > Date.now();

    if (isCodeValid && isNotExpired) {
      user.isVerified = true;
      user.otp = null;
      user.otpExpires = null;
      await user.save();
      // Short-lived proof that this person controls the email; required to reset a password.
      const resetToken = jwt.sign(
        { email: user.email, purpose: "password-reset" },
        process.env.JSON_WEB_TOKEN_SECRET_KEY,
        { expiresIn: "10m" }
      );
      return res
        .status(200)
        .json({ success: true, message: "OTP verified successfully", resetToken });
    } else if (!isCodeValid) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    } else {
      return res.status(400).json({ success: false, message: "OTP expired" });
    }
  } catch (err) {
    console.log("Error in verifyEmail", err);
    res
      .status(500)
      .json({ success: false, message: "Error in verifying email" });
  }
});

router.post(`/signin`, async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email: email });
    if (!existingUser) {
      res.status(404).json({ error: true, msg: "User not found!" });
      return;
    }

    if (existingUser.isVerified === false) {
      res.json({
        error: true,
        isVerify: false,
        msg: "Your account is not active yet please verify your account first or Sign Up with a new user",
      });
      return;
    }

    if (!existingUser.password || !password) {
      return res.status(400).json({ error: true, msg: "Invalid credentials. If you registered with Google, use Google sign-in." });
    }

    const matchPassword = await bcrypt.compare(password, existingUser.password);

    if (!matchPassword) {
      return res.status(400).json({ error: true, msg: "Invalid credentials" });
    }

    const token = signToken(existingUser);

    return res.status(200).send({
      user: existingUser,
      token: token,
      msg: "User Authenticated",
    });
  } catch (error) {
    res.status(500).json({ error: true, msg: "something went wrong" });
    return;
  }
});

router.put(`/changePassword/:id(${MONGO_ID})`, requireAuth, selfOrAdmin, async (req, res) => {
  const { name, phone, password, newPass } = req.body;

  try {
    const existingUser = await User.findById(req.params.id);
    if (!existingUser) {
      return res.status(404).json({ error: true, msg: "User not found!" });
    }

    if (!existingUser.password || !(await bcrypt.compare(password || "", existingUser.password))) {
      return res.status(400).json({ error: true, msg: "Current password is wrong" });
    }

    if (newPass && String(newPass).length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: true, msg: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    }

    const newPassword = newPass ? bcrypt.hashSync(newPass, 10) : existingUser.password;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name: name ?? existingUser.name, phone: phone ?? existingUser.phone, password: newPassword },
      { new: true }
    );

    return res.send(user);
  } catch (err) {
    return res.status(500).json({ error: true, msg: "something went wrong" });
  }
});

router.get(`/`, requireAdmin, async (req, res) => {
  const userList = await User.find();

  if (!userList) {
    res.status(500).json({ success: false });
  }
  res.send(userList);
});

router.get(`/:id(${MONGO_ID})`, requireAuth, selfOrAdmin, async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    res
      .status(500)
      .json({ message: "The user with the given ID was not found." });
  } else {
    res.status(200).send(user);
  }
});

router.delete(`/:id(${MONGO_ID})`, requireAdmin, (req, res) => {
  User.findByIdAndDelete(req.params.id)
    .then((user) => {
      if (user) {
        return res
          .status(200)
          .json({ success: true, message: "the user is deleted!" });
      } else {
        return res
          .status(404)
          .json({ success: false, message: "user not found!" });
      }
    })
    .catch((err) => {
      return res.status(500).json({ success: false, error: err });
    });
});

router.get(`/get/count`, requireAdmin, async (req, res) => {
  const userCount = await User.countDocuments();

  if (!userCount) {
    res.status(500).json({ success: false });
  }
  res.send({
    userCount: userCount,
  });
});

router.post(`/authWithGoogle`, async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: true, msg: "Missing Google ID token" });
  }

  let claims;
  try {
    claims = await verifyFirebaseIdToken(idToken);
  } catch (err) {
    return res.status(401).json({ error: true, msg: "Google sign-in could not be verified" });
  }

  if (!claims.email || claims.email_verified === false) {
    return res.status(401).json({ error: true, msg: "Google account email is not verified" });
  }

  try {
    let user = await User.findOne({ email: claims.email });

    if (!user) {
      user = await User.create({
        name: claims.name || claims.email.split("@")[0],
        email: claims.email,
        images: claims.picture ? [claims.picture] : [],
        isAdmin: false,
        isVerified: true,
      });
    } else if (!user.isVerified) {
      user.isVerified = true; // Google has just proven they own this email
      await user.save();
    }

    return res.status(200).send({
      user,
      token: signToken(user),
      msg: "User Login Successfully!",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: true, msg: "something went wrong" });
  }
});

router.put(`/:id(${MONGO_ID})`, requireAuth, selfOrAdmin, async (req, res) => {
  const { name, phone, email } = req.body;

  const userExist = await User.findById(req.params.id);
  if (!userExist) return res.status(404).send("User not found!");

  let newPassword = userExist.password;
  if (req.body.password) {
    if (String(req.body.password).length < MIN_PASSWORD_LENGTH) {
      return res.status(400).send(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    }
    newPassword = bcrypt.hashSync(req.body.password, 10);
  }

  const update = {
    name: name ?? userExist.name,
    phone: phone ?? userExist.phone,
    email: email ?? userExist.email,
    password: newPassword,
  };
  if (imagesArr.length) update.images = imagesArr;

  const user = await User.findByIdAndUpdate(req.params.id, update, { new: true });

  if (!user) return res.status(400).send("the user cannot be Updated!");

  res.send(user);
});

router.delete("/deleteImage", requireAuth, async (req, res) => {
  const imgUrl = req.query.img;

  // console.log(imgUrl)

  const urlArr = imgUrl.split("/");
  const image = urlArr[urlArr.length - 1];

  const imageName = image.split(".")[0];

  const response = await cloudinary.uploader.destroy(
    imageName,
    (error, result) => {
      // console.log(error, res)
    }
  );

  if (response) {
    res.status(200).send(response);
  }
});

router.post(`/forgotPassword`, async (req, res) => {
  const { email } = req.body;

  try {
    // Generate verification code
    const verifyCode = generateOtp();

    // If the user exists but is not verified, update the existing user

    const existingUser = await User.findOne({ email: email });

    if (!existingUser) {
      // Same response as success so attackers cannot discover which emails are registered.
      return res.status(200).json({ success: true, status: "SUCCESS", message: "OTP Send" });
    }

    if (existingUser) {
      existingUser.otp = verifyCode;
      existingUser.otpExpires = Date.now() + 600000; // 10 minutes
      await existingUser.save();
    }

    // Send verification email
    const resp = sendEmailFun(
      email,
      "Verify Email",
      "",
      "Your OTP is " + verifyCode
    );

    // Send success response
    return res.status(200).json({
      success: true,
      status: "SUCCESS",
      message: "OTP Send",
    });
  } catch (error) {
    console.log(error);
    res.json({ status: "FAILED", msg: "something went wrong" });
    return;
  }
});


router.post(`/forgotPassword/changePassword`, async (req, res) => {
  const { email, newPass, resetToken } = req.body;

  if (!newPass || String(newPass).length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: true, msg: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  try {
    const payload = jwt.verify(resetToken || "", process.env.JSON_WEB_TOKEN_SECRET_KEY, { algorithms: ["HS256"] });
    if (payload.purpose !== "password-reset" || payload.email !== email) {
      return res.status(403).json({ error: true, msg: "Invalid reset session" });
    }
  } catch (err) {
    return res.status(403).json({ error: true, msg: "Reset session expired. Please verify your email again." });
  }

  try {
    const existingUser = await User.findOne({ email: email });
    if (!existingUser) {
      return res.status(404).json({ error: true, msg: "User not found!" });
    }
    existingUser.password = await bcrypt.hash(newPass, 10);
    await existingUser.save();
    return res.status(200).json({ success: true, status: "SUCCESS", message: "Password changed successfully" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: true, msg: "something went wrong" });
  }
});

module.exports = router;
