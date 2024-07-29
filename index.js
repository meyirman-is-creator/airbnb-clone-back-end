const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const { PutObjectCommand } = require("@aws-sdk/client-s3");
const { Client } = require("@googlemaps/google-maps-services-js");
const session = require("express-session");
const nodemailer = require("nodemailer");

const User = require("./models/User.js");
const FindRoommateModel = require("./models/FindRoommate.js");
const AboutRoommateModel = require("./models/AboutRoommate.js");

const authMiddleware = require("./middlewares/auth-middleware.js");
const connectToDB = require("./db/mongoose-connection.js");
const s3 = require("./services/s3-services.js");
const OpenAI = require("openai");

require("dotenv").config();
const client = new Client({});
connectToDB();

const app = express();
const port = process.env.PORT || 8080;
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET || "adsflkjasdfadf"; // Используйте переменные окружения

// Temporary store for verification codes
const verificationStore = new Map();

// Email Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send Verification Email Function
const sendVerificationEmail = async (email, code, type) => {
  const subject =
    type === "passwordReset"
      ? "Код для сброса пароля"
      : "Код для подтверждения регистрации";
  const text =
    type === "passwordReset"
      ? `Ваш код для сброса пароля: ${code}. Если вы не запрашивали сброс пароля, просто игнорируйте это письмо.`
      : `Ваш код для подтверждения регистрации: ${code}. Если вы не запрашивали регистрацию, просто игнорируйте это письмо.`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject,
    text,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error(`Error sending verification email to ${email}:`, error);
  }
};

// Helper function to generate verification code
const generateVerificationCode = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));
app.use(
  cors({
    credentials: true,
    origin: ["https://turamyzba-front-end.vercel.app", "http://localhost:5173"],
  })
);
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: process.env.NODE_ENV === "production" ? "Strict" : "Lax",
    },
  })
);

app.get("/test", (req, res) => {
  console.log("test");
  res.json("test ok");
});

// Login Endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userDoc = await User.findOne({ email });
    if (userDoc) {
      const passOk = bcrypt.compareSync(password, userDoc.password);
      if (passOk) {
        const token = jwt.sign(
          { email: userDoc.email, id: userDoc._id, name: userDoc.name },
          jwtSecret
        );
        res.status(200).json({ accessToken: token });
      } else {
        res.status(422).json("Неверный пароль");
      }
    } else {
      res.status(404).json("Пользователь не найден");
    }
  } catch (error) {
    console.error("Ошибка в процессе логина:", error);
    res.status(500).json("Ошибка сервера");
  }
});

app.post("/register", async (req, res) => {
  const { fullName, nickName, email, password } = req.body;
  const verificationCode = generateVerificationCode();
  const expirationTime = Date.now() + 120000; // 2 minutes

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(422).json({ error: "Этот email уже зарегистрирован" });
    }

    // Store the verification code and expiration time in the temporary store
    verificationStore.set(email, {
      code: verificationCode,
      expiration: expirationTime,
    });

    // Send verification email
    await sendVerificationEmail(email, verificationCode, "register");

    // Create a new user with verification set to false
    const userDoc = new User({
      fullName,
      nickName,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
      verification: false,
    });

    await userDoc.save();

    res
      .status(200)
      .json({ message: "Проверьте свою почту для верификации.", email });
  } catch (error) {
    console.error("Ошибка в процессе регистрации:", error);
    res.status(500).json(error);
  }
});

// Verify Code Endpoint
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  const verificationData = verificationStore.get(email);
  if (
    !verificationData ||
    verificationData.code !== code ||
    verificationData.expiration < Date.now()
  ) {
    return res.status(400).json({ error: "Неверный или истекший код" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    user.verification = true;
    await user.save();
    verificationStore.delete(email);

    const token = jwt.sign(
      { email: user.email, id: user._id, name: user.fullName },
      jwtSecret
    );

    res.status(200).json({ message: "Код подтвержден", accessToken: token });
  } catch (err) {
    console.error("Ошибка при проверке кода верификации:", err);
    res.status(500).json({ error: "Ошибка при проверке кода верификации" });
  }
});

// Profile Endpoint
app.get("/profile", authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    const user = await User.findById(userId, "fullName nickName email");
    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    res.json(user).status(200);
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ error: "Ошибка при получении профиля пользователя" });
  }
});

// Edit Profile Endpoint
app.put("/edit-profile", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { fullName, nickName, email } = req.body;

  try {
    const user = await User.findByIdAndUpdate(
      userId,
      { fullName, nickName, email },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.status(200).json({ message: "Профиль успешно обновлен", user });
  } catch (err) {
    console.error("Ошибка при обновлении профиля:", err);
    res.status(500).json({ error: "Ошибка при обновлении профиля" });
  }
});

// Edit Password Endpoint
app.put("/edit-password", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { oldPassword, newPassword } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const passOk = bcrypt.compareSync(oldPassword, user.password);
    if (!passOk) {
      return res.status(400).json({ error: "Старый пароль неверен" });
    }

    user.password = bcrypt.hashSync(newPassword, bcryptSalt);
    await user.save();

    res.status(200).json({ message: "Пароль успешно изменен" });
  } catch (err) {
    console.error("Ошибка при изменении пароля:", err);
    res.status(500).json({ error: "Ошибка при изменении пароля" });
  }
});

// Logout Endpoint
app.post("/logout", (req, res) => {
  res.cookie("token", "").json(true);
});

// File Upload Middleware
const photosMiddleware = multer({ storage: multer.memoryStorage() });

// Upload Endpoint
app.post("/upload", photosMiddleware.array("photos", 100), async (req, res) => {
  const uploadFiles = [];
  for (let i = 0; i < req.files.length; i++) {
    const file = req.files[i];
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: `${Date.now()}_${file.originalname}`,
      Body: file.buffer,
      ContentType: file.mimetype,
    };

    try {
      const command = new PutObjectCommand(params);
      await s3.send(command);
      const fileUrl = `https://${params.Bucket}.s3.${process.env.AWS_REGION}.amazonaws.com/${params.Key}`;
      uploadFiles.push(fileUrl);
    } catch (err) {
      console.error("Ошибка загрузки файла в S3:", err);
      res.status(500).json({ error: "Ошибка загрузки файла в S3", err });
      return;
    }
  }
  res.json(uploadFiles);
});

// Upload By Link Endpoint
app.post("/upload-by-link", async (req, res) => {
  try {
    const { link } = req.body;
    const response = await axios.get(link, { responseType: "arraybuffer" });
    const buffer = Buffer.from(response.data, "binary");
    const newName = `photo${Date.now()}.jpg`;

    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: newName,
      Body: buffer,
      ContentType: response.headers["content-type"],
    };

    const command = new PutObjectCommand(params);
    await s3.send(command);
    const fileUrl = `https://${params.Bucket}.s3.${process.env.AWS_REGION}.amazonaws.com/${params.Key}`;

    res.json(fileUrl);
  } catch (error) {
    console.error("Ошибка загрузки файла из ссылки:", error);
    res.status(500).json({ error: "Ошибка загрузки файла из ссылки", error });
  }
});

// Find Roommate Create Endpoint
app.post("/findroommate-create", authMiddleware, async (req, res) => {
  const user = req.user;
  const {
    title,
    address,
    addedPhotos,
    monthlyExpensePerPerson,
    moveInStart,
    utilityService,
    deposit,
    maxPeople,
    apartmentInfo,
    ownerInfo,
    roomiePreferences,
    contactNumber,
    callPreference,
    whatsappNumber,
    whatsappNumberPreference,
    selectedGender,
    communalServices,
  } = req.body;

  try {
    const response = await axios.get(
      `https://catalog.api.2gis.com/3.0/items/geocode?q=${address}&fields=items.point&key=${process.env.TWOGIS_API}`
    );

    if (response.data.result.items.length > 0) {
      const location = response.data.result.items[0].point;
      const coordinates = [location.lon, location.lat];
      console.log(address, coordinates);

      const roommateDoc = await FindRoommateModel.create({
        owner: user.id,
        title,
        address: { address, coordinates },
        photos: addedPhotos,
        monthlyExpensePerPerson,
        moveInStart,
        utilityService,
        deposit,
        maxPeople,
        apartmentInfo,
        ownerInfo,
        roomiePreferences,
        contactNumber,
        callPreference,
        whatsappNumber,
        whatsappNumberPreference,
        selectedGender,
        communalServices,
      });
      res.json(roommateDoc);
    } else {
      res.status(400).json({ error: "Address not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error creating roommate listing" });
  }
});

// Find Roommate Update Endpoint
app.put("/findroommate-update/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const user = req.user;
  const {
    title,
    address,
    addedPhotos,
    monthlyExpensePerPerson,
    moveInStart,
    utilityService,
    deposit,
    maxPeople,
    apartmentInfo,
    ownerInfo,
    roomiePreferences,
    contactNumber,
    callPreference,
    whatsappNumber,
    whatsappNumberPreference,
    selectedGender,
    communalServices,
  } = req.body;

  try {
    const response = await axios.get(
      `https://catalog.api.2gis.com/3.0/items/geocode?q=${address}&fields=items.point&key=${process.env.TWOGIS_API}`
    );

    if (response.data.result.items.length > 0) {
      const location = response.data.result.items[0].point;
      const coordinates = [location.lon, location.lat];
      console.log(address, coordinates);

      const roommateDoc = await FindRoommateModel.findByIdAndUpdate(
        id,
        {
          owner: user.id,
          title,
          address: { address, coordinates },
          photos: addedPhotos,
          monthlyExpensePerPerson,
          moveInStart,
          utilityService,
          deposit,
          maxPeople,
          apartmentInfo,
          ownerInfo,
          roomiePreferences,
          contactNumber,
          callPreference,
          whatsappNumber,
          whatsappNumberPreference,
          selectedGender,
          communalServices,
        },
        { new: true }
      );
      res.json(roommateDoc);
    } else {
      res.status(400).json({ error: "Address not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error updating roommate listing" });
  }
});

// About Roommate Create Endpoint
app.post("/aboutroommate-create", authMiddleware, async (req, res) => {
  const user = req.user;
  const {
    active,
    payment,
    gender,
    roomiesPreferences,
    address,
    moveInStart,
    contactNumber,
    callPreference,
    whatsappNumber,
  } = req.body;

  try {
    const roommateDoc = await AboutRoommateModel.create({
      owner: user.id,
      active,
      payment,
      gender,
      roomiesPreferences,
      address,
      moveInStart,
      contactNumber,
      callPreference,
      whatsappNumber,
    });
    res.json(roommateDoc);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error creating roommate listing" });
  }
});

// About Roommate Update Endpoint
app.put("/aboutroommate-update/:id", authMiddleware, async (req, res) => {
  const user = req.user;
  const roommateId = req.params.id;
  const {
    active,
    payment,
    gender,
    roomiesPreferences,
    address,
    moveInStart,
    contactNumber,
    callPreference,
    whatsappNumber,
  } = req.body;

  try {
    const updatedRoommate = await AboutRoommateModel.findByIdAndUpdate(
      roommateId,
      {
        owner: user.id,
        active,
        payment,
        gender,
        roomiesPreferences,
        address,
        moveInStart,
        contactNumber,
        callPreference,
        whatsappNumber,
      },
      { new: true, runValidators: true }
    );

    if (updatedRoommate) {
      res.json(updatedRoommate);
    } else {
      res.status(404).json({ error: "Roommate listing not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error updating roommate listing" });
  }
});

// Find Roommate By ID Endpoint
app.get("/findroommate/:id", async (req, res) => {
  const roommateId = req.params.id;

  try {
    const roommate = await FindRoommateModel.findById(roommateId);
    if (roommate) {
      res.json(roommate);
    } else {
      res.status(404).json({ error: "Roommate listing not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error retrieving roommate listing" });
  }
});

// About Roommate By ID Endpoint
app.get("/aboutroommate/:id", async (req, res) => {
  const roommateId = req.params.id;

  try {
    const roommate = await AboutRoommateModel.findById(roommateId);
    if (roommate) {
      res.json(roommate);
    } else {
      res.status(404).json({ error: "Roommate listing not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error retrieving roommate listing" });
  }
});

// My Announcements Endpoint
app.get("/my-announcements", authMiddleware, async (req, res) => {
  const user = req.user;
  try {
    const myAnnounFindRoomate = await FindRoommateModel.find({
      owner: user.id,
    });
    const myAnnounAboutRoomate = await AboutRoommateModel.find({
      owner: user.id,
    });
    res.status(200).json({ myAnnounFindRoomate, myAnnounAboutRoomate });
  } catch (err) {
    console.log(err);
    res.status(500).json({ messages: "Internal server error" });
  }
});

// Find Roommates Endpoint
app.get("/findroommates", async (req, res) => {
  const { page = 1, limit = 40, search = "" } = req.query;

  try {
    const query = search
      ? { title: { $regex: search, $options: "i" }, active: true }
      : { active: true };
    const roommates = await FindRoommateModel.find(query)
      .skip((page - 1) * limit)
      .limit(Number(limit));

    const total = await FindRoommateModel.countDocuments(query);

    res.json({
      total,
      page: Number(page),
      limit: Number(limit),
      data: roommates,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error retrieving roommate listings" });
  }
});

// About Roommates Endpoint
app.get("/aboutroommates", async (req, res) => {
  const { page = 1, limit = 100, search = "" } = req.query;

  try {
    const query = search ? { address: { $regex: search, $options: "i" } } : {};
    const roommates = await AboutRoommateModel.find(query)
      .skip((page - 1) * limit)
      .limit(Number(limit));

    const total = await AboutRoommateModel.countDocuments(query);

    res.json({
      total,
      page: Number(page),
      limit: Number(limit),
      data: roommates,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error retrieving roommate listings" });
  }
});

// Fetch OpenAI Data
const fetchOpenAIData = async (prompt) => {
  const openai = new OpenAI({
    apiKey: process.env.CHAT_GPT_API,
  });

  let retries = 3;
  while (retries > 0) {
    try {
      const openaiCompletion = await openai.chat.completions.create({
        model: "gpt-4-turbo",
        messages: [
          {
            role: "system",
            content:
              "You are a professional announcements analyzer. Your task is to find the most suitable announcements based on the user's criteria.",
          },
          { role: "user", content: prompt },
        ],
        temperature: 0,
      });

      let aiResponse = openaiCompletion.choices[0].message.content;
      console.log("AI Response:", aiResponse);

      // Remove JSON delimiters
      aiResponse = aiResponse.replace(/json/g, "").replace(/```/g, "");

      return JSON.parse(aiResponse);
    } catch (apiError) {
      if (apiError.code === "insufficient_quota") {
        console.error("OpenAI API quota exceeded:", apiError);
        if (retries === 1) {
          throw new Error(
            "OpenAI API quota exceeded. Please check your plan and billing details."
          );
        }
        await new Promise((res) => setTimeout(res, 3000));
      } else {
        throw apiError;
      }
    }
    retries--;
  }
};

// Find Roommates Search Endpoint
app.get("/findroommates-search", authMiddleware, async (req, res) => {
  const user = req.user;
  const query = req.query.query;

  try {
    const userAnceta = await FindRoommateModel.findOne({ owner: user.id });

    if (!userAnceta) {
      return res.status(404).send({ message: "User anceta not found" });
    }

    const announcements = await FindRoommateModel.find();
    const prompt = `
      You will be provided with a user's profile and a list of announcements. Your task is to find and return the most suitable announcements for the user based on the given profile and search query.
      Resources:
      User: ${JSON.stringify(userAnceta)},
      Announcements: ${JSON.stringify(announcements)},
      query: ${query}.
      WARNING: RETURN JSON FORMAT ONLY FOR FOUND ANNOUNCEMENTS
    `;

    console.log("Prompt:", prompt);

    try {
      const aiResponse = await fetchOpenAIData(prompt);
      res.json(aiResponse);
    } catch (error) {
      console.error("Error fetching data from OpenAI:", error);
      if (error.message.includes("quota exceeded")) {
        res.status(429).send({
          message:
            "OpenAI API quota exceeded. Please check your plan and billing details.",
        });
      } else {
        res.status(500).send({
          message: "An error occurred while processing your request",
        });
      }
    }
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).send({
      message: "An error occurred while processing your request",
    });
  }
});

// Archive Announcement Endpoint
app.put("/archive-announcement/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const updatedAnnouncement = await FindRoommateModel.findByIdAndUpdate(
      id,
      { active: false },
      { new: true }
    );
    if (updatedAnnouncement) {
      res.json(updatedAnnouncement);
    } else {
      res.status(404).json({ error: "Announcement not found" });
    }
  } catch (err) {
    console.error("Error archiving announcement:", err);
    res.status(500).json({ error: "Error archiving announcement" });
  }
});

// Restore Announcement Endpoint
app.put("/restore-announcement/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const updatedAnnouncement = await FindRoommateModel.findByIdAndUpdate(
      id,
      { active: true },
      { new: true }
    );
    if (updatedAnnouncement) {
      res.json(updatedAnnouncement);
    } else {
      res.status(404).json({ error: "Announcement not found" });
    }
  } catch (err) {
    console.error("Error restoring announcement:", err);
    res.status(500).json({ error: "Error restoring announcement" });
  }
});

// Delete Announcement Endpoint
app.delete("/delete-announcement/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedAnnouncement = await FindRoommateModel.findByIdAndDelete(id);
    if (deletedAnnouncement) {
      res.json(deletedAnnouncement);
    } else {
      res.status(404).json({ error: "Announcement not found" });
    }
  } catch (err) {
    console.error("Error deleting announcement:", err);
    res.status(500).json({ error: "Error deleting announcement" });
  }
});

// Маршрут для запроса сброса пароля
app.post("/request-reset-password", async (req, res) => {
  const { email, type } = req.body; // Added `type` to distinguish between password reset and registration
  const verificationCode = generateVerificationCode();
  const expirationTime = Date.now() + 120000; // 2 minutes

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    verificationStore.set(email, {
      code: verificationCode,
      expiration: expirationTime,
    });
    await sendVerificationEmail(email, verificationCode, type);

    res
      .status(200)
      .json({ message: "Код для сброса пароля отправлен на вашу почту" });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Endpoint for verifying reset code
app.post("/verify-reset-code", async (req, res) => {
  const { email, code } = req.body;
  const verificationData = verificationStore.get(email);

  if (
    !verificationData ||
    verificationData.code !== code ||
    verificationData.expiration < Date.now()
  ) {
    return res.status(400).json({ error: "Неверный или истекший код" });
  }

  res.status(200).json({ message: "Код подтвержден" });
});

// Endpoint for resetting password
app.post("/reset-password", async (req, res) => {
  const { email, code, newPassword } = req.body;
  const verificationData = verificationStore.get(email);
  console.log(verificationData)
  if (
    !verificationData 
  ) {
    return res.status(400).json({ error: "Неверный или истекший код" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    user.password = bcrypt.hashSync(newPassword, bcryptSalt);
    await user.save();
    verificationStore.delete(email);

    res.status(200).json({ message: "Пароль успешно сброшен" });
  } catch (err) {
    console.error("Ошибка при сбросе пароля:", err);
    res.status(500).json({ error: "Ошибка при сбросе пароля" });
  }
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
