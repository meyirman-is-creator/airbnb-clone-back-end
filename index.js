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
const jwtSecret = process.env.JWT_SECRET || "default_secret"; // Используйте переменные окружения

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate Token Function
const generateToken = () => {
  return Math.random().toString(36).substr(2, 8);
};

// Send Reset Email Function
const sendResetEmail = async (email, token) => {
  const resetLink = `http://localhost:5173/reset-password/${token}`;
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset',
    text: `You requested a password reset. Click the link to reset your password: ${resetLink}`,
  };

  await transporter.sendMail(mailOptions);
};

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

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userDoc = await User.findOne({ email });
    if (userDoc) {
      const passOk = bcrypt.compareSync(password, userDoc.password);
      if (passOk) {
        jwt.sign(
          { email: userDoc.email, id: userDoc._id, name: userDoc.name },
          jwtSecret,
          (err, token) => {
            console.log(token);
            res.status(200).json({ accessToken: token });
          }
        );
      } else {
        res.status(422).json("pass not ok");
      }
    } else {
      res.status(404).json("user not found");
    }
  } catch (error) {
    console.error("Ошибка в процессе логина:", error);
    res.status(500).json("Ошибка сервера");
  }
});

app.post("/register", async (req, res) => {
  const { fullName, nickName, email, password } = req.body;
  try {
    const userDoc = await User.create({
      fullName,
      nickName,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
    });

    jwt.sign(
      { email: userDoc.email, id: userDoc._id, name: userDoc.fullName },
      jwtSecret,
      (err, token) => {
        if (err) {
          throw err;
        }
        res.status(200).json({ accessToken: token, userDoc });
      }
    );
  } catch (error) {
    console.error("Ошибка в процессе регистрации:", error);
    res.status(422).json(error);
  }
});

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
    res.status(500).json({ error: "Ошибка при получении профиля пользователя" });
  }
});

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

app.post("/logout", (req, res) => {
  res.cookie("token", "").json(true);
});

const photosMiddleware = multer({ storage: multer.memoryStorage() });

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
    communalServices
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
        communalServices
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
    communalServices
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

app.get("/findroommates", async (req, res) => {
  const { page = 1, limit = 40, search = "" } = req.query;

  try {
    const query = search ? { title: { $regex: search, $options: "i" }, active: true } : { active: true };
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

const fetchOpenAIData = async (prompt) => {
  const openai = new OpenAI({
    apiKey: process.env.CHAT_GPT_API,
  });

  let retries = 3;
  while (retries > 0) {
    try {
      const openaiCompletion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          { role: "system", content: "You are a professional job analyzer." },
          { role: "user", content: prompt },
        ],
        temperature: 0,
      });

      let aiResponse = openaiCompletion.choices[0].message.content;
      console.log("AI Response:", aiResponse);

      // Удаляем начальные и конечные символы ```json
      aiResponse = aiResponse.replace(/```json/g, "").replace(/```/g, "");

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
      I will give you a user and announcements and you should analyze the announcements and find suitable announcements for the user.
      Resources: User: ${JSON.stringify(
        userAnceta
      )}, Announcements: ${JSON.stringify(announcements)}.
      The extra queries: ${query}. WARNING: RETURN JSON FORMAT ONLY FOR FOUND ANNOUNCEMENTS
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
        res
          .status(500)
          .send({ message: "An error occurred while processing your request" });
      }
    }
  } catch (err) {
    console.error("Server error:", err);
    res
      .status(500)
      .send({ message: "An error occurred while processing your request" });
  }
});

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
  const { email } = req.body;
  const token = generateToken();

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 3600000;
    await user.save();

    await sendResetEmail(email, token);

    res.status(200).json({ message: 'Токен для сброса пароля отправлен на вашу почту' });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Маршрут для сброса пароля
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Поиск пользователя по токену и проверка срока действия токена
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Неверный или истекший токен' });
    }

    // Обновление пароля и сброс токена
    user.password = bcrypt.hashSync(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Пароль успешно сброшен' });
  } catch (err) {
    console.error("Ошибка при сбросе пароля:", err);
    res.status(500).json({ error: 'Ошибка при сбросе пароля' });
  }
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
