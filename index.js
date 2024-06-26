const express = require("express");
const cors = require("cors");
require("dotenv").config();
const multer = require("multer");
const mongoose = require("mongoose");
const axios = require("axios");
const Place = require("./models/Place.js");
const User = require("./models/User.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");

// Проверка переменной окружения MONGO_URL
if (!process.env.MONGO_URL) {
  console.error("Отсутствует переменная окружения MONGO_URL");
  process.exit(1);
}

// Настройка подключения к MongoDB
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("Подключение к MongoDB успешно установлено");
}).catch((error) => {
  console.error("Ошибка подключения к MongoDB:", error);
  process.exit(1);
});

// Настройка AWS S3
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const app = express();
const port = process.env.PORT || 8080;

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "adfsqwefqdfasdfaf";

app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));
app.use(cors({
  credentials: true,
  origin: "https://airbnb-clone-front-end.vercel.app" || "http://localhost:5173",
}));

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
          { email: userDoc.email, id: userDoc._id },
          jwtSecret,
          {},
          (err, token) => {
            if (err) throw err;
            res.cookie("token", token).json(userDoc);
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
  const { name, email, password } = req.body;
  try {
    const userDoc = await User.create({
      name,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
    });
    res.json(userDoc);
  } catch (error) {
    console.error("Ошибка в процессе регистрации:", error);
    res.status(422).json(error);
  }
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const { name, email, _id } = await User.findById(userData.id);
      res.json({ name, email, _id });
    });
  } else {
    res.status(401).json(null);
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

app.post("/places", (req, res) => {
  try {
    const { token } = req.cookies;
    const {
      title,
      address,
      addedPhotos,
      description,
      perks,
      extraInfo,
      checkIn,
      checkOut,
      maxGuests,
      price,
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const placeDoc = await Place.create({
        owner: userData.id,
        title,
        address,
        photos: addedPhotos,
        description,
        perks,
        extraInfo,
        checkIn,
        checkOut,
        maxGuests,
        price,
      });
      res.json(placeDoc);
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Ошибка создания места" });
  }
});

app.get("/user-places", (req, res) => {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Требуется аутентификация" });
  }

  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: "Неверный токен" });
    const { id } = userData;
    res.json(await Place.find({ owner: id }));
  });
});

app.get("/places/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const place = await Place.findById(id);
    if (!place) {
      return res.status(404).json({ error: "Место не найдено" });
    }
    res.json(place);
  } catch (err) {
    res.status(500).json({ error: "Ошибка получения места" });
  }
});

app.put("/places", async (req, res) => {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Требуется аутентификация" });
  }

  const {
    id,
    title,
    address,
    addedPhotos,
    description,
    perks,
    extraInfo,
    checkIn,
    checkOut,
    maxGuests,
    price,
  } = req.body;
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: "Неверный токен" });
    const placeDoc = await Place.findById(id);
    if (!placeDoc) {
      return res.status(404).json({ error: "Место не найдено" });
    }
    if (userData.id === placeDoc.owner.toString()) {
      placeDoc.set({
        title,
        address,
        photos: addedPhotos,
        description,
        perks,
        extraInfo,
        checkIn,
        checkOut,
        maxGuests,
        price,
      });
      await placeDoc.save();
      res.json("ok");
    } else {
      res.status(403).json({ error: "Нет прав на редактирование" });
    }
  });
});

app.get("/places", async (req, res) => {
  res.json(await Place.find());
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
