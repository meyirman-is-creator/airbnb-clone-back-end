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
const session = require("express-session");
const authMiddleware = require("./middlewares/auth-middleware.js");

// Проверка переменной окружения MONGO_URL
if (!process.env.MONGO_URL) {
  console.error("Отсутствует переменная окружения MONGO_URL");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Подключение к MongoDB успешно установлено");
  })
  .catch((error) => {
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

app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));
app.use(
  cors({
    credentials: true,
    origin: [
      "https://turamyzba-front-end.vercel.app",
      "http://localhost:5173",
    ],
  })
);
app.use(
  session({
    secret: "production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      maxAge: 3600000, // 1 hour
      sameSite: process.env.NODE_ENV === "production" ? "Strict" : "Lax",
    },
  })
);
const jwtSecret = 'adsflkjasdfadf'
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

app.get("/profile", authMiddleware, (req, res) => {
  const user = req.user;
  try {
    console.log(user)
    res.json(user).status(200);
  } catch (err) {
    console.log(err);
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

app.post("/places", authMiddleware, async (req, res) => {
  const user = req.user;
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
  try {
    const placeDoc = await Place.create({
      owner: user.id,
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
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Ошибка создания места" });
  }
});

app.get("/user-places", authMiddleware, async (req, res) => {
  const {id} = req.user;
  try {
    res.status(200).json(await Place.find({ owner: id }));
  } catch (err) {
    console.log(err);
    res.status(500).json({ messages: "Internal server error" });
  }
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

app.put("/places", authMiddleware, async (req, res) => {
  const user = req.user;
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
  const placeDoc = await Place.findById(id);
  if (!placeDoc) {
    return res.status(404).json({ error: "Место не найдено" });
  }
  try {
    if (user.id === placeDoc.owner.toString()) {
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
      res.status(200).json("ok");
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/places", async (req, res) => {
  res.json(await Place.find());
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
