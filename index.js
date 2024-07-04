const express = require("express");
const cors = require("cors");

const jwt = require("jsonwebtoken");
const axios = require("axios");
const bcrypt = require("bcryptjs");

const multer = require("multer");
const cookieParser = require("cookie-parser");

const {PutObjectCommand } = require("@aws-sdk/client-s3");
const { Client } = require("@googlemaps/google-maps-services-js");
const session = require("express-session");

const User = require("./models/User.js");
const  FindRoommateModel = require('./models/FindRoommate.js');

const authMiddleware = require("./middlewares/auth-middleware.js");

const connectToDB = require("./db/mongoose-connection.js");
const s3 = require('./services/s3-services.js')

const AboutRoommateModel = require("./models/AboutRoommate.js");


const OpenAI = require('openai')

require("dotenv").config();
const client = new Client({});

connectToDB()


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
  } = req.body;

  try {
    const response = await axios.get(`https://catalog.api.2gis.com/3.0/items/geocode?q=Алматы ${address}&fields=items.point&key=${process.env.TWOGIS_API}`);
    
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
  const user = req.user;
  const roommateId = req.params.id;
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
  } = req.body;

  try {
    const response = await axios.get(`https://catalog.api.2gis.com/3.0/items/geocode?q=Алматы ${address}&key=${process.env.TWOGIS_API_KEY}`);
    
    if (response.data.result.items.length > 0) {
      const location = response.data.result.items[0].point;
      const coordinates = [location.lon, location.lat];
      console.log(address, coordinates);

      const updatedRoommate = await FindRoommateModel.findByIdAndUpdate(
        roommateId,
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
        },
        { new: true, runValidators: true }
      );

      if (updatedRoommate) {
        res.json(updatedRoommate);
      } else {
        res.status(404).json({ error: "Roommate listing not found" });
      }
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

app.get("/findroommate/:id",  async (req, res) => {
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

app.get("/aboutroommate/:id",  async (req, res) => {
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


app.get("/my-announcements",authMiddleware, async (req, res) => {
  const user = req.user;
  try {
    const myAnnounFindRoomate = await FindRoommateModel.find({ owner: user.id })
    const myAnnounAboutRoomate = await AboutRoommateModel.find({ owner: user.id })
    res.status(200).json({myAnnounFindRoomate, myAnnounAboutRoomate});
  } catch (err) {
    console.log(err);
    res.status(500).json({ messages: "Internal server error" });
  }
});

app.get("/findroommates",  async (req, res) => {
  const { page = 1, limit = 100, search = "" } = req.query;

  try {
    const query = search ? { title: { $regex: search, $options: "i" } } : {};
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

app.get("/aboutroommates",  async (req, res) => {
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

app.get('/findroommates-search', authMiddleware, async (req, res) => {
  const user = req.user;
  const query = req.query.query
  try {
    const userAnceta = await AboutRoommateModel.findOne({ owner: user.id });
    
    if (!userAnceta) {
      return res.status(404).send({ message: 'User anceta not found' });
    }

    const prompt = `I will give u user and announcements and  should analyze the announcements and find suitable announcements for the user. Resources : User: ${userAnceta} Announcements: ${await FindRoommateModel.find()}. The extra queries ${query}. WARNING RETURN JSON FORMAT FINDED ANNOUNCEMENTS ONLY JSON FORMAT`
    console.log(query)
    const openai = new OpenAI({
      apiKey: process.env.CHAT_GPT_API
    })
    const openaiCompletion = await openai.chat.completions.create({
                model: "gpt-3.5-turbo",
                messages: [
                    {role: "system", content: "You are a professional job analyzer."},
                    {role: "user", content: prompt}
                ],
                temperature: 0
            });
    const aiResponse = openaiCompletion.choices[0].message.content;

    res.json(JSON.parse(aiResponse))
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: 'An error occurred while processing your request' });
  }
});


app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
