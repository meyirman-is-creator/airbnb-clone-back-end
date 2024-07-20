const jwt = require("jsonwebtoken");

const jwtSecret = "adsflkjasdfadf";

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = payload;
    next(); // Pass control to the next middleware or route handler
  } catch (err) {
    console.log(err);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

module.exports = authMiddleware;
