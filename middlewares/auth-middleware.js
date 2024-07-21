const jwt = require("jsonwebtoken");

const jwtSecret = "adsflkjasdfadf";

const authMiddleware = (req, res, next) => {
  // Извлечение заголовка авторизации
  const authHeader = req.headers.authorization;
  // Проверка наличия заголовка авторизации
  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  // Извлечение токена из заголовка
  const token = authHeader.split(" ")[1];

  // Проверка наличия токена
  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    // Проверка и декодирование токена
    const payload = jwt.verify(token, jwtSecret);
    // Сохранение полезной нагрузки токена в запросе
    req.user = payload;
    // Переход к следующему обработчику
    next(); 
  } catch (err) {
    console.error("Token verification error:", err);
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

module.exports = authMiddleware;
