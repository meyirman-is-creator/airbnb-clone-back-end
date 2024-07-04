require('dotenv').config()
const mongoose = require("mongoose");


const connectToDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URL, {
            autoIndex: true
        });
        console.log("Подключение к MongoDB успешно установлено");
    } catch (err) {
        console.error("Ошибка подключения к MongoDB:", err);
        process.exit(1);
    }
}

module.exports = connectToDB;
