const mongoose = require("mongoose");
const aboutRoommateSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  active: Boolean,
  payment: Number,
  gender: String,
  roomiesPreferences: String,
  address: String,
  moveInStart: Date,
  contactNumber: String,
  callPreference: Boolean,
  whatsappNumber: String,
});
const AboutRoommateModel = mongoose.model("AboutRoomate", aboutRoommateSchema);

module.exports = AboutRoommateModel;
