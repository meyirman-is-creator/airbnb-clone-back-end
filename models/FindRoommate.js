const mongoose = require("mongoose");
const findRoommateSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  active: Boolean,
  title: String,
  address: String,
  photos: [String],
  monthlyExpensePerPerson: String,
  moveInStart: Date,
  utilityService: String,
  deposit: String,
  maxPeople: Number,
  apartmentInfo: String,
  ownerInfo: String,
  roomiePreferences: String,
  contactNumber: String,
  callPreference: Boolean,
  whatsappNumber: String
});
const FindRoommateModel = mongoose.model("FindRoomate", findRoommateSchema);

module.exports = FindRoommateModel;
