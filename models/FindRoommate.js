const mongoose = require("mongoose");

const findRoommateSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  active: { type: Boolean, default: true },
  title: { type: String, required: true },
  address: {
    address: { type: String, required: true },
    coordinates: { type: [Number], required: true },
  },
  photos: { type: [String] },
  monthlyExpensePerPerson: { type: Number, required: true },
  moveInStart: { type: Date, required: true },
  utilityService: { type: String },
  deposit: { type: Number },
  maxPeople: { type: Number, required: true },
  apartmentInfo: { type: String },
  ownerInfo: { type: String },
  roomiePreferences: { type: String },
  contactNumber: { type: String, required: true },
  callPreference: { type: Boolean, default: false },
  whatsappNumber: { type: String },
  whatsappNumberPreference: { type: Boolean, default: true },
  selectedGender: { type: String, required: true },
  communalServices: { type: Boolean, default: false },
});

const FindRoommateModel = mongoose.model("FindRoommate", findRoommateSchema);

module.exports = FindRoommateModel;
