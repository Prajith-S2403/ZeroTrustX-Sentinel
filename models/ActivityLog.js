const mongoose = require("mongoose");

const ActivityLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  action: {
    type: String,
    required: true
  },
  fileId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "File"
  },
  details: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("ActivityLog", ActivityLogSchema);