const mongoose = require("mongoose");

const BlockchainLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
  },

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  fileId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "File",
  },

  hash: {
    type: String,
    required: true,
  },

  previousHash: {
    type: String,
    default: "GENESIS",
  },

  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model(
  "BlockchainLog",
  BlockchainLogSchema
);