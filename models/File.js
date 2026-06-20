const mongoose = require("mongoose");

const FileSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  originalname: {
    type: String,
    required: true
  },

  filename: {
    type: String,
    required: true
  },

  path: {
    type: String,
    required: true
  },

  // AES fields
  encryptedPath: {
    type: String
  },

  iv: {
    type: String
  },

  isEncrypted: {
    type: Boolean,
    default: true
  },

  mimetype: String,
  size: Number,

  sharedWith: [
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
      },
      permission: {
        type: String,
        enum: ["view", "download"],
        default: "view"
      },
      sharedAt: {
        type: Date,
        default: Date.now
      }
    }
  ],

  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("File", FileSchema);