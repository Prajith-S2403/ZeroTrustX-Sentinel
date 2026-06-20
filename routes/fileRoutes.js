const express = require("express");
const multer = require("multer");
const authMiddleware = require("../middleware/authMiddleware");
const File = require("../models/File");
const User = require("../models/User");
const ActivityLog = require("../models/ActivityLog");
const { encryptFile, decryptFile } = require("../utils/encryption");

const BlockchainLog = require("../models/BlockchainLog");
const { generateHash } = require("../utils/blockchain");

const fs = require("fs");
const path = require("path");

const router = express.Router();


async function createBlockchainLog(action, userId, fileId) {
  const lastLog = await BlockchainLog.findOne().sort({ timestamp: -1 });

  const previousHash = lastLog ? lastLog.hash : "GENESIS";

  const data = {
    action,
    userId,
    fileId,
    previousHash,
    timestamp: new Date(),
  };

  const hash = generateHash(data);

  await BlockchainLog.create({
    action,
    userId,
    fileId,
    hash,
    previousHash,
  });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

// Upload file with AES encryption
router.post("/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const encryptedData = await encryptFile(req.file.path);

    const savedFile = await File.create({
      owner: req.user.id,
      originalname: req.file.originalname,
      filename: req.file.filename,
      path: encryptedData.encryptedPath,
      encryptedPath: encryptedData.encryptedPath,
      iv: encryptedData.iv,
      isEncrypted: true,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });

    await ActivityLog.create({
      user: req.user.id,
      action: "FILE_UPLOADED_ENCRYPTED",
      fileId: savedFile._id,
      details: `${req.file.originalname} uploaded and encrypted`,
    });



    await createBlockchainLog(
  "FILE_UPLOADED_ENCRYPTED",
  req.user.id,
  savedFile._id
);
    res.status(201).json({
      message: "File uploaded, encrypted, and saved successfully",
      file: savedFile,
    });
  } catch (error) {
    res.status(500).json({
      message: "File upload failed",
      error: error.message,
    });
  }
});

// My files
router.get("/my-files", authMiddleware, async (req, res) => {
  try {
    const files = await File.find({ owner: req.user.id }).sort({ uploadedAt: -1 });

    res.status(200).json({
      message: "Files fetched successfully",
      files,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch files",
      error: error.message,
    });
  }
});

// Download file: owner OR shared user with download permission
router.get("/download/:id", authMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    const isOwner = file.owner.toString() === req.user.id;

    const sharedAccess = file.sharedWith.find(
      (share) =>
        share.user.toString() === req.user.id &&
        share.permission === "download"
    );

    if (!isOwner && !sharedAccess) {
      await ActivityLog.create({
        user: req.user.id,
        action: "UNAUTHORIZED_DOWNLOAD_ATTEMPT",
        fileId: file._id,
        details: `Unauthorized download attempt for ${file.originalname}`,
      });

      return res.status(403).json({
        message: "Access denied. You do not have download permission.",
      });
    }

    let downloadPath = file.path;

    if (file.isEncrypted) {
      const tempDir = path.join(__dirname, "..", "temp");

      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
      }

      downloadPath = path.join(tempDir, `${Date.now()}-${file.originalname}`);

      await decryptFile(file.encryptedPath, file.iv, downloadPath);
    }

    await ActivityLog.create({
      user: req.user.id,
      action: "FILE_DOWNLOADED",
      fileId: file._id,
      details: `${file.originalname} downloaded`,
    });

    await createBlockchainLog(
  "FILE_DOWNLOADED",
  req.user.id,
  file._id
);

    res.download(downloadPath, file.originalname, (err) => {
      if (file.isEncrypted && fs.existsSync(downloadPath)) {
        fs.unlinkSync(downloadPath);
      }

      if (err) {
        console.log("Download error:", err.message);
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Download failed",
      error: error.message,
    });
  }
});

// Share file
router.post("/share/:id", authMiddleware, async (req, res) => {
  try {
    const { email, permission } = req.body;

    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    if (file.owner.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Only owner can share this file",
      });
    }

    const userToShare = await User.findOne({ email });

    if (!userToShare) {
      return res.status(404).json({ message: "User not found" });
    }

    if (userToShare._id.toString() === req.user.id) {
      return res.status(400).json({
        message: "You cannot share a file with yourself",
      });
    }

    file.sharedWith.push({
      user: userToShare._id,
      permission: permission || "view",
    });

    await file.save();

    await ActivityLog.create({
      user: req.user.id,
      action: "FILE_SHARED",
      fileId: file._id,
      details: `File shared with ${email}`,
    });



    await createBlockchainLog(
  "FILE_SHARED",
  req.user.id,
  file._id
);

    res.status(200).json({
      message: "File shared successfully",
      file,
    });
  } catch (error) {
    res.status(500).json({
      message: "File sharing failed",
      error: error.message,
    });
  }
});

// Shared with me
router.get("/shared-with-me", authMiddleware, async (req, res) => {
  try {
    const files = await File.find({
      "sharedWith.user": req.user.id,
    }).populate("owner", "name email");

    res.status(200).json({
      message: "Shared files fetched successfully",
      files,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch shared files",
      error: error.message,
    });
  }
});

// Activity logs
router.get("/logs", authMiddleware, async (req, res) => {
  try {
    const logs = await ActivityLog.find({ user: req.user.id })
      .populate("user", "name email")
      .populate("fileId", "originalname filename")
      .sort({ timestamp: -1 });

    res.status(200).json({
      message: "Activity logs fetched successfully",
      logs,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch activity logs",
      error: error.message,
    });
  }
});

// Delete file
router.delete("/delete/:id", authMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    if (file.owner.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Only owner can delete files",
      });
    }

    const filePath = path.join(__dirname, "..", file.path);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await ActivityLog.create({
      user: req.user.id,
      action: "FILE_DELETED",
      fileId: file._id,
      details: `${file.originalname} deleted`,
    });




    await createBlockchainLog(
  "FILE_DELETED",
  req.user.id,
  file._id
);




    await File.findByIdAndDelete(req.params.id);

    res.status(200).json({
      message: "File deleted from database and uploads folder successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Delete failed",
      error: error.message,
    });
  }
});

module.exports = router;