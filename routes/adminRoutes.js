const express = require("express");
const User = require("../models/User");
const File = require("../models/File");
const ActivityLog = require("../models/ActivityLog");


const BlockchainLog = require("../models/BlockchainLog");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");

const router = express.Router();

router.get("/stats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalFiles = await File.countDocuments();
    const encryptedFiles = await File.countDocuments({ isEncrypted: true });
    const totalLogs = await ActivityLog.countDocuments();
    const unauthorizedAttempts = await ActivityLog.countDocuments({
      action: "UNAUTHORIZED_DOWNLOAD_ATTEMPT",
    });

    res.status(200).json({
      totalUsers,
      totalFiles,
      encryptedFiles,
      totalLogs,
      unauthorizedAttempts,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch admin stats",
      error: error.message,
    });
  }
});

router.get("/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("-password");

    res.status(200).json({
      message: "Users fetched successfully",
      users,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch users",
      error: error.message,
    });
  }
});

router.get("/files", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const files = await File.find()
      .populate("owner", "name email role")
      .sort({ uploadedAt: -1 });

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

router.get("/logs", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const logs = await ActivityLog.find()
      .populate("user", "name email role")
      .populate("fileId", "originalname filename")
      .sort({ timestamp: -1 });

    res.status(200).json({
      message: "Logs fetched successfully",
      logs,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch logs",
      error: error.message,
    });
  }
});

router.get("/user-activity/:userId", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const logs = await ActivityLog.find({ user: userId })
      .populate("fileId", "originalname filename")
      .sort({ timestamp: -1 });

    const uploads = logs.filter(
      (log) => log.action === "FILE_UPLOADED_ENCRYPTED"
    ).length;

    const downloads = logs.filter(
      (log) => log.action === "FILE_DOWNLOADED"
    ).length;

    const shares = logs.filter(
      (log) => log.action === "FILE_SHARED"
    ).length;

    const deletes = logs.filter(
      (log) => log.action === "FILE_DELETED"
    ).length;

    const unauthorizedAttempts = logs.filter(
      (log) => log.action === "UNAUTHORIZED_DOWNLOAD_ATTEMPT"
    ).length;

    const threatScore =
      unauthorizedAttempts * 25 + downloads * 2 + deletes * 5;

    res.status(200).json({
      message: "User activity fetched successfully",
      user,
      summary: {
        uploads,
        downloads,
        shares,
        deletes,
        unauthorizedAttempts,
        threatScore,
      },
      logs,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch user activity",
      error: error.message,
    });
  }
});

router.get("/forensics/:userId", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const logs = await ActivityLog.find({ user: userId })
      .populate("fileId", "originalname filename")
      .sort({ timestamp: 1 });

    const unauthorizedAttempts = logs.filter(
      (log) => log.action === "UNAUTHORIZED_DOWNLOAD_ATTEMPT"
    ).length;

    const deletes = logs.filter(
      (log) => log.action === "FILE_DELETED"
    ).length;

    let riskLevel = "LOW";

    if (unauthorizedAttempts >= 3 || deletes >= 3) {
      riskLevel = "HIGH";
    } else if (unauthorizedAttempts >= 1 || deletes >= 1) {
      riskLevel = "MEDIUM";
    }

    const timeline = logs.map((log) => ({
      action: log.action,
      details: log.details,
      file: log.fileId?.originalname || "N/A",
      timestamp: log.timestamp,
    }));

    res.status(200).json({
      message: "Forensic report generated successfully",
      user,
      riskLevel,
      evidenceCount: logs.length,
      unauthorizedAttempts,
      deletes,
      timeline,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to generate forensic report",
      error: error.message,
    });
  }
});





router.get("/blockchain", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const logs = await BlockchainLog.find()
      .populate("userId", "name email role")
      .populate("fileId", "originalname filename")
      .sort({ timestamp: -1 });

    res.status(200).json({
      message: "Blockchain logs fetched successfully",
      logs,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch blockchain logs",
      error: error.message,
    });
  }
});





router.get("/blockchain/verify", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const logs = await BlockchainLog.find().sort({ timestamp: 1 });

    let isValid = true;
    let tamperedBlocks = 0;

    for (let i = 1; i < logs.length; i++) {
      if (logs[i].previousHash !== logs[i - 1].hash) {
        isValid = false;
        tamperedBlocks++;
      }
    }

    res.status(200).json({
      message: "Blockchain verification completed",
      status: isValid ? "VALID" : "TAMPERED",
      totalBlocks: logs.length,
      tamperedBlocks,
    });
  } catch (error) {
    res.status(500).json({
      message: "Blockchain verification failed",
      error: error.message,
    });
  }
});


router.get("/ml-threats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("-password");

    const results = [];

    for (const user of users) {
      const logs = await ActivityLog.find({ user: user._id });

      const uploads = logs.filter(
        (log) => log.action === "FILE_UPLOADED_ENCRYPTED"
      ).length;

      const downloads = logs.filter(
        (log) => log.action === "FILE_DOWNLOADED"
      ).length;

      const shares = logs.filter(
        (log) => log.action === "FILE_SHARED"
      ).length;

      const deletes = logs.filter(
        (log) => log.action === "FILE_DELETED"
      ).length;

      const unauthorizedAttempts = logs.filter(
        (log) => log.action === "UNAUTHORIZED_DOWNLOAD_ATTEMPT"
      ).length;

      let threatScore =
        unauthorizedAttempts * 30 +
        deletes * 10 +
        downloads * 3 +
        shares * 2 +
        uploads * 1;

      if (threatScore > 100) {
        threatScore = 100;
      }

      let riskLevel = "LOW";
      let reason = "Normal activity";

      if (threatScore >= 70) {
        riskLevel = "HIGH";
        reason = "High unauthorized attempts or suspicious file activity";
      } else if (threatScore >= 35) {
        riskLevel = "MEDIUM";
        reason = "Moderate suspicious activity detected";
      }

      results.push({
        userId: user._id,
        name: user.name,
        email: user.email,
        role: user.role || "user",
        uploads,
        downloads,
        shares,
        deletes,
        unauthorizedAttempts,
        threatScore,
        riskLevel,
        reason,
      });
    }

    results.sort((a, b) => b.threatScore - a.threatScore);

    res.status(200).json({
      message: "ML-style threat detection completed",
      results,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to generate ML threat scores",
      error: error.message,
    });
  }
});

module.exports = router;