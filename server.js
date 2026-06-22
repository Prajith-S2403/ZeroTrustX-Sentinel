const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body } = require("express-validator");
const fs = require("fs");

if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}
if (!fs.existsSync("temp")) {
  fs.mkdirSync("temp");
}

const adminRoutes = require("./routes/adminRoutes");

const User = require("./models/User");
const authMiddleware = require("./middleware/authMiddleware");
const adminMiddleware = require("./middleware/adminMiddleware");
const validate = require("./middleware/validationMiddleware");
const fileRoutes = require("./routes/fileRoutes");

const app = express();
const SECRET_KEY = process.env.JWT_SECRET || "zerotrustsecret123";

// Allow requests from the configured frontend URL (or any origin in dev)
const allowedOrigin = process.env.FRONTEND_URL || "*";
app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  })
);
app.use(express.json());
app.use(helmet());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Try again later.",
});

mongoose
  .connect(
    process.env.MONGO_URI ||
      "mongodb://Prajith:Prajith123@ac-lsmp5ng-shard-00-00.t2gd41j.mongodb.net:27017,ac-lsmp5ng-shard-00-01.t2gd41j.mongodb.net:27017,ac-lsmp5ng-shard-00-02.t2gd41j.mongodb.net:27017/zerotrustshare?ssl=true&replicaSet=atlas-cvcjp2-shard-0&authSource=admin&retryWrites=true&w=majority"
  )
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

app.get("/", (req, res) => {
  res.send("Hello from ZeroTrust Share API!");
});

// Register
app.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
  ],
  validate,
  async (req, res) => {
    try {
      const name = req.body.name;
      const email = req.body.email.toLowerCase();
      const password = req.body.password;

      const existingUser = await User.findOne({ email });

      if (existingUser) {
        return res.status(400).json({
          message: "User already exists",
        });
      }

      const user = await User.create({
        name,
        email,
        password,
      });

      res.status(201).json({
        message: "User registered successfully",
        user,
      });
    } catch (error) {
      res.status(500).json({
        message: "Registration failed",
        error: error.message,
      });
    }
  }
);

// Login
app.post(
  "/login",
  loginLimiter,
  [
    body("email").isEmail().withMessage("Valid email is required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  validate,
  async (req, res) => {
    try {
      const email = req.body.email.toLowerCase();
      const password = req.body.password;

      const user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({
          message: "User not found",
        });
      }

      const isMatch = await user.comparePassword(password);

      if (!isMatch) {
        return res.status(401).json({
          message: "Invalid password",
        });
      }

      const token = jwt.sign(
        {
          id: user._id,
          role: user.role || "user",
        },
        SECRET_KEY,
        { expiresIn: "1h" }
      );

      res.status(200).json({
        message: "Login successful",
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role || "user",
        },
      });
    } catch (error) {
      res.status(500).json({
        message: "Login failed",
        error: error.message,
      });
    }
  }
);

// Protected profile
app.get("/profile", authMiddleware, (req, res) => {
  res.status(200).json({
    message: "Protected profile accessed successfully",
    user: req.user,
  });
});

// Admin only
app.get("/admin-dashboard", authMiddleware, adminMiddleware, (req, res) => {
  res.status(200).json({
    message: "Welcome Admin",
  });
});

// File routes
app.use("/api/files", fileRoutes);

app.use("/api/admin", adminRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});