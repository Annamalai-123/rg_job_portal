const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

// ---------------------------------------------------------------------------
// seedAdmin
// Creates the first Admin account if no Admin exists in the database.
// Call this once manually via the /api/auth/seed-admin endpoint (dev only).
// ---------------------------------------------------------------------------
const seedAdmin = async (req, res) => {
  try {
    // Check whether an Admin already exists to prevent duplicate seeding
    const existingAdmin = await User.findOne({ role: "ADMIN" });
    if (existingAdmin) {
      return res.status(409).json({
        success: false,
        message: "An Admin account already exists. Seeding skipped.",
      });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "name, email, and password are required to seed the Admin.",
      });
    }

    // Hash the password — never store plain text
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const admin = await User.create({
      name,
      email,
      passwordHash,
      role: "ADMIN",
      status: "ACTIVE",
    });

    return res.status(201).json({
      success: true,
      message: "Admin account created successfully.",
      data: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        status: admin.status,
      },
    });
  } catch (error) {
    // Handle MongoDB duplicate key error (email already taken)
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }
    console.error("seedAdmin error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

// ---------------------------------------------------------------------------
// login
// POST /api/auth/login
// Verifies email + password and returns a signed JWT on success.
// ---------------------------------------------------------------------------
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    // Find the user by email
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    // Use a generic error message for both "user not found" and "wrong password"
    // This prevents leaking which emails are registered (user enumeration attack).
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    // Verify the submitted password against the stored bcrypt hash
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    // Reject inactive accounts
    if (user.status !== "ACTIVE") {
      return res.status(403).json({
        success: false,
        message: "Your account is not active. Please contact an administrator.",
      });
    }

    // Build the JWT payload — only non-sensitive identifiers
    // Never include passwordHash or any secret inside the token.
    const payload = {
      userId: user._id,
      role: user.role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("login error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

module.exports = { seedAdmin, login };
