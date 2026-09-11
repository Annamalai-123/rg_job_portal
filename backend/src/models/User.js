const mongoose = require("mongoose");

/**
 * User Schema
 *
 * Represents both Admin and Designer users in the Regin Job Portal.
 * Role-based access is enforced at the application layer using the `role` field.
 * Passwords are never stored in plain text — only the bcrypt hash is persisted.
 */
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },

  passwordHash: {
    // Optional — Designers start without a password (status: "INVITED").
    // A hash is set only after the Designer completes the invitation flow.
    type: String,
    required: false,
    default: null,
  },

  role: {
    type: String,
    enum: ["ADMIN", "DESIGNER"],
    required: true,
  },

  status: {
    type: String,
    enum: ["ACTIVE", "INVITED", "INACTIVE"],
    default: "ACTIVE",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
