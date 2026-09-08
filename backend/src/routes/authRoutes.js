const express = require("express");
const router = express.Router();
const { seedAdmin, login } = require("../controllers/authController");

// POST /api/auth/seed-admin
// One-time endpoint to create the first Admin account.
// Should be removed or protected after the initial Admin is created.
router.post("/seed-admin", seedAdmin);

// POST /api/auth/login
// Accepts { email, password } and returns a signed JWT on success.
router.post("/login", login);

module.exports = router;
