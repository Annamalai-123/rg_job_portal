const express = require("express");
const router = express.Router();
const { seedAdmin, login } = require("../controllers/authController");
const { setDesignerPassword } = require("../controllers/designerAuthController");

// POST /api/auth/seed-admin
// One-time endpoint to create the first Admin account.
// Should be removed or protected after the initial Admin is created.
router.post("/seed-admin", seedAdmin);

// POST /api/auth/login
// Accepts { email, password } and returns a signed JWT on success.
router.post("/login", login);

// POST /api/auth/designer/set-password
// ⚠️  DEVELOPMENT ONLY — accepts email directly (no invitation token yet).
// Allows an INVITED Designer to set their password and become ACTIVE.
// TODO: Replace with invitation-token flow before going to production.
router.post("/designer/set-password", setDesignerPassword);

module.exports = router;
