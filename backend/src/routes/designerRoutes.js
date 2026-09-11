const express = require("express");
const router = express.Router();
const { authenticateToken } = require("../middleware/authMiddleware");
const { requireRole } = require("../middleware/roleMiddleware");
const { createDesigner } = require("../controllers/designerController");

// POST /api/designers
// Protected: JWT must be valid AND the caller must be an ADMIN.
//
// Middleware chain (order is critical):
//   1. authenticateToken  — verifies the JWT, populates req.user
//   2. requireRole("ADMIN") — ensures req.user.role === "ADMIN"
//   3. createDesigner     — business logic
router.post(
  "/",
  authenticateToken,
  requireRole("ADMIN"),
  createDesigner
);

module.exports = router;
