require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./src/config/db");
const authRoutes = require("./src/routes/authRoutes");
const designerRoutes = require("./src/routes/designerRoutes");
const { authenticateToken } = require("./src/middleware/authMiddleware");
const { requireRole } = require("./src/middleware/roleMiddleware");

const app = express();

app.use(cors());
app.use(express.json());

// ── Auth routes ──────────────────────────────────────────────────────────────
app.use("/api/auth", authRoutes);

// ── Designer management routes (ADMIN only) ───────────────────────────────────
app.use("/api/designers", designerRoutes);

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    message: "Job Portal Backend is running",
  });
});

// ── Temporary middleware test routes (remove before production) ───────────────

// Any authenticated user (ADMIN or DESIGNER) can access this
app.get("/api/test/protected", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "You are authenticated.",
    user: req.user,
  });
});

// Only ADMIN can access this
app.get(
  "/api/test/admin-only",
  authenticateToken,
  requireRole("ADMIN"),
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome, Admin. You have full access.",
      user: req.user,
    });
  }
);

// Only DESIGNER can access this
app.get(
  "/api/test/designer-only",
  authenticateToken,
  requireRole("DESIGNER"),
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome, Designer.",
      user: req.user,
    });
  }
);

// ─────────────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 5000;

// Connect to MongoDB first, then start the Express server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});