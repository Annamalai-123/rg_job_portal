require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./src/config/db");
const authRoutes = require("./src/routes/authRoutes");

const app = express();

app.use(cors());
app.use(express.json());

// Auth routes
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.json({
    message: "Job Portal Backend is running",
  });
});

const PORT = process.env.PORT || 5000;

// Connect to MongoDB first, then start the Express server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});