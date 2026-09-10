const jwt = require("jsonwebtoken");

/**
 * authenticateToken
 *
 * Middleware that guards any route requiring a valid JWT.
 *
 * Flow:
 *  1. Read the Authorization header.
 *  2. Split off the Bearer prefix to extract the raw token.
 *  3. Verify the token's signature and expiry using JWT_SECRET.
 *  4. Attach the decoded payload to req.user so downstream
 *     handlers and role middleware can read it.
 *  5. Call next() — the request continues to the route handler.
 *
 * No MongoDB query is made here. JWT verification is a pure
 * cryptographic operation using the secret key.
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  // Header must exist and follow the "Bearer <token>" format
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Access denied. No token provided.",
    });
  }

  // Extract the raw token string (everything after "Bearer ")
  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access denied. Token is malformed.",
    });
  }

  try {
    // jwt.verify throws if the signature is invalid OR if the token has expired
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach only what downstream code needs — userId and role
    req.user = {
      userId: decoded.userId,
      role: decoded.role,
    };

    next(); // Token is valid — let the request continue
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Token has expired. Please log in again.",
      });
    }

    // Covers JsonWebTokenError (bad signature, malformed JWT, etc.)
    return res.status(401).json({
      success: false,
      message: "Invalid token.",
    });
  }
};

module.exports = { authenticateToken };
