/**
 * requireRole
 *
 * Factory function that returns a middleware checking the authenticated
 * user's role against a list of allowed roles.
 *
 * Usage (in a route file):
 *   router.get(
 *     "/admin-only",
 *     authenticateToken,          // runs first — verifies JWT, sets req.user
 *     requireRole("ADMIN"),       // runs second — checks the role
 *     myRouteHandler              // runs only if both pass
 *   );
 *
 * Multiple roles can be allowed at once:
 *   requireRole("ADMIN", "DESIGNER")
 *
 * IMPORTANT: authenticateToken MUST run before requireRole in the
 * middleware chain, otherwise req.user will be undefined.
 */
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    // req.user is set by authenticateToken — if it's missing, the
    // middleware chain is wired incorrectly.
    if (!req.user || !req.user.role) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const hasPermission = allowedRoles.includes(req.user.role);

    if (!hasPermission) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role: ${allowedRoles.join(" or ")}. Your role: ${req.user.role}.`,
      });
    }

    next(); // Role is permitted — continue to the route handler
  };
};

module.exports = { requireRole };
