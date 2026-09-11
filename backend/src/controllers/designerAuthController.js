// =============================================================================
// designerAuthController.js
//
// ⚠️  DEVELOPMENT ONLY — V1 Implementation
//
// This controller accepts an email directly to identify the Designer.
// This is intentionally simplified for local development and testing.
//
// PRODUCTION PLAN (NOT YET IMPLEMENTED):
//   Replace the email lookup with a secure, single-use invitation token that
//   is emailed to the Designer when their account is created.  The token will:
//     - be stored (hashed) in the User document alongside an expiry timestamp
//     - be passed in the request body instead of the email
//     - be invalidated immediately after use
//   This eliminates the risk of any arbitrary caller activating an account
//   simply by knowing the Designer's email address.
// =============================================================================

const bcrypt = require("bcryptjs");
const User = require("../models/User");

// Minimum acceptable password length
const MIN_PASSWORD_LENGTH = 8;

// ---------------------------------------------------------------------------
// setDesignerPassword
// POST /api/auth/designer/set-password
//
// Allows an INVITED Designer to choose their password and activate their
// account.  After this completes, the Designer can log in via the standard
// POST /api/auth/login endpoint.
//
// Flow:
//   1. Extract and validate email + password from the request body.
//   2. Look up the user by normalised email.
//   3. Guard: user must exist, must be a DESIGNER, must be INVITED.
//   4. Hash the password with bcrypt (12 salt rounds).
//   5. Persist passwordHash and flip status to "ACTIVE".
//   6. Return a safe response — never echo back the password or hash.
// ---------------------------------------------------------------------------
const setDesignerPassword = async (req, res) => {
  try {
    // ── 1. Extract fields ──────────────────────────────────────────────────
    const { email, password } = req.body;

    // ── 2. Presence validation ─────────────────────────────────────────────
    if (!email || !email.toString().trim()) {
      return res.status(400).json({
        success: false,
        message: "email is required.",
      });
    }

    if (!password || !password.toString().trim()) {
      return res.status(400).json({
        success: false,
        message: "password is required.",
      });
    }

    // ── 3. Minimum password length ─────────────────────────────────────────
    if (password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({
        success: false,
        message: `password must be at least ${MIN_PASSWORD_LENGTH} characters long.`,
      });
    }

    // ── 4. Normalise email ─────────────────────────────────────────────────
    const normalisedEmail = email.toString().trim().toLowerCase();

    // ── 5. Lookup user ─────────────────────────────────────────────────────
    const user = await User.findOne({ email: normalisedEmail });

    if (!user) {
      // Return 404 — the email is not registered at all
      return res.status(404).json({
        success: false,
        message: "No account found with this email address.",
      });
    }

    // ── 6. Role guard ──────────────────────────────────────────────────────
    // Only Designers go through this flow.
    // Admins always have passwords set at seed time.
    if (user.role !== "DESIGNER") {
      return res.status(403).json({
        success: false,
        message: "This endpoint is only available to Designer accounts.",
      });
    }

    // ── 7. Status guard ────────────────────────────────────────────────────
    // Only INVITED Designers need to set a password.
    // ACTIVE → already set up.  INACTIVE → contact admin.
    if (user.status === "ACTIVE") {
      return res.status(409).json({
        success: false,
        message:
          "This account is already active. Use the login endpoint instead.",
      });
    }

    if (user.status === "INACTIVE") {
      return res.status(403).json({
        success: false,
        message:
          "This account is inactive. Please contact an administrator.",
      });
    }

    // At this point status must be "INVITED" — proceed.

    // ── 8. Hash the password ───────────────────────────────────────────────
    // bcrypt.genSalt(12) generates a random salt with a cost factor of 12.
    // A higher cost factor means more compute per hash, making brute-force
    // attacks slower.  12 is the industry-standard balance of security vs
    // performance for 2020s hardware.
    //
    // bcrypt.hash() combines the plain-text password + salt and returns a
    // 60-character string that encodes the algorithm, cost factor, salt, and
    // hash — everything needed to verify the password later.
    //
    // The plain-text password is NEVER written to disk or logged.
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // ── 9. Persist changes ─────────────────────────────────────────────────
    // Flip status to ACTIVE — the Designer is now fully onboarded.
    user.passwordHash = passwordHash;
    user.status = "ACTIVE";
    await user.save();

    // ── 10. Return safe response ────────────────────────────────────────────
    // passwordHash is intentionally excluded.
    return res.status(200).json({
      success: true,
      message:
        "Password set successfully. You can now log in using POST /api/auth/login.",
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    });
  } catch (error) {
    console.error("setDesignerPassword error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

module.exports = { setDesignerPassword };
