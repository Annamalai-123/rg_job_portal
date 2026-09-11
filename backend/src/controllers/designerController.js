const User = require("../models/User");

// ---------------------------------------------------------------------------
// createDesigner
// POST /api/designers
//
// Called only by an authenticated ADMIN (enforced in the route via
// authenticateToken + requireRole("ADMIN")).
//
// Responsibilities:
//   1. Validate that name and email are present in the request body.
//   2. Normalise the email (trim + lowercase) — duplicating what the
//      Mongoose schema does, so we can give a clear error before hitting
//      the DB unique index.
//   3. Reject duplicate emails with 409 Conflict.
//   4. Reject any attempt by the client to set role or status.
//   5. Persist the new user with role="DESIGNER", status="INVITED",
//      and no passwordHash (the invitation flow sets the password later).
//   6. Return a safe response — never expose passwordHash.
// ---------------------------------------------------------------------------
const createDesigner = async (req, res) => {
  try {
    // ── 1. Extract only the fields we trust from the client ─────────────────
    //    Destructure just name and email.  Any other field the client sends
    //    (role, status, passwordHash, etc.) is intentionally ignored.
    const { name, email } = req.body;

    // ── 2. Presence validation ───────────────────────────────────────────────
    if (!name || !name.toString().trim()) {
      return res.status(400).json({
        success: false,
        message: "name is required.",
      });
    }

    if (!email || !email.toString().trim()) {
      return res.status(400).json({
        success: false,
        message: "email is required.",
      });
    }

    // ── 3. Normalise email ───────────────────────────────────────────────────
    //    Mongoose schema also applies lowercase + trim, but doing it here
    //    lets us use the normalised value in the duplicate-check query and
    //    gives us a consistent value regardless of schema changes.
    const normalisedEmail = email.toString().trim().toLowerCase();

    // ── 4. Duplicate-email check ─────────────────────────────────────────────
    //    We check explicitly so we can return 409 with a clear message.
    //    The unique index on the schema also catches races, but that error
    //    (code 11000) is handled in the catch block below as a safety net.
    const existingUser = await User.findOne({ email: normalisedEmail });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "A user with this email already exists.",
      });
    }

    // ── 5. Create the Designer ───────────────────────────────────────────────
    //    role and status are ALWAYS set by the server — never from req.body.
    //    passwordHash is intentionally omitted; the Designer has no password
    //    until they complete the invitation/password-setup flow.
    const designer = await User.create({
      name: name.toString().trim(),
      email: normalisedEmail,
      role: "DESIGNER",   // server-controlled — client cannot override
      status: "INVITED",  // server-controlled — client cannot override
      // passwordHash is left absent; the schema default (null) applies
    });

    // ── 6. Return safe response ──────────────────────────────────────────────
    //    Explicitly select only the fields the client is allowed to see.
    //    passwordHash is never included.
    return res.status(201).json({
      success: true,
      message: "Designer account created successfully.",
      data: {
        id: designer._id,
        name: designer.name,
        email: designer.email,
        role: designer.role,
        status: designer.status,
        createdAt: designer.createdAt,
      },
    });
  } catch (error) {
    // Safety-net for MongoDB duplicate-key race condition
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "A user with this email already exists.",
      });
    }

    console.error("createDesigner error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

module.exports = { createDesigner };
