const jwt = require("jsonwebtoken");

const { readUsers, findByUsername } = require("./usersStore");

function getJwtSecret() {
  const s = String(process.env.JWT_SECRET || "").trim();
  if (!s) throw new Error("JWT_SECRET is required");
  return s;
}

function signToken(user) {
  const secret = getJwtSecret();
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    secret,
    { expiresIn: "12h" }
  );
}

function verifyToken(token) {
  const secret = getJwtSecret();
  return jwt.verify(token, secret);
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.auth = verifyToken(token);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ✅ Admin = rol admin en el store (no solo en el token).
// Esto hace que cambios en permisos apliquen en caliente (token viejo no sirve para admin).
async function requireAdmin(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: "Missing auth" });
  const who = String(req.auth.username || "").trim();
  if (!who) return res.status(401).json({ error: "Missing auth" });

  try {
    const users = await readUsers();
    const u = findByUsername(users, who);
    if (!u || u.role !== "admin") return res.status(403).json({ error: "Admin only" });
    return next();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
}

module.exports = { signToken, requireAuth, requireAdmin };
