const jwt = require("jsonwebtoken");

function getSingleAdminUsername() {
  // Modo PoC: solo un usuario tendrá acceso al admin.
  // Puedes sobreescribirlo por env (Render) si lo necesitas.
  return String(process.env.SINGLE_ADMIN_USERNAME || "jmcastellanos@conversionaventa.com")
    .trim()
    .toLowerCase();
}

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) {
    // Evita que el servidor quede inseguro sin querer.
    // En PoC local, puedes setearlo en .env.
    throw new Error("JWT_SECRET is required");
  }
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

function requireAdmin(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: "Missing auth" });
  // Doble validación: rol + usuario permitido.
  const allowed = getSingleAdminUsername();
  const who = String(req.auth.username || "").trim().toLowerCase();
  if (req.auth.role !== "admin" || who !== allowed) {
    return res.status(403).json({ error: "Admin only" });
  }
  return next();
}

module.exports = { signToken, requireAuth, requireAdmin, getSingleAdminUsername };
