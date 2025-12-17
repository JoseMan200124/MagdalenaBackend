require("dotenv").config();

const express = require("express");
const cors = require("cors");

const {
  ensureStore,
  sanitizeUser,
  listUsers,
  getUserById,
  findByUsername,
  countAdmins,
  createUser,
  updateUser,
  deleteUser,
  isUniqueViolation,
} = require("./lib/usersStore");

const { signToken, requireAuth, requireAdmin } = require("./lib/auth");
const { randomPassword } = require("./lib/utils");

const app = express();
app.use(express.json({ limit: "1mb" }));

const frontendOrigin = (process.env.FRONTEND_ORIGIN || "").trim();
app.use(
    cors({
      origin: frontendOrigin ? [frontendOrigin] : true,
      credentials: true,
    })
);

app.get("/health", (req, res) => res.json({ ok: true }));

function normRole(role) {
  const r = String(role || "").trim().toLowerCase();
  return r === "admin" ? "admin" : "viewer";
}

// Bootstrap: asegura que exista al menos 1 admin inicial
async function bootstrapAtLeastOneAdmin() {
  await ensureStore();

  const adminUser = String(
      process.env.DEFAULT_ADMIN_USER || process.env.SINGLE_ADMIN_USERNAME || "admin@magdalena.com"
  ).trim();

  const adminPass = String(
      process.env.DEFAULT_ADMIN_PASS || process.env.SINGLE_ADMIN_PASSWORD || "12345"
  ).trim();

  let admin = await findByUsername(adminUser);

  if (!admin) {
    await createUser({ username: adminUser, password: adminPass, role: "admin" });
    console.log(`[bootstrap] Created admin user: ${adminUser}`);
    return;
  }

  // Forzamos que exista como admin + que tenga password (si por alguna razón estaba vacío)
  const patch = {};
  if (String(admin.role) !== "admin") patch.role = "admin";
  if (!admin.password) patch.password = adminPass;

  if (Object.keys(patch).length) {
    await updateUser(admin.id, patch);
    console.log(`[bootstrap] Updated admin user: ${adminUser}`);
  }
}

// -------- AUTH --------

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    const user = await findByUsername(username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    // PoC: contraseñas sin cifrar
    if (String(user.password) !== String(password)) return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user);
    return res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

// /me desde Postgres
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const u = await getUserById(req.auth.sub);
    if (!u) return res.status(401).json({ error: "User not found" });
    return res.json({ user: sanitizeUser(u) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

// -------- USERS ADMIN --------

app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await listUsers();
    return res.json({ items: users.map(sanitizeUser) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { username, password, generatePassword, role } = req.body || {};
    const u = String(username || "").trim();
    if (!u) return res.status(400).json({ error: "username required" });

    let pass = String(password || "");
    if (!pass || generatePassword) pass = randomPassword(12);

    try {
      const newUser = await createUser({ username: u, password: pass, role: normRole(role) });

      return res.status(201).json({
        user: sanitizeUser(newUser),
        generatedPassword: (!password || generatePassword) ? pass : null,
      });
    } catch (e) {
      if (isUniqueViolation(e)) return res.status(409).json({ error: "username already exists" });
      throw e;
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { username, password, generatePassword, role } = req.body || {};

    const current = await getUserById(id);
    if (!current) return res.status(404).json({ error: "not found" });

    // username
    const patch = {};
    if (username != null) {
      const nu = String(username).trim();
      if (!nu) return res.status(400).json({ error: "username cannot be empty" });
      patch.username = nu;
    }

    // role: proteger último admin
    if (role != null) {
      const nextRole = normRole(role);
      const wasAdmin = String(current.role) === "admin";

      if (wasAdmin && nextRole !== "admin") {
        const admins = await countAdmins();
        if (admins <= 1) return res.status(400).json({ error: "You cannot remove the last admin" });
      }
      patch.role = nextRole;
    }

    // password
    let generated = null;
    if (generatePassword) {
      generated = randomPassword(12);
      patch.password = generated;
    } else if (password != null) {
      patch.password = String(password);
    }

    try {
      const updated = await updateUser(id, patch);
      return res.json({ user: sanitizeUser(updated), generatedPassword: generated });
    } catch (e) {
      if (isUniqueViolation(e)) return res.status(409).json({ error: "username already exists" });
      throw e;
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");

    // Evita que el admin se borre a sí mismo por accidente
    if (String(req.auth.sub) === id) return res.status(400).json({ error: "You cannot delete yourself" });

    const target = await getUserById(id);
    if (!target) return res.status(404).json({ error: "not found" });

    if (String(target.role) === "admin") {
      const admins = await countAdmins();
      if (admins <= 1) return res.status(400).json({ error: "You cannot delete the last admin" });
    }

    await deleteUser(id);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: "Not found" }));

const port = Number(process.env.PORT || 4000);

bootstrapAtLeastOneAdmin()
    .then(() => {
      app.listen(port, () => console.log(`Backend listening on :${port}`));
    })
    .catch((e) => {
      console.error("[bootstrap] failed:", e);
      process.exit(1);
    });
