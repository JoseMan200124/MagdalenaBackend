require("dotenv").config();

const express = require("express");
const cors = require("cors");

const { readUsers, writeUsers, findByUsername, makeUser, sanitizeUser } = require("./lib/usersStore");
const { signToken, requireAuth, requireAdmin } = require("./lib/auth");
const { randomPassword } = require("./lib/utils");

const app = express();
app.use(express.json({ limit: "1mb" }));

// CORS: si FRONTEND_ORIGIN está definido, restringimos; si no, permitimos cualquiera (demo).
const frontendOrigin = (process.env.FRONTEND_ORIGIN || "").trim();
app.use(
    cors({
      origin: frontendOrigin ? [frontendOrigin] : true,
      credentials: true,
    })
);

// Healthcheck
app.get("/health", (req, res) => res.json({ ok: true }));

function normRole(role) {
  const r = String(role || "").trim().toLowerCase();
  return r === "admin" ? "admin" : "viewer";
}

function countAdmins(users) {
  return users.filter((u) => String(u.role) === "admin").length;
}

// ✅ Bootstrap: asegura que exista al menos 1 admin inicial (pero NO fuerza a los demás a viewer)
async function bootstrapAtLeastOneAdmin() {
  const users = await readUsers();

  const adminUser = String(
      process.env.DEFAULT_ADMIN_USER || process.env.SINGLE_ADMIN_USERNAME || "admin@magdalena.com"
  ).trim();

  const adminPass = String(
      process.env.DEFAULT_ADMIN_PASS || process.env.SINGLE_ADMIN_PASSWORD || "12345"
  ).trim();

  const lower = (s) => String(s || "").trim().toLowerCase();

  let changed = false;
  let admin = users.find((u) => lower(u.username) === lower(adminUser));

  if (!admin) {
    users.push(makeUser({ username: adminUser, password: adminPass, role: "admin" }));
    changed = true;
    console.log(`[bootstrap] Created admin user: ${adminUser}`);
  } else {
    if (admin.role !== "admin") {
      admin.role = "admin";
      changed = true;
    }
    if (!admin.password) {
      admin.password = adminPass;
      changed = true;
    }
    admin.updatedAt = new Date().toISOString();
  }

  if (changed) await writeUsers(users);
}

// -------- AUTH --------

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    const users = await readUsers();
    const user = findByUsername(users, username);
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

// ✅ /me debe venir del STORE para reflejar permisos reales
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const users = await readUsers();
    const u = users.find((x) => String(x.id) === String(req.auth.sub));
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
    const users = await readUsers();
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

    const users = await readUsers();
    if (findByUsername(users, u)) return res.status(409).json({ error: "username already exists" });

    let pass = String(password || "");
    if (!pass || generatePassword) pass = randomPassword(12);

    const newUser = makeUser({ username: u, password: pass, role: normRole(role) });
    users.push(newUser);
    await writeUsers(users);

    // Devolvemos la contraseña solo al crear (si la generamos) para mostrarla una vez.
    return res.status(201).json({
      user: sanitizeUser(newUser),
      generatedPassword: (!password || generatePassword) ? pass : null,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { username, password, generatePassword, role } = req.body || {};

    const users = await readUsers();
    const idx = users.findIndex((u) => String(u.id) === id);
    if (idx < 0) return res.status(404).json({ error: "not found" });

    // Si cambia username, validar unique
    if (username != null) {
      const nu = String(username).trim();
      if (!nu) return res.status(400).json({ error: "username cannot be empty" });

      const exists = users.find(
          (x) => String(x.id) !== id && String(x.username).toLowerCase() === nu.toLowerCase()
      );
      if (exists) return res.status(409).json({ error: "username already exists" });

      users[idx].username = nu;
    }

    // role: proteger último admin
    if (role != null) {
      const nextRole = normRole(role);
      const wasAdmin = String(users[idx].role) === "admin";
      const admins = countAdmins(users);

      if (wasAdmin && nextRole !== "admin" && admins <= 1) {
        return res.status(400).json({ error: "You cannot remove the last admin" });
      }
      users[idx].role = nextRole;
    }

    let generated = null;
    if (generatePassword) {
      generated = randomPassword(12);
      users[idx].password = generated;
    } else if (password != null) {
      users[idx].password = String(password);
    }

    users[idx].updatedAt = new Date().toISOString();
    await writeUsers(users);

    return res.json({ user: sanitizeUser(users[idx]), generatedPassword: generated });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const users = await readUsers();

    // Evita que el admin se borre a sí mismo por accidente
    if (String(req.auth.sub) === id) return res.status(400).json({ error: "You cannot delete yourself" });

    const target = users.find((u) => String(u.id) === id);
    if (!target) return res.status(404).json({ error: "not found" });

    const admins = countAdmins(users);
    if (String(target.role) === "admin" && admins <= 1) {
      return res.status(400).json({ error: "You cannot delete the last admin" });
    }

    const next = users.filter((u) => String(u.id) !== id);
    await writeUsers(next);

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
