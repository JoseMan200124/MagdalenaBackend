require("dotenv").config();

const express = require("express");
const cors = require("cors");

const { readUsers, writeUsers, findByUsername, makeUser, sanitizeUser } = require("./lib/usersStore");
const { signToken, requireAuth, requireAdmin, getSingleAdminUsername } = require("./lib/auth");
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

// Bootstrap: crea/asegura UN (1) admin fijo para este PoC.
async function bootstrapSingleAdmin() {
  const users = await readUsers();

  const adminUsername = getSingleAdminUsername();
  const adminPass = String(process.env.SINGLE_ADMIN_PASSWORD || process.env.DEFAULT_ADMIN_PASS || "12345").trim();

  // Normaliza roles: solo el admin fijo puede ser admin, el resto siempre viewer.
  let changed = false;
  const lower = (s) => String(s || "").trim().toLowerCase();

  let idx = users.findIndex((u) => lower(u.username) === adminUsername);
  if (idx < 0) {
    users.push(makeUser({ username: adminUsername, password: adminPass, role: "admin" }));
    changed = true;
    console.log(`[bootstrap] Created fixed admin user: ${adminUsername}`);
  } else {
    if (users[idx].role !== "admin") {
      users[idx].role = "admin";
      changed = true;
    }
    if (!users[idx].password) {
      users[idx].password = adminPass;
      changed = true;
    }
    users[idx].updatedAt = new Date().toISOString();
  }

  for (const u of users) {
    if (lower(u.username) !== adminUsername && u.role !== "viewer") {
      u.role = "viewer";
      u.updatedAt = new Date().toISOString();
      changed = true;
    }
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

    // En este PoC, solo el admin fijo puede tener rol admin.
    const adminUsername = getSingleAdminUsername();
    const lower = (s) => String(s || "").trim().toLowerCase();
    const effectiveUser = {
      ...user,
      role: lower(user.username) === adminUsername ? "admin" : "viewer",
    };

    const token = signToken(effectiveUser);
    return res.json({ token, user: sanitizeUser(effectiveUser) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  // Lo mínimo: devolver el payload del token
  return res.json({ user: { id: req.auth.sub, username: req.auth.username, role: req.auth.role } });
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
    const { username, password, generatePassword } = req.body || {};
    const u = String(username || "").trim();
    if (!u) return res.status(400).json({ error: "username required" });

    const users = await readUsers();
    if (findByUsername(users, u)) return res.status(409).json({ error: "username already exists" });

    // No permitimos crear otro admin ni reasignar el usuario admin fijo.
    const adminUsername = getSingleAdminUsername();
    if (String(u).trim().toLowerCase() === adminUsername) {
      return res.status(409).json({ error: "reserved admin username" });
    }

    let pass = String(password || "");
    if (!pass || generatePassword) pass = randomPassword(12);

    const newUser = makeUser({ username: u, password: pass, role: "viewer" });
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
    const { username, password, generatePassword } = req.body || {};
    const users = await readUsers();
    const idx = users.findIndex((u) => u.id === id);
    if (idx < 0) return res.status(404).json({ error: "not found" });

    const adminUsername = getSingleAdminUsername();
    const lower = (s) => String(s || "").trim().toLowerCase();
    const isFixedAdminRow = lower(users[idx].username) === adminUsername;

    // Si cambia username, validar unique + proteger username del admin fijo
    if (username != null) {
      const u = String(username).trim();
      if (!u) return res.status(400).json({ error: "username cannot be empty" });
      const exists = users.find((x) => x.id !== id && String(x.username).toLowerCase() === u.toLowerCase());
      if (exists) return res.status(409).json({ error: "username already exists" });

      // No permitir que otro usuario tome el username del admin.
      if (lower(u) === adminUsername && !isFixedAdminRow) {
        return res.status(409).json({ error: "reserved admin username" });
      }

      // No permitir renombrar el admin fijo (evita perder el único admin).
      if (isFixedAdminRow && lower(u) !== adminUsername) {
        return res.status(400).json({ error: "fixed admin username cannot be changed" });
      }
      users[idx].username = u;
    }

    // Solo un admin: siempre forzamos viewer para cualquier usuario que no sea el admin fijo.
    users[idx].role = isFixedAdminRow ? "admin" : "viewer";

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

    const adminUsername = getSingleAdminUsername();
    const lower = (s) => String(s || "").trim().toLowerCase();
    const target = users.find((u) => u.id === id);
    if (target && lower(target.username) === adminUsername) {
      return res.status(400).json({ error: "You cannot delete the fixed admin" });
    }

    // Evita que el admin se borre a sí mismo por accidente
    if (req.auth.sub === id) return res.status(400).json({ error: "You cannot delete yourself" });

    const next = users.filter((u) => u.id !== id);
    if (next.length === users.length) return res.status(404).json({ error: "not found" });

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

bootstrapSingleAdmin()
  .then(() => {
    app.listen(port, () => console.log(`Backend listening on :${port}`));
  })
  .catch((e) => {
    console.error("[bootstrap] failed:", e);
    process.exit(1);
  });
