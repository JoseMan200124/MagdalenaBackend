const crypto = require("crypto");
const { Pool } = require("pg");

function newId() {
  return typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString("hex");
}

function getDatabaseUrl() {
  const url = String(process.env.DATABASE_URL || "").trim();
  if (!url) throw new Error("DATABASE_URL is required");
  return url;
}

function shouldUseSSL(url) {
  // Local dev normalmente no usa SSL
  if (/localhost|127\.0\.0\.1/i.test(url)) return false;
  // Render/hosted suele requerir SSL; evitamos errores tipo “SSL/TLS required”
  if (String(process.env.PGSSLMODE || "").toLowerCase() === "disable") return false;
  return { rejectUnauthorized: false };
}

const DATABASE_URL = getDatabaseUrl();

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: shouldUseSSL(DATABASE_URL),
});

let schemaReady = false;
let schemaPromise = null;

async function ensureStore() {
  if (schemaReady) return;
  if (!schemaPromise) {
    schemaPromise = (async () => {
      // Tabla base
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL,
          password TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'viewer',
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      // Unique case-insensitive (evita duplicados por mayúsculas/minúsculas)
      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq
        ON users (lower(username));
      `);

      // Índice por rol (para contar admins rápido)
      await pool.query(`
        CREATE INDEX IF NOT EXISTS users_role_idx
        ON users (role);
      `);

      schemaReady = true;
    })();
  }
  return schemaPromise;
}

function mapUserRow(r) {
  return {
    id: String(r.id),
    username: String(r.username),
    password: String(r.password),
    role: String(r.role),
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
    updatedAt: r.updated_at instanceof Date ? r.updated_at.toISOString() : String(r.updated_at),
  };
}

function sanitizeUser(user) {
  const { password, ...rest } = user;
  return rest;
}

async function listUsers() {
  await ensureStore();
  const { rows } = await pool.query(
      `SELECT id, username, password, role, created_at, updated_at
     FROM users
     ORDER BY created_at ASC`
  );
  return rows.map(mapUserRow);
}

async function getUserById(id) {
  await ensureStore();
  const { rows } = await pool.query(
      `SELECT id, username, password, role, created_at, updated_at
     FROM users
     WHERE id = $1
     LIMIT 1`,
      [String(id)]
  );
  return rows[0] ? mapUserRow(rows[0]) : null;
}

async function findByUsername(username) {
  await ensureStore();
  const u = String(username || "").trim().toLowerCase();
  const { rows } = await pool.query(
      `SELECT id, username, password, role, created_at, updated_at
     FROM users
     WHERE lower(username) = $1
     LIMIT 1`,
      [u]
  );
  return rows[0] ? mapUserRow(rows[0]) : null;
}

async function countAdmins() {
  await ensureStore();
  const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS n
     FROM users
     WHERE role = 'admin'`
  );
  return rows[0]?.n ?? 0;
}

async function createUser({ username, password, role }) {
  await ensureStore();
  const id = newId();
  const u = String(username || "").trim();
  const p = String(password || "");
  const r = role === "admin" ? "admin" : "viewer";

  const { rows } = await pool.query(
      `INSERT INTO users (id, username, password, role)
     VALUES ($1, $2, $3, $4)
     RETURNING id, username, password, role, created_at, updated_at`,
      [id, u, p, r]
  );

  return mapUserRow(rows[0]);
}

async function updateUser(id, patch) {
  await ensureStore();

  const sets = [];
  const vals = [];
  let i = 1;

  if (patch.username != null) {
    sets.push(`username = $${i++}`);
    vals.push(String(patch.username).trim());
  }
  if (patch.password != null) {
    sets.push(`password = $${i++}`);
    vals.push(String(patch.password));
  }
  if (patch.role != null) {
    sets.push(`role = $${i++}`);
    vals.push(patch.role === "admin" ? "admin" : "viewer");
  }

  // Siempre actualizamos updated_at
  sets.push(`updated_at = now()`);

  vals.push(String(id));
  const whereIdx = i;

  const sql = `
    UPDATE users
    SET ${sets.join(", ")}
    WHERE id = $${whereIdx}
    RETURNING id, username, password, role, created_at, updated_at
  `;

  const { rows } = await pool.query(sql, vals);
  return rows[0] ? mapUserRow(rows[0]) : null;
}

async function deleteUser(id) {
  await ensureStore();
  const { rowCount } = await pool.query(`DELETE FROM users WHERE id = $1`, [String(id)]);
  return rowCount > 0;
}

function isUniqueViolation(e) {
  return String(e?.code || "") === "23505";
}

module.exports = {
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
};
