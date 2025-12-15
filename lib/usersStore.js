const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function newId() {
  // Node 14.17+ soporta randomUUID(); fallback por si acaso.
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");
}

// Por defecto usa backend/data (en Render puede no ser persistente si no montas disco).
const DATA_DIR = process.env.DATA_DIR
  ? process.env.DATA_DIR
  : path.join(process.cwd(), "data");

const USERS_FILE = path.join(DATA_DIR, "users.txt");

// Mutex simple para evitar escrituras concurrentes.
let writeChain = Promise.resolve();

async function ensureStore() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.promises.access(USERS_FILE, fs.constants.F_OK);
  } catch {
    await fs.promises.writeFile(USERS_FILE, JSON.stringify([], null, 2), "utf-8");
  }
}

async function readUsers() {
  await ensureStore();
  const raw = await fs.promises.readFile(USERS_FILE, "utf-8");
  if (!raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch (e) {
    // Si el archivo se corrompe, evitamos tumbar el server; lo tratamos como vacío.
    return [];
  }
}

async function writeUsers(users) {
  await ensureStore();
  const payload = JSON.stringify(users, null, 2);
  // Encadenamos para que no se pisen escrituras.
  writeChain = writeChain.then(() => fs.promises.writeFile(USERS_FILE, payload, "utf-8"));
  return writeChain;
}

function sanitizeUser(user) {
  const { password, ...rest } = user;
  return rest;
}

function findByUsername(users, username) {
  const u = String(username || "").trim().toLowerCase();
  return users.find((x) => String(x.username).toLowerCase() === u);
}

function makeUser({ username, password, role }) {
  return {
    id: newId(),
    username: String(username || "").trim(),
    password: String(password || ""),
    role: role === "admin" ? "admin" : "viewer",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

module.exports = {
  DATA_DIR,
  USERS_FILE,
  ensureStore,
  readUsers,
  writeUsers,
  sanitizeUser,
  findByUsername,
  makeUser,
};
