const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function newId() {
  return typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString("hex");
}

const DATA_DIR = process.env.DATA_DIR
    ? String(process.env.DATA_DIR).trim()
    : path.join(process.cwd(), "data");

const USERS_FILE = path.join(DATA_DIR, "users.txt");
const USERS_BAK_FILE = path.join(DATA_DIR, "users.txt.bak");

let writeChain = Promise.resolve();

async function ensureStore() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });

  try {
    await fs.promises.access(USERS_FILE, fs.constants.F_OK);
  } catch {
    await fs.promises.writeFile(USERS_FILE, JSON.stringify([], null, 2), "utf-8");
  }
}

async function readJsonFile(filePath) {
  try {
    const raw = await fs.promises.readFile(filePath, "utf-8");
    if (!raw.trim()) return null;
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function readUsers() {
  await ensureStore();

  const primary = await readJsonFile(USERS_FILE);
  if (primary) return primary;

  const backup = await readJsonFile(USERS_BAK_FILE);
  if (backup) return backup;

  return [];
}

async function atomicWrite(filePath, backupPath, payload) {
  const tmpPath = path.join(
      DATA_DIR,
      `.users.${process.pid}.${Date.now()}.tmp`
  );

  await fs.promises.writeFile(tmpPath, payload, "utf-8");

  try {
    await fs.promises.copyFile(filePath, backupPath);
  } catch {
  }

  await fs.promises.rename(tmpPath, filePath);
}

async function writeUsers(users) {
  await ensureStore();
  const payload = JSON.stringify(users, null, 2);
  writeChain = writeChain.then(
      () => atomicWrite(USERS_FILE, USERS_BAK_FILE, payload),
      () => atomicWrite(USERS_FILE, USERS_BAK_FILE, payload)
  );

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
