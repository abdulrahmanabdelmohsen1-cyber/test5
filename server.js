require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "symbolspeak.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO app_settings(key,value) VALUES
  ('workspaceLabel','SymbolSpeak Workspace'),
  ('defaultVisibility','all');
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  source_key TEXT NOT NULL UNIQUE,
  meaning TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'all' CHECK(visibility IN ('all','private')),
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const adminName = process.env.ADMIN_USERNAME || "admin";
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 12) {
  console.error("Set ADMIN_PASSWORD to a strong password of at least 12 characters in .env before starting.");
  process.exit(1);
}
const configuredAccount = db.prepare("SELECT id, role FROM users WHERE username=? COLLATE NOCASE").get(adminName);
if (!configuredAccount) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')").run(adminName, hash);
  console.log(`Created initial admin account "${adminName}". Change its password after first login if needed.`);
} else if (configuredAccount.role !== "admin") {
  // The explicitly configured bootstrap account must actually have administrator permissions.
  // Reset its password to ADMIN_PASSWORD so the configured credentials are predictable.
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("UPDATE users SET password_hash=?, role='admin' WHERE id=?").run(hash, configuredAccount.id);
  console.log(`Promoted configured account "${adminName}" to administrator using ADMIN_PASSWORD.`);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  name: "symbolspeak.sid",
  secret: process.env.SESSION_SECRET || "",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET to a random secret of at least 32 characters in .env before starting.");
  process.exit(1);
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many login attempts. Try again in 15 minutes." } });
const norm = s => String(s || "").trim().replace(/\s+/g, " ").toLocaleLowerCase();
const clean = s => typeof s === "string" ? s.trim() : "";
const publicUser = u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.created_at });
function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in." });
  const user = db.prepare("SELECT id, username, role, created_at FROM users WHERE id=?").get(req.session.user.id);
  if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: "Session expired. Please sign in again." }); }
  req.user = user; next();
}
function admin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Administrator permission required." });
  next();
}
function visibleEntries(user) {
  return db.prepare(`
    SELECT e.id,e.source,e.meaning,e.category,e.visibility,e.created_at AS createdAt,
           e.updated_at AS updatedAt,u.username AS createdBy
    FROM entries e JOIN users u ON u.id=e.created_by
    WHERE e.visibility='all' OR e.created_by=? OR ?='admin'
    ORDER BY e.created_at DESC
  `).all(user.id, user.role);
}
app.get("/api/health", (req,res) => res.json({ ok:true }));
app.post("/api/login", loginLimiter, (req,res) => {
  const username = clean(req.body.username), password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Incorrect username or password." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.user = { id: user.id };
    res.json({ user: publicUser(user) });
  });
});
app.post("/api/logout", (req,res) => req.session.destroy(err => {
  res.clearCookie("symbolspeak.sid");
  if (err) return res.status(500).json({ error:"Could not sign out." });
  res.json({ ok:true });
}));
app.get("/api/me", auth, (req,res) => res.json({ user: publicUser(req.user) }));
app.get("/api/entries", auth, (req,res) => res.json({ entries: visibleEntries(req.user) }));
app.post("/api/entries", auth, (req,res) => {
  const source=clean(req.body.source), meaning=clean(req.body.meaning), category=clean(req.body.category).slice(0,80);
  const savedVisibility = db.prepare("SELECT value FROM app_settings WHERE key='defaultVisibility'").get()?.value || "all";
  const visibility = req.body.visibility === "private" ? "private" : (req.body.visibility === "all" ? "all" : savedVisibility);
  if (!source || !meaning) return res.status(400).json({error:"Source phrase and meaning are required."});
  if (source.length>500 || meaning.length>2000) return res.status(400).json({error:"Phrase limit is 500 characters and meaning limit is 2,000 characters."});
  const source_key=norm(source);
  const duplicate=db.prepare("SELECT id,created_by FROM entries WHERE source_key=?").get(source_key);
  if (duplicate) return res.status(409).json({error:"That phrase already exists. Edit the existing entry if you have permission."});
  const result=db.prepare("INSERT INTO entries(source,source_key,meaning,category,visibility,created_by) VALUES(?,?,?,?,?,?)").run(source,source_key,meaning,category,visibility,req.user.id);
  res.status(201).json({entry:db.prepare("SELECT e.id,e.source,e.meaning,e.category,e.visibility,e.created_at AS createdAt,u.username AS createdBy FROM entries e JOIN users u ON u.id=e.created_by WHERE e.id=?").get(result.lastInsertRowid)});
});
app.put("/api/entries/:id", auth, (req,res) => {
  const id=Number(req.params.id), e=db.prepare("SELECT * FROM entries WHERE id=?").get(id);
  if (!e) return res.status(404).json({error:"Entry not found."});
  if (req.user.role!=="admin" && e.created_by!==req.user.id) return res.status(403).json({error:"You can only edit meanings you created."});
  const source=clean(req.body.source), meaning=clean(req.body.meaning), category=clean(req.body.category).slice(0,80), visibility=req.body.visibility==="private"?"private":"all";
  if (!source || !meaning) return res.status(400).json({error:"Source phrase and meaning are required."});
  if (source.length>500 || meaning.length>2000) return res.status(400).json({error:"Phrase limit is 500 characters and meaning limit is 2,000 characters."});
  const key=norm(source), duplicate=db.prepare("SELECT id FROM entries WHERE source_key=? AND id<>?").get(key,id);
  if (duplicate) return res.status(409).json({error:"Another entry already uses that phrase."});
  db.prepare("UPDATE entries SET source=?,source_key=?,meaning=?,category=?,visibility=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(source,key,meaning,category,visibility,id);
  res.json({ok:true});
});
app.delete("/api/entries/:id", auth, (req,res) => {
  const e=db.prepare("SELECT * FROM entries WHERE id=?").get(Number(req.params.id));
  if (!e) return res.status(404).json({error:"Entry not found."});
  if (req.user.role!=="admin" && e.created_by!==req.user.id) return res.status(403).json({error:"You can only delete meanings you created."});
  db.prepare("DELETE FROM entries WHERE id=?").run(e.id); res.json({ok:true});
});
app.post("/api/password", auth, (req,res) => {
  const oldPassword=String(req.body.currentPassword||""), next=String(req.body.newPassword||"");
  const row=db.prepare("SELECT password_hash FROM users WHERE id=?").get(req.user.id);
  if (!bcrypt.compareSync(oldPassword,row.password_hash)) return res.status(400).json({error:"Current password is incorrect."});
  if (next.length<12) return res.status(400).json({error:"New password must be at least 12 characters."});
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(next,12),req.user.id);
  res.json({ok:true});
});
app.get("/api/admin-settings", auth, admin, (req,res) => {
  const rows = db.prepare("SELECT key,value FROM app_settings").all();
  const settings = Object.fromEntries(rows.map(row => [row.key, row.value]));
  res.json({ settings: { workspaceLabel: settings.workspaceLabel || "SymbolSpeak Workspace", defaultVisibility: settings.defaultVisibility === "private" ? "private" : "all" } });
});
app.put("/api/admin-settings", auth, admin, (req,res) => {
  const workspaceLabel = clean(req.body.workspaceLabel).slice(0,60) || "SymbolSpeak Workspace";
  const defaultVisibility = req.body.defaultVisibility === "private" ? "private" : "all";
  const save = db.transaction(() => {
    db.prepare("INSERT INTO app_settings(key,value) VALUES('workspaceLabel',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(workspaceLabel);
    db.prepare("INSERT INTO app_settings(key,value) VALUES('defaultVisibility',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(defaultVisibility);
  });
  save();
  res.json({ ok: true, settings: { workspaceLabel, defaultVisibility } });
});
app.get("/api/users", auth, admin, (req,res) => {
  const users=db.prepare("SELECT id,username,role,created_at AS createdAt FROM users ORDER BY created_at").all();
  res.json({users});
});
app.post("/api/users", auth, admin, (req,res) => {
  const username=clean(req.body.username), password=String(req.body.password||""), role=req.body.role==="admin"?"admin":"user";
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({error:"Username must be 3–32 characters and use letters, numbers, dot, underscore, or hyphen."});
  if (password.length<12) return res.status(400).json({error:"Set a temporary password of at least 12 characters."});
  try {
    const result=db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,bcrypt.hashSync(password,12),role);
    res.status(201).json({user:{id:result.lastInsertRowid,username,role}});
  } catch { res.status(409).json({error:"That username already exists."}); }
});
app.delete("/api/users/:id", auth, admin, (req,res) => {
  const id=Number(req.params.id);
  if (id===req.user.id) return res.status(400).json({error:"You cannot remove your own signed-in account."});
  const target=db.prepare("SELECT id,username,role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({error:"Account not found."});
  if (target.username===adminName) return res.status(400).json({error:"The bootstrap administrator cannot be removed here."});
  db.prepare("DELETE FROM entries WHERE created_by=?").run(id);
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  res.json({ok:true});
});
app.use(express.static(path.join(__dirname,"public")));
app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:"Unexpected server error."}); });
app.listen(PORT, () => console.log(`SymbolSpeak listening on port ${PORT}`));
