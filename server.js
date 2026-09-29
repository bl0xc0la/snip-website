const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://snip.env.pm";
const SESSION_SECRET = process.env.SESSION_SECRET || "replace-this-with-a-long-random-secret";

if (IS_PROD && SESSION_SECRET === "replace-this-with-a-long-random-secret") {
  console.warn("WARNING: set SESSION_SECRET in production.");
}

app.set("trust proxy", 1);

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOADS_DIR = path.join(ROOT, "uploads");
const PFP_DIR = path.join(UPLOADS_DIR, "pfp");
const BANNER_DIR = path.join(UPLOADS_DIR, "banner");
const VIDEO_DIR = path.join(UPLOADS_DIR, "video");
const GIF_DIR = path.join(UPLOADS_DIR, "gif");

for (const dir of [DATA_DIR, PFP_DIR, BANNER_DIR, VIDEO_DIR, GIF_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, "db.json");

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const empty = { users: [], videos: [], comments: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    db.users ||= [];
    db.videos ||= [];
    db.comments ||= [];
    return db;
  } catch {
    return { users: [], videos: [], comments: [] };
  }
}

let db = loadDb();

function saveDb() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    bio: user.bio || "",
    pfp: user.pfp || null,
    banner: user.banner || null,
    createdAt: user.createdAt
  };
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function parseHashtags(raw) {
  const source = Array.isArray(raw) ? raw.join(" ") : String(raw || "");
  const found = source.match(/#[a-z0-9_]+/gi) || [];
  const clean = found.map(x => x.slice(1).toLowerCase());
  return [...new Set(clean)].slice(0, 30);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(
    Buffer.from(actual, "hex"),
    Buffer.from(expectedHash, "hex")
  );
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}

function createSession(userId) {
  const expires = Date.now() + 1000 * 60 * 60 * 24 * 30;
  const body = `${userId}.${expires}`;
  return `${body}.${sign(body)}`;
}

function readSession(token) {
  try {
    const [userId, expires, signature] = String(token || "").split(".");
    const body = `${userId}.${expires}`;
    if (!userId || !expires || !signature || Number(expires) < Date.now()) return null;
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(sign(body)))) return null;
    return db.users.find(u => u.id === userId) || null;
  } catch {
    return null;
  }
}

function setSessionCookie(res, userId) {
  const token = createSession(userId);
  res.cookie("snip_session", token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
    maxAge: 1000 * 60 * 60 * 24 * 30,
    path: "/"
  });
}

function requireAuth(req, res, next) {
  const user = readSession(parseCookie(req, "snip_session"));
  if (!user) return res.status(401).json({ error: "log in first" });
  req.user = user;
  next();
}

function parseCookie(req, name) {
  const raw = req.headers.cookie || "";
  const match = raw.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

function fileUrl(type, filename) {
  return `/uploads/${type}/${filename}`;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === "video") return cb(null, VIDEO_DIR);
    if (file.fieldname === "pfp") return cb(null, PFP_DIR);
    if (file.fieldname === "banner") return cb(null, BANNER_DIR);
    if (file.fieldname === "gif") return cb(null, GIF_DIR);
    cb(new Error("unsupported upload field"));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 250 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const good =
      (file.fieldname === "video" && file.mimetype.startsWith("video/")) ||
      (file.fieldname === "pfp" && file.mimetype.startsWith("image/")) ||
      (file.fieldname === "banner" && file.mimetype.startsWith("image/")) ||
      (file.fieldname === "gif" && file.mimetype === "image/gif");
    cb(good ? null : new Error("invalid file type"), good);
  }
});

app.use("/uploads", express.static(UPLOADS_DIR, {
  maxAge: IS_PROD ? "7d" : 0
}));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "snip-api" });
});

app.post("/api/auth/register", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: "username must be 3-24 chars using letters, numbers or _" });
  }
  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: "password must be 8-200 chars" });
  }
  if (db.users.some(u => u.username === username)) {
    return res.status(409).json({ error: "username is already taken" });
  }

  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt,
    passwordHash: hash,
    bio: "",
    pfp: null,
    banner: null,
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  saveDb();
  setSessionCookie(res, user.id);
  res.status(201).json({ user: publicUser(user) });
});

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.username === username);

  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return res.status(401).json({ error: "invalid username or password" });
  }

  setSessionCookie(res, user.id);
  res.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("snip_session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const user = readSession(parseCookie(req, "snip_session"));
  if (!user) return res.status(401).json({ error: "not logged in" });
  res.json({ user: publicUser(user) });
});

app.post("/api/profile", requireAuth, upload.fields([
  { name: "pfp", maxCount: 1 },
  { name: "banner", maxCount: 1 }
]), (req, res) => {
  const bio = String(req.body.bio || "").slice(0, 180);
  req.user.bio = bio;

  const pfp = req.files?.pfp?.[0];
  const banner = req.files?.banner?.[0];

  if (pfp) req.user.pfp = fileUrl("pfp", pfp.filename);
  if (banner) req.user.banner = fileUrl("banner", banner.filename);

  saveDb();
  res.json({ user: publicUser(req.user) });
});

app.post("/api/videos", requireAuth, upload.single("video"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "video file is required" });

  const title = String(req.body.title || "").trim();
  if (!title) return res.status(400).json({ error: "video title is required" });
  if (title.length > 120) return res.status(400).json({ error: "video title is too long" });

  const hashtags = parseHashtags(req.body.hashtags);
  const video = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    title,
    hashtags,
    video: fileUrl("video", req.file.filename),
    createdAt: new Date().toISOString()
  };

  db.videos.unshift(video);
  saveDb();
  res.status(201).json({ video });
});

function formatVideo(video) {
  const user = db.users.find(u => u.id === video.userId);
  return {
    id: video.id,
    title: video.title,
    hashtags: video.hashtags,
    video: video.video,
    createdAt: video.createdAt,
    username: user?.username || "deleted",
    user: user ? publicUser(user) : { username: "deleted" }
  };
}

app.get("/api/videos", (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  let videos = db.videos;

  if (q) {
    const term = q.startsWith("#") ? q.slice(1) : q;
    videos = videos.filter(v =>
      v.title.toLowerCase().includes(term) ||
      v.hashtags.some(h => h.includes(term)) ||
      db.users.find(u => u.id === v.userId)?.username.includes(term)
    );
  }

  res.json({ videos: videos.slice(0, 100).map(formatVideo) });
});

app.get("/api/users/:username", (req, res) => {
  const username = normalizeUsername(req.params.username);
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: "user not found" });

  const videos = db.videos.filter(v => v.userId === user.id).slice(0, 100).map(formatVideo);
  res.json({ user: { ...publicUser(user), videos } });
});

app.get("/api/videos/:id/comments", (req, res) => {
  const video = db.videos.find(v => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: "video not found" });

  const comments = db.comments
    .filter(c => c.videoId === video.id)
    .sort((a,b) => new Date(a.createdAt) - new Date(b.createdAt))
    .slice(-200)
    .map(c => ({
      id: c.id,
      text: c.text,
      gif: c.gif,
      createdAt: c.createdAt,
      user: publicUser(db.users.find(u => u.id === c.userId))
    }));

  res.json({ comments });
});

app.post("/api/videos/:id/comments", requireAuth, upload.single("gif"), (req, res) => {
  const video = db.videos.find(v => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: "video not found" });

  const text = String(req.body.text || "").trim().slice(0, 500);
  const gif = req.file ? fileUrl("gif", req.file.filename) : null;

  if (!text && !gif) {
    return res.status(400).json({ error: "comment cannot be empty" });
  }

  const comment = {
    id: crypto.randomUUID(),
    videoId: video.id,
    userId: req.user.id,
    text,
    gif,
    createdAt: new Date().toISOString()
  };

  db.comments.push(comment);
  saveDb();
  res.status(201).json({ comment });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `upload error: ${err.message}` });
  }
  res.status(400).json({ error: err.message || "server error" });
});

app.listen(PORT, () => {
  console.log(`snip api listening on http://localhost:${PORT}`);
});
