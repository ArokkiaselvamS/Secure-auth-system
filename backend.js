// ============================================================
// backend.js — Authentication System Server
// Dependencies: express, bcryptjs, jsonwebtoken, nodemailer
// Run: npm install express bcryptjs jsonwebtoken nodemailer
//      node backend.js
// ============================================================

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

// ── Configuration ────────────────────────────────────────────
const PORT = 3000;
const JWT_SECRET = "YOUR_SUPER_SECRET_JWT_KEY_CHANGE_THIS";   // ← change in production
const DB_PATH = path.join(__dirname, "database.json");
const RESET_TOKEN_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

// Gmail SMTP credentials — fill in your own
const GMAIL_USER = "aronarokyam12345@gmail.com";   // ← your Gmail address
const GMAIL_PASS = "puqf nlwc nrvc vykd";       // ← Gmail App Password (not your real password)
//   To create an App Password:
//   Google Account → Security → 2-Step Verification → App passwords

// ── Middleware ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS headers (allows frontend.html opened from file://)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// Serve frontend.html at root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend.html"));
});

// ── DB Helpers ───────────────────────────────────────────────
function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return { users: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), "utf8");
}

// ── JWT Auth Middleware ──────────────────────────────────────
function authenticateJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token." });
  }
}



// ── Nodemailer Transporter ───────────────────────────────────
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_PASS
  }
});

// ── Routes ───────────────────────────────────────────────────

// 1. POST /register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ error: "All fields are required." });

    if (password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters." });

    const db = readDB();
    const existing = db.users.find((u) => u.email === email.toLowerCase());
    if (existing)
      return res.status(409).json({ error: "Email is already registered." });

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = {
      id: crypto.randomUUID(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      resetToken: null,
      tokenExpiry: null,
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    writeDB(db);

    return res.status(201).json({ message: "Registration successful! You can now log in." });
  } catch (err) {
    console.error("[/register]", err);
    return res.status(500).json({ error: "Server error during registration." });
  }
});

// 2. POST /login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required." });

    const db = readDB();
    const user = db.users.find((u) => u.email === email.toLowerCase().trim());

    if (!user)
      return res.status(401).json({ error: "Invalid email or password." });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch)
      return res.status(401).json({ error: "Invalid email or password." });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({
      message: "Login successful.",
      token,
      user: { name: user.name, email: user.email }
    });
  } catch (err) {
    console.error("[/login]", err);
    return res.status(500).json({ error: "Server error during login." });
  }
});

// 3. POST /forgot-password
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ error: "Email is required." });

    const db = readDB();
    const userIdx = db.users.findIndex(
      (u) => u.email === email.toLowerCase().trim()
    );

    // Security: always return success so we don't reveal if email exists
    if (userIdx === -1) {
      return res.json({
        message: "If that email is registered, a 6-digit OTP code has been sent."
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const tokenExpiry = Date.now() + RESET_TOKEN_EXPIRY_MS;

    db.users[userIdx].resetOtp = otp;
    db.users[userIdx].otpExpiry = tokenExpiry;
    db.users[userIdx].resetToken = null;
    db.users[userIdx].tokenExpiry = null;
    writeDB(db);

    await transporter.sendMail({
      from: `"Auth System" <${GMAIL_USER}>`,
      to: db.users[userIdx].email,
      subject: "Password Reset OTP",
      text: `Your 6-digit OTP to reset your password is: ${otp}\n\nThis OTP is valid for 15 minutes.\n\nIf you did not request this, ignore this email.`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #e5e7eb;border-radius:12px;background:#0a0a0f;color:#e2e0ff;">
          <h2 style="color:#7c6af7;margin-bottom:8px;font-size:24px;text-align:center;">Password Reset OTP</h2>
          <p style="color:#6b6a8a;text-align:center;font-size:14px;">Here is your one-time verification code to reset your password. This code expires in <strong>15 minutes</strong>.</p>
          <div style="text-align:center;margin:32px 0;">
            <span style="display:inline-block;padding:16px 32px;background:rgba(124,106,247,0.1);border:1px dashed #7c6af7;color:#3ecfcf;font-size:32px;font-weight:bold;letter-spacing:6px;border-radius:8px;font-family:monospace;">
              ${otp}
            </span>
          </div>
          <p style="color:#6b6a8a;font-size:12px;text-align:center;margin-top:32px;">If you didn't request a password reset, you can safely ignore this email.</p>
        </div>`
    });

    console.log(`[/forgot-password] OTP ${otp} generated and sent to ${db.users[userIdx].email}`);
    return res.json({ message: "If that email is registered, a 6-digit OTP code has been sent." });
  } catch (err) {
    console.error("[/forgot-password]", err);
    return res.status(500).json({ error: "Failed to send reset email. Check SMTP config." });
  }
});

// 5. POST /reset-password — process the actual password reset using OTP
app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password) {
      return res.status(400).json({ error: "Email, OTP, and new password are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    const db = readDB();
    const userIdx = db.users.findIndex(
      (u) => u.email === email.toLowerCase().trim()
    );

    if (userIdx === -1) {
      return res.status(400).json({ error: "Invalid email or OTP." });
    }

    const user = db.users[userIdx];
    if (!user.resetOtp || user.otpExpiry < Date.now() || user.resetOtp !== otp.trim()) {
      return res.status(400).json({ error: "Invalid or expired OTP." });
    }

    db.users[userIdx].password = await bcrypt.hash(password, 12);
    db.users[userIdx].resetOtp = null;
    db.users[userIdx].otpExpiry = null;
    db.users[userIdx].resetToken = null;
    db.users[userIdx].tokenExpiry = null;
    writeDB(db);

    return res.json({ message: "Password has been reset successfully! You can now log in." });
  } catch (err) {
    console.error("[/reset-password POST]", err);
    return res.status(500).json({ error: "Server error during password reset." });
  }
});

// 6. GET /dashboard — Protected route
app.get("/dashboard", authenticateJWT, (req, res) => {
  const db = readDB();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found." });

  return res.json({
    message: `Welcome to your dashboard, ${user.name}!`,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt
    },
    serverTime: new Date().toISOString()
  });
});

// ── Start Server ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log("╔════════════════════════════════════════╗");
  console.log(`║  Auth Server running at :${PORT}          ║`);
  console.log("╠════════════════════════════════════════╣");
  console.log("║  Open: http://localhost:3000           ║");
  console.log("╚════════════════════════════════════════╝");
});
