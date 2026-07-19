import { Router } from "express";
import { db, hashPassword } from "./db";

export const usersRouter = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

usersRouter.post("/register", (req, res) => {
  const { email, password } = req.body as any;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "email and password are required" });
  }

  const normalizedEmail = email.trim().toLowerCase();

  if (!EMAIL_RE.test(normalizedEmail)) {
    return res.status(400).json({ error: "invalid email" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  // Parameterized query — previously this string-interpolated the raw
  // email into SQL (the same class of bug as the login endpoint).
  const existing = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(normalizedEmail);
  if (existing) {
    return res.status(409).json({ error: "email taken" });
  }

  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    normalizedEmail,
    hashPassword(password)
  );
  res.json({ ok: true });
});
