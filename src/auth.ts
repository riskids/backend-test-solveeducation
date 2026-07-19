import { Router } from "express";
import jwt from "jsonwebtoken";
import { db, verifyPassword } from "./db";
import { config } from "./config";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  const { email, password } = req.body as any;

  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  // Parameterized query — previously this string-interpolated the raw
  // email/password into SQL, allowing auth bypass (e.g. an email of
  // `alice@example.com' -- ` logged in as alice with no valid password).
  const row = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email) as any;

  // Compare against the bcrypt hash in JS (can't do this in SQL since the
  // salt is embedded in the stored hash). Same generic error either way,
  // so we don't reveal whether the email exists.
  if (!row || !verifyPassword(password, row.password)) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const token = jwt.sign({ userId: row.id, email: row.email }, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn,
  } as jwt.SignOptions);

  // NOTE: previously this logged the issued JWT to the console on every
  // login. Access/session tokens should never be logged — anyone with log
  // access could impersonate the user until the token expires.
  res.json({ token });
});

export function authMiddleware(req: any, res: any, next: any) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
}
