import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import { config } from "./config";

export const db = new Database(config.dbPath);

// Enforce basic data integrity at the schema level: email must be present
// and unique (register/login previously relied on app-level checks alone).
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT,
    body TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const SALT_ROUNDS = 10;

// bcrypt is salted and slow-by-design, unlike the previous unsalted MD5
// (which is fast, has no salt, and is crackable via rainbow tables in
// seconds for anything password-list-shaped).
export function hashPassword(s: string): string {
  return bcrypt.hashSync(s, SALT_ROUNDS);
}

export function verifyPassword(s: string, hash: string): boolean {
  return bcrypt.compareSync(s, hash);
}

const count = db.prepare("SELECT COUNT(*) as c FROM users").get() as any;
if (count.c === 0) {
  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    "alice@example.com",
    hashPassword("password1")
  );
  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    "bob@example.com",
    hashPassword("password2")
  );
  db.prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)").run(
    1,
    "Alice note",
    "private thoughts"
  );
  db.prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)").run(
    2,
    "Bob note",
    "bob's secrets"
  );
}
