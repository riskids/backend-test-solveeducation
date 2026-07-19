import { Router } from "express";
import { db } from "./db";
import { authMiddleware } from "./auth";

export const notesRouter = Router();

// Notes are private to the user who created them (per the seed data —
// "private thoughts" / "bob's secrets" — this is clearly the intent, even
// though the original code let any authenticated user read everyone's
// notes). If notes are ever meant to be shared/collaborative, this will
// need a real ownership/sharing model instead of "owner-only".

notesRouter.get("/", authMiddleware, (req: any, res) => {
  const notes = db
    .prepare("SELECT * FROM notes WHERE user_id = ?")
    .all(req.user.userId) as any[];

  // All rows belong to the caller, so there's no need for a per-row
  // lookup (the previous version ran one extra query per note just to
  // find its author — a classic N+1, and also the source of the
  // string-interpolated SQL injection below).
  const result = notes.map((n) => ({ ...n, author: req.user.email }));

  res.json(result);
});

notesRouter.get("/:id", authMiddleware, (req: any, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: "invalid note id" });
  }

  const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(id) as any;

  // Return 404 (not 403) for notes that exist but belong to someone else,
  // so a caller can't distinguish "not yours" from "doesn't exist" and
  // enumerate valid note IDs.
  if (!note || note.user_id !== req.user.userId) {
    return res.status(404).json({ error: "not found" });
  }

  res.json(note);
});

notesRouter.post("/", authMiddleware, (req: any, res) => {
  const { title, body } = req.body as any;

  if (typeof title !== "string" || !title.trim()) {
    return res.status(400).json({ error: "title is required" });
  }
  if (typeof body !== "string") {
    return res.status(400).json({ error: "body is required" });
  }

  const info = db
    .prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)")
    .run(req.user.userId, title, body);
  res.json({ id: info.lastInsertRowid });
});
