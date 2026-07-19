import express from "express";
import cors from "cors";
import { authRouter } from "./auth";
import { usersRouter } from "./users";
import { notesRouter } from "./notes";
import { config } from "./config";

export const app = express();

app.use(express.json({ limit: "100kb" }));

// Auth here is a bearer token in the Authorization header, not a cookie,
// so there's no ambient-credential CSRF risk from a permissive origin the
// way there would be with cookie auth — `credentials: true` (which the
// previous version paired with `origin: "*"`, a combination browsers
// reject anyway) was unnecessary and misleading about the security model.
// CORS_ORIGIN can be set to a comma-separated allowlist for production.
app.use(
  cors({
    origin: config.corsOrigin === "*" ? "*" : config.corsOrigin.split(","),
  })
);

app.use("/auth", authRouter);
app.use("/users", usersRouter);
app.use("/notes", notesRouter);

app.use((err: any, req: any, res: any, next: any) => {
  // Log the full error server-side for debugging, but never hand a stack
  // trace (file paths, dependency versions, code structure) to the
  // client — that's a reconnaissance gift to an attacker. Only include
  // the message outside production, where it's a convenience, not a leak.
  console.error(err);
  res.status(500).json({
    error: config.nodeEnv === "production" ? "internal server error" : err.message,
  });
});

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`listening on ${config.port}`);
  });
}
