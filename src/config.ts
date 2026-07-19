const nodeEnv = process.env.NODE_ENV || "development";

if (!process.env.JWT_SECRET && nodeEnv === "production") {
  // Fail fast rather than silently signing tokens with a public,
  // guessable default secret in production.
  throw new Error("JWT_SECRET must be set in production");
}

if (!process.env.JWT_SECRET) {
  console.warn(
    "[config] JWT_SECRET not set — using an insecure default for local development only."
  );
}

export const config = {
  nodeEnv,
  jwtSecret: process.env.JWT_SECRET || "supersecret",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1h",
  dbPath: process.env.DB_PATH || "notes.db",
  port: Number(process.env.PORT) || 3000,
  corsOrigin: process.env.CORS_ORIGIN || "*",
};
