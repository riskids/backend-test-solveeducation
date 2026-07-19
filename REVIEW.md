# Review: Notes API
---

## Blocker
### 1. SQL injection on almost every query
`auth.ts` (login), `users.ts` (register), `notes.ts` (list/get) all build queries with string interpolation instead of parameters:

```ts
db.prepare(`SELECT * FROM users WHERE email = '${email}' AND password = '...'`)
db.prepare(`SELECT * FROM notes WHERE id = ${req.params.id}`)
```

Proof:

Login bypass, no real password needed:
```
POST /auth/login  {"email": "alice@example.com' -- ", "password": "anything"}
→ 200, valid token for alice
```

Dump every user's email + password hash through a GET request, as a regular logged-in user (bob):
```
GET /notes/0%20UNION%20SELECT%20id,1,email,password%20FROM%20users--
→ 200 {"title":"alice@example.com","body":"<md5 hash>"}
```
That second one's the one that matters, a normal user account can pull the entire users table through a notes-reading endpoint.

**Fix:** every query now uses `?` placeholders with bound parameters. No reason to ever interpolate with `better-sqlite3`.

### 2. IDOR — any user can read anyone's notes
`GET /notes` returns every note in the DB to any logged-in user. `GET /notes/:id` never checks ownership. Seed data is literally called "private thoughts" / "bob's secrets" — clearly not intentional.

```
# logged in as bob
GET /notes/1  (alice's note)  → 200, full contents
```

**Fix:**
- `GET /notes` now filters `WHERE user_id = ?`.
- `GET /notes/:id` checks ownership, returns `404` (not `403`) if it's someone else's — so note IDs can't be enumerated.
- Assumption: notes are private per-user, since that's what the seed data implies. If the actual intent is shared notes, that's a product decision, not something to quietly assume away in a code review.

### 3. Passwords hashed with unsalted MD5
```ts
crypto.createHash("md5").update(s).digest("hex");
```
Fast, unsalted, crackable via rainbow tables.

**Fix:** replaced with bcrypt (cost 10). Kept the `hashPassword` signature the same, added `verifyPassword` since comparison now has to happen in JS (salt lives inside the hash, can't compare in SQL anymore).

---

## Should-fix
**4. Tokens never expire + JWT secret silently defaults** — no `expiresIn` on `jwt.sign`, and `config.ts` fell back to `"supersecret"` with zero warning, in any environment. Fixed: tokens expire in 1h, startup throws if `JWT_SECRET` is missing in production.

**5. Token logged to console on every login** — `console.log("issued token for", email, token)`. Anyone with log access could impersonate that user. Removed.

**6. Error handler leaks stack traces to the client** — `res.json({ error: err.message, stack: err.stack })`. Confirmed it fires on plain bad input (empty password on register) and hands back full file paths + stack. Fixed: full error logged server-side, generic message returned in production.

**7. CORS: wildcard origin + `credentials: true`** — contradictory (browsers won't send credentials to a wildcard origin anyway), and unnecessary since auth is a bearer token, not a cookie. Dropped `credentials: true`, origin now configurable via `CORS_ORIGIN`.

**8. No input validation anywhere** — missing fields caused a 500 with a leaked stack trace instead of a clean 400. Added minimal checks: required fields, basic email format, min password length (8), non-empty note title.

**9. `.gitignore` doesn't exclude `.env` or the db file** — only `node_modules/` was ignored, so `.env` (JWT secret + an unused `ADMIN_PASSWORD`) and `notes.db` (everyone's password hash) would've been committed on the first commit. Added `.env`, `*.db`, `dist/` to `.gitignore`, added a committed `.env.example`.

---

## Nice-to-have (not fixed yet)
- N+1 query in the old `GET /notes` (one extra query per note for the author lookup) — went away as a side effect of the IDOR fix.
- Unused `ADMIN_PASSWORD` in `.env` — dead secret, remove it or actually implement the role it implies.
- No rate limiting on `/auth/login` — bcrypt raises the cost, but nothing stops unlimited attempts.
- `npm audit` flags esbuild (via vitest's dev server) as moderate/high dev-only, but worth its own version-bump PR (1→4 is breaking).
- No pagination on `GET /notes` — fine at seed-data scale, not at real scale.

---