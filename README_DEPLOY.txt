# Deploying the centralized Teacher/Facilitator system

## What changed
- `db.js` — **new file.** All Postgres access: schema creation, password hashing,
  session tokens, classes, students, progress. Nothing in here touches your
  existing multiplayer rooms/leaderboard code.
- `server.js` — your existing server, unchanged in every route it already had
  (rooms, `/api/mp/*`, leaderboard, static file serving). Added:
  - `require("./db")`
  - A block of new routes under `/api/teacher/*` and `/api/student/*`
  - `db.initDb()` runs once before the server starts listening
- `package.json` — **new file** (or add `"pg": "^8.11.5"` to your existing one's
  `dependencies` if you already have a package.json in the repo).
- `index.html` — updated:
  - Teacher gate screen is now a real login/register form (username + password)
    instead of a per-device access code.
  - Teacher dashboard has a new "My Classes" panel — create a class, get a
    join code, filter the roster by class.
  - Profile screen has a "Join Class" field for students.
  - `pushProgressSnapshot` / `fetchRemoteRosterAndMerge` now talk to the new
    dedicated endpoints instead of piggybacking on the generic `mpStore`
    key/value API.

## Render setup
1. **Add a Postgres database** in the Render dashboard (the free tier is fine
   to start). Render will give you an **Internal Database URL**.
2. On your existing web service, add an environment variable:
   - `DATABASE_URL` = the Internal Database URL from step 1
   (Render auto-links these for you if you create the Postgres from the same
   project and select "Add to service" — either way works.)
3. Make sure `pg` is in `package.json` → `dependencies` (see above), then
   redeploy. On boot, `db.initDb()` creates all tables automatically — no
   manual migration step.
4. If `DATABASE_URL` is ever missing, the server still starts and multiplayer
   still works — only `/api/teacher/*` and `/api/student/*` respond `503`
   until it's set.

## Local testing (optional)
```
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/adaptcocu node server.js
```

## New API surface (all under the same origin as the existing app)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/teacher/register` | — | create a teacher account, returns a token |
| POST | `/api/teacher/login` | — | log in, returns a token |
| POST | `/api/teacher/logout` | Bearer | invalidate this device's token |
| GET  | `/api/teacher/me` | Bearer | who am I |
| POST | `/api/teacher/classes` | Bearer | create a class, returns a join code |
| GET  | `/api/teacher/classes` | Bearer | list my classes |
| GET  | `/api/teacher/roster?classId=` | Bearer | roster scoped to my class(es) only |
| GET  | `/api/teacher/student?codename=` | Bearer | one student's full snapshot (ownership-checked) |
| POST | `/api/student/join-class` | — | student links their codename to a class via its join code |
| PUT  | `/api/student/progress` | — | upsert a student's progress snapshot |

## Known trade-offs (worth knowing, not blocking)
- Student-facing endpoints (`join-class`, `progress`) aren't authenticated —
  a codename functions like a shared secret, same trust model the app
  already used for the old `progress:<codename>` key. Good enough for a
  classroom deployment; if you ever need to harden it further, the natural
  next step is issuing each student a per-device token at onboarding.
- No "delete a class" or "remove a student from a class" endpoint yet —
  straightforward to add to `db.js` + `server.js` if you want it.
- Session tokens don't expire. Fine for a semester-long classroom tool;
  add an `expires_at` check in `getTeacherByToken` if you want auto-logout.
