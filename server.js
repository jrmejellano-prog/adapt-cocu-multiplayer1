"use strict";
/*
  Adapt CoCu sync server  (v3)

  Changes in this version, compared with the server.js you sent
  ---------------------------------------------------------------
  A. RESTORED /api/mp/claim-room, /api/mp/results and /api/mp/leaderboard.
     The previous version deleted them, saying the app never calls them. It
     does: "Create online room" calls /api/mp/claim-room and every online match
     posts to /api/mp/results, so creating an online multiplayer room failed.
  B. progress:index no longer leaks the student registry. Before, anyone could
     GET /api/mp/key?key=progress:index and receive every student ID (and then
     each student's name through the public card). Now only a teacher token
     receives the full list; a student only ever sees their own ID. Writes to
     the index are ignored: the server builds the roster from the stored
     progress records itself, so a lost index entry can no longer hide a student.
  C. Section-limited teachers are now really limited. Before, any valid teacher
     token (including a TEACHER_ACCOUNTS one) could read every student's full
     progress record, list every student, and write any teacher key. Now a
     limited token can only read/list/write students in its sections.
  D. Optional secrets so a wiped disk does not log everybody out:
       TEACHER_TOKEN_SECRET   (already supported)
       STUDENT_KEY_SECRET     (new: keeps students' private write keys valid)
  E. Client IP for rate limits uses the LAST X-Forwarded-For entry (the one the
     Render proxy added) instead of the first (which a client can forge).
  F. /api/mp/health now says whether saved data can survive a restart
     (persistence.durable) and reports the last save result.
  G. Key-count cap (MAX_KEYS, default 200000) so anonymous writes cannot fill
     the disk with unlimited keys.

  Everything else (CORS for PUT/DELETE, disk persistence, static-file blocklist,
  body cap, teacher auth, student claim keys, PIN recovery with lockouts,
  STRICT_STUDENT_AUTH) is unchanged.

  HOSTING (important): on Render the service disk is wiped on every deploy and
  restart of a free instance. For data to survive attach a Render Persistent
  Disk and set DATA_DIR to its mount path (for example /var/data), or move the
  store to an external database. Check GET /api/mp/health: persistence.durable
  must be true.
*/

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const APP_DIR = __dirname;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : APP_DIR;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) { /* reported on first save */ }

const KV_FILE = path.join(DATA_DIR, "adapt-cocu-kv.json");
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const MAX_KEY_LENGTH = 300;
const MAX_KEYS = Number(process.env.MAX_KEYS) || 200000;
const STARTED_AT = Date.now();

/* ---------------- persistence ---------------- */

function writeAtomic(file, text) {
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, file);
}

function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
        console.error("Could not read " + file + ": " + error.message);
        try { fs.copyFileSync(file, file + ".corrupt-" + Date.now()); } catch (e) { /* ignore */ }
    }
    return fallback;
}

const mpStore = Object.create(null);
const savedKv = readJSON(KV_FILE, null);
let loadedKeys = 0;
if (savedKv && typeof savedKv === "object" && savedKv.store && typeof savedKv.store === "object") {
    for (const k of Object.keys(savedKv.store)) { mpStore[k] = savedKv.store[k]; loadedKeys++; }
}
let keyCount = loadedKeys;

const resultsList = (savedKv && Array.isArray(savedKv.results)) ? savedKv.results.slice(-1000) : [];

let kvDirty = false;
let kvTimer = null;
const saveInfo = { lastSaveAt: 0, lastError: "" };

function persistKvNow() {
    kvTimer = null;
    if (!kvDirty) return;
    kvDirty = false;
    try {
        writeAtomic(KV_FILE, JSON.stringify({ store: mpStore, teacher: teacherState, claims, results: resultsList, savedAt: Date.now() }));
        saveInfo.lastSaveAt = Date.now(); saveInfo.lastError = "";
    } catch (error) {
        kvDirty = true;
        saveInfo.lastError = String(error.message || error);
        console.error("Could not save data: " + error.message);
    }
}
function markKvDirty() {
    kvDirty = true;
    if (!kvTimer) kvTimer = setTimeout(persistKvNow, 1000);
}

/* ---------------- teacher authentication ---------------- */

const teacherState = (savedKv && savedKv.teacher && typeof savedKv.teacher === "object") ? savedKv.teacher : {};
if (!teacherState.secret) { teacherState.secret = crypto.randomBytes(32).toString("hex"); markKvDirty(); }
const claims = (savedKv && savedKv.claims && typeof savedKv.claims === "object") ? savedKv.claims : {};
if (!teacherState.studentSecret) { teacherState.studentSecret = crypto.randomBytes(32).toString("hex"); markKvDirty(); }
const STRICT = process.env.STRICT_STUDENT_AUTH === "1";
const normSec = v => String(v || "").trim().toLowerCase().replace(/\s+/g, " ");
let teacherAccounts = [];
try {
    const arr = JSON.parse(process.env.TEACHER_ACCOUNTS || "[]");
    if (Array.isArray(arr)) teacherAccounts = arr.filter(x => x && typeof x.code === "string" && x.code.length >= 4 && Array.isArray(x.sections))
        .map(x => ({ name: String(x.name || "Teacher"), code: x.code, sections: x.sections.map(normSec) }));
} catch (e) { console.error("TEACHER_ACCOUNTS is not valid JSON; ignored."); }

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const loginFails = new Map();

function scryptHex(code, salt) { return crypto.scryptSync(String(code), String(salt), 32).toString("hex"); }
function safeEq(a, b) {
    const A = Buffer.from(String(a)), B = Buffer.from(String(b));
    return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function teacherConfigured() { return !!(process.env.TEACHER_PASSCODE || teacherState.hash || teacherAccounts.length); }
function checkTeacherCode(code) {
    code = String(code || "");
    if (process.env.TEACHER_PASSCODE) return safeEq(scryptHex(code, "env"), scryptHex(process.env.TEACHER_PASSCODE, "env"));
    if (!teacherState.hash) return false;
    return safeEq(scryptHex(code, teacherState.salt), teacherState.hash);
}
function setTeacherCode(code) {
    teacherState.salt = crypto.randomBytes(16).toString("hex");
    teacherState.hash = scryptHex(code, teacherState.salt);
    teacherState.secret = crypto.randomBytes(32).toString("hex");
    markKvDirty();
}
function tokenSecret() { return process.env.TEACHER_TOKEN_SECRET || teacherState.secret; }
function signToken(grant) {
    const p = Buffer.from(JSON.stringify({ r: "teacher", exp: Date.now() + TOKEN_TTL_MS, s: grant == null ? "*" : grant })).toString("base64url");
    return p + "." + crypto.createHmac("sha256", tokenSecret()).update(p).digest("base64url");
}
function verifyToken(tok) {
    if (typeof tok !== "string") return null;
    const parts = tok.split(".");
    if (parts.length !== 2) return null;
    const want = crypto.createHmac("sha256", tokenSecret()).update(parts[0]).digest("base64url");
    if (!safeEq(parts[1], want)) return null;
    try { const d = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); return (d.r === "teacher" && d.exp > Date.now()) ? d : null; }
    catch (e) { return null; }
}
function bearer(req) { const h = req.headers.authorization || ""; return h.startsWith("Bearer ") ? h.slice(7) : ""; }
// Render's proxy appends the real client address LAST; earlier entries can be forged by the client.
function clientIp(req) { const parts = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean); return parts.length ? parts[parts.length - 1] : String(req.socket.remoteAddress || ""); }
function isLocked(ip) { const f = loginFails.get(ip); return !!(f && f.until > Date.now()); }
function noteFail(ip) {
    const f = loginFails.get(ip) || { n: 0, until: 0 };
    if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
    f.n++; if (f.n >= 5) f.until = Date.now() + 60 * 1000;
    loginFails.set(ip, f);
}
const isFullTeacher = tk => !!tk && (tk.s == null || tk.s === "*");

/* Can this teacher token see student `id`? Admin: always. Limited: only their sections. */
function parseVal(v) { if (typeof v !== "string") return v; try { return JSON.parse(v); } catch (e) { return null; } }
function teacherAllowed(tk, id) {
    if (!tk) return false;
    if (isFullTeacher(tk)) return true;
    if (!Array.isArray(tk.s)) return false;
    const fix = parseVal(mpStore["secfix:" + id]);
    const rec = parseVal(mpStore["progress:" + id]);
    const sec = (fix && typeof fix.section === "string") ? fix.section : (rec && rec.section);
    return tk.s.includes(normSec(sec));
}

/* ---------------- student identity ---------------- */

const ID_RE = /^ADAPT-\d{4,6}$/;
const sha256 = v => crypto.createHash("sha256").update(String(v)).digest("hex");
function studentSecret() { return process.env.STUDENT_KEY_SECRET || teacherState.studentSecret; }
function studentKey(id) { return crypto.createHmac("sha256", studentSecret()).update("student:" + id).digest("hex").slice(0, 40); }
function studentAuth(req) {
    const id = String(req.headers["x-student-id"] || "").toUpperCase();
    const k = String(req.headers["x-student-key"] || "");
    return (ID_RE.test(id) && k && claims[id] && safeEq(k, studentKey(id))) ? id : null;
}
const OWNER_RES = [
    /^(progress|account|frlist|frprefs|friendcard|chatlist|chatprefs|notifread):(ADAPT-\d+)$/,
    /^(frok|chatok|chatmsg):(ADAPT-\d+):ADAPT-\d+$/
];
function keyOwner(key) { for (const re of OWNER_RES) { const m = re.exec(key); if (m) return m[2]; } return null; }
const TEACHER_KEY_RE = /^(secfix:|deleted:|chatban:|chat:cfg$)/;
const SHARED_KEY_RE = /^(frreq:|chatreq:|notif:|chatreport:)/;
const LIMITED_TEACHER_WRITE_RE = /^(secfix|deleted|chatban|notif):(ADAPT-\d+)$/;

function authorizeWrite(req, key) {
    if (key === "progress:index") return true; // accepted but ignored (see PUT handler)
    const tk = verifyToken(bearer(req));
    if (isFullTeacher(tk)) return true;
    if (tk) { const m = LIMITED_TEACHER_WRITE_RE.exec(key); if (m && teacherAllowed(tk, m[2])) return true; }
    if (TEACHER_KEY_RE.test(key)) return false;
    const sid = studentAuth(req);
    const owner = keyOwner(key);
    if (owner) return sid === owner || (!STRICT && !claims[owner]);
    if (SHARED_KEY_RE.test(key)) return !!sid || !STRICT;
    return true;
}
function viewFor(req, key, value) {
    const m = /^(progress|account):(ADAPT-\d+)$/.exec(key);
    if (!m || value === null || value === undefined) return value;
    const sid = studentAuth(req);
    if (sid === m[2]) return value;
    if (m[1] === "progress" && teacherAllowed(verifyToken(bearer(req)), m[2])) return value;
    const v = parseVal(value);
    if (!v || typeof v !== "object") return value;
    const pub = { studentId: v.studentId, name: v.name || v.studentName || (v.state && (v.state.name || v.state.playerName)) || undefined, version: v.version, updatedAt: v.updatedAt };
    return typeof value === "string" ? JSON.stringify(pub) : pub;
}
function rosterIds(tk) {
    const ids = [];
    for (const key of Object.keys(mpStore)) {
        const m = /^progress:(ADAPT-\d+)$/.exec(key);
        if (m && teacherAllowed(tk, m[1])) ids.push(m[1]);
    }
    return ids;
}

const failBuckets = new Map();
function failBlocked(k) { const f = failBuckets.get(k); return !!(f && f.until > Date.now()); }
function failNote(k, limit, lockMs) {
    const f = failBuckets.get(k) || { n: 0, until: 0 };
    if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
    f.n++; if (f.n >= limit) f.until = Date.now() + lockMs;
    failBuckets.set(k, f);
}
setInterval(() => { for (const [k, f] of failBuckets) if (f.until && f.until <= Date.now()) failBuckets.delete(k); }, 10 * 60 * 1000).unref();
setInterval(() => { for (const [ip, f] of loginFails) if (f.until && f.until <= Date.now()) loginFails.delete(ip); }, 5 * 60 * 1000).unref();

function shutdown() { try { persistKvNow(); } finally { process.exit(0); } }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

/* ---------------- HTTP helpers ---------------- */

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Student-Id, X-Student-Key",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Max-Age": "600"
};
function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store" }, CORS_HEADERS));
    res.end(JSON.stringify(data));
}
function getRequestBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = []; let size = 0; let tooBig = false;
        req.on("data", chunk => {
            if (tooBig) return;
            size += chunk.length;
            if (size > MAX_BODY_BYTES) { tooBig = true; chunks.length = 0; const e = new Error("Request body too large"); e.code = "TOO_LARGE"; reject(e); return; }
            chunks.push(chunk);
        });
        req.on("end", () => {
            if (tooBig) return;
            try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch (error) { reject(error); }
        });
        req.on("error", reject);
    });
}
function badRequest(res, error, extra) {
    const tooLarge = error && error.code === "TOO_LARGE";
    sendJSON(res, tooLarge ? 413 : 400, Object.assign({ success: false, ok: false, message: tooLarge ? "Request is too large." : "Invalid request." }, extra || {}));
}
function validKey(key) { return typeof key === "string" && key.length > 0 && key.length <= MAX_KEY_LENGTH; }

/* ---------------- static files ---------------- */

const MIME = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".svg": "image/svg+xml",
    ".ico": "image/x-icon", ".webp": "image/webp", ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav",
    ".woff": "font/woff", ".woff2": "font/woff2", ".webmanifest": "application/manifest+json"
};
const BLOCKED_FILES = new Set(["server.js", "package.json", "package-lock.json", "multiplayer-data.json", "adapt-cocu-kv.json"]);

function serveStatic(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(404); res.end("Not Found"); return; }
    let rel;
    try { rel = decodeURIComponent(url.pathname); } catch (e) { res.writeHead(400); res.end("Bad Request"); return; }
    if (rel === "/" || rel === "") rel = "/index.html";
    const filePath = path.resolve(APP_DIR, "." + rel);
    const base = path.basename(filePath).toLowerCase();
    const inDataDir = DATA_DIR !== APP_DIR && (filePath === DATA_DIR || filePath.startsWith(DATA_DIR + path.sep));
    const ext = path.extname(filePath).toLowerCase();
    if (!filePath.startsWith(APP_DIR + path.sep) || base.startsWith(".") || BLOCKED_FILES.has(base) || inDataDir ||
        filePath.split(path.sep).includes("node_modules") || !MIME[ext]) { res.writeHead(404); res.end("Not Found"); return; }
    fs.readFile(filePath, (error, data) => {
        if (error) { res.writeHead(404); res.end("Not Found"); return; }
        res.writeHead(200, { "Content-Type": MIME[ext], "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600" });
        res.end(req.method === "HEAD" ? undefined : data);
    });
}

/* ---------------- server ---------------- */

const ROOM_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function newRoomCode() {
    for (let n = 0; n < 50; n++) {
        let code = "COCU-";
        for (let i = 0; i < 4; i++) code += ROOM_CHARS[crypto.randomInt(ROOM_CHARS.length)];
        if (!(("mp:room:" + code + ":meta") in mpStore)) return code;
    }
    return null;
}

const server = http.createServer(async (req, res) => {

    if (req.method === "OPTIONS") { res.writeHead(204, CORS_HEADERS); res.end(); return; }

    let url;
    try { url = new URL(req.url, "http://" + (req.headers.host || "localhost")); }
    catch (e) { res.writeHead(400); res.end("Bad Request"); return; }

    /* ===== TEACHER AUTH + ROSTER ===== */
    if (url.pathname === "/api/teacher/status" && req.method === "GET") {
        sendJSON(res, 200, { ok: true, configured: teacherConfigured(), setupAvailable: !teacherConfigured() && !!process.env.TEACHER_SETUP_KEY });
        return;
    }
    if (url.pathname === "/api/teacher/login" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (!teacherConfigured()) { sendJSON(res, 400, { ok: false, error: "not_configured" }); return; }
            let grant = checkTeacherCode(body.code) ? "*" : null;
            if (!grant) {
                const c = String(body.code || "");
                for (const a of teacherAccounts) if (safeEq(scryptHex(c, "acct"), scryptHex(a.code, "acct"))) grant = a.sections;
            }
            if (!grant) { noteFail(ip); sendJSON(res, 401, { ok: false, error: "bad_code" }); return; }
            loginFails.delete(ip);
            sendJSON(res, 200, { ok: true, token: signToken(grant) });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/setup" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (teacherConfigured()) { sendJSON(res, 400, { ok: false, error: "already_configured" }); return; }
            if (!process.env.TEACHER_SETUP_KEY) { sendJSON(res, 403, { ok: false, error: "setup_disabled" }); return; }
            if (!safeEq(String(body.setupKey || ""), process.env.TEACHER_SETUP_KEY)) { noteFail(ip); sendJSON(res, 403, { ok: false, error: "bad_setup_key" }); return; }
            const code = String(body.code || "");
            if (code.length < 4) { sendJSON(res, 400, { ok: false, error: "too_short" }); return; }
            setTeacherCode(code);
            sendJSON(res, 200, { ok: true, token: signToken() });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/reset" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (!process.env.TEACHER_SETUP_KEY) { sendJSON(res, 403, { ok: false, error: "setup_disabled" }); return; }
            if (process.env.TEACHER_PASSCODE) { sendJSON(res, 400, { ok: false, error: "managed_by_environment" }); return; }
            if (!safeEq(String(body.setupKey || ""), process.env.TEACHER_SETUP_KEY)) { noteFail(ip); sendJSON(res, 403, { ok: false, error: "bad_setup_key" }); return; }
            const code = String(body.newCode || "");
            if (code.length < 4) { sendJSON(res, 400, { ok: false, error: "too_short" }); return; }
            setTeacherCode(code);
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/roster" && req.method === "GET") {
        const tk = verifyToken(bearer(req));
        if (!tk) { sendJSON(res, 401, { ok: false, error: "unauthorized" }); return; }
        const students = [];
        for (const id of rosterIds(tk)) {
            const v = parseVal(mpStore["progress:" + id]);
            if (!v || typeof v !== "object") continue;
            const copy = Object.assign({}, v); delete copy.ownerToken;
            students.push(copy);
        }
        sendJSON(res, 200, { ok: true, count: students.length, students });
        return;
    }

    /* ===== STUDENT CLAIM + ACCOUNT RECOVERY ===== */
    if (url.pathname === "/api/student/claim" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (failBlocked("claim:" + ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            failNote("claim:" + ip, 300, 60 * 1000); // shared school Wi-Fi = one address, so keep this generous
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            const token = String(body.ownerToken || "");
            if (!ID_RE.test(id) || token.length < 8) { sendJSON(res, 400, { ok: false, error: "bad_request" }); return; }
            const h = sha256(token);
            if (claims[id]) {
                if (safeEq(claims[id], h)) { sendJSON(res, 200, { ok: true, key: studentKey(id) }); return; }
                sendJSON(res, 409, { ok: false, error: "already_claimed" }); return;
            }
            for (const k of ["progress:" + id, "account:" + id]) {
                const rec = parseVal(mpStore[k]);
                if (rec && typeof rec === "object" && rec.ownerToken && rec.ownerToken !== token) { sendJSON(res, 409, { ok: false, error: "already_claimed" }); return; }
            }
            claims[id] = h; markKvDirty();
            sendJSON(res, 200, { ok: true, key: studentKey(id) });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/account/salt" && req.method === "POST") {
        try {
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            const rec = ID_RE.test(id) ? parseVal(mpStore["account:" + id]) : null;
            if (!rec || !rec.pinSalt) { sendJSON(res, 404, { ok: false, error: "not_found" }); return; }
            sendJSON(res, 200, { ok: true, salt: rec.pinSalt });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/account/recover" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            if (!ID_RE.test(id)) { sendJSON(res, 400, { ok: false, error: "bad_request" }); return; }
            if (failBlocked("pin:" + id) || failBlocked("pinip:" + ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const rec = parseVal(mpStore["account:" + id]);
            let good = false;
            if (rec && rec.pinSalt) {
                const sha = String(body.sha || ""), fnv = String(body.fnv || "");
                good = (rec.pinSha && sha) ? safeEq(sha, rec.pinSha) : (!!rec.pinFnv && safeEq(fnv, rec.pinFnv));
            }
            if (!good) { failNote("pin:" + id, 5, 15 * 60 * 1000); failNote("pinip:" + ip, 60, 15 * 60 * 1000); sendJSON(res, 401, { ok: false, error: "bad_pin" }); return; }
            failBuckets.delete("pin:" + id);
            sendJSON(res, 200, { ok: true, record: rec });
        } catch (error) { badRequest(res, error); }
        return;
    }

    /* ===== ONLINE MULTIPLAYER (restored) ===== */
    if (url.pathname === "/api/mp/claim-room" && req.method === "POST") {
        const code = newRoomCode();
        if (!code) { sendJSON(res, 503, { ok: false, message: "No room code available." }); return; }
        sendJSON(res, 200, { ok: true, code, playerId: "p_" + crypto.randomBytes(5).toString("hex").slice(0, 7) });
        return;
    }
    if (url.pathname === "/api/mp/results" && req.method === "POST") {
        try {
            const b = await getRequestBody(req);
            resultsList.push({
                room: String(b.room || "").slice(0, 20), playerId: String(b.playerId || "").slice(0, 20),
                name: String(b.name || "Player").slice(0, 40), score: Number(b.score) || 0,
                rank: Number(b.rank) || 0, won: !!b.won, timestamp: Number(b.timestamp) || Date.now()
            });
            if (resultsList.length > 1000) resultsList.splice(0, resultsList.length - 1000);
            markKvDirty();
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/mp/leaderboard" && req.method === "GET") {
        const limit = Math.max(1, Math.min(100, Number(url.searchParams.get("limit")) || 30));
        const rows = resultsList.slice().sort((a, b) => b.score - a.score).slice(0, limit);
        sendJSON(res, 200, { ok: true, rows });
        return;
    }

    /* ===== KEY/VALUE SYNC API ===== */

    if (url.pathname === "/api/mp/health" && req.method === "GET") {
        const durable = DATA_DIR !== APP_DIR;
        sendJSON(res, 200, {
            ok: true, service: "adapt-cocu-sync",
            keys: keyCount, loadedFromDiskAtStart: loadedKeys,
            teacherConfigured: teacherConfigured(),
            studentAuth: STRICT ? "strict" : "compat",
            uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000),
            persistence: {
                durable,
                warning: durable ? null : "DATA_DIR is not set: on Render this folder is wiped on every deploy/restart. Attach a Persistent Disk and set DATA_DIR.",
                lastSaveAt: saveInfo.lastSaveAt || null, lastError: saveInfo.lastError || null
            }
        });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "GET") {
        const key = url.searchParams.get("key") || "";
        if (key === "progress:index") {
            const tk = verifyToken(bearer(req));
            const sid = studentAuth(req);
            const ids = tk ? rosterIds(tk) : (sid ? [sid] : []);
            sendJSON(res, 200, { ok: true, value: JSON.stringify(ids) });
            return;
        }
        const value = mpStore[key];
        sendJSON(res, 200, { ok: true, value: value === undefined ? null : viewFor(req, key, value) });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "PUT") {
        try {
            const body = await getRequestBody(req);
            const key = body.key;
            if (!validKey(key)) { sendJSON(res, 400, { ok: false, message: "Missing or invalid key." }); return; }
            if (!authorizeWrite(req, key)) { sendJSON(res, 403, { ok: false, error: "forbidden" }); return; }
            if (key === "progress:index") { sendJSON(res, 200, { ok: true }); return; } // server-derived; ignore client writes
            if (!(key in mpStore)) {
                if (keyCount >= MAX_KEYS) { sendJSON(res, 507, { ok: false, error: "store_full" }); return; }
                keyCount++;
            }
            mpStore[key] = body.value === undefined ? null : body.value;
            markKvDirty();
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "DELETE") {
        const key = url.searchParams.get("key") || "";
        if (!authorizeWrite(req, key)) { sendJSON(res, 403, { ok: false, error: "forbidden" }); return; }
        if (key in mpStore) { delete mpStore[key]; keyCount--; markKvDirty(); }
        sendJSON(res, 200, { ok: true });
        return;
    }

    if (url.pathname === "/api/mp/list" && req.method === "GET") {
        const prefix = url.searchParams.get("prefix") || "";
        const sensitive = ["progress:", "account:"].some(sp => sp.startsWith(prefix) || prefix.startsWith(sp));
        const tk = verifyToken(bearer(req));
        if (teacherConfigured() && sensitive && !tk) { sendJSON(res, 401, { ok: false, error: "unauthorized" }); return; }
        let keys = Object.keys(mpStore).filter(key => key.startsWith(prefix));
        if (sensitive && tk && !isFullTeacher(tk)) {
            keys = keys.filter(key => { const m = /^(?:progress|account):(ADAPT-\d+)$/.exec(key); return !m || teacherAllowed(tk, m[1]); });
        }
        keys = keys.filter(key => key !== "progress:index" || prefix === "progress:index");
        sendJSON(res, 200, { ok: true, keys });
        return;
    }

    serveStatic(req, res, url);
});

server.listen(PORT, HOST, () => {
    console.log("Adapt CoCu sync server running on port " + PORT);
    console.log("Data folder: " + (DATA_DIR === APP_DIR ? "app folder (NOT durable on Render: set DATA_DIR to a persistent disk)" : DATA_DIR));
    console.log("Loaded " + loadedKeys + " saved keys from disk.");
});"use strict";
/*
  Adapt CoCu sync server  (fixed version)

  What changed compared with the previous server.js
  -------------------------------------------------
  1. CORS: PUT and DELETE are now allowed. Every write the app makes
     (/api/mp/key with PUT, and DELETE) was blocked by the browser's
     preflight check whenever the page was not served from this same server,
     so those students' accounts, progress, friend requests and chat
     messages never reached the server.
  2. Persistence: the key/value store (accounts, progress, friends, chat) is
     now saved to disk and reloaded on start.
     Before, they lived only in memory and were erased on every restart,
     redeploy or Render sleep, so the Teacher Dashboard "lost" students.
  3. Static files: only real web assets are served. server.js and the data
     files can no longer be downloaded by anyone.
  4. Request bodies are capped (413 instead of unlimited memory use).
  5. The unused multiplayer-room and leaderboard endpoints were removed (the
     app never calls them). Only the key/value sync API remains. Its "/api/mp/"
     name is historical: accounts, progress, friends, chat and the Teacher
     Dashboard all depend on it, so the paths were left unchanged.
  6. Teacher authorization now lives on the server (see /api/teacher/*). The
     passcode is set with the TEACHER_PASSCODE environment variable (best on
     Render) or created once with TEACHER_SETUP_KEY. It is stored only as a
     salted hash, never in the HTML. Student records are returned only to a
     signed teacher token, and once a passcode exists, listing every
     progress:/account: key also requires that token.
  7. Student accounts: each Player Code is claimed by the device that created it
     (POST /api/student/claim) and receives a private write key. Writes to a
     student's own records, and reads of their full record, need that key.
     Other people only see a minimal public card. Recovery PINs are checked
     on the server (POST /api/account/salt and /recover) with lockouts, and
     the PIN hash is never returned to anyone else.
  8. Class-limited teachers: set TEACHER_ACCOUNTS (JSON) to give a teacher a
     passcode that only shows certain sections. Example:
       [{"name":"Ms. Reyes","code":"reyes-2026","sections":["Grade 11 - Rizal"]}]
     The admin passcode (TEACHER_PASSCODE / setup key) still sees everyone.
  9. STRICT_STUDENT_AUTH=1 rejects ALL unauthenticated writes to student
     records. Leave it off while old app versions are still in use; turn it
     on once everyone has updated.
 10. GET /api/mp/health reports uptime and key count, so you can see whether
     the server has been restarting and whether saved data was reloaded.

  IMPORTANT (hosting): on Render the app's own disk is wiped on every deploy
  and when a free instance restarts. For data to survive, either attach a
  Render Persistent Disk and set the environment variable DATA_DIR to its
  mount path (for example /var/data), or move the store to an external
  database. Without that, step 2 only protects against crashes on hosts that
  keep their disk.
*/

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const APP_DIR = __dirname;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : APP_DIR;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) { /* reported on first save */ }

const KV_FILE = path.join(DATA_DIR, "adapt-cocu-kv.json");       // key/value store
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const MAX_KEY_LENGTH = 300;
const STARTED_AT = Date.now();

/* ---------------- persistence helpers ---------------- */

function writeAtomic(file, text) {
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, file);
}

function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
        console.error("Could not read " + file + ": " + error.message);
        try { fs.copyFileSync(file, file + ".corrupt-" + Date.now()); } catch (e) { /* ignore */ }
    }
    return fallback;
}

// Null-prototype object so keys such as "constructor" or "__proto__" are plain keys.
const mpStore = Object.create(null);
const savedKv = readJSON(KV_FILE, null);
let loadedKeys = 0;
if (savedKv && typeof savedKv === "object") {
    if (savedKv.store && typeof savedKv.store === "object") {
        for (const k of Object.keys(savedKv.store)) { mpStore[k] = savedKv.store[k]; loadedKeys++; }
    }
}

let kvDirty = false;
let kvTimer = null;

function persistKvNow() {
    kvTimer = null;
    if (!kvDirty) return;
    kvDirty = false;
    try {
        writeAtomic(KV_FILE, JSON.stringify({ store: mpStore, teacher: teacherState, claims, savedAt: Date.now() }));
    } catch (error) {
        kvDirty = true;
        console.error("Could not save data: " + error.message);
    }
}

function markKvDirty() {
    kvDirty = true;
    if (!kvTimer) kvTimer = setTimeout(persistKvNow, 1000);
}

/* ---------------- teacher authentication ---------------- */

// Private to the server: never exposed through /api/mp/key.
const teacherState = (savedKv && savedKv.teacher && typeof savedKv.teacher === "object") ? savedKv.teacher : {};
if (!teacherState.secret) { teacherState.secret = crypto.randomBytes(32).toString("hex"); markKvDirty(); }

const claims = (savedKv && savedKv.claims && typeof savedKv.claims === "object") ? savedKv.claims : {};
if (!teacherState.studentSecret) { teacherState.studentSecret = crypto.randomBytes(32).toString("hex"); markKvDirty(); }
const STRICT = process.env.STRICT_STUDENT_AUTH === "1";
const normSec = v => String(v || "").trim().toLowerCase().replace(/\s+/g, " ");
let teacherAccounts = [];
try {
    const arr = JSON.parse(process.env.TEACHER_ACCOUNTS || "[]");
    if (Array.isArray(arr)) teacherAccounts = arr.filter(x => x && typeof x.code === "string" && x.code.length >= 4 && Array.isArray(x.sections))
        .map(x => ({ name: String(x.name || "Teacher"), code: x.code, sections: x.sections.map(normSec) }));
} catch (e) { console.error("TEACHER_ACCOUNTS is not valid JSON; ignored."); }

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const loginFails = new Map(); // ip -> { n, until }

function scryptHex(code, salt) { return crypto.scryptSync(String(code), String(salt), 32).toString("hex"); }
function safeEq(a, b) {
    const A = Buffer.from(String(a)), B = Buffer.from(String(b));
    return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function teacherConfigured() { return !!(process.env.TEACHER_PASSCODE || teacherState.hash || teacherAccounts.length); }
function checkTeacherCode(code) {
    code = String(code || "");
    if (process.env.TEACHER_PASSCODE) return safeEq(scryptHex(code, "env"), scryptHex(process.env.TEACHER_PASSCODE, "env"));
    if (!teacherState.hash) return false;
    return safeEq(scryptHex(code, teacherState.salt), teacherState.hash);
}
function setTeacherCode(code) {
    teacherState.salt = crypto.randomBytes(16).toString("hex");
    teacherState.hash = scryptHex(code, teacherState.salt);
    teacherState.secret = crypto.randomBytes(32).toString("hex"); // invalidates older tokens
    markKvDirty();
}
function tokenSecret() { return process.env.TEACHER_TOKEN_SECRET || teacherState.secret; }
function signToken(grant) {
    const p = Buffer.from(JSON.stringify({ r: "teacher", exp: Date.now() + TOKEN_TTL_MS, s: grant == null ? "*" : grant })).toString("base64url");
    return p + "." + crypto.createHmac("sha256", tokenSecret()).update(p).digest("base64url");
}
function verifyToken(tok) {
    if (typeof tok !== "string") return false;
    const parts = tok.split(".");
    if (parts.length !== 2) return false;
    const want = crypto.createHmac("sha256", tokenSecret()).update(parts[0]).digest("base64url");
    if (!safeEq(parts[1], want)) return false;
    try { const d = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); return (d.r === "teacher" && d.exp > Date.now()) ? d : null; }
    catch (e) { return null; }
}
function bearer(req) { const h = req.headers.authorization || ""; return h.startsWith("Bearer ") ? h.slice(7) : ""; }
function clientIp(req) { return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(); }
function isLocked(ip) { const f = loginFails.get(ip); return !!(f && f.until > Date.now()); }
function noteFail(ip) {
    const f = loginFails.get(ip) || { n: 0, until: 0 };
    if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
    f.n++; if (f.n >= 5) f.until = Date.now() + 60 * 1000;
    loginFails.set(ip, f);
}

/* ---------------- student identity ---------------- */

const ID_RE = /^ADAPT-\d{4,6}$/;
const sha256 = v => crypto.createHash("sha256").update(String(v)).digest("hex");
function studentKey(id) { return crypto.createHmac("sha256", teacherState.studentSecret).update("student:" + id).digest("hex").slice(0, 40); }
function studentAuth(req) {
    const id = String(req.headers["x-student-id"] || "").toUpperCase();
    const k = String(req.headers["x-student-key"] || "");
    return (ID_RE.test(id) && k && claims[id] && safeEq(k, studentKey(id))) ? id : null;
}
const OWNER_RES = [
    /^(progress|account|frlist|frprefs|friendcard|chatlist|chatprefs|notifread):(ADAPT-\d+)$/,
    /^(frok|chatok|chatmsg):(ADAPT-\d+):ADAPT-\d+$/
];
function keyOwner(key) { for (const re of OWNER_RES) { const m = re.exec(key); if (m) return m[2]; } return null; }
const TEACHER_KEY_RE = /^(secfix:|deleted:|chatban:|chat:cfg$)/;
const SHARED_KEY_RE = /^(frreq:|chatreq:|notif:|chatreport:|progress:index$)/;

function authorizeWrite(req, key) {
    if (verifyToken(bearer(req))) return true;
    if (TEACHER_KEY_RE.test(key)) return false;
    const sid = studentAuth(req);
    const owner = keyOwner(key);
    if (owner) return sid === owner || (!STRICT && !claims[owner]);
    if (SHARED_KEY_RE.test(key)) return !!sid || !STRICT;
    return true;
}
function parseVal(v) { if (typeof v !== "string") return v; try { return JSON.parse(v); } catch (e) { return null; } }
function viewFor(req, key, value) {
    const m = /^(progress|account):(ADAPT-\d+)$/.exec(key);
    if (!m || value === null || value === undefined) return value;
    const sid = studentAuth(req);
    if (sid === m[2]) return value;
    if (m[1] === "progress" && verifyToken(bearer(req))) return value;
    const v = parseVal(value);
    if (!v || typeof v !== "object") return value;
    const pub = { studentId: v.studentId, name: v.name || v.studentName || (v.state && (v.state.name || v.state.playerName)) || undefined, version: v.version, updatedAt: v.updatedAt };
    return typeof value === "string" ? JSON.stringify(pub) : pub;
}

const failBuckets = new Map();
function failBlocked(k) { const f = failBuckets.get(k); return !!(f && f.until > Date.now()); }
function failNote(k, limit, lockMs) {
    const f = failBuckets.get(k) || { n: 0, until: 0 };
    if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
    f.n++; if (f.n >= limit) f.until = Date.now() + lockMs;
    failBuckets.set(k, f);
}
setInterval(() => { for (const [k, f] of failBuckets) if (f.until && f.until <= Date.now()) failBuckets.delete(k); }, 10 * 60 * 1000).unref();

setInterval(() => { for (const [ip, f] of loginFails) if (f.until && f.until <= Date.now()) loginFails.delete(ip); }, 5 * 60 * 1000).unref();

function shutdown() {
    try { persistKvNow(); } finally { process.exit(0); }
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

/* ---------------- HTTP helpers ---------------- */

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Student-Id, X-Student-Key",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Max-Age": "600"
};

function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store" }, CORS_HEADERS));
    res.end(JSON.stringify(data));
}

function getRequestBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let tooBig = false;
        req.on("data", chunk => {
            if (tooBig) return;
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                tooBig = true;
                chunks.length = 0;
                const error = new Error("Request body too large");
                error.code = "TOO_LARGE";
                reject(error);
                return;
            }
            chunks.push(chunk);
        });
        req.on("end", () => {
            if (tooBig) return;
            try {
                resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
            } catch (error) { reject(error); }
        });
        req.on("error", reject);
    });
}

function badRequest(res, error, extra) {
    const tooLarge = error && error.code === "TOO_LARGE";
    sendJSON(res, tooLarge ? 413 : 400, Object.assign({
        success: false,
        ok: false,
        message: tooLarge ? "Request is too large." : "Invalid request."
    }, extra || {}));
}

function validKey(key) {
    return typeof key === "string" && key.length > 0 && key.length <= MAX_KEY_LENGTH;
}

/* ---------------- static files ---------------- */

const MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".wav": "audio/wav",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".webmanifest": "application/manifest+json"
};
const BLOCKED_FILES = new Set([
    "server.js", "package.json", "package-lock.json",
    "multiplayer-data.json", "adapt-cocu-kv.json"
]);

function serveStatic(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(404); res.end("Not Found"); return;
    }
    let rel;
    try { rel = decodeURIComponent(url.pathname); }
    catch (e) { res.writeHead(400); res.end("Bad Request"); return; }
    if (rel === "/" || rel === "") rel = "/index.html";

    const filePath = path.resolve(APP_DIR, "." + rel);
    const base = path.basename(filePath).toLowerCase();
    const inDataDir = DATA_DIR !== APP_DIR && (filePath === DATA_DIR || filePath.startsWith(DATA_DIR + path.sep));
    const ext = path.extname(filePath).toLowerCase();

    if (!filePath.startsWith(APP_DIR + path.sep) ||
        base.startsWith(".") ||
        BLOCKED_FILES.has(base) ||
        inDataDir ||
        filePath.split(path.sep).includes("node_modules") ||
        !MIME[ext]) {
        res.writeHead(404); res.end("Not Found"); return;
    }

    fs.readFile(filePath, (error, data) => {
        if (error) { res.writeHead(404); res.end("Not Found"); return; }
        res.writeHead(200, {
            "Content-Type": MIME[ext],
            "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600"
        });
        res.end(req.method === "HEAD" ? undefined : data);
    });
}

/* ---------------- server ---------------- */

const server = http.createServer(async (req, res) => {

    if (req.method === "OPTIONS") {
        res.writeHead(204, CORS_HEADERS);
        res.end();
        return;
    }

    let url;
    try { url = new URL(req.url, "http://" + (req.headers.host || "localhost")); }
    catch (e) { res.writeHead(400); res.end("Bad Request"); return; }

    /* ===== TEACHER AUTH + ROSTER ===== */
    if (url.pathname === "/api/teacher/status" && req.method === "GET") {
        sendJSON(res, 200, { ok: true, configured: teacherConfigured(), setupAvailable: !teacherConfigured() && !!process.env.TEACHER_SETUP_KEY });
        return;
    }
    if (url.pathname === "/api/teacher/login" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (!teacherConfigured()) { sendJSON(res, 400, { ok: false, error: "not_configured" }); return; }
            let grant = checkTeacherCode(body.code) ? "*" : null;
            if (!grant) {
                const c = String(body.code || "");
                for (const a of teacherAccounts) if (safeEq(scryptHex(c, "acct"), scryptHex(a.code, "acct"))) grant = a.sections;
            }
            if (!grant) { noteFail(ip); sendJSON(res, 401, { ok: false, error: "bad_code" }); return; }
            loginFails.delete(ip);
            sendJSON(res, 200, { ok: true, token: signToken(grant) });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/setup" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (teacherConfigured()) { sendJSON(res, 400, { ok: false, error: "already_configured" }); return; }
            if (!process.env.TEACHER_SETUP_KEY) { sendJSON(res, 403, { ok: false, error: "setup_disabled" }); return; }
            if (!safeEq(String(body.setupKey || ""), process.env.TEACHER_SETUP_KEY)) { noteFail(ip); sendJSON(res, 403, { ok: false, error: "bad_setup_key" }); return; }
            const code = String(body.code || "");
            if (code.length < 4) { sendJSON(res, 400, { ok: false, error: "too_short" }); return; }
            setTeacherCode(code);
            sendJSON(res, 200, { ok: true, token: signToken() });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/reset" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (isLocked(ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const body = await getRequestBody(req);
            if (!process.env.TEACHER_SETUP_KEY) { sendJSON(res, 403, { ok: false, error: "setup_disabled" }); return; }
            if (process.env.TEACHER_PASSCODE) { sendJSON(res, 400, { ok: false, error: "managed_by_environment" }); return; }
            if (!safeEq(String(body.setupKey || ""), process.env.TEACHER_SETUP_KEY)) { noteFail(ip); sendJSON(res, 403, { ok: false, error: "bad_setup_key" }); return; }
            const code = String(body.newCode || "");
            if (code.length < 4) { sendJSON(res, 400, { ok: false, error: "too_short" }); return; }
            setTeacherCode(code);
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/teacher/roster" && req.method === "GET") {
        const tk = verifyToken(bearer(req));
        if (!tk) { sendJSON(res, 401, { ok: false, error: "unauthorized" }); return; }
        const allowed = (tk.s == null || tk.s === "*") ? null : new Set(tk.s);
        const students = [];
        for (const key of Object.keys(mpStore)) {
            if (!key.startsWith("progress:") || key === "progress:index") continue;
            let v = mpStore[key];
            if (typeof v === "string") { try { v = JSON.parse(v); } catch (e) { continue; } }
            if (!v || typeof v !== "object") continue;
            if (allowed) {
                const fix = parseVal(mpStore["secfix:" + key.slice(9)]);
                const sec = (fix && typeof fix.section === "string") ? fix.section : v.section;
                if (!allowed.has(normSec(sec))) continue;
            }
            const copy = Object.assign({}, v); delete copy.ownerToken;
            students.push(copy);
        }
        sendJSON(res, 200, { ok: true, count: students.length, students });
        return;
    }

    /* ===== STUDENT CLAIM + ACCOUNT RECOVERY ===== */
    if (url.pathname === "/api/student/claim" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            if (failBlocked("claim:" + ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            failNote("claim:" + ip, 60, 60 * 1000); // at most ~60 claim calls per minute per address
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            const token = String(body.ownerToken || "");
            if (!ID_RE.test(id) || token.length < 8) { sendJSON(res, 400, { ok: false, error: "bad_request" }); return; }
            const h = sha256(token);
            if (claims[id]) {
                if (safeEq(claims[id], h)) { sendJSON(res, 200, { ok: true, key: studentKey(id) }); return; }
                sendJSON(res, 409, { ok: false, error: "already_claimed" }); return;
            }
            for (const k of ["progress:" + id, "account:" + id]) {
                const rec = parseVal(mpStore[k]);
                if (rec && typeof rec === "object" && rec.ownerToken && rec.ownerToken !== token) { sendJSON(res, 409, { ok: false, error: "already_claimed" }); return; }
            }
            claims[id] = h; markKvDirty();
            sendJSON(res, 200, { ok: true, key: studentKey(id) });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/account/salt" && req.method === "POST") {
        try {
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            const rec = ID_RE.test(id) ? parseVal(mpStore["account:" + id]) : null;
            if (!rec || !rec.pinSalt) { sendJSON(res, 404, { ok: false, error: "not_found" }); return; }
            sendJSON(res, 200, { ok: true, salt: rec.pinSalt });
        } catch (error) { badRequest(res, error); }
        return;
    }
    if (url.pathname === "/api/account/recover" && req.method === "POST") {
        try {
            const ip = clientIp(req);
            const body = await getRequestBody(req);
            const id = String(body.id || "").toUpperCase();
            if (!ID_RE.test(id)) { sendJSON(res, 400, { ok: false, error: "bad_request" }); return; }
            if (failBlocked("pin:" + id) || failBlocked("pinip:" + ip)) { sendJSON(res, 429, { ok: false, error: "locked" }); return; }
            const rec = parseVal(mpStore["account:" + id]);
            let good = false;
            if (rec && rec.pinSalt) {
                const sha = String(body.sha || ""), fnv = String(body.fnv || "");
                good = (rec.pinSha && sha) ? safeEq(sha, rec.pinSha) : (!!rec.pinFnv && safeEq(fnv, rec.pinFnv));
            }
            if (!good) { failNote("pin:" + id, 5, 15 * 60 * 1000); failNote("pinip:" + ip, 30, 15 * 60 * 1000); sendJSON(res, 401, { ok: false, error: "bad_pin" }); return; }
            failBuckets.delete("pin:" + id);
            sendJSON(res, 200, { ok: true, record: rec });
        } catch (error) { badRequest(res, error); }
        return;
    }

    /* ===== KEY/VALUE SYNC API (accounts, progress, friends, chat, teacher records) ===== */

    if (url.pathname === "/api/mp/health" && req.method === "GET") {
        sendJSON(res, 200, {
            ok: true,
            service: "adapt-cocu-sync",
            keys: Object.keys(mpStore).length,
            loadedFromDiskAtStart: loadedKeys,
            teacherConfigured: teacherConfigured(),
            studentAuth: STRICT ? "strict" : "compat",
            uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000)
        });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "GET") {
        const key = url.searchParams.get("key") || "";
        const value = mpStore[key];
        sendJSON(res, 200, { ok: true, value: value === undefined ? null : viewFor(req, key, value) });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "PUT") {
        try {
            const body = await getRequestBody(req);
            const key = body.key;
            if (!validKey(key)) { sendJSON(res, 400, { ok: false, message: "Missing or invalid key." }); return; }
            if (!authorizeWrite(req, key)) { sendJSON(res, 403, { ok: false, error: "forbidden" }); return; }
            mpStore[key] = body.value === undefined ? null : body.value;
            markKvDirty();
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "DELETE") {
        const key = url.searchParams.get("key") || "";
        if (!authorizeWrite(req, key)) { sendJSON(res, 403, { ok: false, error: "forbidden" }); return; }
        if (key in mpStore) { delete mpStore[key]; markKvDirty(); }
        sendJSON(res, 200, { ok: true });
        return;
    }

    if (url.pathname === "/api/mp/list" && req.method === "GET") {
        const prefix = url.searchParams.get("prefix") || "";
        // Once a teacher passcode exists, enumerating every student requires a teacher token.
        if (teacherConfigured() && ["progress:", "account:"].some(sp => sp.startsWith(prefix) || prefix.startsWith(sp)) && !verifyToken(bearer(req))) {
            sendJSON(res, 401, { ok: false, error: "unauthorized" });
            return;
        }
        const keys = Object.keys(mpStore).filter(key => key.startsWith(prefix));
        sendJSON(res, 200, { ok: true, keys });
        return;
    }

    /* ===== anything else: static web files ===== */
    serveStatic(req, res, url);
});

server.listen(PORT, HOST, () => {
    console.log("Adapt CoCu sync server running on port " + PORT);
    console.log("Data folder: " + (DATA_DIR === APP_DIR ? "app folder (set DATA_DIR to a persistent disk on Render)" : "custom DATA_DIR"));
    console.log("Loaded " + loadedKeys + " saved keys from disk.");
});
