"use strict";
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
  6. GET /api/mp/health reports uptime and key count, so you can see whether
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
        writeAtomic(KV_FILE, JSON.stringify({ store: mpStore, savedAt: Date.now() }));
    } catch (error) {
        kvDirty = true;
        console.error("Could not save data: " + error.message);
    }
}

function markKvDirty() {
    kvDirty = true;
    if (!kvTimer) kvTimer = setTimeout(persistKvNow, 1000);
}

function shutdown() {
    try { persistKvNow(); } finally { process.exit(0); }
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

/* ---------------- HTTP helpers ---------------- */

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
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

    /* ===== KEY/VALUE SYNC API (accounts, progress, friends, chat, teacher records) ===== */

    if (url.pathname === "/api/mp/health" && req.method === "GET") {
        sendJSON(res, 200, {
            ok: true,
            service: "adapt-cocu-sync",
            keys: Object.keys(mpStore).length,
            loadedFromDiskAtStart: loadedKeys,
            uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000)
        });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "GET") {
        const key = url.searchParams.get("key") || "";
        const value = mpStore[key];
        sendJSON(res, 200, { ok: true, value: value === undefined ? null : value });
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "PUT") {
        try {
            const body = await getRequestBody(req);
            const key = body.key;
            if (!validKey(key)) { sendJSON(res, 400, { ok: false, message: "Missing or invalid key." }); return; }
            mpStore[key] = body.value === undefined ? null : body.value;
            markKvDirty();
            sendJSON(res, 200, { ok: true });
        } catch (error) { badRequest(res, error); }
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "DELETE") {
        const key = url.searchParams.get("key") || "";
        if (key in mpStore) { delete mpStore[key]; markKvDirty(); }
        sendJSON(res, 200, { ok: true });
        return;
    }

    if (url.pathname === "/api/mp/list" && req.method === "GET") {
        const prefix = url.searchParams.get("prefix") || "";
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
