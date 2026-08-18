const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const DATA_FILE = path.join(__dirname, "multiplayer-data.json");

let rooms = {};
let players = {};
let leaderboard = [];

// Storage used by the online multiplayer HTML client.
let mpStore = {};
let mpResults = [];

if (fs.existsSync(DATA_FILE)) {
    try {
        leaderboard = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch (error) {
        leaderboard = [];
    }
}

function saveLeaderboard() {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(leaderboard, null, 2)
    );
}

function generateRoomCode() {
    let code;

    do {
        code =
            "COCU-" +
            Math.random()
                .toString(36)
                .substring(2, 6)
                .toUpperCase();
    } while (rooms[code]);

    return code;
}

function generatePlayerId() {
    return crypto.randomBytes(8).toString("hex");
}

function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods":
            "GET, POST, OPTIONS"
    });

    res.end(JSON.stringify(data));
}

function getRequestBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk;
        });

        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (error) {
                reject(error);
            }
        });

        req.on("error", reject);
    });
}

function getRoomState(roomCode) {
    const room = rooms[roomCode];

    if (!room) {
        return null;
    }

    return {
        code: room.code,
        hostId: room.hostId,
        subject: room.subject,
        started: room.started,
        players: room.players.map(player => ({
            id: player.id,
            name: player.name,
            score: player.score,
            ready: player.ready,
            finished: player.finished
        }))
    };
}

function updateLeaderboard(player) {
    let existing = leaderboard.find(
        item => item.name === player.name
    );

    if (!existing) {
        existing = {
            name: player.name,
            games: 0,
            wins: 0,
            top3: 0,
            bestScore: 0
        };

        leaderboard.push(existing);
    }

    existing.games++;

    if (player.position === 1) {
        existing.wins++;
    }

    if (player.position <= 3) {
        existing.top3++;
    }

    if (player.score > existing.bestScore) {
        existing.bestScore = player.score;
    }

    saveLeaderboard();
}

const server = http.createServer(async (req, res) => {

    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers":
                "Content-Type",
            "Access-Control-Allow-Methods":
                "GET, POST, OPTIONS"
        });

        res.end();
        return;
    }

    const url = new URL(
        req.url,
        `http://${req.headers.host}`
    );

    /*
    ========================================
    CREATE ROOM
    ========================================
    */

    if (
        req.method === "POST" &&
        url.pathname === "/api/create-room"
    ) {

        try {

            const body =
                await getRequestBody(req);

            const name =
                String(body.name || "Player")
                    .trim()
                    .substring(0, 20);

            const playerId =
                generatePlayerId();

            const roomCode =
                generateRoomCode();

            rooms[roomCode] = {

                code: roomCode,

                hostId: playerId,

                subject: null,

                started: false,

                players: [
                    {
                        id: playerId,
                        name: name,
                        score: 0,
                        ready: true,
                        finished: false
                    }
                ]

            };

            players[playerId] = {
                roomCode
            };

            sendJSON(res, 200, {

                success: true,

                roomCode,

                playerId,

                room:
                    getRoomState(roomCode)

            });

        } catch (error) {

            sendJSON(res, 400, {
                success: false,
                message: "Invalid request."
            });

        }

        return;
    }

    /*
    ========================================
    JOIN ROOM
    ========================================
    */

    if (
        req.method === "POST" &&
        url.pathname === "/api/join-room"
    ) {

        try {

            const body =
                await getRequestBody(req);

            const roomCode =
                String(body.roomCode || "")
                    .trim()
                    .toUpperCase();

            const name =
                String(body.name || "Player")
                    .trim()
                    .substring(0, 20);

            const room =
                rooms[roomCode];

            if (!room) {

                sendJSON(res, 404, {
                    success: false,
                    message: "Room not found."
                });

                return;
            }

            if (room.started) {

                sendJSON(res, 400, {
                    success: false,
                    message:
                        "The game has already started."
                });

                return;
            }

            if (room.players.length >= 4) {

                sendJSON(res, 400, {
                    success: false,
                    message:
                        "This lobby is full."
                });

                return;
            }

            const playerId =
                generatePlayerId();

            room.players.push({

                id: playerId,

                name: name,

                score: 0,

                ready: true,

                finished: false

            });

            players[playerId] = {
                roomCode
            };

            sendJSON(res, 200, {

                success: true,

                roomCode,

                playerId,

                room:
                    getRoomState(roomCode)

            });

        } catch (error) {

            sendJSON(res, 400, {
                success: false,
                message: "Invalid request."
            });

        }

        return;
    }

    /*
    ========================================
    GET ROOM
    ========================================
    */

    if (
        req.method === "GET" &&
        url.pathname === "/api/room"
    ) {

        const roomCode =
            url.searchParams.get("code");

        const room =
            rooms[roomCode];

        if (!room) {

            sendJSON(res, 404, {
                success: false,
                message: "Room not found."
            });

            return;
        }

        sendJSON(res, 200, {

            success: true,

            room:
                getRoomState(roomCode)

        });

        return;
    }

    /*
    ========================================
    START GAME
    ========================================
    */

    if (
        req.method === "POST" &&
        url.pathname === "/api/start-game"
    ) {

        try {

            const body =
                await getRequestBody(req);

            const roomCode =
                String(body.roomCode || "")
                    .toUpperCase();

            const playerId =
                body.playerId;

            const subject =
                body.subject || "General";

            const room =
                rooms[roomCode];

            if (!room) {

                sendJSON(res, 404, {
                    success: false,
                    message: "Room not found."
                });

                return;
            }

            if (room.hostId !== playerId) {

                sendJSON(res, 403, {
                    success: false,
                    message:
                        "Only the host can start the game."
                });

                return;
            }

            room.subject = subject;

            room.started = true;

            room.players.forEach(player => {

                player.score = 0;

                player.finished = false;

            });

            sendJSON(res, 200, {

                success: true,

                room:
                    getRoomState(roomCode)

            });

        } catch (error) {

            sendJSON(res, 400, {
                success: false,
                message: "Invalid request."
            });

        }

        return;
    }

    /*
    ========================================
    UPDATE SCORE
    ========================================
    */

    if (
        req.method === "POST" &&
        url.pathname === "/api/update-score"
    ) {

        try {

            const body =
                await getRequestBody(req);

            const playerId =
                body.playerId;

            const score =
                Number(body.score || 0);

            const playerInfo =
                players[playerId];

            if (!playerInfo) {

                sendJSON(res, 404, {
                    success: false,
                    message:
                        "Player session not found."
                });

                return;
            }

            const room =
                rooms[playerInfo.roomCode];

            if (!room) {

                sendJSON(res, 404, {
                    success: false,
                    message: "Room not found."
                });

                return;
            }

            const player =
                room.players.find(
                    p => p.id === playerId
                );

            if (!player) {

                sendJSON(res, 404, {
                    success: false,
                    message: "Player not found."
                });

                return;
            }

            player.score = score;

            if (body.finished) {
                player.finished = true;
            }

            const ranked =
                [...room.players]
                    .sort(
                        (a, b) =>
                            b.score - a.score
                    );

            ranked.forEach(
                (p, index) => {
                    p.position = index + 1;
                }
            );

            if (player.finished) {

                updateLeaderboard({
                    ...player,
                    position:
                        player.position || 0
                });

            }

            sendJSON(res, 200, {

                success: true,

                room:
                    getRoomState(
                        playerInfo.roomCode
                    )

            });

        } catch (error) {

            sendJSON(res, 400, {
                success: false,
                message: "Invalid request."
            });

        }

        return;
    }

    /*
    ========================================
    LEADERBOARD
    ========================================
    */

    if (
        req.method === "GET" &&
        url.pathname === "/api/leaderboard"
    ) {

        const sorted =
            [...leaderboard]
                .sort(
                    (a, b) =>
                        b.wins - a.wins ||
                        b.bestScore -
                            a.bestScore
                );

        sendJSON(res, 200, {

            success: true,

            leaderboard:
                sorted.slice(0, 50)

        });

        return;
    }

    /*
    ========================================
    LEAVE ROOM
    ========================================
    */

    if (
        req.method === "POST" &&
        url.pathname === "/api/leave-room"
    ) {

        try {

            const body =
                await getRequestBody(req);

            const playerId =
                body.playerId;

            const playerInfo =
                players[playerId];

            if (!playerInfo) {

                sendJSON(res, 200, {
                    success: true
                });

                return;
            }

            const room =
                rooms[playerInfo.roomCode];

            if (room) {

                room.players =
                    room.players.filter(
                        p => p.id !== playerId
                    );

                if (
                    room.hostId === playerId &&
                    room.players.length > 0
                ) {

                    room.hostId =
                        room.players[0].id;

                }

                if (
                    room.players.length === 0
                ) {

                    delete rooms[
                        playerInfo.roomCode
                    ];

                }

            }

            delete players[playerId];

            sendJSON(res, 200, {
                success: true
            });

        } catch (error) {

            sendJSON(res, 400, {
                success: false
            });

        }

        return;
    }

    /*
    ========================================
    SERVE HTML / STATIC FILES
    ========================================
    */

    /* ========================================
       ONLINE MULTIPLAYER KEY/VALUE API
       ======================================== */

    if (url.pathname === "/api/mp/health" && req.method === "GET") {
        sendJSON(res, 200, { ok: true, service: "adapt-cocu-multiplayer" });
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
            const key = String(body.key || "");
            if (!key) {
                sendJSON(res, 400, { ok: false, message: "Missing key." });
                return;
            }
            mpStore[key] = body.value;
            sendJSON(res, 200, { ok: true });
        } catch (error) {
            sendJSON(res, 400, { ok: false, message: "Invalid request." });
        }
        return;
    }

    if (url.pathname === "/api/mp/key" && req.method === "DELETE") {
        const key = url.searchParams.get("key") || "";
        delete mpStore[key];
        sendJSON(res, 200, { ok: true });
        return;
    }

    if (url.pathname === "/api/mp/list" && req.method === "GET") {
        const prefix = url.searchParams.get("prefix") || "";
        const keys = Object.keys(mpStore).filter(key => key.startsWith(prefix));
        sendJSON(res, 200, { ok: true, keys });
        return;
    }

    if (url.pathname === "/api/mp/results" && req.method === "POST") {
        try {
            const body = await getRequestBody(req);
            const room = String(body.room || "");
            const playerId = String(body.playerId || "");
            if (!room || !playerId) {
                sendJSON(res, 400, { ok: false, message: "Missing room or playerId." });
                return;
            }
            mpResults.push({
                room,
                playerId,
                name: String(body.name || "Player").substring(0, 20),
                score: Number(body.score || 0),
                rank: Number(body.rank || 0),
                won: !!body.won,
                timestamp: Number(body.timestamp || Date.now())
            });
            if (mpResults.length > 1000) mpResults.splice(0, mpResults.length - 1000);
            sendJSON(res, 200, { ok: true });
        } catch (error) {
            sendJSON(res, 400, { ok: false, message: "Invalid request." });
        }
        return;
    }

    if (url.pathname === "/api/mp/leaderboard" && req.method === "GET") {
        const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 30)));
        const byPlayer = {};
        for (const row of mpResults) {
            const key = row.playerId;
            if (!byPlayer[key]) byPlayer[key] = { name: row.name, games: 0, wins: 0, bestScore: 0 };
            byPlayer[key].games++;
            if (row.won) byPlayer[key].wins++;
            if (row.score > byPlayer[key].bestScore) byPlayer[key].bestScore = row.score;
        }
        const rows = Object.values(byPlayer)
            .sort((a, b) => b.wins - a.wins || b.bestScore - a.bestScore)
            .slice(0, limit);
        sendJSON(res, 200, { ok: true, rows });
        return;
    }

    let filePath;

    if (
        url.pathname === "/" ||
        url.pathname === "/index.html"
    ) {

        filePath =
            path.join(
                __dirname,
                "index.html"
            );

    } else {

        filePath =
            path.join(
                __dirname,
                url.pathname
            );

    }

    if (!filePath.startsWith(__dirname)) {

        res.writeHead(403);
        res.end("Forbidden");
        return;

    }

    fs.readFile(
        filePath,
        (error, data) => {

            if (error) {

                res.writeHead(404);
                res.end("Not Found");
                return;

            }

            let contentType =
                "text/plain";

            if (
                filePath.endsWith(".html")
            ) {
                contentType =
                    "text/html";
            }

            if (
                filePath.endsWith(".css")
            ) {
                contentType =
                    "text/css";
            }

            if (
                filePath.endsWith(".js")
            ) {
                contentType =
                    "application/javascript";
            }

            res.writeHead(200, {
                "Content-Type":
                    contentType
            });

            res.end(data);

        }
    );

});

server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `Adapt CoCu multiplayer server running on port ${PORT}`
        );

        console.log(
            `Public deployment: use the HTTPS URL assigned by your hosting provider.`
        );

    }
);