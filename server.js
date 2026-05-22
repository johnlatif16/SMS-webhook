require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ENV =====
const SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// Firebase config (جاهز للمرحلة الجاية)
let FIREBASE_CONFIG = {};
try {
    FIREBASE_CONFIG = JSON.parse(process.env.FIREBASE_CONFIG || "{}");
} catch (e) {
    console.log("Invalid FIREBASE_CONFIG JSON");
}

// ===== Middleware =====
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// ===== In-memory storage (مؤقت) =====
let messages = [];

// ===== JWT Login =====
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = jwt.sign(
            { username },
            SECRET,
            { expiresIn: "2h" }
        );

        return res.json({ token });
    }

    return res.status(401).json({ message: "Invalid credentials" });
});

// ===== JWT Middleware =====
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(403).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(authHeader, SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// ===== SMS Webhook =====
// يستقبل أي رسالة من مزود SMS أو تطبيق موبايل
app.post("/sms", (req, res) => {
    const { sender, message, date, phone } = req.body;

    const allowedSenders = ["Orange Cash", "VF-Cash"];

    if (allowedSenders.includes(sender)) {
        const msg = {
            id: Date.now(),
            sender,
            message,
            phone: phone || null,
            date: date || new Date().toISOString()
        };

        messages.push(msg);

        console.log("New SMS stored:", msg);
    }

    res.json({ status: "ok" });
});

// ===== Get messages (protected dashboard API) =====
app.get("/api/messages", verifyToken, (req, res) => {
    res.json(messages);
});

// ===== Clear messages (اختياري) =====
app.delete("/api/messages", verifyToken, (req, res) => {
    messages = [];
    res.json({ status: "cleared" });
});

// ===== Serve pages =====
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public/login.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public/dashboard.html"));
});

// ===== Health check =====
app.get("/health", (req, res) => {
    res.json({
        status: "running",
        firebase_loaded: Object.keys(FIREBASE_CONFIG).length > 0
    });
});

// ===== Start server =====
app.listen(PORT, () => {
    console.log("Server running on port:", PORT);
});