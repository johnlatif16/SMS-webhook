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

// قائمة سوداء للتوكنات المسجلة الخروج (اختياري للتعزيز)
let blacklistedTokens = new Set();

// ===== JWT Login =====
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = jwt.sign(
            { username, loginTime: Date.now() },
            SECRET,
            { expiresIn: "2h" }
        );

        return res.json({ 
            token, 
            username,
            message: "تم تسجيل الدخول بنجاح" 
        });
    }

    return res.status(401).json({ message: "Invalid credentials" });
});

// ===== JWT Middleware =====
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(403).json({ message: "No token provided" });
    }

    // التحقق من القائمة السوداء
    if (blacklistedTokens.has(authHeader)) {
        return res.status(401).json({ message: "Token has been invalidated" });
    }

    try {
        const decoded = jwt.verify(authHeader, SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// ===== LOGOUT Endpoint =====
app.post("/api/logout", verifyToken, (req, res) => {
    try {
        const token = req.headers["authorization"];
        
        // إضافة التوكن إلى القائمة السوداء
        if (token) {
            blacklistedTokens.add(token);
            
            // تنظيف القائمة السوداء من التوكنات منتهية الصلاحية (اختياري)
            cleanBlacklistedTokens();
        }
        
        console.log(`User ${req.user.username} logged out at ${new Date().toISOString()}`);
        
        res.json({ 
            success: true, 
            message: "Logged out successfully" 
        });
    } catch (error) {
        console.error("Logout error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Error during logout" 
        });
    }
});

// دالة لتنظيف القائمة السوداء (إزالة التوكنات منتهية الصلاحية)
function cleanBlacklistedTokens() {
    const now = Date.now();
    for (const token of blacklistedTokens) {
        try {
            const decoded = jwt.decode(token);
            if (decoded && decoded.exp && decoded.exp * 1000 < now) {
                blacklistedTokens.delete(token);
            }
        } catch (e) {
            // إذا كان التوكن غير صالح، قم بإزالته
            blacklistedTokens.delete(token);
        }
    }
}

// ===== SMS Webhook =====
app.post("/sms", (req, res) => {
    const { sender, message, date, phone } = req.body;

    const allowedSenders = ["Orange Cash", "VF-Cash"];

    if (allowedSenders.includes(sender)) {
        const msg = {
            id: Date.now(),
            sender,
            message,
            phone: phone || null,
            date: date || new Date().toISOString(),
            receivedAt: new Date().toISOString()
        };

        messages.push(msg);
        
        // الاحتفاظ بآخر 1000 رسالة فقط (لتجنب استهلاك الذاكرة)
        if (messages.length > 1000) {
            messages = messages.slice(-1000);
        }

        console.log("New SMS stored:", msg);
    } else {
        console.log(`Unallowed sender: ${sender}`);
    }

    res.json({ status: "ok", message: "SMS received" });
});

// ===== Get messages (protected dashboard API) =====
app.get("/api/messages", verifyToken, (req, res) => {
    // إرجاع الرسائل مرتبة من الأحدث إلى الأقدم
    const sortedMessages = [...messages].reverse();
    res.json(sortedMessages);
});

// ===== Get messages with pagination (اختياري للتحسين) =====
app.get("/api/messages/page/:page", verifyToken, (req, res) => {
    const page = parseInt(req.params.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    
    const paginatedMessages = messages.slice(startIndex, endIndex);
    
    res.json({
        messages: paginatedMessages.reverse(),
        currentPage: page,
        totalPages: Math.ceil(messages.length / limit),
        totalMessages: messages.length
    });
});

// ===== Clear messages =====
app.delete("/api/messages", verifyToken, (req, res) => {
    messages = [];
    console.log(`All messages cleared by user: ${req.user.username}`);
    res.json({ 
        status: "cleared", 
        message: "All messages have been deleted" 
    });
});

// ===== Delete specific message =====
app.delete("/api/messages/:id", verifyToken, (req, res) => {
    const messageId = parseInt(req.params.id);
    const initialLength = messages.length;
    
    messages = messages.filter(msg => msg.id !== messageId);
    
    if (messages.length < initialLength) {
        console.log(`Message ${messageId} deleted by ${req.user.username}`);
        res.json({ 
            success: true, 
            message: "Message deleted successfully" 
        });
    } else {
        res.status(404).json({ 
            success: false, 
            message: "Message not found" 
        });
    }
});

// ===== Get single message =====
app.get("/api/messages/:id", verifyToken, (req, res) => {
    const messageId = parseInt(req.params.id);
    const message = messages.find(msg => msg.id === messageId);
    
    if (message) {
        res.json(message);
    } else {
        res.status(404).json({ 
            message: "Message not found" 
        });
    }
});

// ===== Get statistics =====
app.get("/api/stats", verifyToken, (req, res) => {
    const stats = {
        totalMessages: messages.length,
        uniqueSenders: [...new Set(messages.map(m => m.sender))],
        lastMessage: messages.length > 0 ? messages[messages.length - 1] : null,
        lastUpdate: new Date().toISOString()
    };
    
    res.json(stats);
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
        firebase_loaded: Object.keys(FIREBASE_CONFIG).length > 0,
        messages_count: messages.length,
        blacklisted_tokens: blacklistedTokens.size,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// ===== Start server =====
app.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════
    ✅ Server running on port: ${PORT}
    📱 SMS Dashboard API is ready
    🔐 JWT authentication enabled
    📊 Health check: http://localhost:${PORT}/health
    ═══════════════════════════════════════
    `);
});

// ===== Cleanup on server shutdown =====
process.on('SIGINT', () => {
    console.log('\n🛑 Server shutting down...');
    blacklistedTokens.clear();
    process.exit();
});
