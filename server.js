require('dotenv').config();
const express = require('express');
const mongoose = require("mongoose");
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require("cookie-parser");
const CryptoJS = require("crypto-js");
const { ObjectId } = require("mongodb");

const SECRET_KEY = process.env.ENCRYPTION_KEY || "mysecretkey123"; // 🔐 Store in .env
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/passmanga';
const PORT = process.env.PORT || 3000;

const authRoutes = require("./routes/authRoutes");
const Password = require("./models/password"); // 💾 Password Model

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

// ✅ Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => {
        console.error("❌ MongoDB Error:", err);
        process.exit(1);
    });

app.use("/api/auth", authRoutes);

// ✅ Middleware: Token Verification
function verifyToken(req, res, next) {
    let token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token provided" });

    try {
        token = token.split(" ")[1];
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // 🆔 Attach user ID from token
        next();
    } catch (error) {
        console.error("JWT Verification Error:", error);
        res.status(403).json({ error: "Invalid Token" });
    }
}

// ✅ POST: Save Encrypted Password
app.post('/api/passwords', verifyToken, async (req, res) => {
    try {
        let { site, name, password } = req.body;
        if (!site || !name || !password) return res.status(400).json({ error: "Missing fields" });

        // ✅ Encrypt password before saving
        const encryptedPassword = CryptoJS.AES.encrypt(password, SECRET_KEY).toString();

        const newPassword = new Password({
            userId: req.user.id, // 🆔 Store per user
            site,
            name,
            password: encryptedPassword
        });

        await newPassword.save();
        res.json({ success: true, message: "Password saved successfully!" });
    } catch (error) {
        console.error("Insert Error:", error);
        res.status(500).json({ error: "Database insertion failed" });
    }
});

// ✅ GET: Fetch User-Specific Passwords
app.get('/api/passwords', verifyToken, async (req, res) => {
    try {
        const passwords = await Password.find({ userId: req.user.id });

        // ✅ Decrypt passwords before sending
        const decryptedPasswords = passwords.map(item => ({
            _id: item._id,
            site: item.site,
            name: item.name,
            password: CryptoJS.AES.decrypt(item.password, SECRET_KEY).toString(CryptoJS.enc.Utf8),
        }));

        res.json(decryptedPasswords);
    } catch (error) {
        console.error("Fetch Error:", error);
        res.status(500).json({ error: "Failed to fetch passwords" });
    }
});

// ✅ PUT: Update Password
app.put("/api/passwords/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { site, name, password } = req.body;

        if (!id || !site || !name || !password) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const encryptedPassword = CryptoJS.AES.encrypt(password, SECRET_KEY).toString();

        const updatedPassword = await Password.findOneAndUpdate(
            { _id: id, userId: req.user.id },
            { site, name, password: encryptedPassword },
            { new: true }
        );

        if (!updatedPassword) {
            return res.status(403).json({ error: "Unauthorized or Password not found" });
        }

        res.json({ success: true, message: "Password updated successfully!" });
    } catch (error) {
        console.error("Update Error:", error);
        res.status(500).json({ error: "Database update failed" });
    }
});

// ✅ DELETE: Remove Password
app.delete('/api/passwords', verifyToken, async (req, res) => {
    try {
        const { id } = req.body;
        if (!id) return res.status(400).json({ error: "Id is required" });

        const deletedPassword = await Password.findOneAndDelete({ _id: id, userId: req.user.id });

        if (!deletedPassword) {
            return res.status(403).json({ error: "Unauthorized or Password not found" });
        }

        res.json({ success: true, message: "Password deleted successfully!" });
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ error: "Database deletion failed" });
    }
});

// ✅ Default Route
app.get("/", (req, res) => {
    res.send("Welcome to Password Manager API!");
});

// ✅ Start Server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on port ${PORT}`);
});
