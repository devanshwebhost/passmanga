const express = require("express");
const bcrypt = require("bcryptjs"); // ✅ Hashing Passwords for Security
const Password = require("../models/Password");
const authMiddleware = require("../middleware/authMiddleware");
const router = express.Router();

// 🔐 Create New Password (Only for Logged-in User)
router.post("/", authMiddleware, async (req, res) => {
    try {
        const { site, name, password } = req.body;

        // ✅ Hash Password Before Saving (Security Improvement)
        const hashedPassword = await bcrypt.hash(password, 10);

        const newPassword = new Password({
            userId: req.user.id, // 👈 Store user-specific data
            site,
            name,
            password: hashedPassword
        });

        await newPassword.save();
        res.status(201).json({ message: "Password saved successfully!" });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Server error" });
    }
});

// 🔐 Get User-Specific Passwords
router.get("/", authMiddleware, async (req, res) => {
    try {
        const passwords = await Password.find({ userId: req.user.id });
        res.json(passwords);
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 🔐 Delete Password (Only if it belongs to logged-in user)
router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedPassword = await Password.findOneAndDelete({ _id: id, userId: req.user.id });

        if (!deletedPassword) {
            return res.status(403).json({ error: "Unauthorized or Password not found" });
        }

        res.json({ message: "Password deleted successfully" });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 🔐 Update Password (Only if it belongs to logged-in user)
router.put("/:id", authMiddleware, async (req, res) => {
    try {
        const { site, name, password } = req.body;

        // ✅ Hash New Password Before Updating (Security Improvement)
        const hashedPassword = await bcrypt.hash(password, 10);

        const updatedPassword = await Password.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id }, // 👈 Ensure only the owner can update
            { site, name, password: hashedPassword },
            { new: true }
        );

        if (!updatedPassword) {
            return res.status(403).json({ error: "Unauthorized or Password not found" });
        }

        res.json({ message: "Password updated successfully!" });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

module.exports = router;
