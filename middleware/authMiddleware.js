const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.header("Authorization");

        // ✅ Check if Token Exists & is in Correct Format
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ error: "Access Denied: No Token Provided" });
        }

        // ✅ Extract Token from Header
        const token = authHeader.split(" ")[1];

        // ✅ Verify Token
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // 👈 Attach user info from token to request

        next();
    } catch (error) {
        // ✅ Handle Token Expiration
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Session Expired! Please login again." });
        }

        // ✅ Handle Invalid Token
        return res.status(400).json({ error: "Invalid Token" });
    }
};

module.exports = authMiddleware;
