const mongoose = require("mongoose");

const passwordSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // 🔥 Add userId
    site: { type: String, required: true },
    name: { type: String, required: true },
    password: { type: String, required: true }
});

module.exports = mongoose.model("Password", passwordSchema);
