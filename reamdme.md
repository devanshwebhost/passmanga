const express = require('express');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { ObjectId } = require("mongodb");
const jwt = require('jsonwebtoken');
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");

require('dotenv').config();

const url = process.env.MONGO_URI || 'mongodb://localhost:27017/';
const client = new MongoClient(url);
const dbName = 'passmanga';

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

let db, collection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db(dbName);
    collection = db.collection("passwords");
    console.log("✅ MongoDB Connected");
  } catch (error) {
    console.error("❌ MongoDB Connection Error:", error);
  }
}
connectDB();

function verifyToken(req, res, next) {
  let token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
      token = token.split(" ")[1];
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      req.user = verified;
      next();
  } catch (error) {
      console.error("JWT Verification Error:", error);
      res.status(403).json({ error: "Invalid Token" });
  }
}

app.get('/api/passwords', verifyToken, async (req, res) => {
  if (!collection) return res.status(500).json({ error: "Database not connected" });

  const findResult = await collection.find({}).toArray();
  res.json(findResult);
});

app.post('/api/passwords', verifyToken, async (req, res) => {
  try {
    let { site, name, password } = req.body;
    if (!site || !name || !password) return res.status(400).json({ error: "Missing fields" });

    if (!collection) return res.status(500).json({ error: "Database not connected" });

    const existing = await collection.findOne({ site, name });
    if (existing) return res.status(409).json({ error: "Password already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await collection.insertOne({ site, name, password: hashedPassword });

    res.json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    console.error("Insert Error:", error);
    res.status(500).json({ error: "Database insertion failed" });
  }
});

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
