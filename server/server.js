const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";

const app = express();
app.use(cors());
app.use(express.json());

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Expect "Bearer TOKEN"
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user; // attach decoded user data to the request
    next();
  });
}

const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "notes_app",
});

// Test DB connection
db.getConnection((err, conn) => {
  if (err) {
    console.error("DB connection failed:", err);
  } else {
    console.log("DB connected");
    conn.release();
  }
});

// Routes will go here
// GET all notes for the authenticated user
app.get("/api/notes", authenticateToken, (req, res) => {
  db.query(
    "SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC",
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      res.json(results);
    }
  );
});

// POST create new note for authenticated user
app.post("/api/notes", authenticateToken, (req, res) => {
  const { title, content } = req.body;
  if (!title) return res.status(400).json({ error: "Title is required" });

  db.query(
    "INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)",
    [title, content, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ message: "Note created", noteId: result.insertId });
    }
  );
});

// PUT update note by ID for authenticated user
app.put("/api/notes/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  if (!title) return res.status(400).json({ error: "Title is required" });

  db.query(
    "UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?",
    [title, content, id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      if (result.affectedRows === 0)
        return res.status(404).json({ error: "Note not found" });
      res.json({ message: "Note updated" });
    }
  );
});

// DELETE note by ID for authenticated user
app.delete("/api/notes/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  db.query(
    "DELETE FROM notes WHERE id = ? AND user_id = ?",
    [id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      if (result.affectedRows === 0)
        return res.status(404).json({ error: "Note not found" });
      res.json({ message: "Note deleted" });
    }
  );
});

// Register new user
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });

  const hashedPassword = bcrypt.hashSync(password, 8);

  db.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY")
          return res.status(400).json({ error: "Username already exists" });
        return res.status(500).json({ error: err });
      }
      res.json({ message: "User registered successfully" });
    }
  );
});

// Login user
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      if (results.length === 0)
        return res.status(400).json({ error: "Invalid credentials" });

      const user = results[0];
      const passwordMatch = bcrypt.compareSync(password, user.password);

      if (!passwordMatch)
        return res.status(400).json({ error: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.json({ message: "Login successful", token });
    }
  );
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
