
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Check Supabase environment variables
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
  console.error("Missing Supabase environment variables.");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Homepage
app.get("/", (req, res) => {
  res.json({
    name: "DivineAPI",
    description: "Personal API for Divine projects",
    version: "1.3.0",
    status: "online"
  });
});

// API status
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "DivineAPI",
    status: "online",
    version: "1.3.0"
  });
});

// Projects
app.get("/api/projects", (req, res) => {
  res.json({
    success: true,
    projects: [
      { name: "DivineTube", status: "Active" },
      { name: "DivineSocial", status: "In development" },
      { name: "DivineAPI", status: "Active" }
    ]
  });
});

// Save a message to Supabase
app.post("/api/message", async (req, res) => {
  try {
    const { name, message } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof message !== "string" ||
      !name.trim() ||
      !message.trim()
    ) {
      return res.status(400).json({
        success: false,
        error: "A valid name and message are required."
      });
    }

    if (name.length > 80 || message.length > 2000) {
      return res.status(400).json({
        success: false,
        error: "Name or message is too long."
      });
    }

    const { error } = await supabase
      .from("messages")
      .insert({
        name: name.trim(),
        message: message.trim()
      });

    if (error) {
      console.error("Supabase error:", error.message);

      return res.status(500).json({
        success: false,
        error: "Could not save the message."
      });
    }

    return res.status(201).json({
      success: true,
      message: "Your message was saved!"
    });

  } catch (error) {
    console.error("Server error:", error);

    return res.status(500).json({
      success: false,
      error: "An unexpected server error occurred."
    });
  }
});

// Export app for Vercel
module.exports = app;
