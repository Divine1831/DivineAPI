
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "20kb" }));

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
  throw new Error("Missing Supabase environment variables.");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// Verify authentication token
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Authentication required."
    });
  }

  const { data, error } = await supabase.auth.getUser(token);

  if (error || !data.user) {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired access token."
    });
  }

  req.user = data.user;
  req.token = token;
  next();
}

// Homepage
app.get("/", (req, res) => {
  res.json({
    name: "DivineAPI",
    description: "Personal API for Divine projects",
    version: "2.0.0",
    status: "online"
  });
});

// API status
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "DivineAPI",
    version: "2.0.0",
    status: "online"
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

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        success: false,
        error: "Enter a valid email and password of at least 8 characters."
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email: email.trim(),
      password,
      options: {
        emailRedirectTo: "https://divinetube-6-0.vercel.app/"
      }
    });

    if (error) {
      return res.status(400).json({
        success: false,
        error: error.message
      });
    }

    res.status(201).json({
      success: true,
      message: "Registration received. Check your email for verification.",
      user: data.user
        ? {
            id: data.user.id,
            email: data.user.email
          }
        : null,
      needsEmailVerification: !data.session
    });

  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({
      success: false,
      error: "Registration failed."
    });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required."
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password
    });

    if (error || !data.session) {
      return res.status(401).json({
        success: false,
        error: "Login failed. Check your details and email verification."
      });
    }

    res.json({
      success: true,
      message: "Login successful.",
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      user: {
        id: data.user.id,
        email: data.user.email
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      success: false,
      error: "Login failed."
    });
  }
});

// CURRENT USER
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email
    }
  });
});

// LOGOUT
app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    const userClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${req.token}`
          }
        },
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    const { error } = await userClient.auth.signOut({ scope: "local" });

    if (error) {
      return res.status(400).json({
        success: false,
        error: "Logout failed."
      });
    }

    res.json({
      success: true,
      message: "Logged out. Clear the session tokens in your app."
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Logout failed."
    });
  }
});

// FORGOT PASSWORD
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};

    if (typeof email !== "string" || !email.trim()) {
      return res.status(400).json({
        success: false,
        error: "A valid email is required."
      });
    }

    const { error } = await supabase.auth.resetPasswordForEmail(
      email.trim(),
      {
        redirectTo: "https://divinetube-6-0.vercel.app/"
      }
    );

    if (error) {
      return res.status(400).json({
        success: false,
        error: "Password reset request failed."
      });
    }

    res.json({
      success: true,
      message: "If the account exists, a reset email will be sent."
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Password reset request failed."
    });
  }
});

// SAVE MESSAGE
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

    res.status(201).json({
      success: true,
      message: "Your message was saved!"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: "An unexpected server error occurred."
    });
  }
});

module.exports = app;
