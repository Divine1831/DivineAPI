
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();

// MIDDLEWARE
app.use(cors());
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

// SUPABASE CONFIGURATION
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

const FRONTEND_URL = "https://divineapi-platform.vercel.app";

// AUTHENTICATION MIDDLEWARE
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

  try {
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
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(401).json({
      success: false,
      error: "Authentication failed."
    });
  }
}

// HOMEPAGE
app.get("/", (req, res) => {
  res.json({
    name: "DivineAPI",
    description: "Personal API for Divine projects",
    version: "2.5.0",
    status: "online"
  });
});

// API STATUS
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "DivineAPI",
    version: "2.5.0",
    status: "online"
  });
});

// PROJECTS
app.get("/api/projects", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("projects")
      .select("id, name, status, description, created_at")
      .order("created_at", { ascending: true });

    if (error) {
      console.error("Projects error:", error.message);

      return res.status(500).json({
        success: false,
        error: "Could not load projects."
      });
    }

    return res.json({
      success: true,
      projects: data
    });
  } catch (error) {
    console.error("Projects error:", error.message);

    return res.status(500).json({
      success: false,
      error: "An unexpected error occurred."
    });
  }
});

// PUBLISH API
app.post("/api/marketplace/publish", requireAuth, async (req, res) => {
  try {
    const {
      name,
      slug,
      description,
      category,
      base_url,
      version,
      auth_type
    } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof slug !== "string" ||
      typeof description !== "string" ||
      typeof category !== "string" ||
      typeof base_url !== "string"
    ) {
      return res.status(400).json({
        success: false,
        error: "Please provide all required API details."
      });
    }

    if (
      !name.trim() ||
      !slug.trim() ||
      !description.trim() ||
      !category.trim() ||
      name.length > 100 ||
      slug.length > 100 ||
      description.length > 2000 ||
      category.length > 60
    ) {
      return res.status(400).json({
        success: false,
        error: "One or more fields are invalid or too long."
      });
    }

    const cleanSlug = slug.trim().toLowerCase();

    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(cleanSlug)) {
      return res.status(400).json({
        success: false,
        error: "Slug must use lowercase letters, numbers and hyphens."
      });
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(base_url.trim());

      if (
        parsedUrl.protocol !== "https:" ||
        parsedUrl.username ||
        parsedUrl.password
      ) {
        throw new Error("Invalid URL");
      }
    } catch {
      return res.status(400).json({
        success: false,
        error: "Enter a valid public HTTPS base URL."
      });
    }

    const selectedAuth = auth_type || "None";
    const allowedAuth = ["None", "API Key", "Bearer Token"];

    if (!allowedAuth.includes(selectedAuth)) {
      return res.status(400).json({
        success: false,
        error: "Unsupported authentication type."
      });
    }

    const cleanVersion =
      typeof version === "string" && version.trim()
        ? version.trim()
        : "1.0.0";

    if (cleanVersion.length > 30) {
      return res.status(400).json({
        success: false,
        error: "Version is too long."
      });
    }

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

    const { data, error } = await userClient
      .from("apis")
      .insert({
        provider_id: req.user.id,
        name: name.trim(),
        slug: cleanSlug,
        description: description.trim(),
        category: category.trim(),
        base_url: parsedUrl.origin,
        version: cleanVersion,
        auth_type: selectedAuth,
        status: "Pending"
      })
      .select(
        "id, name, slug, description, category, base_url, version, auth_type, status, created_at"
      )
      .single();

    if (error) {
      console.error("API publishing error:", error.message);

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          error: "That API slug is already in use."
        });
      }

      return res.status(500).json({
        success: false,
        error: "Could not submit your API."
      });
    }

    return res.status(201).json({
      success: true,
      message: "API submitted successfully. It is awaiting admin approval.",
      api: data
    });
  } catch (error) {
    console.error("API publishing error:", error.message);

    return res.status(500).json({
      success: false,
      error: "An unexpected error occurred."
    });
  }
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
        emailRedirectTo: FRONTEND_URL + "/"
      }
    });

    if (error) {
      return res.status(400).json({
        success: false,
        error: error.message
      });
    }

    return res.status(201).json({
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

    return res.status(500).json({
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

    return res.json({
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

    return res.status(500).json({
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

    const { error } = await userClient.auth.signOut({
      scope: "local"
    });

    if (error) {
      console.error("Logout error:", error.message);

      return res.status(400).json({
        success: false,
        error: "Logout failed."
      });
    }

    return res.json({
      success: true,
      message: "Logout request completed. Clear stored tokens in your app."
    });
  } catch (error) {
    console.error("Logout error:", error.message);

    return res.status(500).json({
      success: false,
      error: "Logout failed."
    });
  }
});

// FORGOT PASSWORD
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const body = req.body || {};

    const email =
      typeof body.email === "string"
        ? body.email.trim()
        : "";

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email was not received. Check the request body."
      });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address."
      });
    }

    const { error } = await supabase.auth.resetPasswordForEmail(
      email,
      {
        redirectTo: FRONTEND_URL + "/update-password.html"
      }
    );

    if (error) {
      console.error("Password reset error:", error.message);

      return res.status(400).json({
        success: false,
        error: error.message
      });
    }

    return res.json({
      success: true,
      message: "If the account exists, a reset email will be sent."
    });
  } catch (error) {
    console.error("Forgot password error:", error.message);

    return res.status(500).json({
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
      console.error("Message error:", error.message);

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
    console.error("Message error:", error.message);

    return res.status(500).json({
      success: false,
      error: "An unexpected server error occurred."
    });
  }
});

module.exports = app;
