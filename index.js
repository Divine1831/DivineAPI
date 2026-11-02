
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();

const FRONTEND_URL = "https://divineapi-platform.vercel.app";
const API_VERSION = "2.8.0";

app.use(cors({
  origin: [FRONTEND_URL]
}));

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

// SERVER-ONLY PRIVILEGED CLIENT
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Missing server-side Supabase secret.");
}

const adminSupabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// SUPABASE USER AUTHENTICATION
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

// USER-SCOPED SUPABASE CLIENT
function userSupabase(req) {
  return createClient(
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
}

// DIVINEAPI DEVELOPER KEY AUTHENTICATION
async function requireApiKey(req, res, next) {
  const rawKey = req.get("x-api-key");

  if (
    typeof rawKey !== "string" ||
    !/^divine_live_[A-Za-z0-9_-]{30,}$/.test(rawKey)
  ) {
    return res.status(401).json({
      success: false,
      error: "A valid x-api-key header is required."
    });
  }

  try {
    const keyHash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const { data: key, error } = await adminSupabase
      .from("api_keys")
      .select("id, user_id, expires_at")
      .eq("key_hash", keyHash)
      .is("revoked_at", null)
      .maybeSingle();

    if (error) {
      console.error("API key lookup error:", error.message);
      return res.status(500).json({
        success: false,
        error: "Could not verify API key."
      });
    }

    if (!key) {
      return res.status(401).json({
        success: false,
        error: "Invalid or revoked API key."
      });
    }

    if (
      key.expires_at &&
      new Date(key.expires_at).getTime() <= Date.now()
    ) {
      return res.status(401).json({
        success: false,
        error: "API key has expired."
      });
    }

    const { error: updateError } = await adminSupabase
      .from("api_keys")
      .update({
        last_used_at: new Date().toISOString()
      })
      .eq("id", key.id);

    if (updateError) {
      console.error("Usage update error:", updateError.message);
    }

    req.apiUser = { id: key.user_id };
    req.apiKeyId = key.id;

    next();
  } catch (error) {
    console.error("API key authentication error:", error.message);
    return res.status(500).json({
      success: false,
      error: "API key authentication failed."
    });
  }
}

// HOMEPAGE
app.get("/", (req, res) => {
  res.json({
    name: "DivineAPI",
    description: "A developer API marketplace.",
    version: API_VERSION,
    status: "online"
  });
});

// STATUS
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "DivineAPI",
    version: API_VERSION,
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

    if (error) throw error;

    res.json({
      success: true,
      projects: data
    });
  } catch (error) {
    console.error("Projects error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not load projects."
    });
  }
});

// PUBLIC API MARKETPLACE CATALOGUE
app.get("/api/marketplace/apis", async (req, res) => {
  try {
    const q = typeof req.query.q === "string"
      ? req.query.q.trim().slice(0, 80)
      : "";

    const category = typeof req.query.category === "string"
      ? req.query.category.trim().slice(0, 60)
      : "";

    const page = Math.max(
      1,
      Math.min(100000, Number.parseInt(req.query.page, 10) || 1)
    );

    const limit = Math.min(
      30,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 12)
    );

    let query = supabase
      .from("apis")
      .select(
        "id, name, slug, description, category, base_url, version, auth_type, created_at",
        { count: "exact" }
      )
      .eq("status", "Approved")
      .order("created_at", { ascending: false });

    if (q) {
      const safeSearch = q.replace(/[,%()]/g, " ");
      query = query.ilike("name", `%${safeSearch}%`);
    }

    if (category) {
      query = query.ilike("category", category);
    }

    const from = (page - 1) * limit;
    const to = from + limit - 1;

    const { data, error, count } = await query.range(from, to);

    if (error) throw error;

    res.json({
      success: true,
      page,
      limit,
      total: count || 0,
      total_pages: Math.ceil((count || 0) / limit),
      apis: data
    });
  } catch (error) {
    console.error("Marketplace error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not load marketplace APIs."
    });
  }
});

// GET MARKETPLACE CATEGORIES
app.get("/api/marketplace/categories", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("apis")
      .select("category")
      .eq("status", "Approved");

    if (error) throw error;

    const categories = [
      ...new Set(
        (data || [])
          .map(item => item.category)
          .filter(Boolean)
      )
    ].sort((a, b) => a.localeCompare(b));

    res.json({
      success: true,
      total: categories.length,
      categories
    });
  } catch (error) {
    console.error("Categories error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not load categories."
    });
  }
});

// GET ONE APPROVED API BY SLUG
app.get("/api/marketplace/apis/:slug", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("apis")
      .select(
        "id, name, slug, description, category, base_url, version, auth_type, created_at"
      )
      .eq("slug", req.params.slug)
      .eq("status", "Approved")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        success: false,
        error: "Approved API not found."
      });
    }

    res.json({
      success: true,
      api: data
    });
  } catch (error) {
    console.error("API details error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not load API details."
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
      typeof base_url !== "string" ||
      !name.trim() ||
      !slug.trim() ||
      !description.trim() ||
      !category.trim()
    ) {
      return res.status(400).json({
        success: false,
        error: "Please provide all required API details."
      });
    }

    if (
      name.length > 100 ||
      slug.length > 100 ||
      description.length > 2000 ||
      category.length > 60
    ) {
      return res.status(400).json({
        success: false,
        error: "One or more fields are too long."
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

    if (!["None", "API Key", "Bearer Token"].includes(selectedAuth)) {
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

    const { data, error } = await userSupabase(req)
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
      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          error: "That API slug is already in use."
        });
      }
      throw error;
    }

    res.status(201).json({
      success: true,
      message: "API submitted for admin approval.",
      api: data
    });
  } catch (error) {
    console.error("Publish error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not submit your API."
    });
  }
});

// GENERATE DEVELOPER API KEY
app.post("/api/keys/generate", requireAuth, async (req, res) => {
  try {
    const name = typeof req.body?.name === "string"
      ? req.body.name.trim()
      : "";

    if (!name || name.length > 60) {
      return res.status(400).json({
        success: false,
        error: "Provide a key name between 1 and 60 characters."
      });
    }

    const rawKey =
      "divine_live_" +
      crypto.randomBytes(32).toString("base64url");

    const keyHash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const { data, error } = await userSupabase(req)
      .from("api_keys")
      .insert({
        user_id: req.user.id,
        name,
        key_prefix: rawKey.slice(0, 16),
        key_hash: keyHash
      })
      .select("id, name, key_prefix, created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Copy this key now. It will not be shown again.",
      api_key: rawKey,
      key: data
    });
  } catch (error) {
    console.error("Key generation error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not generate API key."
    });
  }
});

// LIST API KEYS
app.get("/api/keys", requireAuth, async (req, res) => {
  try {
    const { data, error } = await userSupabase(req)
      .from("api_keys")
      .select(
        "id, name, key_prefix, created_at, last_used_at, expires_at, revoked_at"
      )
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      keys: data
    });
  } catch (error) {
    console.error("Key list error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not load API keys."
    });
  }
});

// REVOKE API KEY
app.post("/api/keys/:id/revoke", requireAuth, async (req, res) => {
  try {
    const { data, error } = await userSupabase(req)
      .from("api_keys")
      .update({
        revoked_at: new Date().toISOString()
      })
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .is("revoked_at", null)
      .select("id, name, key_prefix, revoked_at")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        success: false,
        error: "Active API key not found."
      });
    }

    res.json({
      success: true,
      message: "API key revoked.",
      key: data
    });
  } catch (error) {
    console.error("Key revoke error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not revoke API key."
    });
  }
});

// TEST DEVELOPER API KEY
app.get("/api/developer/me", requireApiKey, (req, res) => {
  res.json({
    success: true,
    message: "API key authentication successful!",
    user_id: req.apiUser.id
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
        emailRedirectTo: FRONTEND_URL + "/"
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
      message: "Registration received. Check your email.",
      user: data.user
        ? { id: data.user.id, email: data.user.email }
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
    const { error } = await userSupabase(req).auth.signOut({
      scope: "local"
    });

    if (error) throw error;

    res.json({
      success: true,
      message: "Logout completed. Clear stored tokens in your app."
    });
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(400).json({
      success: false,
      error: "Logout failed."
    });
  }
});

// FORGOT PASSWORD
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = typeof req.body?.email === "string"
      ? req.body.email.trim()
      : "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address."
      });
    }

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: FRONTEND_URL + "/update-password.html"
    });

    if (error) throw error;

    res.json({
      success: true,
      message: "If the account exists, a reset email will be sent."
    });
  } catch (error) {
    console.error("Password reset error:", error.message);
    res.status(400).json({
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
      !message.trim() ||
      name.length > 80 ||
      message.length > 2000
    ) {
      return res.status(400).json({
        success: false,
        error: "Provide a valid name and message."
      });
    }

    const { error } = await supabase
      .from("messages")
      .insert({
        name: name.trim(),
        message: message.trim()
      });

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Your message was saved!"
    });
  } catch (error) {
    console.error("Message error:", error.message);
    res.status(500).json({
      success: false,
      error: "Could not save your message."
    });
  }
});

module.exports = app;
