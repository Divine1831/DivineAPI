const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();

const VERSION = "3.0.0";
const FRONTEND_URL = "https://divineapi-platform.vercel.app";
const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

app.use(cors({
  origin: FRONTEND_URL,
  methods: [...ALLOWED_METHODS, "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-api-key"]
}));

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

// --------------------------------------------------
// SUPABASE CONFIGURATION
// --------------------------------------------------

const {
  SUPABASE_URL,
  SUPABASE_KEY,
  SUPABASE_SERVICE_ROLE_KEY
} = process.env;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  throw new Error("Missing SUPABASE_URL or SUPABASE_KEY.");
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

// Privileged client: SERVER ONLY.
const adminSupabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

function userSupabase(token) {
  return createClient(SUPABASE_URL, SUPABASE_KEY, {
    global: {
      headers: {
        Authorization: `Bearer ${token}`
      }
    },
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });
}

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

// --------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";

  if (!token) {
    return sendError(res, 401, "Authentication required.");
  }

  try {
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return sendError(res, 401, "Invalid or expired access token.");
    }

    req.user = data.user;
    req.token = token;
    req.userClient = userSupabase(token);

    return next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    return sendError(res, 401, "Authentication failed.");
  }
}

// --------------------------------------------------
// ADMIN AUTHORIZATION
// --------------------------------------------------

async function requireAdmin(req, res, next) {
  try {
    const { data, error } = await adminSupabase
      .from("admin_users")
      .select("user_id, role")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) {
      console.error("Admin verification error:", error.message);
      return sendError(res, 500, "Could not verify admin permissions.");
    }

    if (!data || !["admin", "super_admin"].includes(data.role)) {
      return sendError(res, 403, "Administrator access required.");
    }

    req.adminRole = data.role;

    return next();
  } catch (error) {
    console.error("Admin middleware error:", error.message);
    return sendError(res, 500, "Admin verification failed.");
  }
}

async function requireSuperAdmin(req, res, next) {
  if (req.adminRole !== "super_admin") {
    return sendError(res, 403, "Super Admin access required.");
  }

  return next();
}

// --------------------------------------------------
// HOMEPAGE AND STATUS
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    name: "DivineAPI",
    description: "API marketplace and developer platform.",
    version: VERSION,
    status: "online"
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "DivineAPI",
    version: VERSION,
    status: "online"
  });
});

// --------------------------------------------------
// PROJECTS
// --------------------------------------------------

app.get("/api/projects", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("projects")
      .select("id, name, status, description, created_at")
      .order("created_at", { ascending: true });

    if (error) {
      console.error("Projects error:", error.message);
      return sendError(res, 500, "Could not load projects.");
    }

    return res.json({
      success: true,
      projects: data
    });
  } catch (error) {
    console.error("Projects error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// PUBLISH API
// --------------------------------------------------

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
      return sendError(res, 400, "Please provide all required API details.");
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
      return sendError(res, 400, "One or more fields are invalid or too long.");
    }

    const cleanSlug = slug.trim().toLowerCase();

    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(cleanSlug)) {
      return sendError(
        res,
        400,
        "Slug must use lowercase letters, numbers and hyphens."
      );
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
      return sendError(res, 400, "Enter a valid public HTTPS base URL.");
    }

    const selectedAuth = auth_type || "None";
    const allowedAuth = ["None", "API Key", "Bearer Token"];

    if (!allowedAuth.includes(selectedAuth)) {
      return sendError(res, 400, "Unsupported authentication type.");
    }

    const cleanVersion =
      typeof version === "string" && version.trim()
        ? version.trim()
        : "1.0.0";

    if (cleanVersion.length > 30) {
      return sendError(res, 400, "Version is too long.");
    }

    const { data, error } = await req.userClient
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
        return sendError(res, 409, "That API slug is already in use.");
      }

      return sendError(res, 500, "Could not submit your API.");
    }

    return res.status(201).json({
      success: true,
      message: "API submitted successfully. It is awaiting admin approval.",
      api: data
    });
  } catch (error) {
    console.error("API publishing error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// PUBLIC MARKETPLACE
// --------------------------------------------------

app.get("/api/marketplace/apis", async (req, res) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);

    const limit = Math.min(
      30,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 12)
    );

    const from = (page - 1) * limit;
    const to = from + limit - 1;

    let query = supabase
      .from("apis")
      .select(
        "id, name, slug, description, category, base_url, version, auth_type, status, created_at",
        { count: "exact" }
      )
      .eq("status", "Approved")
      .order("created_at", { ascending: false })
      .range(from, to);

    const search = typeof req.query.q === "string"
      ? req.query.q.trim().slice(0, 80)
      : "";

    const category = typeof req.query.category === "string"
      ? req.query.category.trim().slice(0, 60)
      : "";

    if (search) {
      const safeSearch = search.replace(/[,%()]/g, " ");
      query = query.ilike("name", `%${safeSearch}%`);
    }

    if (category) {
      query = query.ilike("category", category);
    }

    const { data, error, count } = await query;

    if (error) {
      console.error("Marketplace error:", error.message);
      return sendError(res, 500, "Could not load marketplace APIs.");
    }

    return res.json({
      success: true,
      page,
      limit,
      total: count || 0,
      total_pages: Math.ceil((count || 0) / limit),
      apis: data || []
    });
  } catch (error) {
    console.error("Marketplace error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// MARKETPLACE CATEGORIES
// --------------------------------------------------

app.get("/api/marketplace/categories", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("apis")
      .select("category")
      .eq("status", "Approved");

    if (error) {
      console.error("Category error:", error.message);
      return sendError(res, 500, "Could not load categories.");
    }

    const categories = [...new Set(
      (data || []).map(item => item.category).filter(Boolean)
    )].sort();

    return res.json({
      success: true,
      categories
    });
  } catch (error) {
    console.error("Category error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// SINGLE MARKETPLACE API
// --------------------------------------------------

app.get("/api/marketplace/apis/:slug", async (req, res) => {
  try {
    const slug = String(req.params.slug || "").trim().toLowerCase();

    const { data, error } = await supabase
      .from("apis")
      .select(
        "id, name, slug, description, category, base_url, version, auth_type, status, created_at"
      )
      .eq("slug", slug)
      .eq("status", "Approved")
      .maybeSingle();

    if (error) {
      console.error("API detail error:", error.message);
      return sendError(res, 500, "Could not load API details.");
    }

    if (!data) {
      return sendError(res, 404, "API not found.");
    }

    return res.json({
      success: true,
      api: data
    });
  } catch (error) {
    console.error("API detail error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// API PROVIDER DOCUMENTATION
// --------------------------------------------------

// Validate endpoint paths
function validEndpointPath(path) {
  return (
    typeof path === "string" &&
    path.length <= 200 &&
    path.startsWith("/") &&
    !path.startsWith("//") &&
    !/[?#\s]/.test(path)
  );
}

// Validate documentation data
function validateEndpointBody(body, partial = false) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "A valid JSON request body is required.";
  }

  if (!partial || body.name !== undefined) {
    if (
      typeof body.name !== "string" ||
      !body.name.trim() ||
      body.name.length > 100
    ) {
      return "Endpoint name must be 1 to 100 characters.";
    }
  }

  if (!partial || body.method !== undefined) {
    if (!ALLOWED_METHODS.includes(body.method)) {
      return "Method must be GET, POST, PUT, PATCH or DELETE.";
    }
  }

  if (!partial || body.path !== undefined) {
    if (!validEndpointPath(body.path)) {
      return "Enter a valid endpoint path beginning with /.";
    }
  }

  if (!partial || body.description !== undefined) {
    if (
      typeof body.description !== "string" ||
      !body.description.trim() ||
      body.description.length > 2000
    ) {
      return "Description must be 1 to 2000 characters.";
    }
  }

  if (body.parameters !== undefined) {
    if (
      !Array.isArray(body.parameters) ||
      body.parameters.length > 50
    ) {
      return "Parameters must be an array containing at most 50 items.";
    }
  }

  for (const field of ["request_example", "response_example"]) {
    if (
      body[field] !== undefined &&
      body[field] !== null &&
      typeof body[field] !== "object"
    ) {
      return `${field} must be a JSON object or array.`;
    }
  }

  return null;
}

// ADD ENDPOINT DOCUMENTATION
app.post(
  "/api/marketplace/apis/:slug/endpoints",
  requireAuth,
  async (req, res) => {
    try {
      const slug = String(req.params.slug || "").trim().toLowerCase();

      const validationError = validateEndpointBody(req.body);

      if (validationError) {
        return sendError(res, 400, validationError);
      }

      const { data: api, error: apiError } = await req.userClient
        .from("apis")
        .select("id, provider_id, slug")
        .eq("slug", slug)
        .eq("provider_id", req.user.id)
        .maybeSingle();

      if (apiError) {
        console.error("Endpoint API lookup error:", apiError.message);
        return sendError(res, 500, "Could not verify API ownership.");
      }

      if (!api) {
        return sendError(res, 404, "Your API was not found.");
      }

      const {
        name,
        method,
        path,
        description,
        parameters = [],
        request_example = null,
        response_example = null
      } = req.body;

      const { data, error } = await req.userClient
        .from("api_endpoints")
        .insert({
          api_id: api.id,
          provider_id: req.user.id,
          name: name.trim(),
          method,
          path,
          description: description.trim(),
          parameters,
          request_example,
          response_example
        })
        .select(
          "id, api_id, name, method, path, description, parameters, request_example, response_example, created_at, updated_at"
        )
        .single();

      if (error) {
        console.error("Add endpoint error:", error.message);
        return sendError(res, 500, "Could not save endpoint documentation.");
      }

      return res.status(201).json({
        success: true,
        message: "Endpoint documentation created.",
        endpoint: data
      });
    } catch (error) {
      console.error("Add endpoint error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// LIST DOCUMENTATION FOR AN APPROVED API
app.get(
  "/api/marketplace/apis/:slug/endpoints",
  async (req, res) => {
    try {
      const slug = String(req.params.slug || "").trim().toLowerCase();

      const { data: api, error: apiError } = await supabase
        .from("apis")
        .select("id, slug")
        .eq("slug", slug)
        .eq("status", "Approved")
        .maybeSingle();

      if (apiError) {
        console.error("Endpoint API lookup error:", apiError.message);
        return sendError(res, 500, "Could not load API information.");
      }

      if (!api) {
        return sendError(res, 404, "Approved API not found.");
      }

      const { data, error } = await supabase
        .from("api_endpoints")
        .select(
          "id, name, method, path, description, parameters, request_example, response_example, created_at, updated_at"
        )
        .eq("api_id", api.id)
        .order("created_at", { ascending: true });

      if (error) {
        console.error("List endpoints error:", error.message);
        return sendError(res, 500, "Could not load endpoint documentation.");
      }

      return res.json({
        success: true,
        api_slug: api.slug,
        total: (data || []).length,
        endpoints: data || []
      });
    } catch (error) {
      console.error("List endpoints error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// EDIT ENDPOINT DOCUMENTATION
app.patch(
  "/api/marketplace/endpoints/:id",
  requireAuth,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validUuid(id)) {
        return sendError(res, 400, "Invalid endpoint ID.");
      }

      const validationError = validateEndpointBody(req.body, true);

      if (validationError) {
        return sendError(res, 400, validationError);
      }

      const allowedFields = [
        "name",
        "method",
        "path",
        "description",
        "parameters",
        "request_example",
        "response_example"
      ];

      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];

          if (field === "name" || field === "description") {
            updates[field] = req.body[field].trim();
          }
        }
      }

      if (Object.keys(updates).length === 0) {
        return sendError(res, 400, "Provide at least one field to update.");
      }

      updates.updated_at = new Date().toISOString();

      const { data, error } = await req.userClient
        .from("api_endpoints")
        .update(updates)
        .eq("id", id)
        .select(
          "id, name, method, path, description, parameters, request_example, response_example, updated_at"
        )
        .maybeSingle();

      if (error) {
        console.error("Update endpoint error:", error.message);
        return sendError(res, 500, "Could not update endpoint documentation.");
      }

      if (!data) {
        return sendError(
          res,
          404,
          "Endpoint not found or you do not own it."
        );
      }

      return res.json({
        success: true,
        message: "Endpoint documentation updated.",
        endpoint: data
      });
    } catch (error) {
      console.error("Update endpoint error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// DELETE ENDPOINT DOCUMENTATION
app.delete(
  "/api/marketplace/endpoints/:id",
  requireAuth,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validUuid(id)) {
        return sendError(res, 400, "Invalid endpoint ID.");
      }

      const { data, error } = await req.userClient
        .from("api_endpoints")
        .delete()
        .eq("id", id)
        .select("id, name")
        .maybeSingle();

      if (error) {
        console.error("Delete endpoint error:", error.message);
        return sendError(res, 500, "Could not delete endpoint documentation.");
      }

      if (!data) {
        return sendError(
          res,
          404,
          "Endpoint not found or you do not own it."
        );
      }

      return res.json({
        success: true,
        message: "Endpoint documentation deleted.",
        endpoint: data
      });
    } catch (error) {
      console.error("Delete endpoint error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// --------------------------------------------------
// ADMIN DASHBOARD
// --------------------------------------------------

app.get(
  "/api/admin/dashboard",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const { count: pendingCount, error: pendingError } =
        await adminSupabase
          .from("apis")
          .select("id", { count: "exact", head: true })
          .eq("status", "Pending");

      if (pendingError) throw pendingError;

      const { count: approvedCount, error: approvedError } =
        await adminSupabase
          .from("apis")
          .select("id", { count: "exact", head: true })
          .eq("status", "Approved");

      if (approvedError) throw approvedError;

      const { count: rejectedCount, error: rejectedError } =
        await adminSupabase
          .from("apis")
          .select("id", { count: "exact", head: true })
          .eq("status", "Rejected");

      if (rejectedError) throw rejectedError;

      return res.json({
        success: true,
        admin: {
          user_id: req.user.id,
          email: req.user.email,
          role: req.adminRole
        },
        statistics: {
          pending: pendingCount || 0,
          approved: approvedCount || 0,
          rejected: rejectedCount || 0
        }
      });
    } catch (error) {
      console.error("Admin dashboard error:", error.message);
      return sendError(res, 500, "Could not load admin dashboard.");
    }
  }
);

// LIST PENDING SUBMISSIONS
app.get(
  "/api/admin/apis/pending",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await adminSupabase
        .from("apis")
        .select(
          "id, provider_id, name, slug, description, category, base_url, version, auth_type, status, created_at"
        )
        .eq("status", "Pending")
        .order("created_at", { ascending: true });

      if (error) {
        console.error("Pending APIs error:", error.message);
        return sendError(res, 500, "Could not load pending submissions.");
      }

      return res.json({
        success: true,
        apis: data || []
      });
    } catch (error) {
      console.error("Pending APIs error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// APPROVE A PENDING API
app.post(
  "/api/admin/apis/:id/approve",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validUuid(id)) {
        return sendError(res, 400, "Invalid API ID.");
      }

      const { data, error } = await adminSupabase
        .from("apis")
        .update({ status: "Approved" })
        .eq("id", id)
        .eq("status", "Pending")
        .select("id, name, slug, status")
        .maybeSingle();

      if (error) {
        console.error("Approve API error:", error.message);
        return sendError(res, 500, "Could not approve API.");
      }

      if (!data) {
        return sendError(res, 404, "Pending API not found.");
      }

      return res.json({
        success: true,
        message: "API approved and published.",
        api: data
      });
    } catch (error) {
      console.error("Approve API error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// REJECT A PENDING API
app.post(
  "/api/admin/apis/:id/reject",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validUuid(id)) {
        return sendError(res, 400, "Invalid API ID.");
      }

      const { data, error } = await adminSupabase
        .from("apis")
        .update({ status: "Rejected" })
        .eq("id", id)
        .eq("status", "Pending")
        .select("id, name, slug, status")
        .maybeSingle();

      if (error) {
        console.error("Reject API error:", error.message);
        return sendError(res, 500, "Could not reject API.");
      }

      if (!data) {
        return sendError(res, 404, "Pending API not found.");
      }

      return res.json({
        success: true,
        message: "API submission rejected.",
        api: data
      });
    } catch (error) {
      console.error("Reject API error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// ONLY SUPER ADMIN CAN ADD ANOTHER ADMIN
app.post(
  "/api/admin/admins",
  requireAuth,
  requireAdmin,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { user_id, role } = req.body || {};

      if (!validUuid(user_id)) {
        return sendError(res, 400, "A valid user ID is required.");
      }

      if (!["admin", "super_admin"].includes(role)) {
        return sendError(res, 400, "Invalid admin role.");
      }

      const { data, error } = await adminSupabase
        .from("admin_users")
        .upsert(
          { user_id, role },
          { onConflict: "user_id" }
        )
        .select("user_id, role")
        .single();

      if (error) {
        console.error("Add admin error:", error.message);
        return sendError(res, 500, "Could not add administrator.");
      }

      return res.status(201).json({
        success: true,
        message: "Administrator role updated.",
        admin: data
      });
    } catch (error) {
      console.error("Add admin error:", error.message);
      return sendError(res, 500, "Unexpected server error.");
    }
  }
);

// --------------------------------------------------
// API KEY MANAGEMENT
// --------------------------------------------------

// GENERATE A DEVELOPER API KEY
app.post("/api/keys/generate", requireAuth, async (req, res) => {
  try {
    const name = typeof req.body?.name === "string"
      ? req.body.name.trim()
      : "";

    if (!name || name.length > 60) {
      return sendError(res, 400, "Key name must be 1 to 60 characters.");
    }

    const rawKey =
      "divine_live_" + crypto.randomBytes(32).toString("base64url");

    const keyHash = sha256(rawKey);
    const keyPrefix = rawKey.slice(0, 18);

    const { data, error } = await req.userClient
      .from("api_keys")
      .insert({
        user_id: req.user.id,
        name,
        key_prefix: keyPrefix,
        key_hash: keyHash
      })
      .select("id, name, key_prefix, created_at")
      .single();

    if (error) {
      console.error("Key generation error:", error.message);
      return sendError(res, 500, "Could not generate API key.");
    }

    return res.status(201).json({
      success: true,
      message: "API key created. Copy it now; it will not be shown again.",
      key: rawKey,
      api_key: data
    });
  } catch (error) {
    console.error("Key generation error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// LIST USER'S API KEYS
app.get("/api/keys", requireAuth, async (req, res) => {
  try {
    const { data, error } = await req.userClient
      .from("api_keys")
      .select(
        "id, name, key_prefix, created_at, last_used_at, expires_at, revoked_at"
      )
      .order("created_at", { ascending: false });

    if (error) {
      console.error("List keys error:", error.message);
      return sendError(res, 500, "Could not load API keys.");
    }

    return res.json({
      success: true,
      keys: data || []
    });
  } catch (error) {
    console.error("List keys error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// REVOKE A USER'S OWN KEY
app.post("/api/keys/:id/revoke", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    if (!validUuid(id)) {
      return sendError(res, 400, "Invalid API key ID.");
    }

    const { data, error } = await req.userClient
      .from("api_keys")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", id)
      .is("revoked_at", null)
      .select("id, name, revoked_at")
      .maybeSingle();

    if (error) {
      console.error("Revoke key error:", error.message);
      return sendError(res, 500, "Could not revoke API key.");
    }

    if (!data) {
      return sendError(res, 404, "Active API key not found.");
    }

    return res.json({
      success: true,
      message: "API key revoked.",
      key: data
    });
  } catch (error) {
    console.error("Revoke key error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// API KEY AUTHENTICATION
// --------------------------------------------------

async function requireApiKey(req, res, next) {
  const rawKey = req.headers["x-api-key"];

  if (typeof rawKey !== "string" || !rawKey.startsWith("divine_live_")) {
    return sendError(res, 401, "A valid x-api-key header is required.");
  }

  try {
    const keyHash = sha256(rawKey);

    const { data, error } = await adminSupabase
      .from("api_keys")
      .select("id, user_id, revoked_at, expires_at")
      .eq("key_hash", keyHash)
      .maybeSingle();

    if (error) {
      console.error("API key lookup error:", error.message);
      return sendError(res, 500, "Could not verify API key.");
    }

    if (!data || data.revoked_at) {
      return sendError(res, 401, "Invalid or revoked API key.");
    }

    if (data.expires_at && new Date(data.expires_at) <= new Date()) {
      return sendError(res, 401, "API key has expired.");
    }

    await adminSupabase
      .from("api_keys")
      .update({ last_used_at: new Date().toISOString() })
      .eq("id", data.id);

    req.apiKey = {
      id: data.id,
      user_id: data.user_id
    };

    return next();
  } catch (error) {
    console.error("API key authentication error:", error.message);
    return sendError(res, 500, "API key verification failed.");
  }
}

// DEVELOPER TEST ENDPOINT
app.get("/api/developer/me", requireApiKey, (req, res) => {
  return res.json({
    success: true,
    message: "Developer API key verified.",
    developer: {
      user_id: req.apiKey.user_id
    }
  });
});

// --------------------------------------------------
// AUTH REGISTER
// --------------------------------------------------

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
      return sendError(
        res,
        400,
        "Enter a valid email and password of at least 8 characters."
      );
    }

    const { data, error } = await supabase.auth.signUp({
      email: email.trim(),
      password,
      options: {
        emailRedirectTo: FRONTEND_URL + "/"
      }
    });

    if (error) {
      return sendError(res, 400, error.message);
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
    return sendError(res, 500, "Registration failed.");
  }
});

// --------------------------------------------------
// AUTH LOGIN
// --------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return sendError(res, 400, "Email and password are required.");
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password
    });

    if (error || !data.session) {
      return sendError(
        res,
        401,
        "Login failed. Check your details and email verification."
      );
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
    return sendError(res, 500, "Login failed.");
  }
});

// --------------------------------------------------
// CURRENT USER
// --------------------------------------------------

app.get("/api/auth/me", requireAuth, (req, res) => {
  return res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email
    }
  });
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    const { error } = await req.userClient.auth.signOut({
      scope: "local"
    });

    if (error) {
      console.error("Logout error:", error.message);
      return sendError(res, 400, "Logout failed.");
    }

    return res.json({
      success: true,
      message: "Logout request completed. Clear stored tokens in your app."
    });
  } catch (error) {
    console.error("Logout error:", error.message);
    return sendError(res, 500, "Logout failed.");
  }
});

// --------------------------------------------------
// FORGOT PASSWORD
// --------------------------------------------------

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = typeof req.body?.email === "string"
      ? req.body.email.trim()
      : "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return sendError(res, 400, "Please provide a valid email address.");
    }

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: FRONTEND_URL + "/update-password.html"
    });

    if (error) {
      console.error("Password reset error:", error.message);
      return sendError(res, 400, error.message);
    }

    return res.json({
      success: true,
      message: "If the account exists, a reset email will be sent."
    });
  } catch (error) {
    console.error("Forgot password error:", error.message);
    return sendError(res, 500, "Password reset request failed.");
  }
});

// --------------------------------------------------
// SAVE MESSAGE
// --------------------------------------------------

app.post("/api/message", async (req, res) => {
  try {
    const { name, message } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof message !== "string" ||
      !name.trim() ||
      !message.trim()
    ) {
      return sendError(res, 400, "A valid name and message are required.");
    }

    if (name.length > 80 || message.length > 2000) {
      return sendError(res, 400, "Name or message is too long.");
    }

    const { error } = await supabase
      .from("messages")
      .insert({
        name: name.trim(),
        message: message.trim()
      });

    if (error) {
      console.error("Message error:", error.message);
      return sendError(res, 500, "Could not save the message.");
    }

    return res.status(201).json({
      success: true,
      message: "Your message was saved!"
    });
  } catch (error) {
    console.error("Message error:", error.message);
    return sendError(res, 500, "Unexpected server error.");
  }
});

// --------------------------------------------------
// EXPORT FOR VERCEL
// --------------------------------------------------

module.exports = app;
