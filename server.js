import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

dotenv.config();

const requiredEnv = [
    "PORT",
    "SESSION_SECRET",
    "JWT_SECRET",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_CALLBACK_URL",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
];

for (const k of requiredEnv) {
    if (!process.env[k]) {
        console.error(`Missing env var: ${k}`);
        process.exit(1);
    }
}
const redirect_url = process.env.REDIRECT_URL || "http://localhost:5173";
const app = express();
app.set("trust proxy", 1);
app.use(express.json());

app.use(cors({
    origin: [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:3939",
        "https://qzizzlearn.vercel.app",
        "https://qzizz-backend.onrender.com",
        /\.vercel\.app$/,
    ],
    credentials: true,
}));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        proxy: true, // Added for production behind proxy (Render)
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 1000 * 60 * 60,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function issueJwt(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const claims = jwt.verify(token, process.env.JWT_SECRET);
        req.user = claims;
        next();
    } catch (e) {
        return res.status(403).json({ error: "Invalid or expired token" });
    }
}

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
            proxy: true, // Added for correct callback handling behind proxy
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                console.log("Google profile received:", profile); // Debug log

                const email =
                    profile.emails && profile.emails.length ? profile.emails[0].value : null;
                const name = profile.displayName || "";

                if (!email) {
                    console.error("No email in Google profile"); // Debug log
                    return done(new Error("No email returned by Google profile"));
                }

                const { data: existing, error: selErr } = await supabase
                    .from("userinfo")
                    .select("*")
                    .eq("mail", email)
                    .maybeSingle();

                if (selErr) {
                    console.error("Database error during user lookup:", selErr);
                    return done(selErr);
                }

                let dbUser = existing;

                // If user doesn't exist, create new user
                if (!existing) {
                    const { data: inserted, error: insErr } = await supabase
                        .from("userinfo")
                        .insert([
                            {
                                mail: email,
                                name: name,
                                pass: "google-auth",
                                accr_tm: new Date().toISOString(),
                                lstlogin_tm: new Date().toISOString(),
                            },
                        ])
                        .select()
                        .single();

                    if (insErr) {
                        console.error("Database error during user creation:", insErr);
                        return done(insErr);
                    }
                    dbUser = inserted;
                } else {
                    const { error: updateErr } = await supabase
                        .from("userinfo")
                        .update({ lstlogin_tm: new Date().toISOString() })
                        .eq("mail", email);

                    if (updateErr) {
                        console.error("Database error during login update:", updateErr);
                    }
                }

                return done(null, {
                    appUserId: dbUser.id,
                    appUserEmail: email,
                    name: dbUser.name,
                });
            } catch (e) {
                console.error("Detailed Google OAuth error:", e); // Enhanced logging
                return done(e);
            }
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    done(null, obj);
});

// Single root route
app.get("/", (req, res) => {
    res.json({ ok: true, message: "Auth server running" });
});

app.post("/signup", async (req, res) => {
    try {
        const { mail, pass } = req.body;
        const name = mail && mail.split ? mail.split("@")[0] : "";
        if (!mail || !pass) {
            return res.status(400).json({ error: "mail and pass required" });
        }

        // Check if user already exists
        const { data: existing, error: selErr } = await supabase
            .from("user")
            .select("*")
            .eq("email", mail)
            .maybeSingle();

        if (selErr) {
            console.error("Database error during signup lookup:", selErr);
            return res.status(500).json({ error: "Database error" });
        }

        if (existing) {
            return res.status(409).json({ error: "User already exists" });
        }

        // Hash password
        const hashed = await bcrypt.hash(pass, 12);

        // Create new user
        const { data: inserted, error: insErr } = await supabase
            .from("user")
            .insert([
                {
                    name: name || "",
                    email: mail,
                    role: "warehouse_operator",
                    password_hash: hashed,
                    created_at: new Date().toISOString(),
                },
            ])
            .select()
            .single();

        if (insErr) {
            console.error("Database error during signup:", insErr);
            return res.status(500).json({ error: "Failed to create user" });
        }

        const token = issueJwt({ id: inserted.id, email: inserted.email });
        return res.json({
            ok: true,
            token,
            user: { id: inserted.id, email: inserted.email, name: inserted.name }
        });
    } catch (e) {
        console.error("Signup error:", e);
        return res.status(500).json({ error: "Signup failed" });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { mail, pass } = req.body;
        if (!mail || !pass) {
            return res.status(400).json({ error: "mail and pass required" });
        }

        // Find user
        const { data: user, error: selErr } = await supabase
            .from("user")
            .select("*")
            .eq("email", mail)
            .maybeSingle();

        if (selErr) {
            console.error("Database error during login:", selErr);
            return res.status(500).json({ error: "Database error" });
        }

        if (!user || !user.password_hash) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(pass, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = issueJwt({ id: user.id, email: user.email });
        return res.json({
            ok: true,
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (e) {
        console.error("Login error:", e);
        return res.status(500).json({ error: "Login failed" });
    }
});

app.get(
    "/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
        session: true
    })
);

app.get(
    "/auth/google/callback",
    (req, res, next) => {
        console.log("=== OAUTH CALLBACK DEBUG ===");
        console.log("Query params:", req.query);
        console.log("Session before auth:", req.session);
        console.log("Headers:", JSON.stringify(req.headers, null, 2));
        console.log("Environment check:", {
            NODE_ENV: process.env.NODE_ENV,
            CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL
        });
        next();
    },
    (req, res, next) => {
        passport.authenticate("google", {
            failureRedirect: "/auth/failure",
            session: true,
        })(req, res, (err) => {
            if (err) {
                console.error("Passport authenticate error:", err);
                return res.redirect(`${redirect_url}/?error=auth_error`);
            }
            next();
        });
    },
    (req, res) => {
        try {
            console.log("=== AUTH SUCCESS ===");
            console.log("User:", req.user);
            console.log("Session after auth:", req.session);

            const user = req.user;
            if (!user || !user.appUserId || !user.appUserEmail) {
                console.error("User identity not resolved:", user);
                return res.redirect(`${redirect_url}/?error=auth_failed`);
            }

            const token = issueJwt({ id: user.appUserId, email: user.appUserEmail });
            res.redirect(`${redirect_url}/?token=${token}&ok=true`);
        } catch (e) {
            console.error("Error in Google callback:", e);
            res.redirect(`${redirect_url}/?error=callback_failed`);
        }
    }
);

// Auth failure route
app.get("/auth/failure", (req, res) => {
    res.redirect(`${redirect_url}/?error=auth_failed`);
});

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
    res.json({ message: "This is protected", user: req.user });
});

// Logout
app.post("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).json({ error: "Logout failed" });
        }
        req.session.destroy((err) => {
            if (err) {
                console.error("Session destroy error:", err);
                return res.status(500).json({ error: "Session cleanup failed" });
            }
            res.json({ ok: true });
        });
    });
});

app.post("/warehouses", authenticateToken, async (req, res) => {
  try {
    const email = req.body.mail;

    // 1) find user_id from email
    const { data: users, error: error1 } = await supabase
      .from("user")
      .select("user_id")
      .eq("email", email);

    if (error1) {
      console.error("Database error fetching user:", error1);
      return res.status(500).json({ error: "Database error" });
    }

    if (!users || users.length === 0) {
      console.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    const userId = users[0].user_id;

    // 2) get warehouses for that user
    const { data: warehouses, error: error2 } = await supabase
      .from("warehouse")
      .select("*")
      .eq("user_id", userId);

    if (error2) {
      console.error("Database error fetching warehouse data:", error2);
      return res.status(500).json({ error: "Database error" });
    }

    // 3) get alerts for that user
    const { data: alerts, error: alertsErr } = await supabase
      .from("alert")
      .select("*")
      .eq("user_id", userId)
      .eq("is_resolved", false)
      .order("created_at", { ascending: false });

    if (alertsErr) {
      console.error("Database error fetching alerts:", alertsErr);
      return res.status(500).json({ error: "Database error fetching alerts" });
    }

    const alertsCount = alerts ? alerts.length : 0;

    // 4) send everything in one response
    return res.status(200).json({
      warehouses: warehouses || [],
      alerts: alerts || [],
      alertsCount,
    });
  } catch (e) {
    console.error("Unexpected error in /warehouses:", e);
    return res.status(500).json({ error: "Server error" });
  }
});
app.post("/create-warehouse", authenticateToken, async (req, res) => {
    try {
        const email = req.user && req.user.email;
        const { name, location, capacity } = req.body;

        if (!email) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        if (!name || !location || typeof capacity === "undefined") {
            return res.status(400).json({ error: "name, location and capacity are required" });
        }

        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", email)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
            console.error("User not found for email:", email);
            return res.status(404).json({ error: "User not found" });
        }

        const { data: created, error: insertErr } = await supabase
            .from("warehouse")
            .insert([
                {
                    user_id: user.user_id,
                    location,
                    storage_capacity: capacity,
                    name,
                    created_at: new Date().toISOString(),
                },
            ])
            .select()
            .single();

        if (insertErr) {
            console.error("Database error creating warehouse:", insertErr);
            return res.status(500).json({ error: "Database error creating warehouse" });
        }

        res.status(201).json({ message: "Warehouse created successfully", warehouse: created });
    } catch (e) {
        console.error("Create warehouse error:", e);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/getinfo_warehouse", authenticateToken, async (req, res) => {
    try {
        const warehouse_id = req.body.warehouse_id;
        if (!warehouse_id) {
            return res.status(400).json({ error: "warehouse_id is required" });
        }

        // Fetch single warehouse row
        const { data: warehouse, error: whErr } = await supabase
            .from("warehouse")
            .select("*")
            .eq("id", warehouse_id)
            .maybeSingle();

        if (whErr) {
            console.error("Database error fetching warehouse:", whErr);
            return res.status(500).json({ error: "Database error fetching warehouse" });
        }

        if (!warehouse) {
            console.error("Warehouse not found for id:", warehouse_id);
            return res.status(404).json({ error: "Warehouse not found" });
        }

        // Fetch batches for that warehouse (can be empty array)
        const { data: batches, error: batchesErr } = await supabase
            .from("batches")
            .select("*")
            .eq("warehouse_id", warehouse_id);

        if (batchesErr) {
            console.error("Database error fetching batches:", batchesErr);
            return res.status(500).json({ error: "Database error fetching batches" });
        }

        return res.status(200).json({ warehouse, batches });
    } catch (e) {
        console.error("Unexpected error in getinfo_warehouse:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/get-products-sensors", authenticateToken, async (req, res) => {
    try {
        const { warehouseId, mail } = req.body;
        if (!warehouseId || !mail) {
            return res.status(400).json({ error: "warehouseId and mail are required" });
        }

        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error fetching user" });
        }
        if (!user) {
            console.error("User not found for email:", mail);
            return res.status(404).json({ error: "User not found" });
        }

        const { data: products, error: productsErr } = await supabase
            .from("products")
            .select("*")
            .eq("user_id", user.user_id);

        if (productsErr) {
            console.error("Database error fetching products:", productsErr);
            return res.status(500).json({ error: "Database error fetching products" });
        }
        const { data: sensors, error: sensorsErr } = await supabase
            .from("sensor_device")
            .select("*")
            .eq("warehouse_id", warehouseId);

        if (sensorsErr) {
            console.error("Database error fetching sensors opoppopop:", sensorsErr);
            return res.status(500).json({ error: "Database error fetching sensors" });
        }

        return res.status(200).json({ products, sensors });
    } catch (e) {
        console.error("Unexpected error in get-products-sensors:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/getproducts", authenticateToken, async (req, res) => {
    try {
        const email = req.body.mail;
        const { data, error: error1 } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", email);
        if (error1) {
            console.error("Database error fetching user:", error1);
            return res.status(500).json({ error: "Database error" });
        }
        if (!data || data.length === 0) {
            console.error("User not found");
            return res.status(404).json({ error: "User not found" });
        }
        const { data: products, error: error2 } = await supabase
            .from("products")
            .select("*")
            .eq("user_id", data[0].user_id);
        if (error2) {
            console.error("Database error fetching products:", error2);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(200).json({ products });
    } catch (e) {
        console.error("Get products error:", e);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/delete-product", authenticateToken, async (req, res) => {
    try {
        const product_id = req.body.product_id;

        const { error } = await supabase
            .from("products")
            .delete()
            .eq("product_id", product_id);

        if (error) {
            console.error("Database error deleting product:", error);
            return res.status(500).json({ error: "Database error deleting product" });
        }

        return res.status(200).json({ message: "Product deleted successfully" });
    } catch (e) {
        console.error("Delete product error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/create-product", authenticateToken, async (req, res) => {
    try {
        const { name, description, mail, min_temp, max_temp, min_humi, max_humi } = req.body;
        console.log("Create product request body:", req.body);

        if (!name || !description || !mail) {
            return res.status(400).json({ error: "name, description and mail are required" });
        }

        // Fetch user and ensure exists
        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
            console.error("User not found for email:", mail);
            return res.status(404).json({ error: "User not found" });
        }

        // Insert product and return the created row
        const { data: created, error: insertErr } = await supabase
            .from("products")
            .insert([
                {
                    product_name: name,
                    description,
                    user_id: user.user_id,
                    min_temp: min_temp ?? null,
                    max_temp: max_temp ?? null,
                    min_humidity: min_humi ?? null,
                    max_humidity: max_humi ?? null
                }
            ])
            .select()
            .single();

        if (insertErr) {
            console.error("Database error creating product:", insertErr);
            return res.status(500).json({ error: "Database error creating product" });
        }

        return res.status(201).json({ message: "Product created successfully", product: created });
    } catch (e) {
        console.error("Create product error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

// GET SENSORS  -->  POST /getsensors
app.post("/getsensors", authenticateToken, async (req, res) => {
    try {
        const email = req.body.mail;
        const warehouseId = req.body.warehouseId;

        if (!email || !warehouseId) {
            return res.status(400).json({ error: "mail and warehouseId are required" });
        }

        const { data: userRows, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", email);

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!userRows || userRows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        const userId = userRows[0].user_id;

        const { data: sensors, error: sensorErr } = await supabase
            .from("sensor_device")  
            .select("*")
            .eq("status",false)
            .eq("warehouse_id", warehouseId);

        if (sensorErr) {
            console.error("Database error fetching sensors:", sensorErr);
            return res.status(500).json({ error: "Database error" });
        }

        return res.status(200).json({ sensors });
    } catch (e) {
        console.error("Get sensors error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/getallsensors", authenticateToken, async (req, res) => {
    try {
        const email = req.body.mail;
        const warehouseId = req.body.warehouseId;

        if (!email || !warehouseId) {
            return res.status(400).json({ error: "mail and warehouseId are required" });
        }

        const { data: userRows, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", email);

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!userRows || userRows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        const userId = userRows[0].user_id;

        const { data: sensors, error: sensorErr } = await supabase
            .from("sensor_device")  
            .select("*")
            .eq("warehouse_id", warehouseId);

        if (sensorErr) {
            console.error("Database error fetching sensors:", sensorErr);
            return res.status(500).json({ error: "Database error" });
        }

        return res.status(200).json({ sensors });
    } catch (e) {
        console.error("Get sensors error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});


// CREATE SENSOR  -->  POST /creatsensor
app.post("/creatsensor", authenticateToken, async (req, res) => {
    try {
        const {
            mail,
            warehouseId,
            ip_address,
            sensor_type,
            device_id,
        } = req.body;

        if (!mail || !warehouseId || !ip_address || !sensor_type) {
            return res
                .status(400)
                .json({ error: "mail, warehouseId, ip_address and sensor_type are required" });
        }

        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const { data: created, error: insertErr } = await supabase
            .from("sensor_device")   // or "sensors"
            .insert([
                {
                    warehouse_id: warehouseId,
                    ip_address,
                    status: false,
                    sensor_type,
                    device_id: device_id ?? null,
                    installed_on: new Date().toISOString(),
                },
            ])
            .select()
            .single();

        if (insertErr) {
            console.error("Database error creating sensor:", insertErr);
            return res.status(500).json({ error: "Database error creating sensor" });
        }

        return res
            .status(201)
            .json({ message: "Sensor created successfully", sensor: created });
    } catch (e) {
        console.error("Create sensor error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/create-batch", authenticateToken, async (req, res) => {
    try {
        const { mail, warehouseId, productId, sensorId, quantity } = req.body;
        console.log("Create batch request body:", req.body);

        if (
            mail == null ||
            warehouseId == null ||
            productId == null ||
            sensorId == null ||
            quantity == null
        ) {
            return res.status(400).json({
                error:
                    "mail, warehouseId, productId, sensorId, quantity are required",
            });
        }

        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const { data: createdBatch, error: batchErr } = await supabase
            .from("batches")
            .insert([
                {
                    product_id: productId,      // use as-is
                    warehouse_id: warehouseId,
                    number_of_batches: quantity,
                    sensor_id: sensorId,
                },
            ])
            .select()
            .single();

        if (batchErr) {
            console.error("Database error creating batch:", batchErr);
            return res
                .status(500)
                .json({ error: "Database error creating batch" });
        }

        const { error: sensorUpdateErr } = await supabase
            .from("sensor_device")
            .update({
                status: true,
                batch_id: createdBatch.batch_id,
            })
            .eq("sensor_id", sensorId);

        if (sensorUpdateErr) {
            console.error("Database error updating sensor:", sensorUpdateErr);
            return res
                .status(500)
                .json({ error: "Database error assigning sensor" });
        }

        return res.status(201).json({
            message: "Batch created and sensor assigned successfully",
            batch: createdBatch,
        });
    } catch (e) {
        console.error("Create batch error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});

app.post("/delete-batch", authenticateToken, async (req, res) => {
    try {
        const { mail, batchId } = req.body;
        console.log("Delete batch request:", req.body);

        if (!mail || !batchId) {
            return res
                .status(400)
                .json({ error: "mail and batchId are required" });
        }

        // verify user exists (optional but consistent with other routes)
        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Database error fetching user:", userErr);
            return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // free sensor linked to this batch (set status back to available)
        const { error: sensorUpdateErr } = await supabase
            .from("sensor_device")
            .update({
                status: false,
                batch_id: null,
            })
            .eq("batch_id", batchId);

        if (sensorUpdateErr) {
            console.error("Database error updating sensor on delete:", sensorUpdateErr);
            return res
                .status(500)
                .json({ error: "Database error releasing sensor" });
        }

        // delete batch itself
        const { error: deleteErr } = await supabase
            .from("batches")
            .delete()
            .eq("id", batchId);

        if (deleteErr) {
            console.error("Database error deleting batch:", deleteErr);
            return res
                .status(500)
                .json({ error: "Database error deleting batch" });
        }

        return res
            .status(200)
            .json({ message: "Batch deleted (outboarded) successfully" });
    } catch (e) {
        console.error("Delete batch error:", e);
        return res.status(500).json({ error: "Server error" });
    }
});


// Get all alerts for a user (used by Home + Alerts page)
app.post("/alerts", authenticateToken, async (req, res) => {
  try {
    const { mail } = req.body;
    console.log("ALERTS /alerts mail =", mail);

    if (!mail) {
      return res.status(400).json({ error: "mail is required" });
    }

    // find user_id for this email
    const { data: user, error: userErr } = await supabase
      .from("user")
      .select("user_id, email")
      .eq("email", mail)
      .maybeSingle();

    console.log("ALERTS user =", user, "err =", userErr);

    if (userErr) {
      return res.status(500).json({ error: "Database error fetching user" });
    }
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // fetch alerts belonging to that user
    const { data: alerts, error: alertsErr } = await supabase
      .from("alert")
      .select("*")
      .eq("user_id", user.user_id)
      .eq("is_resolved", false)
      .order("created_at", { ascending: false });

    if (alertsErr) {
      console.error("Database error fetching alerts:", alertsErr);
      return res.status(500).json({ error: "Database error fetching alerts" });
    }

    console.log(
      "ALERTS returning",
      alerts ? alerts.length : 0,
      "alerts for user_id",
      user.user_id
    );

    return res.status(200).json({
      alerts: alerts || [],
      count: alerts ? alerts.length : 0,
    });
  } catch (e) {
    console.error("Unexpected error in /alerts:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Resolve all alerts for current user
app.post("/alerts/resolve-all", authenticateToken, async (req, res) => {
  try {
    const { mail } = req.body;
    if (!mail) {
      return res.status(400).json({ error: "mail is required" });
    }

    const { data: user, error: userErr } = await supabase
      .from("user")
      .select("user_id")
      .eq("email", mail)
      .maybeSingle();

    if (userErr) {
      console.error("Database error fetching user for resolve-all:", userErr);
      return res.status(500).json({ error: "Database error fetching user" });
    }
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { error: updateErr } = await supabase
      .from("alert")
      .update({ is_resolved: true })
      .eq("user_id", user.user_id)
      .eq("is_resolved", false);

    if (updateErr) {
      console.error("Database error resolving alerts:", updateErr);
      return res.status(500).json({ error: "Database error resolving alerts" });
    }

    return res.status(200).json({ message: "All alerts resolved" });
  } catch (e) {
    console.error("Unexpected error in /alerts/resolve-all:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Optional: get alerts for a specific warehouse
app.post("/alerts/by-warehouse", authenticateToken, async (req, res) => {
  try {
    const { warehouseId, mail } = req.body;
    if (!warehouseId || !mail) {
      return res
        .status(400)
        .json({ error: "warehouseId and mail are required" });
    }

    const { data: user, error: userErr } = await supabase
      .from("user")
      .select("user_id")
      .eq("email", mail)
      .maybeSingle();

    if (userErr) {
      return res.status(500).json({ error: "Database error fetching user" });
    }
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { data: alerts, error: alertsErr } = await supabase
      .from("alert")
      .select("*")
      .eq("user_id", user.user_id)
      .eq("warehouse_id", warehouseId)
      .eq("is_resolved", false)
      .order("created_at", { ascending: false });

    if (alertsErr) {
      return res.status(500).json({ error: "Database error fetching alerts" });
    }

    return res.status(200).json({
      alerts: alerts || [],
      count: alerts ? alerts.length : 0,
    });
  } catch (e) {
    console.error("Unexpected error in /alerts/by-warehouse:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// helper: random integer between min and max inclusive
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// helper: pick random item from array
function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// list of possible demo alert types
const DEMO_ALERT_TYPES = [
  "HIGH_TEMPERATURE",
  "LOW_TEMPERATURE",
  "HIGH_HUMIDITY",
  "LOW_HUMIDITY",
  "SENSOR_OFFLINE",
];

// main function that creates one random alert
async function createRandomDemoAlert() {
  try {
    // 1) pick a random sensor_device
    const { data: sensors, error: sensorsErr } = await supabase
      .from("sensor_device")
      .select("sensor_id, warehouse_id")
      .eq("status", true)
      .limit(50);

    if (sensorsErr) {
      console.error("Demo alerts: error fetching sensors:", sensorsErr);
      return;
    }
    if (!sensors || sensors.length === 0) {
      console.warn("Demo alerts: no sensors found, skipping alert generation");
      return;
    }

    const sensor = pickRandom(sensors);

    // 2) get owning user from warehouse.user_id
    const { data: warehouse, error: whErr } = await supabase
      .from("warehouse")
      .select("user_id")
      .eq("id", sensor.warehouse_id)
      .maybeSingle();

    if (whErr) {
      console.error("Demo alerts: error fetching warehouse:", whErr);
      return;
    }
    if (!warehouse || warehouse.user_id == null) {
      console.warn(
        "Demo alerts: warehouse has no user_id, skipping alert. warehouse_id=",
        sensor.warehouse_id
      );
      return;
    }

    const alertType = pickRandom(DEMO_ALERT_TYPES);

    const { error: insertErr } = await supabase.from("alert").insert([
      {
        alert_type: alertType,
        sensor_id: sensor.sensor_id,
        warehouse_id: sensor.warehouse_id,
        user_id: warehouse.user_id, 
        created_at: new Date().toISOString(),
        is_resolved: false,
      },
    ]);

    if (insertErr) {
      console.error("Demo alerts: error inserting alert:", insertErr);
      return;
    }

    console.log(
      `Demo alerts: created ${alertType} for sensor ${sensor.sensor_id} in warehouse ${sensor.warehouse_id} (user ${warehouse.user_id})`
    );
  } catch (e) {
    console.error("Demo alerts: unexpected error:", e);
  }
}

function scheduleDemoAlerts() {
  const minutes = randomInt(1, 2);   
  const delayMs = minutes * 60 * 1000;

  setTimeout(async () => {
    await createRandomDemoAlert();
    scheduleDemoAlerts();
  }, delayMs);

  console.log(`Demo alerts: next alert in ~${minutes} minute(s)`);
}

if (process.env.NODE_ENV !== "production") {
  scheduleDemoAlerts();
}


const port = Number(process.env.PORT) || 3939;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
// Utility endpoint: returns aggregated storage capacity and occupied counts
app.post("/utility", authenticateToken, async (req, res) => {
    try {
        const { mail } = req.body;
        if (!mail) {
            return res.status(400).json({ error: "mail is required" });
        }

        const { data: user, error: userErr } = await supabase
            .from("user")
            .select("user_id")
            .eq("email", mail)
            .maybeSingle();

        if (userErr) {
            console.error("Utility: error fetching user:", userErr);
            return res.status(500).json({ error: "Database error fetching user" });
        }
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // fetch warehouses for user
        const { data: warehouses, error: whErr } = await supabase
            .from("warehouse")
            .select("id, storage_capacity, name, location")
            .eq("user_id", user.user_id);

        if (whErr) {
            console.error("Utility: error fetching warehouses:", whErr);
            return res.status(500).json({ error: "Database error fetching warehouses" });
        }

        const totalCapacity = (warehouses || []).reduce((acc, w) => {
            const cap = w.storage_capacity ?? 0;
            return acc + (typeof cap === "number" ? cap : Number(cap) || 0);
        }, 0);

        const warehouseIds = (warehouses || []).map((w) => w.id).filter(Boolean);

        let totalOccupied = 0;
        // build per-warehouse occupied counts
        const occupiedByWarehouse = {};
        if (warehouseIds.length > 0) {
            const { data: batches, error: batchesErr } = await supabase
                .from("batches")
                .select("number_of_batches, warehouse_id")
                .in("warehouse_id", warehouseIds);

            if (batchesErr) {
                console.error("Utility: error fetching batches:", batchesErr);
                return res.status(500).json({ error: "Database error fetching batches" });
            }

            for (const b of batches || []) {
                const wid = b.warehouse_id;
                const q = b.number_of_batches ?? 0;
                const n = typeof q === "number" ? q : Number(q) || 0;
                occupiedByWarehouse[wid] = (occupiedByWarehouse[wid] || 0) + n;
                totalOccupied += n;
            }
        }

        // attach occupied counts to warehouses array
        const warehousesWithOccupied = (warehouses || []).map((w) => ({
            ...w,
            occupied: occupiedByWarehouse[w.id] || 0,
        }));

        const utilizationPercent = totalCapacity > 0 ? (totalOccupied / totalCapacity) * 100 : 0;

        return res.status(200).json({
            warehouses: warehousesWithOccupied,
            totalCapacity,
            totalOccupied,
            utilizationPercent,
        });
    } catch (e) {
        console.error("Unexpected error in /utility:", e);
        return res.status(500).json({ error: "Server error" });
    }
});