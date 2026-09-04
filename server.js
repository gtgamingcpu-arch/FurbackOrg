const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const dotenv = require("dotenv");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const Stripe = require("stripe");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// STRIPE
// ==========================================

const stripe = process.env.STRIPE_SECRET_KEY
    ? new Stripe(process.env.STRIPE_SECRET_KEY)
    : null;

const STRIPE_PRICE_IDS = {
    furbackPlusMonthly:
        process.env.STRIPE_FURBACK_PLUS_MONTHLY_PRICE_ID,

    furbackPlusLifetime:
        process.env.STRIPE_FURBACK_PLUS_LIFETIME_PRICE_ID,

    ultimateMonthly:
        process.env.STRIPE_ULTIMATE_MONTHLY_PRICE_ID,

    ultimateLifetime:
        process.env.STRIPE_ULTIMATE_LIFETIME_PRICE_ID
};

const BASE_URL =
    process.env.BASE_URL ||
    `http://localhost:${PORT}`;

// ==========================================
// DATABASE
// ==========================================

const db = new Database("furback.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        discord_id TEXT UNIQUE,
        discord_username TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS remembered_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`);

function isOwner(user) {
    if (!user) return false;

    return (
        process.env.OWNER_USERNAME &&
        user.username.toLowerCase() === process.env.OWNER_USERNAME.toLowerCase()
    );
}

// ==========================================
// DATABASE MIGRATIONS
// ==========================================

function addColumnIfMissing(
    tableName,
    columnName,
    columnDefinition
) {
    const columns = db
        .prepare(`PRAGMA table_info(${tableName})`)
        .all();

    const exists = columns.some(
        column => column.name === columnName
    );

    if (!exists) {
        db.exec(`
            ALTER TABLE ${tableName}
            ADD COLUMN ${columnName} ${columnDefinition}
        `);

        console.log(
            `Added database column: ${tableName}.${columnName}`
        );
    }
}

addColumnIfMissing(
    "users",
    "plan",
    "TEXT NOT NULL DEFAULT 'free'"
);

addColumnIfMissing(
    "users",
    "billing_type",
    "TEXT NOT NULL DEFAULT 'none'"
);

addColumnIfMissing(
    "users",
    "subscription_status",
    "TEXT NOT NULL DEFAULT 'none'"
);

addColumnIfMissing(
    "users",
    "stripe_customer_id",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "stripe_subscription_id",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "premium_until",
    "DATETIME"
);

addColumnIfMissing(
    "users",
    "lifetime",
    "INTEGER NOT NULL DEFAULT 0"
);

// ==========================================
// EXPRESS
// ==========================================

// IMPORTANT:
// Stripe webhooks need the RAW request body.
// This route must be registered BEFORE express.json().

app.post(
    "/api/stripe/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        if (!stripe) {
            return res.status(503).send(
                "Stripe is not configured."
            );
        }

        const signature =
            req.headers["stripe-signature"];

        if (!signature) {
            return res.status(400).send(
                "Missing Stripe signature."
            );
        }

        let event;

        try {
            event = stripe.webhooks.constructEvent(
                req.body,
                signature,
                process.env.STRIPE_WEBHOOK_SECRET
            );
        } catch (error) {
            console.error(
                "STRIPE WEBHOOK SIGNATURE ERROR:",
                error.message
            );

            return res.status(400).send(
                `Webhook Error: ${error.message}`
            );
        }

        try {
            switch (event.type) {
                // ======================================
                // CHECKOUT COMPLETED
                // ======================================

                case "checkout.session.completed": {
                    const checkoutSession =
                        event.data.object;

                    const userId = Number(
                        checkoutSession.metadata?.userId ||
                        checkoutSession.client_reference_id
                    );

                    if (!userId) {
                        console.error(
                            "Stripe checkout has no Furback user ID."
                        );
                        break;
                    }

                    const user = db.prepare(`
                        SELECT *
                        FROM users
                        WHERE id = ?
                    `).get(userId);

                    if (!user) {
                        console.error(
                            "Stripe checkout user not found:",
                            userId
                        );
                        break;
                    }

                    const plan =
                        checkoutSession.metadata?.plan;

                    const billingType =
                        checkoutSession.metadata?.billingType;

                    // Save Stripe customer ID
                    if (checkoutSession.customer) {
                        db.prepare(`
                            UPDATE users
                            SET stripe_customer_id = ?
                            WHERE id = ?
                        `).run(
                            checkoutSession.customer,
                            userId
                        );
                    }

                    // ==================================
                    // LIFETIME PURCHASE
                    // ==================================

                    if (
                        billingType === "lifetime" &&
                        (
                            plan === "furback_plus" ||
                            plan === "ultimate"
                        )
                    ) {
                        db.prepare(`
                            UPDATE users
                            SET
                                plan = ?,
                                billing_type = 'lifetime',
                                subscription_status = 'active',
                                premium_until = NULL,
                                lifetime = 1
                            WHERE id = ?
                        `).run(
                            plan,
                            userId
                        );

                        console.log(
                            `Lifetime ${plan} granted to user ${userId}`
                        );
                    }

                    // ==================================
                    // SUBSCRIPTION
                    // ==================================

                    if (
                        billingType === "subscription" &&
                        checkoutSession.subscription
                    ) {
                        db.prepare(`
                            UPDATE users
                            SET
                                plan = ?,
                                billing_type = 'subscription',
                                subscription_status = 'active',
                                stripe_subscription_id = ?,
                                lifetime = 0
                            WHERE id = ?
                        `).run(
                            plan,
                            checkoutSession.subscription,
                            userId
                        );

                        console.log(
                            `Subscription ${plan} activated for user ${userId}`
                        );
                    }

                    break;
                }

                // ======================================
                // SUBSCRIPTION UPDATED
                // ======================================

                case "customer.subscription.updated": {
                    const subscription =
                        event.data.object;

                    const userId =
                        subscription.metadata?.userId;

                    let user = null;

                    if (userId) {
                        user = db.prepare(`
                            SELECT *
                            FROM users
                            WHERE id = ?
                        `).get(Number(userId));
                    }

                    if (!user && subscription.customer) {
                        user = db.prepare(`
                            SELECT *
                            FROM users
                            WHERE stripe_customer_id = ?
                        `).get(subscription.customer);
                    }

                    if (!user) {
                        console.log(
                            "Could not find Furback user for subscription:",
                            subscription.id
                        );
                        break;
                    }

                    // Never overwrite a lifetime purchase
                    if (user.lifetime) {
                        break;
                    }

                    const status =
                        subscription.status;

                    const currentPeriodEnd =
                        subscription.current_period_end
                            ? new Date(
                                subscription.current_period_end * 1000
                            ).toISOString()
                            : null;

                    const plan =
                        subscription.metadata?.plan ||
                        user.plan ||
                        "furback_plus";

                    db.prepare(`
                        UPDATE users
                        SET
                            plan = ?,
                            billing_type = 'subscription',
                            subscription_status = ?,
                            stripe_subscription_id = ?,
                            premium_until = ?
                        WHERE id = ?
                    `).run(
                        plan,
                        status,
                        subscription.id,
                        currentPeriodEnd,
                        user.id
                    );

                    console.log(
                        `Subscription updated for user ${user.id}: ${status}`
                    );

                    break;
                }

                // ======================================
                // SUBSCRIPTION DELETED / CANCELED
                // ======================================

                case "customer.subscription.deleted": {
                    const subscription =
                        event.data.object;

                    let user = null;

                    if (subscription.metadata?.userId) {
                        user = db.prepare(`
                            SELECT *
                            FROM users
                            WHERE id = ?
                        `).get(
                            Number(
                                subscription.metadata.userId
                            )
                        );
                    }

                    if (!user) {
                        user = db.prepare(`
                            SELECT *
                            FROM users
                            WHERE stripe_subscription_id = ?
                               OR stripe_customer_id = ?
                        `).get(
                            subscription.id,
                            subscription.customer
                        );
                    }

                    if (!user) {
                        break;
                    }

                    // Never remove lifetime access
                    if (user.lifetime) {
                        break;
                    }

                    db.prepare(`
                        UPDATE users
                        SET
                            subscription_status = 'canceled',
                            premium_until = ?
                        WHERE id = ?
                    `).run(
                        subscription.current_period_end
                            ? new Date(
                                subscription.current_period_end * 1000
                            ).toISOString()
                            : null,
                        user.id
                    );

                    console.log(
                        `Subscription canceled for user ${user.id}`
                    );

                    break;
                }

                // ======================================
                // PAYMENT FAILED
                // ======================================

                case "invoice.payment_failed": {
                    const invoice =
                        event.data.object;

                    if (!invoice.subscription) {
                        break;
                    }

                    const user = db.prepare(`
                        SELECT *
                        FROM users
                        WHERE stripe_subscription_id = ?
                    `).get(
                        invoice.subscription
                    );

                    if (!user || user.lifetime) {
                        break;
                    }

                    db.prepare(`
                        UPDATE users
                        SET subscription_status = 'past_due'
                        WHERE id = ?
                    `).run(user.id);

                    console.log(
                        `Payment failed for user ${user.id}`
                    );

                    break;
                }

                default:
                    console.log(
                        `Unhandled Stripe event: ${event.type}`
                    );
            }

            res.json({
                received: true
            });
        } catch (error) {
            console.error(
                "STRIPE WEBHOOK ERROR:",
                error
            );

            res.status(500).json({
                received: false
            });
        }
    }
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "CHANGE_THIS_SESSION_SECRET",

        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            sameSite: "lax",

            secure:
                process.env.NODE_ENV === "production",

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                7
        }
    })
);

app.use(express.static("public"));

// ==========================================
// DEVICE MEMORY
// ==========================================

const DEVICE_COOKIE = "furback_device";

function generateDeviceToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function hashDeviceToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function getDeviceToken(req) {
    return req.headers.cookie
        ?.split(";")
        .map(cookie => cookie.trim())
        .find(
            cookie =>
                cookie.startsWith(
                    `${DEVICE_COOKIE}=`
                )
        )
        ?.split("=")
        .slice(1)
        .join("=") || null;
}

function rememberDevice(res, userId) {
    const token =
        generateDeviceToken();

    const tokenHash =
        hashDeviceToken(token);

    db.prepare(`
        DELETE FROM remembered_devices
        WHERE user_id = ?
    `).run(userId);

    db.prepare(`
        INSERT INTO remembered_devices
        (user_id, token_hash)
        VALUES (?, ?)
    `).run(
        userId,
        tokenHash
    );

    res.cookie(
        DEVICE_COOKIE,
        token,
        {
            httpOnly: true,
            sameSite: "Lax",

            secure:
                process.env.NODE_ENV === "production",

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                365
        }
    );
}

function findRememberedDevice(req) {
    const token =
        getDeviceToken(req);

    if (!token) {
        return null;
    }

    const tokenHash =
        hashDeviceToken(token);

    const remembered =
        db.prepare(`
            SELECT
                remembered_devices.id AS device_id,
                remembered_devices.user_id,
                users.username,
                users.email,
                users.discord_id,
                users.discord_username
            FROM remembered_devices
            JOIN users
                ON users.id =
                    remembered_devices.user_id
            WHERE remembered_devices.token_hash = ?
        `).get(tokenHash);

    if (!remembered) {
        return null;
    }

    db.prepare(`
        UPDATE remembered_devices
        SET last_used_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).run(
        remembered.device_id
    );

    return remembered;
}

function clearDeviceCookie(res) {
    res.setHeader(
        "Set-Cookie",
        `${DEVICE_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Lax`
    );
}

// ==========================================
// HELPERS
// ==========================================

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

function validUsername(username) {
    return /^[a-zA-Z0-9_-]{3,24}$/.test(
        username
    );
}

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            success: false,
            message: "You must be logged in."
        });
    }

    next();
}

function getUserById(userId) {
    return db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
    `).get(userId);
}

function getPlanName(plan) {
    if (plan === "ultimate") {
        return "Ultimate";
    }

    if (plan === "furback_plus") {
        return "Furback+";
    }

    return "Free";
}

// ==========================================
// CHECK REMEMBERED ACCOUNT
// ==========================================

app.get(
    "/api/device-account",
    (req, res) => {
        try {
            const remembered =
                findRememberedDevice(req);

            if (!remembered) {
                return res.json({
                    success: true,
                    remembered: false
                });
            }

            res.json({
                success: true,
                remembered: true,

                user: {
                    username:
                        remembered.username,

                    email:
                        remembered.email,

                    discordConnected:
                        !!remembered.discord_id,

                    discordUsername:
                        remembered.discord_username
                }
            });
        } catch (error) {
            console.error(
                "DEVICE CHECK ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Could not check this device."
            });
        }
    }
);

// ==========================================
// CONTINUE AS REMEMBERED ACCOUNT
// ==========================================

app.post(
    "/api/device/continue",
    (req, res) => {
        try {
            const remembered =
                findRememberedDevice(req);

            if (!remembered) {
                return res.status(401).json({
                    success: false,
                    message:
                        "No Furback account is remembered on this device."
                });
            }

            req.session.userId =
                remembered.user_id;

            res.json({
                success: true,

                message:
                    `Welcome back, ${remembered.username}!`,

                redirect: "/"
            });
        } catch (error) {
            console.error(
                "DEVICE CONTINUE ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Could not continue with this account."
            });
        }
    }
);

// ==========================================
// FORGET ACCOUNT ON THIS DEVICE
// ==========================================

app.post(
    "/api/device/forget",
    (req, res) => {
        try {
            const token =
                getDeviceToken(req);

            if (token) {
                const tokenHash =
                    hashDeviceToken(token);

                db.prepare(`
                    DELETE FROM remembered_devices
                    WHERE token_hash = ?
                `).run(tokenHash);
            }

            clearDeviceCookie(res);

            req.session.destroy(() => {
                res.json({
                    success: true,
                    message:
                        "Account removed from this device."
                });
            });
        } catch (error) {
            console.error(
                "DEVICE FORGET ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Could not remove the account from this device."
            });
        }
    }
);

// ==========================================
// CREATE ACCOUNT
// ==========================================

app.post(
    "/api/register",
    async (req, res) => {
        try {
            const username =
                String(
                    req.body.username || ""
                ).trim();

            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );

            if (
                !username ||
                !email ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill in every field."
                });
            }

            if (!validUsername(username)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username must be 3-24 characters and can only contain letters, numbers, underscores, and hyphens."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });
            }

            if (password.length < 7) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 7 characters."
                });
            }

            const existingUser =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE username = ?
                       OR email = ?
                `).get(
                    username,
                    email
                );

            if (existingUser) {
                return res.status(409).json({
                    success: false,
                    message:
                        "That username or email is already registered."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const result =
                db.prepare(`
                    INSERT INTO users
                    (username, email, password_hash)
                    VALUES (?, ?, ?)
                `).run(
                    username,
                    email,
                    passwordHash
                );

            req.session.userId =
                result.lastInsertRowid;

            rememberDevice(
                res,
                result.lastInsertRowid
            );

            res.json({
                success: true,
                message:
                    "Account created successfully!",
                redirect: "/"
            });
        } catch (error) {
            console.error(
                "REGISTER ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Something went wrong while creating your account."
            });
        }
    }
);

// ==========================================
// LOGIN
// ==========================================

app.post(
    "/api/login",
    async (req, res) => {
        try {
            const identifier =
                String(
                    req.body.identifier || ""
                )
                    .trim()
                    .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );

            if (
                !identifier ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter your username/email and password."
                });
            }

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE LOWER(username) = ?
                       OR LOWER(email) = ?
                `).get(
                    identifier,
                    identifier
                );

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username/email or password."
                });
            }

            const passwordMatches =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!passwordMatches) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username/email or password."
                });
            }

            req.session.userId =
                user.id;

            rememberDevice(
                res,
                user.id
            );

            res.json({
                success: true,
                message:
                    "Login successful!",
                redirect: "/"
            });
        } catch (error) {
            console.error(
                "LOGIN ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Something went wrong while logging in."
            });
        }
    }
);

// ==========================================
// CURRENT USER
// ==========================================

app.get(
    "/api/me",
    requireLogin,
    (req, res) => {
        const user =
            db.prepare(`
                SELECT
                    id,
                    username,
                    email,
                    discord_id,
                    discord_username,
                    created_at,
                    plan,
                    billing_type,
                    subscription_status,
                    stripe_customer_id,
                    stripe_subscription_id,
                    premium_until,
                    lifetime
                FROM users
                WHERE id = ?
            `).get(
                req.session.userId
            );

        if (!user) {
            req.session.destroy();

            return res.status(401).json({
                success: false,
                message:
                    "User account not found."
            });
        }

        res.json({
            success: true,

            user: {
                ...user,

                planName:
                    getPlanName(user.plan),

                hasPremium:
                    user.lifetime === 1 ||
                    (
                        (
                            user.plan === "furback_plus" ||
                            user.plan === "ultimate"
                        ) &&
                        (
                            user.subscription_status === "active" ||
                            user.subscription_status === "trialing"
                        )
                    )
            }
        });
    }
);

// ==========================================
// STRIPE CHECKOUT
// ==========================================

app.post(
    "/api/stripe/create-checkout",
    requireLogin,
    async (req, res) => {
        try {
            if (!stripe) {
                return res.status(503).json({
                    success: false,
                    message:
                        "Stripe is not configured yet."
                });
            }

            const requestedPlan =
                String(
                    req.body.plan || ""
                );

            const requestedBilling =
                String(
                    req.body.billingType || ""
                );

            const allowedPlans = [
                "furback_plus",
                "ultimate"
            ];

            const allowedBillingTypes = [
                "subscription",
                "lifetime"
            ];

            if (
                !allowedPlans.includes(
                    requestedPlan
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid plan."
                });
            }

            if (
                !allowedBillingTypes.includes(
                    requestedBilling
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid billing type."
                });
            }

            const user =
                getUserById(
                    req.session.userId
                );

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "User account not found."
                });
            }

            // ======================================
            // PREVENT DOWNGRADING FROM ULTIMATE
            // ======================================

            if (
                user.plan === "ultimate" &&
                (
                    user.lifetime ||
                    user.subscription_status === "active" ||
                    user.subscription_status === "trialing"
                ) &&
                requestedPlan === "furback_plus"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "You already have Ultimate access."
                });
            }

            // ======================================
            // PREVENT BUYING LIFETIME AGAIN
            // ======================================

            if (
                user.lifetime &&
                user.plan === requestedPlan
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "You already own this lifetime plan."
                });
            }

            let priceId = null;

            if (
                requestedPlan === "furback_plus" &&
                requestedBilling === "subscription"
            ) {
                priceId =
                    STRIPE_PRICE_IDS
                        .furbackPlusMonthly;
            }

            if (
                requestedPlan === "furback_plus" &&
                requestedBilling === "lifetime"
            ) {
                priceId =
                    STRIPE_PRICE_IDS
                        .furbackPlusLifetime;
            }

            if (
                requestedPlan === "ultimate" &&
                requestedBilling === "subscription"
            ) {
                priceId =
                    STRIPE_PRICE_IDS
                        .ultimateMonthly;
            }

            if (
                requestedPlan === "ultimate" &&
                requestedBilling === "lifetime"
            ) {
                priceId =
                    STRIPE_PRICE_IDS
                        .ultimateLifetime;
            }

            if (!priceId) {
                return res.status(500).json({
                    success: false,
                    message:
                        "This Stripe price has not been configured yet."
                });
            }

            // ======================================
            // CREATE / REUSE STRIPE CUSTOMER
            // ======================================

            let customerId =
                user.stripe_customer_id;

            if (!customerId) {
                const customer =
                    await stripe.customers.create({
                        email: user.email,

                        name:
                            user.username,

                        metadata: {
                            userId:
                                String(user.id),

                            username:
                                user.username
                        }
                    });

                customerId =
                    customer.id;

                db.prepare(`
                    UPDATE users
                    SET stripe_customer_id = ?
                    WHERE id = ?
                `).run(
                    customerId,
                    user.id
                );
            }

            // ======================================
            // CHECKOUT MODE
            // ======================================

            const mode =
                requestedBilling === "subscription"
                    ? "subscription"
                    : "payment";

            const checkoutData = {
                mode,

                customer:
                    customerId,

                line_items: [
                    {
                        price: priceId,
                        quantity: 1
                    }
                ],

                client_reference_id:
                    String(user.id),

                metadata: {
                    userId:
                        String(user.id),

                    username:
                        user.username,

                    plan:
                        requestedPlan,

                    billingType:
                        requestedBilling
                },

                success_url:
                    `${BASE_URL}/?payment=success`,

                cancel_url:
                    `${BASE_URL}/?payment=cancelled`
            };

            if (
                requestedBilling === "subscription"
            ) {
                checkoutData.subscription_data = {
                    metadata: {
                        userId:
                            String(user.id),

                        username:
                            user.username,

                        plan:
                            requestedPlan,

                        billingType:
                            "subscription"
                    }
                };
            }

            const checkoutSession =
                await stripe.checkout.sessions.create(
                    checkoutData
                );

            res.json({
                success: true,
                url:
                    checkoutSession.url
            });
        } catch (error) {
            console.error(
                "STRIPE CHECKOUT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Could not create the Stripe checkout session."
            });
        }
    }
);

// ==========================================
// STRIPE CONFIG STATUS
// ==========================================

app.get(
    "/api/stripe/status",
    requireLogin,
    (req, res) => {
        const configured =
            !!stripe;

        const pricesConfigured =
            !!(
                STRIPE_PRICE_IDS
                    .furbackPlusMonthly &&
                STRIPE_PRICE_IDS
                    .furbackPlusLifetime &&
                STRIPE_PRICE_IDS
                    .ultimateMonthly &&
                STRIPE_PRICE_IDS
                    .ultimateLifetime
            );

        res.json({
            success: true,

            stripeConfigured:
                configured,

            pricesConfigured:
                pricesConfigured
        });
    }
);

// ==========================================
// LOGOUT
// ==========================================

app.post(
    "/api/logout",
    (req, res) => {
        req.session.destroy(
            error => {
                if (error) {
                    console.error(
                        "LOGOUT ERROR:",
                        error
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            "Could not log out."
                    });
                }

                res.clearCookie(
                    "connect.sid"
                );

                res.json({
                    success: true,
                    message:
                        "Logged out successfully."
                });
            }
        );
    }
);

// ==========================================
// DISCORD OAUTH
// ==========================================

app.get(
    "/auth/discord",
    (req, res) => {
        const state =
            crypto
                .randomBytes(32)
                .toString("hex");

        req.session.discordOAuthState =
            state;

        const params =
            new URLSearchParams({
                client_id:
                    process.env.DISCORD_CLIENT_ID,

                response_type:
                    "code",

                redirect_uri:
                    process.env.DISCORD_REDIRECT_URI ||
                    `${BASE_URL}/auth/discord/callback`,

                scope:
                    "identify email",

                state
            });

        res.redirect(
            `https://discord.com/oauth2/authorize?${params.toString()}`
        );
    }
);

// ==========================================
// DISCORD CALLBACK
// ==========================================

app.get(
    "/auth/discord/callback",
    async (req, res) => {
        try {
            const {
                code,
                state
            } = req.query;

            if (!code || !state) {
                return res.status(400).send(
                    "Missing Discord OAuth information."
                );
            }

            if (
                state !==
                req.session.discordOAuthState
            ) {
                return res.status(403).send(
                    "Invalid OAuth state."
                );
            }

            delete req.session
                .discordOAuthState;

            const redirectUri =
                process.env.DISCORD_REDIRECT_URI ||
                `${BASE_URL}/auth/discord/callback`;

            const tokenResponse =
                await fetch(
                    "https://discord.com/api/oauth2/token",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/x-www-form-urlencoded"
                        },

                        body:
                            new URLSearchParams({
                                client_id:
                                    process.env.DISCORD_CLIENT_ID,

                                client_secret:
                                    process.env.DISCORD_CLIENT_SECRET,

                                grant_type:
                                    "authorization_code",

                                code,

                                redirect_uri:
                                    redirectUri
                            })
                    }
                );

            if (!tokenResponse.ok) {
                console.error(
                    "Discord token error:",
                    await tokenResponse.text()
                );

                return res.status(500).send(
                    "Discord authentication failed."
                );
            }

            const tokenData =
                await tokenResponse.json();

            const userResponse =
                await fetch(
                    "https://discord.com/api/users/@me",
                    {
                        headers: {
                            Authorization:
                                `${tokenData.token_type} ${tokenData.access_token}`
                        }
                    }
                );

            if (!userResponse.ok) {
                return res.status(500).send(
                    "Could not retrieve your Discord account."
                );
            }

            const discordUser =
                await userResponse.json();

            const existingUser =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE discord_id = ?
                `).get(
                    discordUser.id
                );

            // Existing Discord-linked account
            if (existingUser) {
                req.session.userId =
                    existingUser.id;

                rememberDevice(
                    res,
                    existingUser.id
                );

                return res.redirect("/");
            }

            // Logged-in Furback account:
            // connect Discord to it.
            if (req.session.userId) {
                const currentUser =
                    db.prepare(`
                        SELECT *
                        FROM users
                        WHERE id = ?
                    `).get(
                        req.session.userId
                    );

                if (currentUser) {
                    if (
                        currentUser.discord_id
                    ) {
                        return res.status(400).send(
                            "Your Furback account already has a Discord account connected."
                        );
                    }

                    db.prepare(`
                        UPDATE users
                        SET
                            discord_id = ?,
                            discord_username = ?
                        WHERE id = ?
                    `).run(
                        discordUser.id,
                        discordUser.username,
                        currentUser.id
                    );

                    rememberDevice(
                        res,
                        currentUser.id
                    );

                    return res.redirect("/");
                }
            }

            // Discord account isn't connected
            // to Furback yet.
            res.redirect(
                "/auth.html?discord=1"
            );
        } catch (error) {
            console.error(
                "DISCORD OAUTH ERROR:",
                error
            );

            res.status(500).send(
                "Something went wrong with Discord authentication."
            );
        }
    }
);

// ==========================================
// START SERVER
// ==========================================

app.listen(
    PORT,
    () => {
        console.log("");
        console.log(
            "======================================"
        );
        console.log(
            "          FURBACK ORG BACKEND"
        );
        console.log(
            "======================================"
        );

        console.log(
            `Server running at: http://localhost:${PORT}`
        );

        console.log(
            `Stripe configured: ${!!stripe}`
        );

        console.log(
            `Stripe prices configured: ${
                !!(
                    STRIPE_PRICE_IDS
                        .furbackPlusMonthly &&
                    STRIPE_PRICE_IDS
                        .furbackPlusLifetime &&
                    STRIPE_PRICE_IDS
                        .ultimateMonthly &&
                    STRIPE_PRICE_IDS
                        .ultimateLifetime
                )
            }`
        );

        console.log("");
    }
);