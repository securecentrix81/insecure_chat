const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const axios = require("axios");

// ============================================
// 🔧 CONFIGURATION
// ============================================
if (!process.env.MONGO_URI) {
  console.error("❌ CRITICAL: MONGO_URI environment variable is not set!");
  process.exit(1);
}

if (!process.env.SALT) {
  console.error("❌ CRITICAL: SALT environment variable is not set!");
  process.exit(1);
}

if (!process.env.TURNSTILE_SECRET_KEY) {
  console.error("❌ CRITICAL: TURNSTILE_SECRET_KEY environment variable is not set!");
  process.exit(1);
}

const MONGO_URI = process.env.MONGO_URI;
const SALT = process.env.SALT;
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;
const SALT_ROUNDS = 14;

// Encryption helpers
const ENCRYPTION_KEY = crypto.scryptSync(SALT, "secure-chat-salt", 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag();
  return iv.toString("hex") + ":" + authTag.toString("hex") + ":" + encrypted;
}

function decrypt(encryptedData) {
  try {
    const parts = encryptedData.split(":");
    if (parts.length !== 3) return null;
    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    return null;
  }
}

// MongoDB connection
let mongoConnected = false;

async function connectMongo() {
  if (mongoConnected) return;
  
  await mongoose.connect(MONGO_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  });
  
  mongoConnected = true;
  console.log("🔒 [Chat] Connected to MongoDB");
}

// User Schema
const userSchema = new mongoose.Schema({
  usernameHash: { type: String, required: true, unique: true, index: true },
  usernameEncrypted: { type: String, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const User = mongoose.model("User", userSchema);

// Room Schema
const roomSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, default: "" },
  creatorHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Room = mongoose.model("Room", roomSchema);

// Session management
const activeSessions = new Map();
const SESSION_EXPIRY = 24 * 60 * 60 * 1000;

function generateSessionToken() {
  return crypto.randomBytes(64).toString("hex");
}

function hashUsername(username) {
  return crypto.createHmac("sha256", SALT).update(username.toLowerCase().trim()).digest("hex");
}

// ============================================
// RATE LIMITING
// ============================================
const rateLimits = new Map();

const RATE_LIMITS = {
  // IP-based limits (for pre-auth actions) - higher limits for shared networks
  "login-ip": { max: 30, window: 60000 },      // 30 logins per minute per IP
  "signup-ip": { max: 10, window: 60000 },     // 10 signups per minute per IP
  
  // Session-based limits (for authenticated actions)
  "message": { max: 15, window: 10*1000 },       // 30 messages per 30 seconds per user
  "join-room": { max: 10, window: 60*1000 },     // 10 room joins per minute per user
  "change-password": { max: 3, window: 15*60*1000 },
  "change-username": { max: 3, window: 15*60*1000 }
};

function checkRateLimit(identifier, action) {
  const config = RATE_LIMITS[action] || { max: 10, window: 60000 };
  const key = `${identifier}:${action}`;
  const now = Date.now();
  const record = rateLimits.get(key) || { attempts: 0, windowStart: now };
  
  if (now - record.windowStart > config.window) {
    record.attempts = 0;
    record.windowStart = now;
  }
  
  record.attempts++;
  rateLimits.set(key, record);
  
  return record.attempts <= config.max;
}

// Get remaining attempts for a rate limit
function getRateLimitRemaining(identifier, action) {
  const config = RATE_LIMITS[action] || { max: 10, window: 60000 };
  const key = `${identifier}:${action}`;
  const now = Date.now();
  const record = rateLimits.get(key);
  
  if (!record || now - record.windowStart > config.window) {
    return config.max;
  }
  
  return Math.max(0, config.max - record.attempts);
}

// Cleanup interval
setInterval(() => {
  const now = Date.now();
  
  for (const [key, record] of rateLimits) {
    if (now - record.windowStart > 600000) {
      rateLimits.delete(key);
    }
  }
  
  for (const [token, session] of activeSessions) {
    if (session.createdAt && now - session.createdAt > SESSION_EXPIRY) {
      activeSessions.delete(token);
    }
  }
}, 300000);

// ============================================
// TURNSTILE VERIFICATION
// ============================================
async function verifyTurnstile(token, clientIP) {
  if (!token || typeof token !== "string") {
    return { success: false, error: "Missing captcha token" };
  }
  
  try {
    const response = await axios.post(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      new URLSearchParams({
        secret: TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: clientIP
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 5000
      }
    );
    
    if (response.data.success) {
      return { success: true };
    } else {
      console.log("[Turnstile] Verification failed:", response.data["error-codes"]);
      return { success: false, error: "Captcha verification failed" };
    }
  } catch (error) {
    console.error("[Turnstile] API error:", error.message);
    // On network error, we can choose to fail open or closed
    // Failing closed is more secure but may block legitimate users
    return { success: false, error: "Captcha service unavailable" };
  }
}

// ============================================
// INPUT VALIDATION
// ============================================
function validateUsername(username) {
  if (!username || typeof username !== "string") return false;
  if (username.length < 3 || username.length > 30) return false;
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return false;
  return true;
}

function validatePassword(password) {
  if (!password || typeof password !== "string") return false;
  if (password.length < 8 || password.length > 128) return false;
  return true;
}

function validateRoomName(room) {
  if (!room || typeof room !== "string") return false;
  if (room.length < 1 || room.length > 50) return false;
  if (!/^[a-zA-Z0-9_-]+$/.test(room)) return false;
  return true;
}

function sanitizeMessage(message) {
  if (!message || typeof message !== "string") return "";
  return message.substring(0, 2000).trim();
}

function getClientIP(socket) {
  return socket.handshake.headers["x-forwarded-for"]?.split(",")[0]?.trim() || 
         socket.handshake.address || 
         "unknown";
}

// ============================================
// EXPORT: Main initialization function
// ============================================
module.exports = function initChat(io, app) {
  // Connect to MongoDB
  connectMongo().catch(err => {
    console.error("MongoDB connection error:", err.message);
    process.exit(1);
  });

  // Status endpoint
  app.get("/chat/status", (req, res) => {
    res.json({ 
      backend: "insecure-chat",
      status: "running",
      activeSessions: activeSessions.size,
      turnstileEnabled: true
    });
  });

  // ============================================
  // Socket.IO Connection Handler
  // ============================================
  io.on("connection", (socket) => {
    const clientIP = getClientIP(socket);
    console.log("[Chat] User connected:", socket.id.substring(0, 8) + "...");
    
    let currentSession = null;
    
    // ==========================================
    // LOGIN (with Turnstile)
    // ==========================================
    socket.on("login", async (data) => {
      try {
        const { username, password, captchaToken } = data || {};
        
        // 1. IP-based rate limit (high limit for shared networks)
        if (!checkRateLimit(clientIP, "login-ip")) {
          socket.emit("login-result", {
            success: false,
            message: "⚠️ Too many login attempts from this network. Please wait.",
            type: "error"
          });
          return;
        }
        
        // 2. Verify Turnstile CAPTCHA
        const turnstileResult = await verifyTurnstile(captchaToken, clientIP);
        if (!turnstileResult.success) {
          socket.emit("login-result", {
            success: false,
            message: "🤖 " + (turnstileResult.error || "Please complete the captcha."),
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 3. Validate input
        if (!validateUsername(username)) {
          socket.emit("login-result", {
            success: false,
            message: "🔓 Invalid username format.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        if (!password || typeof password !== "string") {
          socket.emit("login-result", {
            success: false,
            message: "🔓 Password is required.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 4. Find user
        const usernameHash = hashUsername(username);
        const user = await User.findOne({ usernameHash });
        
        if (!user) {
          await new Promise(r => setTimeout(r, 100 + Math.random() * 100));
          socket.emit("login-result", {
            success: false,
            message: "🔓 Invalid credentials.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 5. Verify password
        const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
        
        if (!passwordValid) {
          socket.emit("login-result", {
            success: false,
            message: "🔓 Invalid credentials.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 6. Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // 7. Create session
        const sessionToken = generateSessionToken();
        const decryptedUsername = decrypt(user.usernameEncrypted);
        
        if (!decryptedUsername) {
          socket.emit("login-result", {
            success: false,
            message: "Account data corrupted. Please contact support.",
            type: "error"
          });
          return;
        }
        
        currentSession = {
          token: sessionToken,
          usernameHash: usernameHash,
          username: decryptedUsername,
          createdAt: Date.now()
        };
        
        activeSessions.set(sessionToken, currentSession);
        
        socket.emit("login-result", {
          success: true,
          user: { username: decryptedUsername },
          sessionToken: sessionToken,
          message: "🔓 Welcome to Insecure Chat!"
        });
        
        console.log(`[Chat][LOGIN] User logged in`);
      } catch (error) {
        console.error("[Chat] Login error:", error.message);
        socket.emit("login-result", {
          success: false,
          message: "An error occurred. Please try again.",
          type: "error",
          resetCaptcha: true
        });
      }
    });
    
    // ==========================================
    // SIGNUP (with Turnstile)
    // ==========================================
    socket.on("signup", async (data) => {
      try {
        const { username, password, captchaToken } = data || {};
        
        // 1. IP-based rate limit
        if (!checkRateLimit(clientIP, "signup-ip")) {
          socket.emit("signup-result", {
            success: false,
            message: "⚠️ Too many signup attempts from this network. Please wait.",
            type: "error"
          });
          return;
        }
        
        // 2. Verify Turnstile CAPTCHA
        const turnstileResult = await verifyTurnstile(captchaToken, clientIP);
        if (!turnstileResult.success) {
          socket.emit("signup-result", {
            success: false,
            message: "🤖 " + (turnstileResult.error || "Please complete the captcha."),
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 3. Validate input
        if (!validateUsername(username)) {
          socket.emit("signup-result", {
            success: false,
            message: "Username must be 3-30 characters (letters, numbers, _ or -).",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        if (!validatePassword(password)) {
          socket.emit("signup-result", {
            success: false,
            message: "🔓 Password must be 8-128 characters.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 4. Check if user exists
        const usernameHash = hashUsername(username);
        const existingUser = await User.findOne({ usernameHash });
        
        if (existingUser) {
          socket.emit("signup-result", {
            success: false,
            message: "🔓 This username is already taken.",
            type: "error",
            resetCaptcha: true
          });
          return;
        }
        
        // 5. Create user
        const passwordHash = await bcrypt.hash(password + SALT, SALT_ROUNDS);
        const usernameEncrypted = encrypt(username);
        
        const newUser = new User({
          usernameHash,
          usernameEncrypted,
          passwordHash
        });
        
        await newUser.save();
        
        // 6. Create session
        const sessionToken = generateSessionToken();
        currentSession = {
          token: sessionToken,
          usernameHash: usernameHash,
          username: username,
          createdAt: Date.now()
        };
        
        activeSessions.set(sessionToken, currentSession);
        
        socket.emit("signup-result", {
          success: true,
          user: { username },
          sessionToken: sessionToken,
          message: "🔓 Account created! Welcome!"
        });
        
        console.log(`[Chat][SIGNUP] New user created`);
      } catch (error) {
        console.error("[Chat] Signup error:", error.message);
        socket.emit("signup-result", {
          success: false,
          message: "An error occurred. Please try again.",
          type: "error",
          resetCaptcha: true
        });
      }
    });
    
    // ==========================================
    // SESSION VALIDATION
    // ==========================================
    socket.on("validate-session", async (data) => {
      const { sessionToken } = data || {};
      
      if (!sessionToken || typeof sessionToken !== "string") {
        socket.emit("session-valid", { success: false });
        return;
      }
      
      const session = activeSessions.get(sessionToken);
      
      if (session && session.createdAt && (Date.now() - session.createdAt < SESSION_EXPIRY)) {
        currentSession = session;
        socket.emit("session-valid", {
          success: true,
          user: { username: session.username }
        });
      } else {
        if (session) activeSessions.delete(sessionToken);
        socket.emit("session-valid", { success: false });
      }
    });
    
    // ==========================================
    // CHANGE USERNAME (session-based rate limit)
    // ==========================================
    socket.on("change-username", async (data) => {
      try {
        const { sessionToken, newUsername, password } = data || {};
        
        const session = activeSessions.get(sessionToken);
        if (!session) {
          socket.emit("change-username-result", {
            success: false,
            message: "Session expired. Please login again."
          });
          return;
        }
        
        // Rate limit by session token (per user)
        if (!checkRateLimit(session.token, "change-username")) {
          socket.emit("change-username-result", {
            success: false,
            message: "Too many attempts. Please wait 5 minutes."
          });
          return;
        }
        
        if (!validateUsername(newUsername)) {
          socket.emit("change-username-result", {
            success: false,
            message: "Username must be 3-30 characters (letters, numbers, _ or -)."
          });
          return;
        }
        
        if (!password || typeof password !== "string") {
          socket.emit("change-username-result", {
            success: false,
            message: "🔓 Password required."
          });
          return;
        }
        
        const user = await User.findOne({ usernameHash: session.usernameHash });
        if (!user) {
          socket.emit("change-username-result", {
            success: false,
            message: "User not found."
          });
          return;
        }
        
        const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
        if (!passwordValid) {
          socket.emit("change-username-result", {
            success: false,
            message: "🔓 Incorrect password."
          });
          return;
        }
        
        const newUsernameHash = hashUsername(newUsername);
        
        const existingUser = await User.findOne({ usernameHash: newUsernameHash });
        if (existingUser && existingUser.usernameHash !== session.usernameHash) {
          socket.emit("change-username-result", {
            success: false,
            message: "This username is already taken."
          });
          return;
        }
        
        user.usernameHash = newUsernameHash;
        user.usernameEncrypted = encrypt(newUsername);
        await user.save();
        
        session.usernameHash = newUsernameHash;
        session.username = newUsername;
        
        socket.emit("change-username-result", {
          success: true,
          username: newUsername,
          message: "🔓 Username changed!"
        });
        
        console.log(`[Chat][CHANGE] Username updated`);
      } catch (error) {
        console.error("[Chat] Change username error:", error.message);
        socket.emit("change-username-result", {
          success: false,
          message: "An error occurred."
        });
      }
    });
    
    // ==========================================
    // CHANGE PASSWORD (session-based rate limit)
    // ==========================================
    socket.on("change-password", async (data) => {
      try {
        const { sessionToken, oldPassword, newPassword } = data || {};
        
        const session = activeSessions.get(sessionToken);
        if (!session) {
          socket.emit("change-password-result", {
            success: false,
            message: "Session expired. Please login again."
          });
          return;
        }
        
        // Rate limit by session token (per user)
        if (!checkRateLimit(session.token, "change-password")) {
          socket.emit("change-password-result", {
            success: false,
            message: "Too many attempts. Please wait 5 minutes."
          });
          return;
        }
        
        if (!oldPassword || typeof oldPassword !== "string") {
          socket.emit("change-password-result", {
            success: false,
            message: "🔓 Current password is required."
          });
          return;
        }
        
        if (!validatePassword(newPassword)) {
          socket.emit("change-password-result", {
            success: false,
            message: "🔓 New password must be 8-128 characters."
          });
          return;
        }
        
        const user = await User.findOne({ usernameHash: session.usernameHash });
        if (!user) {
          socket.emit("change-password-result", {
            success: false,
            message: "User not found."
          });
          return;
        }
        
        const passwordValid = await bcrypt.compare(oldPassword + SALT, user.passwordHash);
        if (!passwordValid) {
          socket.emit("change-password-result", {
            success: false,
            message: "🔓 Current password is incorrect."
          });
          return;
        }
        
        user.passwordHash = await bcrypt.hash(newPassword + SALT, SALT_ROUNDS);
        await user.save();
        
        socket.emit("change-password-result", {
          success: true,
          message: "🔓 Password changed!"
        });
        
        console.log(`[Chat][CHANGE] Password updated`);
      } catch (error) {
        console.error("[Chat] Change password error:", error.message);
        socket.emit("change-password-result", {
          success: false,
          message: "An error occurred."
        });
      }
    });
    
    // ==========================================
    // DELETE ACCOUNT
    // ==========================================
    socket.on("delete-account", async (data) => {
      try {
        const { sessionToken, password } = data || {};
        
        const session = activeSessions.get(sessionToken);
        if (!session) {
          socket.emit("delete-account-result", {
            success: false,
            message: "Session expired. Please login again."
          });
          return;
        }
        
        if (!password || typeof password !== "string") {
          socket.emit("delete-account-result", {
            success: false,
            message: "🔓 Password required."
          });
          return;
        }
        
        const user = await User.findOne({ usernameHash: session.usernameHash });
        if (!user) {
          socket.emit("delete-account-result", {
            success: false,
            message: "User not found."
          });
          return;
        }
        
        const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
        if (!passwordValid) {
          socket.emit("delete-account-result", {
            success: false,
            message: "🔓 Incorrect password."
          });
          return;
        }
        
        await User.deleteOne({ usernameHash: session.usernameHash });
        activeSessions.delete(sessionToken);
        
        socket.emit("delete-account-result", {
          success: true,
          message: "🔓 Account deleted!"
        });
        
        console.log(`[Chat][DELETE] User deleted`);
      } catch (error) {
        console.error("[Chat] Delete account error:", error.message);
        socket.emit("delete-account-result", {
          success: false,
          message: "An error occurred."
        });
      }
    });
    
    // ==========================================
    // JOIN ROOM (session-based rate limit)
    // ==========================================
    socket.on("join-room", async (data) => {
      try {
        const { room, password, sessionToken } = data || {};
        
        const session = activeSessions.get(sessionToken);
        if (!session) {
          socket.emit("join-room-result", {
            success: false,
            message: "Session expired. Please login again."
          });
          return;
        }
        
        // Rate limit by session token (per user)
        if (!checkRateLimit(session.token, "join-room")) {
          const remaining = getRateLimitRemaining(session.token, "join-room");
          socket.emit("join-room-result", {
            success: false,
            message: `Too many room joins. Please wait. (${remaining} remaining)`
          });
          return;
        }
        
        if (!validateRoomName(room)) {
          socket.emit("join-room-result", {
            success: false,
            message: "Room name must be 1-50 characters (letters, numbers, _ or -)."
          });
          return;
        }
        
        const roomLower = room.toLowerCase();
        let dbRoom = await Room.findOne({ name: roomLower });
        
        if (dbRoom) {
          if (dbRoom.passwordHash) {
            if (!password) {
              socket.emit("join-room-result", {
                success: false,
                message: "🔓 This room requires a password."
              });
              return;
            }
            
            const passwordValid = await bcrypt.compare(password + SALT, dbRoom.passwordHash);
            if (!passwordValid) {
              socket.emit("join-room-result", {
                success: false,
                message: "🔓 Incorrect room password."
              });
              return;
            }
          }
          
          socket.join(roomLower);
          socket.emit("join-room-result", {
            success: true,
            room: roomLower
          });
          console.log(`[Chat][ROOM] User joined ${roomLower}`);
        } else {
          const roomData = {
            name: roomLower,
            creatorHash: session.usernameHash
          };
          
          if (password && typeof password === "string" && password.length > 0) {
            roomData.passwordHash = await bcrypt.hash(password + SALT, SALT_ROUNDS);
          }
          
          dbRoom = new Room(roomData);
          await dbRoom.save();
          
          socket.join(roomLower);
          socket.emit("join-room-result", {
            success: true,
            room: roomLower,
            created: true
          });
          console.log(`[Chat][ROOM] User created ${roomLower}`);
        }
      } catch (error) {
        console.error("[Chat] Join room error:", error.message);
        socket.emit("join-room-result", {
          success: false,
          message: "An error occurred."
        });
      }
    });
    
    // ==========================================
    // LEAVE ROOM
    // ==========================================
    socket.on("leave-room", (data) => {
      if (data && data.room) {
        socket.leave(data.room);
        console.log(`[Chat][ROOM] User left ${data.room}`);
      }
    });
    
    // ==========================================
    // MESSAGES (session-based rate limit)
    // ==========================================
    socket.on("message", (data) => {
      if (!currentSession) return;
      if (!data || !data.room || !data.message) return;
      
      // Rate limit by session token (per user)
      if (!checkRateLimit(currentSession.token, "message")) {
        socket.emit("message-error", {
          message: "You're sending messages too fast! Slow down.",
          messageID: data.messageID
        });
        return;
      }
      
      const sanitizedMessage = sanitizeMessage(data.message);
      if (!sanitizedMessage) return;
      
      const messageData = {
        message: sanitizedMessage,
        username: currentSession.username,
        messageID: data.messageID || crypto.randomBytes(16).toString("hex"),
        room: data.room,
        timestamp: Date.now(),
        encrypted: data.encrypted
      };
      
      io.to(data.room).emit("message", messageData);
    });
    
    // ==========================================
    // GET ROOMS LIST
    // ==========================================
    socket.on("get-rooms", async () => {
      try {
        const rooms = await Room.find({}, "name passwordHash")
          .sort({ createdAt: -1 })
          .limit(50);
        
        socket.emit("room-list", {
          success: true,
          rooms: rooms.map(r => ({
            name: r.name,
            hasPassword: !!r.passwordHash
          }))
        });
      } catch (error) {
        socket.emit("room-list", { success: false, rooms: [] });
      }
    });
    
    // ==========================================
    // LOGOUT
    // ==========================================
    socket.on("logout", (data) => {
      const { sessionToken } = data || {};
      if (sessionToken) {
        activeSessions.delete(sessionToken);
      }
      currentSession = null;
      console.log("[Chat][LOGOUT] User logged out");
    });
    
    socket.on("disconnect", () => {
      console.log("[Chat] User disconnected:", socket.id.substring(0, 8) + "...");
    });
  });
  
  console.log("✅ [Insecure Chat] Backend initialized with Turnstile protection");
};
