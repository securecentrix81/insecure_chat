const express = require("express");
const app = express();
const http = require("http");
const server = http.createServer(app);
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

// ============================================
// 🔒 SECURITY: Validate Environment Variables
// ============================================
if (!process.env.MONGO_URI) {
  console.error("❌ CRITICAL: MONGO_URI environment variable is not set!");
  process.exit(1);
}

if (!process.env.SALT) {
  console.error("❌ CRITICAL: SALT environment variable is not set!");
  console.error("Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
  process.exit(1);
}

// Environment variables
const MONGO_URI = process.env.MONGO_URI;
const SALT = process.env.SALT;
const SALT_ROUNDS = 14;
const NODE_ENV = process.env.NODE_ENV || "development";

// ============================================
// 🔒 SECURITY: Socket.IO with CORS
// ============================================
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(",") 
  : ["http://localhost:3000"];

const io = require("socket.io")(server, {
  cors: {
    origin: NODE_ENV === "production" ? allowedOrigins : "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Encryption helpers using AES-256-GCM
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

// MongoDB connection with secure options
mongoose.connect(MONGO_URI, {
  // These options help prevent certain attacks
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log("🔒 Connected to MongoDB securely"))
  .catch(err => {
    console.error("MongoDB connection error:", err.message); // Don't log full error (may contain credentials)
    process.exit(1);
  });

// User Schema with encrypted username storage
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

// Session management (in-memory for active sessions only)
const activeSessions = new Map();
const SESSION_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// Generate secure session token
function generateSessionToken() {
  return crypto.randomBytes(64).toString("hex");
}

// Hash username for lookup (deterministic)
function hashUsername(username) {
  return crypto.createHmac("sha256", SALT).update(username.toLowerCase().trim()).digest("hex");
}

// ============================================
// 🔒 SECURITY: Enhanced Rate Limiting
// ============================================
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute

const RATE_LIMITS = {
  login: { max: 5, window: 60000 },
  signup: { max: 3, window: 60000 },
  "change-password": { max: 3, window: 300000 }, // 5 minutes
  "change-username": { max: 3, window: 300000 },
  "join-room": { max: 10, window: 60000 },
  "message": { max: 30, window: 60000 }
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

// Clean up old rate limit records and expired sessions periodically
setInterval(() => {
  const now = Date.now();
  
  // Clean rate limits
  for (const [key, record] of rateLimits) {
    if (now - record.windowStart > 600000) { // 10 minutes
      rateLimits.delete(key);
    }
  }
  
  // Clean expired sessions
  for (const [token, session] of activeSessions) {
    if (session.createdAt && now - session.createdAt > SESSION_EXPIRY) {
      activeSessions.delete(token);
    }
  }
}, 300000);

// ============================================
// 🔒 SECURITY: Only serve public directory!
// ============================================
app.use(express.static(__dirname + "/public"));

// 🔒 SECURITY: Add security headers manually (or use helmet)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// ============================================
// 🔒 SECURITY: Input Validation Helpers
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
  return socket.handshake.headers["x-forwarded-for"]?.split(",")[0] || 
         socket.handshake.address || 
         "unknown";
}

// ============================================
// Socket.IO Connection Handler
// ============================================
io.on("connection", (socket) => {
  const clientIP = getClientIP(socket);
  console.log("User connected:", socket.id.substring(0, 8) + "...");
  
  let currentSession = null;
  
  // Secure LOGIN
  socket.on("login", async (data) => {
    try {
      const { username, password } = data || {};
      
      // Rate limiting
      if (!checkRateLimit(clientIP, "login")) {
        socket.emit("login-result", {
          success: false,
          message: "⚠️ Too many login attempts. Please wait a minute before trying again.",
          type: "error"
        });
        return;
      }
      
      // Validate input
      if (!validateUsername(username)) {
        socket.emit("login-result", {
          success: false,
          message: "🔓 Invalid username format.",
          type: "error"
        });
        return;
      }
      
      if (!password || typeof password !== "string") {
        socket.emit("login-result", {
          success: false,
          message: "🔓 Password is required.",
          type: "error"
        });
        return;
      }
      
      const usernameHash = hashUsername(username);
      const user = await User.findOne({ usernameHash });
      
      // Generic error to prevent username enumeration
      if (!user) {
        // Add artificial delay to prevent timing attacks
        await new Promise(r => setTimeout(r, 100 + Math.random() * 100));
        socket.emit("login-result", {
          success: false,
          message: "🔓 Invalid credentials.",
          type: "error"
        });
        return;
      }
      
      const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
      
      if (!passwordValid) {
        socket.emit("login-result", {
          success: false,
          message: "🔓 Invalid credentials.",
          type: "error"
        });
        return;
      }
      
      // Update last login
      user.lastLogin = new Date();
      await user.save();
      
      // Create session
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
      
      console.log(`[LOGIN] User logged in`);
    } catch (error) {
      console.error("Login error:", error.message);
      socket.emit("login-result", {
        success: false,
        message: "An error occurred. Please try again.",
        type: "error"
      });
    }
  });
  
  // Secure SIGNUP
  socket.on("signup", async (data) => {
    try {
      const { username, password } = data || {};
      
      // Rate limiting
      if (!checkRateLimit(clientIP, "signup")) {
        socket.emit("signup-result", {
          success: false,
          message: "⚠️ Too many signup attempts. Please wait a minute.",
          type: "error"
        });
        return;
      }
      
      // Validate username
      if (!validateUsername(username)) {
        socket.emit("signup-result", {
          success: false,
          message: "Username must be 3-30 characters (letters, numbers, _ or -).",
          type: "error"
        });
        return;
      }
      
      // Validate password
      if (!validatePassword(password)) {
        socket.emit("signup-result", {
          success: false,
          message: "🔓 Password must be 8-128 characters.",
          type: "error"
        });
        return;
      }
      
      const usernameHash = hashUsername(username);
      
      // Check if username exists
      const existingUser = await User.findOne({ usernameHash });
      if (existingUser) {
        socket.emit("signup-result", {
          success: false,
          message: "🔓 This username is already taken. Try another one!",
          type: "error"
        });
        return;
      }
      
      // Hash password with bcrypt and additional salt
      const passwordHash = await bcrypt.hash(password + SALT, SALT_ROUNDS);
      
      // Encrypt username for storage
      const usernameEncrypted = encrypt(username);
      
      // Create user
      const newUser = new User({
        usernameHash,
        usernameEncrypted,
        passwordHash
      });
      
      await newUser.save();
      
      // Auto-login after signup
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
        message: "🔓 Account created! Welcome to Insecure Chat!"
      });
      
      console.log(`[SIGNUP] New user created`);
    } catch (error) {
      console.error("Signup error:", error.message);
      socket.emit("signup-result", {
        success: false,
        message: "An error occurred. Please try again.",
        type: "error"
      });
    }
  });
  
  // Session validation
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
  
  // Secure CHANGE USERNAME
  socket.on("change-username", async (data) => {
    try {
      const { sessionToken, newUsername, password } = data || {};
      
      // Rate limiting
      if (!checkRateLimit(clientIP, "change-username")) {
        socket.emit("change-username-result", {
          success: false,
          message: "Too many attempts. Please wait."
        });
        return;
      }
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("change-username-result", {
          success: false,
          message: "Session expired. Please login again."
        });
        return;
      }
      
      // Validate new username
      if (!validateUsername(newUsername)) {
        socket.emit("change-username-result", {
          success: false,
          message: "Username must be 3-30 characters (letters, numbers, _ or -)."
        });
        return;
      }
      
      // Require password verification
      if (!password || typeof password !== "string") {
        socket.emit("change-username-result", {
          success: false,
          message: "🔓 Password required to change username."
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
      
      // Check if new username is taken
      const existingUser = await User.findOne({ usernameHash: newUsernameHash });
      if (existingUser && existingUser.usernameHash !== session.usernameHash) {
        socket.emit("change-username-result", {
          success: false,
          message: "This username is already taken."
        });
        return;
      }
      
      // Update user
      user.usernameHash = newUsernameHash;
      user.usernameEncrypted = encrypt(newUsername);
      await user.save();
      
      // Update session
      session.usernameHash = newUsernameHash;
      session.username = newUsername;
      
      socket.emit("change-username-result", {
        success: true,
        username: newUsername,
        message: "🔓 Username changed successfully!"
      });
      
      console.log(`[CHANGE] Username updated`);
    } catch (error) {
      console.error("Change username error:", error.message);
      socket.emit("change-username-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // Secure CHANGE PASSWORD
  socket.on("change-password", async (data) => {
    try {
      const { sessionToken, oldPassword, newPassword } = data || {};
      
      // Rate limiting
      if (!checkRateLimit(clientIP, "change-password")) {
        socket.emit("change-password-result", {
          success: false,
          message: "Too many attempts. Please wait."
        });
        return;
      }
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("change-password-result", {
          success: false,
          message: "Session expired. Please login again."
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
      
      // Hash new password
      user.passwordHash = await bcrypt.hash(newPassword + SALT, SALT_ROUNDS);
      await user.save();
      
      socket.emit("change-password-result", {
        success: true,
        message: "🔓 Password changed successfully!"
      });
      
      console.log(`[CHANGE] Password updated for user`);
    } catch (error) {
      console.error("Change password error:", error.message);
      socket.emit("change-password-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // Secure DELETE ACCOUNT
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
          message: "🔓 Password required to delete account."
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
      
      // Delete user
      await User.deleteOne({ usernameHash: session.usernameHash });
      
      // Invalidate session
      activeSessions.delete(sessionToken);
      
      socket.emit("delete-account-result", {
        success: true,
        message: "🔓 Account deleted. All your data has been securely erased!"
      });
      
      console.log(`[DELETE] User account deleted`);
    } catch (error) {
      console.error("Delete account error:", error.message);
      socket.emit("delete-account-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // JOIN ROOM
  socket.on("join-room", async (data) => {
    try {
      const { room, password, sessionToken } = data || {};
      
      // Rate limiting
      if (!checkRateLimit(clientIP, "join-room")) {
        socket.emit("join-room-result", {
          success: false,
          message: "Too many attempts. Please wait."
        });
        return;
      }
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("join-room-result", {
          success: false,
          message: "Session expired. Please login again."
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
        // Room exists, check password
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
        console.log(`[ROOM] User joined ${roomLower}`);
      } else {
        // Create new room
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
        console.log(`[ROOM] User created and joined ${roomLower}`);
      }
    } catch (error) {
      console.error("Join room error:", error.message);
      socket.emit("join-room-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // LEAVE ROOM
  socket.on("leave-room", (data) => {
    if (data && data.room) {
      socket.leave(data.room);
      console.log(`[ROOM] User left ${data.room}`);
    }
  });
  
  // MESSAGES - In-memory only, never stored!
  socket.on("message", (data) => {
    if (!currentSession) return;
    if (!data || !data.room || !data.message) return;
    
    // Rate limiting
    if (!checkRateLimit(clientIP, "message")) {
      return; // Silently drop message
    }
    
    // Sanitize message
    const sanitizedMessage = sanitizeMessage(data.message);
    if (!sanitizedMessage) return;
    
    const messageData = {
      message: sanitizedMessage,
      username: currentSession.username,
      messageID: data.messageID || crypto.randomBytes(16).toString("hex"),
      room: data.room,
      timestamp: Date.now()
    };
    
    // Broadcast to room (never saved!)
    io.to(data.room).emit("message", messageData);
  });
  
  // LOGOUT
  socket.on("logout", (data) => {
    const { sessionToken } = data || {};
    if (sessionToken) {
      activeSessions.delete(sessionToken);
    }
    currentSession = null;
    console.log("[LOGOUT] User logged out");
  });
  
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id.substring(0, 8) + "...");
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔒 Secure Chat Server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
});
