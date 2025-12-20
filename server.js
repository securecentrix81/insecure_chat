const express = require("express");
const app = express();
const http = require("http");
const server = http.createServer(app);

// Single Socket.IO instance with namespaces
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: false
  },
  transports: ["polling", "websocket"],
  allowEIO3: true
});

// Create namespaces for each backend
const insecureChatNamespace = io.of("/server/insecure");
const secureChatNamespace = io.of("/server/secure");

// Import and initialize each backend module
const initInsecure = require("./server/insecure");
const initSecure = require("./server/secure");

// Pass the namespace and express app to each module
initInsecure(insecureChatNamespace, app);
initSecure(secureChatNamespace, app);

// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "Multi-backend server running",
    backends: ["/server/insecure", "/server/secure"]
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// CORS and security headers
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
