// ============================================
// 🔧 CONFIGURATION - UPDATE THIS!
// ============================================
// Replace with your Render backend URL (no trailing slash!)
const BACKEND_URL = "https://chat-0qsk.onrender.com/socket/insecure";
// ============================================

// Connect to remote backend
const socket = io(BACKEND_URL, {
  transports: ["polling", "websocket"], // Try polling first, then upgrade
  withCredentials: false, // Set to false for cross-origin without cookies
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  timeout: 120000
});

// Loading screen elements
const loadingScreen = document.getElementById("loading-screen")
const loadingStatus = document.getElementById("loading-status")
const loadingProgressBar = document.getElementById("loading-progress-bar")

// Simulate progress while connecting
let progress = 0
const progressInterval = setInterval(() => {
  if (progress < 90) {
    progress += Math.random()*90/120*500/1000
    loadingProgressBar.style.width = Math.min(progress, 90) + "%"
  }
}, 500)

// Update status messages
const statusMessages = [
  "Connecting to server...",
  "This may take a few minutes...",
  "Waking up server...",
  "Sending passwords to hacker...",
  "Establishing insecure connection...",
]
let statusIndex = 0
const statusInterval = setInterval(() => {
  statusIndex = (statusIndex + 1) % statusMessages.length
  loadingStatus.textContent = statusMessages[statusIndex]
}, 3000)

// When connected, hide loading screen
socket.on("connect", () => {
  clearInterval(progressInterval)
  clearInterval(statusInterval)
  loadingProgressBar.style.width = "100%"
  loadingStatus.textContent = "Connected!"
  
  setTimeout(() => {
    loadingScreen.classList.add("hidden")
    authView.classList.remove("hidden")
  }, 400)
})

// Handle connection error
socket.on("connect_error", () => {
  loadingStatus.textContent = "Connection failed. Retrying..."
  loadingProgressBar.style.background = "#dc2626"
})

// State
let currentUser = null;
let currentRoom = null;
let sessionToken = null;
let currentRoomPassword = null;

// Connection status element
const connectionStatus = document.getElementById("connection-status");

function showConnectionStatus(message, type) {
  if (connectionStatus) {
    connectionStatus.textContent = message;
    connectionStatus.className = `connection-status ${type}`;
    connectionStatus.style.display = "block";
  }
}

function hideConnectionStatus() {
  if (connectionStatus) {
    connectionStatus.style.display = "none";
  }
}

// Try to restore session from localStorage
const savedSession = localStorage.getItem("insecure-chat-session");
if (savedSession) {
  try {
    const parsed = JSON.parse(savedSession);
    sessionToken = parsed.token;
    // Will validate after connection
  } catch (e) {
    localStorage.removeItem("insecure-chat-session");
  }
}

// DOM Elements - Views
const authView = document.getElementById("auth-view");
const homeView = document.getElementById("home-view");
const chatView = document.getElementById("chat-view");

// DOM Elements - Auth
const loginTab = document.getElementById("login-tab");
const signupTab = document.getElementById("signup-tab");
const loginForm = document.getElementById("login-form");
const signupForm = document.getElementById("signup-form");

// DOM Elements - Login
const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const loginBtn = document.getElementById("login-btn");
const loginFeedback = document.getElementById("login-feedback");

// DOM Elements - Signup
const signupUsername = document.getElementById("signup-username");
const signupPassword = document.getElementById("signup-password");
const signupBtn = document.getElementById("signup-btn");
const signupFeedback = document.getElementById("signup-feedback");

// DOM Elements - Home
const currentUserBadge = document.getElementById("current-user-badge");
const logoutBtn = document.getElementById("logout-btn");
const joinRoomCard = document.getElementById("join-room-card");
const settingsCard = document.getElementById("settings-card");

// DOM Elements - Join Room
const joinRoomPanel = document.getElementById("join-room-panel");
const roomName = document.getElementById("room-name");
const roomPassword = document.getElementById("room-password");
const joinRoomBtn = document.getElementById("join-room-btn");
const cancelRoomBtn = document.getElementById("cancel-room-btn");
const roomFeedback = document.getElementById("room-feedback");

// DOM Elements - Settings
const settingsPanel = document.getElementById("settings-panel");
const closeSettingsBtn = document.getElementById("close-settings-btn");
const newUsername = document.getElementById("new-username");
const usernameChangePassword = document.getElementById("username-change-password");
const changeUsernameBtn = document.getElementById("change-username-btn");
const usernameFeedback = document.getElementById("username-feedback");
const oldPassword = document.getElementById("old-password");
const newPassword = document.getElementById("new-password");
const changePasswordBtn = document.getElementById("change-password-btn");
const passwordFeedback = document.getElementById("password-feedback");
const deleteAccountBtn = document.getElementById("delete-account-btn");

// DOM Elements - Delete Modal
const deleteModal = document.getElementById("delete-modal");
const deletePassword = document.getElementById("delete-password");
const deleteFeedback = document.getElementById("delete-feedback");
const cancelDeleteBtn = document.getElementById("cancel-delete-btn");
const confirmDeleteBtn = document.getElementById("confirm-delete-btn");

// DOM Elements - Chat
const roomBadge = document.getElementById("room-badge");
const exitRoomBtn = document.getElementById("exit-room-btn");
const chatBox = document.getElementById("chat-box");
const msgInput = document.getElementById("msg-input");
const sendBtn = document.getElementById("send-btn");

const roomList = document.getElementById("room-list");
const refreshRoomsBtn = document.getElementById("refresh-rooms-btn");


// Converts string <-> ArrayBuffer
function strToBuf(str) {
  return new TextEncoder().encode(str);
}

function bufToStr(buf) {
  return new TextDecoder().decode(buf);
}

// Base64 helpers (for safe text encoding)
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Derive a key from a password (PBKDF2 + SHA-256)
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", strToBuf(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 1000000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt a string with AES-GCM
async function encryptAES(value, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // for PBKDF2
  const iv = crypto.getRandomValues(new Uint8Array(12));   // AES-GCM nonce
  const key = await deriveKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    strToBuf(value)
  );

  // Combine all and encode
  const result = {
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
    data: bufToBase64(ciphertext)
  };
  return btoa(JSON.stringify(result));
}

// Decrypt a string with AES-GCM
async function decryptAES(encrypted, password) {
  const { salt, iv, data } = JSON.parse(atob(encrypted));
  const key = await deriveKey(password, base64ToBuf(salt));

  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuf(iv) },
    key,
    base64ToBuf(data)
  );

  return bufToStr(plaintextBuf);
}

// Helper Functions
function showFeedback(element, message, type) {
  element.innerHTML = message;
  element.className = `feedback show ${type}`;
}

function hideFeedback(element) {
  element.className = "feedback";
}

function showView(view) {
  authView.classList.add("hidden");
  homeView.classList.add("hidden");
  chatView.classList.add("hidden");
  view.classList.remove("hidden");
}

function saveSession() {
  if (sessionToken && currentUser) {
    localStorage.setItem("insecure-chat-session", JSON.stringify({
      token: sessionToken,
      username: currentUser.username
    }));
  }
}

function clearSession() {
  localStorage.removeItem("insecure-chat-session");
  sessionToken = null;
  currentUser = null;
}

// Turnstile tokens
let loginTurnstileToken = null;
let signupTurnstileToken = null;

// Turnstile callbacks (called by Cloudflare when widget is solved)
function onLoginTurnstileSuccess(token) {
  loginTurnstileToken = token;
}

function onSignupTurnstileSuccess(token) {
  signupTurnstileToken = token;
}

// Make callbacks globally accessible
window.onLoginTurnstileSuccess = onLoginTurnstileSuccess;
window.onSignupTurnstileSuccess = onSignupTurnstileSuccess;

// Function to reset Turnstile widgets
function resetTurnstile(widgetId) {
  if (window.turnstile) {
    try {
      turnstile.reset(widgetId);
    } catch (e) {
      console.log("Turnstile reset failed:", e);
    }
  }
}

// Connection event handlers
socket.on("connect", () => {
  console.log("✅ Connected to server:", socket.id);
  hideConnectionStatus();
  
  // Re-validate session on connect
  if (sessionToken) {
    socket.emit("validate-session", { sessionToken });
  }
});

socket.on("connect_error", (error) => {
  console.error("Connection error:", error.message || error);
  console.error("Backend URL:", BACKEND_URL);
  console.error("Transport:", socket.io.engine?.transport?.name || "none");
  showConnectionStatus("⚠️ Cannot connect to server. Check console for details.", "error");
});

socket.on("disconnect", (reason) => {
  console.log("Disconnected:", reason);
  showConnectionStatus("🔌 Disconnected from server. Reconnecting...", "warning");
});

socket.io.on("reconnect", (attemptNumber) => {
  console.log("Reconnected after", attemptNumber, "attempts");
  hideConnectionStatus();
});

socket.io.on("reconnect_attempt", (attemptNumber) => {
  console.log("Reconnection attempt", attemptNumber);
});

socket.io.on("reconnect_error", (error) => {
  console.error("Reconnection error:", error.message || error);
});

socket.io.on("reconnect_failed", () => {
  console.error("Failed to reconnect after all attempts");
  showConnectionStatus("❌ Failed to connect. Please refresh the page.", "error");
});

// Session validation response
socket.on("session-valid", (data) => {
  if (data.success) {
    currentUser = data.user;
    currentUserBadge.textContent = currentUser.username;
    showView(homeView);
  } else {
    clearSession();
  }
});

// Auth Tab Switching
loginTab.addEventListener("click", () => {
  loginTab.classList.add("active");
  signupTab.classList.remove("active");
  loginForm.classList.remove("hidden");
  signupForm.classList.add("hidden");
  hideFeedback(loginFeedback);
});

signupTab.addEventListener("click", () => {
  signupTab.classList.add("active");
  loginTab.classList.remove("active");
  signupForm.classList.remove("hidden");
  loginForm.classList.add("hidden");
  hideFeedback(signupFeedback);
});

// Login
loginBtn.addEventListener("click", () => {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  
  if (!username || !password) {
    showFeedback(loginFeedback, "Please enter both username and password!", "error");
    return;
  }
  
  if (!loginTurnstileToken) {
    showFeedback(loginFeedback, "🤖 Please complete the captcha verification.", "error");
    return;
  }
  
  loginBtn.disabled = true;
  loginBtn.textContent = "Logging in...";
  
  socket.emit("login", { 
    username, 
    password,
    captchaToken: loginTurnstileToken
  });
});

// Handle Enter key for login
loginUsername.addEventListener("keydown", (e) => {
  if (e.key === "Enter") loginPassword.focus();
});

loginPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") loginBtn.click();
});

socket.on("login-result", (data) => {
  loginBtn.disabled = false;
  loginBtn.textContent = "Login";
  
  if (data.success) {
    currentUser = data.user;
    sessionToken = data.sessionToken;
    currentUserBadge.textContent = currentUser.username;
    saveSession();
    showView(homeView);
    hideFeedback(loginFeedback);
    loginPassword.value = "";
    loginTurnstileToken = null;
  } else {
    showFeedback(loginFeedback, data.message, data.type || "error");
    
    // Reset captcha if server tells us to
    if (data.resetCaptcha) {
      loginTurnstileToken = null;
      resetTurnstile("#login-turnstile");
    }
  }
});

// Signup
signupBtn.addEventListener("click", () => {
  const username = signupUsername.value.trim();
  const password = signupPassword.value;
  
  if (!username) {
    showFeedback(signupFeedback, "Please enter a username", "error");
    return;
  }
  
  if (username.length < 3 || username.length > 30) {
    showFeedback(signupFeedback, "Username must be between 3 and 30 characters", "error");
    return;
  }
  
  if (!password || password.length < 8) {
    showFeedback(signupFeedback, "Password must be at least 8 characters.", "error");
    return;
  }
  
  if (!signupTurnstileToken) {
    showFeedback(signupFeedback, "Please complete the captcha verification.", "error");
    return;
  }
  
  signupBtn.disabled = true;
  signupBtn.textContent = "Creating account...";
  
  socket.emit("signup", { 
    username, 
    password,
    captchaToken: signupTurnstileToken
  });
});

// Handle Enter key for signup
signupUsername.addEventListener("keydown", (e) => {
  if (e.key === "Enter") signupPassword.focus();
});

signupPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") signupBtn.click();
});

socket.on("signup-result", (data) => {
  signupBtn.disabled = false;
  signupBtn.textContent = "Create Account";
  
  if (data.success) {
    currentUser = data.user;
    sessionToken = data.sessionToken;
    currentUserBadge.textContent = currentUser.username;
    saveSession();
    showFeedback(signupFeedback, "✅ " + data.message, "success");
    signupTurnstileToken = null;
    setTimeout(() => {
      showView(homeView);
      signupPassword.value = "";
    }, 1500);
  } else {
    showFeedback(signupFeedback, data.message, data.type || "error");
    
    // Reset captcha if server tells us to
    if (data.resetCaptcha) {
      signupTurnstileToken = null;
      resetTurnstile("#signup-turnstile");
    }
  }
});

// Logout
logoutBtn.addEventListener("click", () => {
  socket.emit("logout", { sessionToken });
  clearSession();
  currentRoom = null;
  showView(authView);
  loginUsername.value = "";
  loginPassword.value = "";
  joinRoomPanel.classList.add("hidden");
  settingsPanel.classList.add("hidden");
});

// Join Room
joinRoomCard.addEventListener("click", () => {
  joinRoomPanel.classList.remove("hidden");
  settingsPanel.classList.add("hidden");
  hideFeedback(roomFeedback);
  socket.emit("get-rooms"); // ← Add this line
});
refreshRoomsBtn.addEventListener("click", () => {
  roomList.innerHTML = '<div class="room-list-empty">Loading...</div>';
  socket.emit("get-rooms");
});

cancelRoomBtn.addEventListener("click", () => {
  joinRoomPanel.classList.add("hidden");
});

joinRoomBtn.addEventListener("click", () => {
  const room = roomName.value.trim() || "general";
  const password = roomPassword.value;
  
  if (!/^[a-zA-Z0-9_-]+$/.test(room)) {
    showFeedback(roomFeedback, "Room name can only contain letters, numbers, underscores, and hyphens", "error");
    return;
  }
  
  // Store password for encryption (use room name if no password provided)
  currentRoomPassword = password || room;
  
  socket.emit("join-room", { room, password, sessionToken });
});

// Handle Enter key for room
roomName.addEventListener("keydown", (e) => {
  if (e.key === "Enter") joinRoomBtn.click();
});

socket.on("join-room-result", (data) => {
  if (data.success) {
    currentRoom = data.room;
    roomBadge.textContent = data.room;
    clearChat();
    showView(chatView);
    hideFeedback(roomFeedback);
    roomPassword.value = "";
    roomName.value = "";
  } else {
    showFeedback(roomFeedback, data.message, "error");
  }
});

exitRoomBtn.addEventListener("click", () => {
  socket.emit("leave-room", { room: currentRoom });
  currentRoom = null;
  currentRoomPassword = null; // ← ADD THIS
  showView(homeView);
  joinRoomPanel.classList.add("hidden");
});

// Settings
settingsCard.addEventListener("click", () => {
  settingsPanel.classList.remove("hidden");
  joinRoomPanel.classList.add("hidden");
  newUsername.value = currentUser.username;
  hideFeedback(usernameFeedback);
  hideFeedback(passwordFeedback);
});

closeSettingsBtn.addEventListener("click", () => {
  settingsPanel.classList.add("hidden");
});

// Change Username
changeUsernameBtn.addEventListener("click", () => {
  const username = newUsername.value.trim();
  const password = usernameChangePassword.value;
  
  if (!username) {
    showFeedback(usernameFeedback, "Please enter a username", "error");
    return;
  }
  
  if (!password) {
    showFeedback(usernameFeedback, "Password required to change username", "error");
    return;
  }
  
  socket.emit("change-username", { 
    sessionToken,
    newUsername: username,
    password
  });
});

socket.on("change-username-result", (data) => {
  if (data.success) {
    currentUser.username = data.username;
    currentUserBadge.textContent = data.username;
    saveSession();
    showFeedback(usernameFeedback, "✅ " + data.message, "success");
    usernameChangePassword.value = "";
  } else {
    showFeedback(usernameFeedback, data.message, "error");
  }
});

// Change Password
changePasswordBtn.addEventListener("click", () => {
  const oldPwd = oldPassword.value;
  const newPwd = newPassword.value;
  
  if (!oldPwd) {
    showFeedback(passwordFeedback, "Current password is required", "error");
    return;
  }
  
  if (!newPwd || newPwd.length < 8) {
    showFeedback(passwordFeedback, "New password must be at least 8 characters", "error");
    return;
  }
  
  socket.emit("change-password", { 
    sessionToken,
    oldPassword: oldPwd, 
    newPassword: newPwd 
  });
});

socket.on("change-password-result", (data) => {
  if (data.success) {
    showFeedback(passwordFeedback, "✅ " + data.message, "success");
    oldPassword.value = "";
    newPassword.value = "";
  } else {
    showFeedback(passwordFeedback, data.message, "error");
  }
});

// Delete Account
deleteAccountBtn.addEventListener("click", () => {
  deleteModal.classList.remove("hidden");
  deletePassword.value = "";
  hideFeedback(deleteFeedback);
});

cancelDeleteBtn.addEventListener("click", () => {
  deleteModal.classList.add("hidden");
});

confirmDeleteBtn.addEventListener("click", () => {
  const password = deletePassword.value;
  
  if (!password) {
    showFeedback(deleteFeedback, "Password required to delete account", "error");
    return;
  }
  
  socket.emit("delete-account", { 
    sessionToken,
    password
  });
});

socket.on("delete-account-result", (data) => {
  if (data.success) {
    alert(data.message);
    clearSession();
    deleteModal.classList.add("hidden");
    showView(authView);
  } else {
    showFeedback(deleteFeedback, data.message, "error");
  }
});

// Chat Functions
function clearChat() {
  chatBox.innerHTML = `
    <div class="empty-state" id="empty-state">
      <div class="empty-state-icon">💬</div>
      <div>No messages yet</div>
      <div style="font-size: 0.85rem;">Start chatting!</div>
      <div class="insecurity-note">
        ⚠️ Messages are NOT stored anywhere. When you leave, they're gone forever!
      </div>
    </div>
  `;
}

// Replace your send function
async function send() {
  if (msgInput.value.trim() === "") return;
  
  const originalMessage = msgInput.value.substring(0, 2000);
  
  const randomID = crypto.randomUUID ? crypto.randomUUID() : 
    Math.random().toString(36).substring(2) + Date.now().toString(36);
  
  try {
    // Encrypt the message
    const encryptedMessage = await encryptAES(originalMessage, currentRoomPassword);
    
    const data = {
      message: encryptedMessage,
      username: currentUser.username,
      messageID: randomID,
      room: currentRoom,
      encrypted: true // Flag so receivers know to decrypt
    };
    
    socket.emit("message", data);
    
    // Render original message for self (we already know what we sent)
    renderMessage({
      message: originalMessage,
      username: currentUser.username,
      messageID: randomID,
      room: currentRoom
    }, true);
    
    msgInput.value = "";
    
  } catch (error) {
    console.error("Encryption failed:", error);
    showFeedback(roomFeedback, "Failed to encrypt message", "error");
  }
}

function escapeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderMessage(data, isSelf) {
  const emptyState = document.getElementById("empty-state");
  if (emptyState) emptyState.remove();
  
  const msgIDElement = document.getElementById("msg-" + data.messageID);
  if (msgIDElement) {
    msgIDElement.classList.remove("unloaded");
    return;
  }
  
  const msgDiv = document.createElement("div");
  const isCurrentUser = data.username === currentUser?.username;
  msgDiv.className = `message ${isSelf ? "unloaded" : ""} ${isCurrentUser ? "user-msg" : "other-msg"}`;
  msgDiv.id = `msg-${data.messageID}`;
  
  // Add encryption indicator
  const lockIcon = data.decryptionFailed ? "🔓❌" : "🔒";
  
  msgDiv.innerHTML = `
    <div class="message-header">
      <span class="message-author">${escapeHTML(data.username)}</span>
      <span class="encryption-badge" title="End-to-end encrypted">${lockIcon}</span>
    </div>
    <div class="message-text">${escapeHTML(data.message)}</div>
  `;
  
  chatBox.appendChild(msgDiv);
  chatBox.scrollTop = chatBox.scrollHeight;
}

sendBtn.addEventListener("click", send);

msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) send();
});

socket.on("message", async (data) => {
  if (data.room === currentRoom) {
    // Skip our own messages (already rendered)
    if (data.username === currentUser?.username) {
      // Just mark as loaded if we sent it
      const msgEl = document.getElementById("msg-" + data.messageID);
      if (msgEl) msgEl.classList.remove("unloaded");
      return;
    }
    
    // Decrypt if encrypted
    if (data.encrypted && currentRoomPassword) {
      try {
        data.message = await decryptAES(data.message, currentRoomPassword);
      } catch (error) {
        console.error("Decryption failed:", error);
        data.message = "🔒 [Cannot decrypt - wrong room password?]";
        data.decryptionFailed = true;
      }
    }
    
    renderMessage(data, false);
  }
});

socket.on("room-list", (data) => {
  if (!data.success || data.rooms.length === 0) {
    roomList.innerHTML = '<div class="room-list-empty">No rooms yet. Create one below!</div>';
    return;
  }
  
  roomList.innerHTML = data.rooms.map(room => `
    <div class="room-list-item" data-room="${escapeHTML(room.name)}" data-protected="${room.hasPassword}">
      <span class="room-list-name">#${escapeHTML(room.name)}</span>
      ${room.hasPassword ? '<span class="room-list-lock">🔒</span>' : ''}
    </div>
  `).join("");
  
  // Add click handlers
  roomList.querySelectorAll(".room-list-item").forEach(item => {
    item.addEventListener("click", () => {
      const name = item.dataset.room;
      const isProtected = item.dataset.protected === "true";
      
      roomName.value = name;
      
      if (isProtected) {
        roomPassword.focus();
        showFeedback(roomFeedback, "🔒 This room requires a password", "info");
      } else {
        roomPassword.value = "";
        joinRoomBtn.click();
      }
    });
  });
});

// Handle message rate limit errors
socket.on("message-error", (data) => {
  // Mark the message as failed
  const msgEl = document.getElementById("msg-" + data.messageID);
  if (msgEl) {
    msgEl.classList.add("failed");
    msgEl.querySelector(".message-text").innerHTML += ' <span style="color: #dc2626; font-size: 0.8rem;">(Rate limited)</span>';
  }
  
  // Show a brief notification
  console.warn("Message rate limited:", data.message);
});

// Password visibility toggle
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
  } else {
    input.type = "password";
    btn.textContent = "👁️";
  }
}

window.togglePassword = togglePassword;
