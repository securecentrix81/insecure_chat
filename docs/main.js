// ============================================
// 🔧 CONFIGURATION - UPDATE THIS!
// ============================================
// Replace with your Render backend URL
const BACKEND_URL = "https://secure-chat-2177.onrender.com/";
// ============================================

// Connect to remote backend
const socket = io(BACKEND_URL, {
  transports: ["websocket", "polling"],
  withCredentials: true
});

// State
let currentUser = null;
let currentRoom = null;
let sessionToken = null;

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

// Connection event handlers
socket.on("connect", () => {
  console.log("Connected to server");
  hideConnectionStatus();
  
  // Re-validate session on connect
  if (sessionToken) {
    socket.emit("validate-session", { sessionToken });
  }
});

socket.on("connect_error", (error) => {
  console.error("Connection error:", error);
  showConnectionStatus("⚠️ Cannot connect to server. Retrying...", "error");
});

socket.on("disconnect", (reason) => {
  console.log("Disconnected:", reason);
  showConnectionStatus("🔌 Disconnected from server. Reconnecting...", "warning");
});

socket.on("reconnect", (attemptNumber) => {
  console.log("Reconnected after", attemptNumber, "attempts");
  hideConnectionStatus();
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
    showFeedback(loginFeedback, "🔓 Please enter both username and password!", "error");
    return;
  }
  
  loginBtn.disabled = true;
  loginBtn.textContent = "Logging in...";
  
  socket.emit("login", { username, password });
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
  loginBtn.textContent = "🔓 Login";
  
  if (data.success) {
    currentUser = data.user;
    sessionToken = data.sessionToken;
    currentUserBadge.textContent = currentUser.username;
    saveSession();
    showView(homeView);
    hideFeedback(loginFeedback);
    loginPassword.value = "";
  } else {
    showFeedback(loginFeedback, data.message, data.type || "error");
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
    showFeedback(signupFeedback, "🔓 Password must be at least 8 characters.", "error");
    return;
  }
  
  signupBtn.disabled = true;
  signupBtn.textContent = "Creating account...";
  
  socket.emit("signup", { username, password });
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
  signupBtn.textContent = "🔓 Create Account";
  
  if (data.success) {
    currentUser = data.user;
    sessionToken = data.sessionToken;
    currentUserBadge.textContent = currentUser.username;
    saveSession();
    showFeedback(signupFeedback, "✅ " + data.message, "success");
    setTimeout(() => {
      showView(homeView);
      signupPassword.value = "";
    }, 1500);
  } else {
    showFeedback(signupFeedback, data.message, data.type || "error");
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

// Exit Room
exitRoomBtn.addEventListener("click", () => {
  socket.emit("leave-room", { room: currentRoom });
  currentRoom = null;
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
    showFeedback(usernameFeedback, "🔓 Password required to change username", "error");
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
    showFeedback(passwordFeedback, "🔓 Current password is required", "error");
    return;
  }
  
  if (!newPwd || newPwd.length < 8) {
    showFeedback(passwordFeedback, "🔓 New password must be at least 8 characters", "error");
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
    showFeedback(deleteFeedback, "🔓 Password required to delete account", "error");
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
      <div class="empty-state-icon">🔓</div>
      <div>No messages yet</div>
      <div style="font-size: 0.85rem;">Start chatting!</div>
      <div class="insecurity-note">
        ⚠️ Messages are NOT stored anywhere. When you leave, they're gone forever!
      </div>
    </div>
  `;
}

function send() {
  if (msgInput.value.trim() === "") return;
  
  const randomID = crypto.randomUUID ? crypto.randomUUID() : 
    Math.random().toString(36).substring(2) + Date.now().toString(36);
  
  const data = {
    message: msgInput.value.substring(0, 2000),
    username: currentUser.username,
    messageID: randomID,
    room: currentRoom
  };
  
  socket.emit("message", data);
  renderMessage(data, true);
  msgInput.value = "";
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
  
  msgDiv.innerHTML = `
    <div class="message-header">
      <span class="message-author">${escapeHTML(data.username)}</span>
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

socket.on("message", (data) => {
  if (data.room === currentRoom) {
    renderMessage(data, false);
  }
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
