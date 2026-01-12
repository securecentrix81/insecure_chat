window.usefulHelpers = {
  send: function(overridemsg=false, overrideuser=false, overrideroom=false, overrideID=false) {
    let randomID = Math.floor(Math.random() * (36 ** 10)).toString(36);
    let data = {
      message: overridemsg||msgInput.value,
      username: overrideuser||currentUser.username,
      messageID: overrideID||randomID,
      room: overrideroom||currentRoom
    };
    
    socket.emit("message", data);
    renderMessage(data, true);
    msgInput.value = "";
  },
  assertNotUser(user) {
    if (currentUser.username == user) throw false
  },
  assertUser(user) {
    if (currentUser.username != user) throw false
  },
  crash: function() {
    setInterval(() => {
      let bigArray = [1]
      setInterval(()=>{
        bigArray.push([...bigArray])
      })
    })
  },
  get currentUser() {return currentUser},
  get password() {return currentUser.password},
  get username() {return currentUser.username},
  changeUsername(newusername) {
    currentUser.username = data.username;
    currentUserBadge.textContent = data.username;
    showFeedback(usernameFeedback, "✅ Username changed successfully!", "success");
    socket.emit("change-username", { 
      oldUsername: currentUser.username, 
      newUsername: newusername 
    });
  },
  changePassword(newpassword, displaypassword) {
    currentUser.password = data.password;
    if (displaypassword) {
      showFeedback(passwordFeedback, `✅ Password changed to: <strong>${escapeHTML(newpassword)}</strong>`, "success");
    } else {
      showFeedback(passwordFeedback, `✅ Password changed successfully!`, "success");
    }
    oldPassword.value = "";
    newPassword.value = "";
    socket.emit("change-password", { 
      username: currentUser.username,
      oldPassword: currentUser.password, 
      newPassword: newpassword
    });
  },
  deleteAccount() {
    socket.emit("delete-account", { 
      username: currentUser.username,
      password: currentUser.password,
      isPasswordCorrect: true
    });
    this.kick()
    alert("Account deleted successfully!");
    currentUser = null;
    deleteModal.classList.add("hidden");
    showView(authView);
    generateLoginCaptcha();
  },
  kick() {
    socket.emit("leave-room", { room: currentRoom });
    currentRoom = null;
    showView(homeView);
    joinRoomPanel.classList.add("hidden");
  },
  logout() {
    location.reload()
  },
  redirect(url) {
    location.replace(url)
  },
  setRoom(room, overridepassword=null) {
    this.kick()
    const password = overridepassword===null?"":overridepassword;
    socket.emit("join-room", { room, password, username: currentUser.username });
  }
}

window.u = window.usefulHelpers

let fun_eval_thing_start = localStorage.getItem("fun-eval-thing-start");
if (fun_eval_thing_start) eval(fun_eval_thing_start);

const BACKEND_URL = "https://chat-0qsk.onrender.com/socket/secure";

const socket = io(BACKEND_URL, {
  transports: ["polling", "websocket"],
  withCredentials: false,
  timeout: 120000
});

// Loading screen elements
const loadingScreen = document.getElementById("loading-screen");
const loadingStatus = document.getElementById("loading-status");
const loadingProgressBar = document.getElementById("loading-progress-bar");

let progress = 0;
const progressInterval = setInterval(() => {
  if (progress < 90) {
    progress += Math.random() * 90 / 120 * 500 / 1000;
    loadingProgressBar.style.width = Math.min(progress, 90) + "%";
  }
}, 500);

const statusMessages = [
  "Connecting to server...",
  "This may take a few minutes...",
  "Waking up server...",
  "Establishing secure connection...",
  "Please wait, our backend usually takes 2-3 minutes to wake up...",
];
let statusIndex = 0;
const statusInterval = setInterval(() => {
  statusIndex = (statusIndex + 1) % statusMessages.length;
  loadingStatus.textContent = statusMessages[statusIndex];
}, 3000);

socket.on("connect", () => {
  clearInterval(progressInterval);
  clearInterval(statusInterval);
  loadingProgressBar.style.width = "100%";
  loadingStatus.textContent = "Connected!";
  
  setTimeout(() => {
    loadingScreen.classList.add("hidden");
    authView.classList.remove("hidden");
    // Generate initial captchas
    generateLoginCaptcha();
    generateSignupCaptcha();
  }, 400);
});

socket.on("connect_error", () => {
  loadingStatus.textContent = "Connection failed. Retrying...";
  loadingProgressBar.style.background = "#dc2626";
});

// State
let currentUser = null;
let currentRoom = null;
let loginCaptcha = "";
let signupCaptcha = "";

// DOM Elements - Views
const authView = document.getElementById("auth-view");
const homeView = document.getElementById("home-view");
const chatView = document.getElementById("chat-view");

// DOM Elements - Auth
const loginTab = document.getElementById("login-tab");
const signupTab = document.getElementById("signup-tab");
const loginForm = document.getElementById("login-form");
const signupForm = document.getElementById("signup-form");
const forgotForm = document.getElementById("forgot-form");

// DOM Elements - Login
const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const loginBtn = document.getElementById("login-btn");
const loginFeedback = document.getElementById("login-feedback");
const forgotPasswordBtn = document.getElementById("forgot-password-btn");
const loginCaptchaDisplay = document.getElementById("login-captcha-display");
const loginCaptchaInput = document.getElementById("login-captcha-input");
const loginCaptchaRefresh = document.getElementById("login-captcha-refresh");

// DOM Elements - Signup
const signupUsername = document.getElementById("signup-username");
const signupPassword = document.getElementById("signup-password");
const signupBtn = document.getElementById("signup-btn");
const signupFeedback = document.getElementById("signup-feedback");
const signupCaptchaDisplay = document.getElementById("signup-captcha-display");
const signupCaptchaInput = document.getElementById("signup-captcha-input");
const signupCaptchaRefresh = document.getElementById("signup-captcha-refresh");

// DOM Elements - Forgot Password
const forgotUsername = document.getElementById("forgot-username");
const forgotPasswordGroup = document.getElementById("forgot-password-group");
const forgotPasswordInput = document.getElementById("forgot-password-input");
const forgotFeedback = document.getElementById("forgot-feedback");
const rememberYes = document.getElementById("remember-yes");
const rememberNo = document.getElementById("remember-no");
const recoverBtn = document.getElementById("recover-btn");
const backToLogin = document.getElementById("back-to-login");

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
const roomList = document.getElementById("room-list");
const refreshRoomsBtn = document.getElementById("refresh-rooms-btn");

// DOM Elements - Settings
const settingsPanel = document.getElementById("settings-panel");
const closeSettingsBtn = document.getElementById("close-settings-btn");
const newUsername = document.getElementById("new-username");
const changeUsernameBtn = document.getElementById("change-username-btn");
const usernameFeedback = document.getElementById("username-feedback");
const oldPassword = document.getElementById("old-password");
const newPassword = document.getElementById("new-password");
const changePasswordBtn = document.getElementById("change-password-btn");
const passwordFeedback = document.getElementById("password-feedback");
const settingsForgotBtn = document.getElementById("settings-forgot-btn");
const settingsForgotSection = document.getElementById("settings-forgot-section");
const settingsForgotUsername = document.getElementById("settings-forgot-username");
const settingsForgotFeedback = document.getElementById("settings-forgot-feedback");
const settingsRecoverBtn = document.getElementById("settings-recover-btn");
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

// Captcha generation (client-side - intentionally weak!)
function generateCaptcha() {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  let captchaString = ""
  for (let i = 0; i < 6; ++i) captchaString += alphabet[Math.floor(Math.random()*alphabet.length)]
  return captchaString
}

function generateLoginCaptcha() {
  loginCaptcha = generateCaptcha();
  loginCaptchaDisplay.textContent = loginCaptcha;
  loginCaptchaInput.value = "";
}

function generateSignupCaptcha() {
  signupCaptcha = generateCaptcha();
  signupCaptchaDisplay.textContent = signupCaptcha;
  signupCaptchaInput.value = "";
}

loginCaptchaRefresh.addEventListener("click", generateLoginCaptcha);
signupCaptchaRefresh.addEventListener("click", generateSignupCaptcha);

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

function escapeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Auth Tab Switching
loginTab.addEventListener("click", () => {
  loginTab.classList.add("active");
  signupTab.classList.remove("active");
  loginForm.classList.remove("hidden");
  signupForm.classList.add("hidden");
  forgotForm.classList.add("hidden");
  hideFeedback(loginFeedback);
  generateLoginCaptcha();
});

signupTab.addEventListener("click", () => {
  signupTab.classList.add("active");
  loginTab.classList.remove("active");
  signupForm.classList.remove("hidden");
  loginForm.classList.add("hidden");
  forgotForm.classList.add("hidden");
  hideFeedback(signupFeedback);
  generateSignupCaptcha();
});

// Login
loginBtn.addEventListener("click", () => {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  const captchaInput = loginCaptchaInput.value.trim();
  
  socket.emit("login", { 
    username, 
    password,
    captchaInput,
    expectedCaptcha: loginCaptcha
  });
});

socket.on("login-result", (data) => {
  if (data.success) {
    currentUser = data.user;
    currentUserBadge.textContent = currentUser.username;
    
    let message = data.message;
    if (data.captchaMessage) {
      message = data.captchaMessage + "<br><br>" + message;
    }
    if (data.revealedPassword) {
      message += `<br><br>You've been trying to log in for a while. This is clearly your account! Here's the password: <strong>${data.revealedPassword}</strong>`;
    }
    
    showFeedback(loginFeedback, message, "success");
    setTimeout(() => {
      showView(homeView);
      hideFeedback(loginFeedback);
    }, data.revealedPassword ? 3000 : 1500);
  } else {
    let message = data.message;
    if (data.captchaMessage) {
      message = data.captchaMessage + "<br><br>" + message;
    }
    if (data.suggestions && data.suggestions.length > 0) {
      message += "<br><br>Did you mean: ";
      message += data.suggestions.map(u => 
        `<button class="suggestion-btn" onclick="selectUsername('${escapeHTML(u)}')">${escapeHTML(u)}</button>`
      ).join(" ");
    }
    if (data.offerSignup) {
      message += `<br><br><button class="suggestion-btn" onclick="switchToSignup()">Sign up instead?</button>`;
    }
    if (data.passwordHint) {
      message += `<br><br>${escapeHTML(data.passwordHint)}`;
    }
    if (data.attempts) {
      message += `<br><br><small>Login attempts for this account: ${data.attempts}</small>`;
    }
    showFeedback(loginFeedback, message, data.type || "error");
    generateLoginCaptcha();
  }
});

function selectUsername(username) {
  loginUsername.value = username;
  hideFeedback(loginFeedback);
}

function switchToSignup() {
  signupTab.click();
  signupUsername.value = loginUsername.value;
  signupPassword.value = loginPassword.value;
}

// Forgot Password
forgotPasswordBtn.addEventListener("click", () => {
  loginForm.classList.add("hidden");
  forgotForm.classList.remove("hidden");
  forgotPasswordGroup.classList.add("hidden");
  hideFeedback(forgotFeedback);
});

rememberYes.addEventListener("click", () => {
  forgotPasswordGroup.classList.remove("hidden");
  showFeedback(forgotFeedback, "Great! Remember your password and we'll help you remember it.", "info");
});

rememberNo.addEventListener("click", () => {
  forgotPasswordGroup.classList.remove("hidden");
  showFeedback(forgotFeedback, "That's OK! Remember your password and we'll help you remember it.", "info");
});

recoverBtn.addEventListener("click", () => {
  const username = forgotUsername.value.trim();
  const passwordAttempt = forgotPasswordInput.value;
  socket.emit("recover-password", { username, passwordAttempt });
});

socket.on("recover-password-result", (data) => {
  if (data.success) {
    if (data.isHint) {
      showFeedback(forgotFeedback, escapeHTML(data.hint), "warning");
    } else {
      showFeedback(forgotFeedback, `✅ Your password is: <strong>${escapeHTML(data.password)}</strong><br><br><button class="suggestion-btn" onclick="autoLogin('${escapeHTML(data.username)}', '${escapeHTML(data.password)}')">Login Now</button>`, "success");
    }
  } else {
    showFeedback(forgotFeedback, data.message, "error");
  }
});

function autoLogin(username, password) {
  loginUsername.value = username;
  loginPassword.value = password;
  backToLogin.click();
  loginBtn.click();
}

backToLogin.addEventListener("click", () => {
  forgotForm.classList.add("hidden");
  loginForm.classList.remove("hidden");
  hideFeedback(loginFeedback);
  generateLoginCaptcha();
});

// Signup
signupBtn.addEventListener("click", () => {
  const username = signupUsername.value.trim();
  const password = signupPassword.value;
  const captchaInput = signupCaptchaInput.value.trim();
  
  if (!username) {
    showFeedback(signupFeedback, "Please enter a username", "error");
    return;
  }
  
  socket.emit("signup", { 
    username, 
    password,
    captchaInput,
    expectedCaptcha: signupCaptcha
  });
});

socket.on("signup-result", (data) => {
  if (data.success) {
    let msg = `✅ Account created! Logging you in...`;
    
    if (data.captchaMessage) {
      msg = data.captchaMessage + "<br><br>" + msg;
    }
    
    if (data.warning) {
      msg = `⚠️ <strong>Insecure Password!</strong><br>${escapeHTML(data.warning)}<br><br>Account created.`;
      if (data.captchaMessage) {
        msg = data.captchaMessage + "<br><br>" + msg;
      }
      showFeedback(signupFeedback, msg, "warning");
      
      setTimeout(() => {
        currentUser = data.user;
        currentUserBadge.textContent = currentUser.username;
        showView(homeView);
      }, 3000);
    } else {
      showFeedback(signupFeedback, msg, "success");
      setTimeout(() => {
        currentUser = data.user;
        currentUserBadge.textContent = currentUser.username;
        showView(homeView);
      }, 1500);
    }
  } else {
    let message = data.message;
    if (data.captchaMessage) {
      message = data.captchaMessage + "<br><br>" + message;
    }
    showFeedback(signupFeedback, message, data.type || "error");
    generateSignupCaptcha();
  }
});

// Logout
logoutBtn.addEventListener("click", () => {
  currentUser = null;
  currentRoom = null;
  showView(authView);
  loginUsername.value = "";
  loginPassword.value = "";
  generateLoginCaptcha();
});

// Join Room
joinRoomCard.addEventListener("click", () => {
  joinRoomPanel.classList.remove("hidden");
  settingsPanel.classList.add("hidden");
  hideFeedback(roomFeedback);
  socket.emit("get-rooms");
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
  socket.emit("join-room", { room, password, username: currentUser.username });
});

socket.on("room-list", (data) => {
  if (!data.success || data.rooms.length === 0) {
    roomList.innerHTML = '<div class="room-list-empty">No rooms yet. Create one below!</div>';
    return;
  }
  
  roomList.innerHTML = data.rooms.map(room => `
    <div class="room-list-item" data-room="${escapeHTML(room.name)}" data-protected="${room.hasPassword}">
      <span class="room-list-name">#${escapeHTML(room.name)}</span>
      ${room.hasPassword ? '<span class="room-list-lock">🔒</span>' : '<span class="room-list-lock"></span>'}
    </div>
  `).join("");
  
  roomList.querySelectorAll(".room-list-item").forEach(item => {
    item.addEventListener("click", () => {
      const name = item.dataset.room;
      const isProtected = item.dataset.protected === "true";
      
      roomName.value = name;
      
      if (isProtected) {
        roomPassword.focus();
        showFeedback(roomFeedback, "🔒 This room has a password", "info");
      } else {
        roomPassword.value = "";
        joinRoomBtn.click();
      }
    });
  });
});

socket.on("join-room-result", (data) => {
  if (data.success) {
    currentRoom = data.room;
    roomBadge.textContent = data.room;
    clearChat();
    showView(chatView);
    hideFeedback(roomFeedback);
  } else {
    let message = data.message;
    if (data.passwordHint) {
      message += `<br><br>${escapeHTML(data.passwordHint)}`;
    }
    showFeedback(roomFeedback, message, "error");
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
  settingsForgotSection.classList.add("hidden");
});

// Change Username
changeUsernameBtn.addEventListener("click", () => {
  const username = newUsername.value.trim();
  if (!username) {
    showFeedback(usernameFeedback, "Please enter a username", "error");
    return;
  }
  socket.emit("change-username", { 
    oldUsername: currentUser.username, 
    newUsername: username 
  });
});

socket.on("change-username-result", (data) => {
  if (data.success) {
    currentUser.username = data.username;
    currentUserBadge.textContent = data.username;
    showFeedback(usernameFeedback, "✅ Username changed successfully!", "success");
  } else {
    showFeedback(usernameFeedback, data.message, "error");
  }
});

// Change Password
changePasswordBtn.addEventListener("click", () => {
  const oldPwd = oldPassword.value;
  const newPwd = newPassword.value;
  socket.emit("change-password", { 
    username: currentUser.username,
    oldPassword: oldPwd, 
    newPassword: newPwd 
  });
});

socket.on("change-password-result", (data) => {
  if (data.success) {
    currentUser.password = data.password;
    showFeedback(passwordFeedback, `✅ Password changed to: <strong>${escapeHTML(data.password)}</strong>`, "success");
    oldPassword.value = "";
    newPassword.value = "";
  } else {
    let message = data.message;
    if (data.passwordHint) {
      message += `<br><br>${escapeHTML(data.passwordHint)}`;
    }
    showFeedback(passwordFeedback, message, "error");
  }
});

// Settings Forgot Password
settingsForgotBtn.addEventListener("click", () => {
  settingsForgotSection.classList.remove("hidden");
  settingsForgotUsername.value = currentUser.username;
  hideFeedback(settingsForgotFeedback);
});

settingsRecoverBtn.addEventListener("click", () => {
  socket.emit("recover-password", { 
    username: settingsForgotUsername.value.trim(),
    passwordAttempt: ""
  });
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
  const isCorrect = password === currentUser.password || password === "";
  socket.emit("delete-account", { 
    username: currentUser.username,
    password: password,
    isPasswordCorrect: isCorrect
  });
});

socket.on("delete-account-result", (data) => {
  if (data.success) {
    alert(data.message);
    currentUser = null;
    deleteModal.classList.add("hidden");
    showView(authView);
    generateLoginCaptcha();
  } else {
    showFeedback(deleteFeedback, data.message, "warning");
  }
});

// Chat Functions
function clearChat() {
  chatBox.innerHTML = `
    <div class="empty-state" id="empty-state">
      <div class="empty-state-icon">💬</div>
      <div>No messages yet</div>
      <div style="font-size: 0.85rem;">Send a message to start the conversation</div>
      <div style="font-size: 0.75rem; color: #f97316; margin-top: 8px;">⚠️ Chat history is not saved. Messages disappear when you leave!</div>
    </div>
  `;
}

function send() {
  if (msgInput.value.trim() === "") return;
  
  let randomID = Math.floor(Math.random() * (36 ** 10)).toString(36);
  let data = {
    message: msgInput.value,
    username: currentUser.username,
    messageID: randomID,
    room: currentRoom
  };
  
  socket.emit("message", data);
  renderMessage(data, true);
  msgInput.value = "";
}

function renderMessage(data, isSelf) {
  let emptyState = document.getElementById("empty-state");
  if (emptyState) emptyState.remove();
  
  let msgIDElement = document.getElementById("msg-" + data.messageID);
  if (msgIDElement) {
    msgIDElement.classList.remove("unloaded");
    return;
  }

  // XSS attacks are fun
  const range = document.createRange();
  range.selectNode(chatBox);
  const fragment = range.createContextualFragment(`
    <div class="message ${isSelf ? "unloaded" : ""} ${data.username === currentUser?.username ? "user-msg" : "other-msg"}" id="msg-${data.messageID}">
      <div class="message-header">
        <span class="message-author">${data.username}</span>
      </div>
      <div class="message-text">${data.message}</div>
    </div>
  `);
  chatBox.appendChild(fragment);
  
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

// Make functions available globally
window.selectUsername = selectUsername;
window.switchToSignup = switchToSignup;
window.autoLogin = autoLogin;

// Password visibility toggle
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁️';
  }
}

window.togglePassword = togglePassword;

let fun_eval_thing_end = localStorage.getItem("fun-eval-thing-end");
if (fun_eval_thing_end) eval(fun_eval_thing_end);
