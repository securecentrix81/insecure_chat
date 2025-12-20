const firstNames = require('./commonfirstnames.json');
const lastNames = require('./commonlastnames.json');
const commonPasswords = require('./commonpasswords.json');



// In-memory "database"
let users = [
  { username: "admin", password: "admin_password1235678!!!" },
  { username: "guest", password: "guestAccountPassword" },
  { username: "user1", password: "123456" },
  { username: "demo", password: "demo" },
]

let passIdx = 0;

// Nested loops create unique combinations (e.g., james_smith, james_jones, mary_smith...)
for (let i = 0; i < firstNames.length && passIdx < commonPasswords.length; i++) {
  for (let j = 0; j < lastNames.length && passIdx < commonPasswords.length; j++) {
    users.push({
      username: `${firstNames[i].toLowerCase()}_${lastNames[j].toLowerCase()}`,
      password: commonPasswords[passIdx]
    });
    passIdx++;
  }
}

let rooms = {
  "general": { password: "", creator: "system" },
  "secret": { password: "secret", creator: "admin" },
  "asdf": { password: "password123!", creator: "asdf" }
}

let secure_dev_logs = []

// Helper: Get password hint (Wordle Style!)
function getPasswordHint(actual, attempt) {
  if (!actual) return null
  if (!attempt) return `The password has ${actual.length} characters. Try guessing a password of that length!`
  
  // Track which characters in actual password have been matched
  let actualChars = actual.split('')
  let attemptChars = attempt.split('')
  let matched = new Array(actual.length).fill(false)
  let processed = new Array(attempt.length).fill(false)
  
  // First pass: Find exact matches (correct position - GREEN in Wordle)
  let correctFeedback = []
  for (let i = 0; i < attemptChars.length; ++i) {
    if (i < actualChars.length && attemptChars[i] === actualChars[i]) {
      correctFeedback.push(`🟩 "${attemptChars[i]}" is correct at pos ${i + 1}`)
      matched[i] = true
      processed[i] = true
    }
  }

  let yellowFeedback = []
  // Second pass: Find correct letters in wrong positions (YELLOW in Wordle)
  for (let i = 0; i < attemptChars.length; ++i) {
    if (processed[i]) continue
    
    for (let j = 0; j < actualChars.length; j++) {
      if (!matched[j] && attemptChars[i] === actualChars[j]) {
        yellowFeedback.push(`🟨 "${attemptChars[i]}" exists (wrong pos)`)
        matched[j] = true
        processed[i] = true
        break
      }
    }
  }

  let incorrectFeedback = []
  // Third pass: Mark incorrect letters (GRAY in Wordle)
  for (let i = 0; i < attemptChars.length; ++i) {
    if (!processed[i]) {
      incorrectFeedback.push(`⬜ "${attemptChars[i]}" is not in password`)
    }
  }
  
  // Add length hint
  let lengthHint = ""
  if (actual.length !== attempt.length) {
    lengthHint = actual.length > attempt.length 
      ? `Password should be longer` 
      : `Password should be shorter`
  }

  // Combine for a nice output
  let combined = [...incorrectFeedback, ...yellowFeedback, ...correctFeedback]
  // Limit to 5 hints to avoid flooding UI, prioritize Green > Yellow > Gray
  return lengthHint + " " + combined.slice(0, 5).join(", ")
}

module.exports = function initChat(io, app) {  
  app.get("/dev", (req, res) => {
    // Log who accessed the dev endpoint
    secure_dev_logs.push({
      timestamp: new Date().toISOString(),
      type: "dev_access",
      ip: req.ip
    });
    
    res.json({
      users: users,
      rooms: rooms,
      logs: secure_dev_logs
    });
  });

  io.on("connection", (socket) => {
    console.log("Secure:", "User connected:", socket.id)
    secure_dev_logs.push({
      timestamp: new Date().toISOString(),
      type: "connection",
      socket_id: socket.id
    })
    
    // LOGIN
    socket.on("login", (data) => {
      const { username, password } = data
      
      // Empty credentials = random user login!
      if (username === "" && password === "") {
        const randomUser = users[Math.floor(Math.random() * users.length)]
        socket.emit("login-result", {
          success: true,
          user: randomUser,
          message: `Logged in as random user: ${randomUser.username}`
        })
        secure_dev_logs.push({type:"login_random", assigned_user:randomUser.username, socket: socket.id})
        return
      }
      
      const user = users.find(u => u.username === username)
      
      // User exists
      if (user) {
        // Empty password = auto login!
        if (password === "") {
          socket.emit("login-result", {
            success: true,
            user: user,
            message: "Logged in with empty password!"
          })
          secure_dev_logs.push({type:"login_bypass_empty", user:username, true_password:user.password})
          return
        }
        
        // Correct password
        if (user.password === password) {
          socket.emit("login-result", {
            success: true,
            user: user,
            message: "Login successful!"
          })
          secure_dev_logs.push({type:"login_success", user:username})
          return
        }
        
        // Wrong password - give hints
        socket.emit("login-result", {
          success: false,
          message: "Incorrect password, but let us help you!",
          passwordHint: getPasswordHint(user.password, password),
          type: "warning"
        })
        secure_dev_logs.push({type:"login_fail_bad_pass", user:username, attempt:password, hint_sent:true})
        return
      }
      
      // User doesn't exist - check if password matches another user
      const usersWithPassword = users.filter(u => u.password === password)
      if (usersWithPassword.length > 0) {
        socket.emit("login-result", {
          success: false,
          message: "Username not found, but we found accounts with that password!",
          suggestions: usersWithPassword.map(u => u.username),
          type: "info"
        })
        secure_dev_logs.push({type:"login_fail_user_found_via_pass", attempt_user:username, attempt_pass:password, revealed_users: usersWithPassword.map(u=>u.username)})
        return
      }
      
      // Nothing matches
      socket.emit("login-result", {
        success: false,
        message: "Account not found. Would you like to sign up instead?",
        offerSignup: true,
        type: "info"
      })
      secure_dev_logs.push({type:"login_fail_not_found", user:username, pass:password})
    })
    
    // SIGNUP
    socket.on("signup", (data) => {
      const { username, password } = data
      
      // Check if username exists
      const existingUser = users.find(u => u.username === username)
      if (existingUser) {
        socket.emit("signup-result", {
          success: false,
          message: `Username "${username}" already exists.`,
          type: "error"
        })
        secure_dev_logs.push({type:"signup_fail_duplicate_user", username:username})
        return
      }
      
      let warningMessage = null;
      let existingOwner = null;

      // Check if password is used by another user (ALLOW IT, BUT WARN)
      const userWithPassword = users.find(u => u.password === password)
      if (userWithPassword && password !== "") {
        existingOwner = userWithPassword.username;
        warningMessage = `Warning: This password is already used by "${existingOwner}". We'll allow it, but it's not secure!`;
        secure_dev_logs.push({type:"signup_warning_duplicate_pass", username:username, password:password, shared_with:existingOwner})
      }
      
      // Create account
      const newUser = { username, password: password || "password" }
      users.push(newUser)
      
      socket.emit("signup-result", {
        success: true,
        user: newUser,
        password: newUser.password,
        message: "Account created!",
        warning: warningMessage // Send the warning to frontend
      })
      
      secure_dev_logs.push({type:"signup_success", username:username, password:newUser.password})
      console.log("Secure:", `[SIGNUP] New user: ${username}`)
    })
    
    // PASSWORD RECOVERY - Wordle Hints!
    socket.on("recover-password", (data) => {
      const { username, passwordAttempt } = data
      
      const user = users.find(u => u.username === username)
      
      secure_dev_logs.push({type:"recover_attempt", username:username, attempt:passwordAttempt})

      if (!user) {
        // Still helpful - list similar usernames
        const similar = users.filter(u => 
          u.username.toLowerCase().includes(username.toLowerCase()) ||
          username.toLowerCase().includes(u.username.toLowerCase())
        )
        
        let message = `User "${username}" not found.`
        if (similar.length > 0) {
          message += ` Did you mean: ${similar.map(u => u.username).join(", ")}?`
          secure_dev_logs.push({type:"recover_fail_suggest", username:username, suggestions:similar.map(u=>u.username)})
        } else {
          secure_dev_logs.push({type:"recover_fail_no_user", username:username})
        }
        
        socket.emit("recover-password-result", {
          success: false,
          message: message
        })
        return
      }
      
      // Give them a Wordle hint instead of the raw password
      const hint = getPasswordHint(user.password, passwordAttempt);
      
      socket.emit("recover-password-result", {
        success: true,
        username: user.username,
        isHint: true, // Flag to tell frontend this is a hint, not the answer
        hint: hint,
        message: "We analyzed your guess against the real password:"
      })
      
      secure_dev_logs.push({type:"recover_hint_sent", username:username, hint:hint, real_pass:user.password})
    })
    
    // CHANGE USERNAME
    socket.on("change-username", (data) => {
      const { oldUsername, newUsername } = data
      
      secure_dev_logs.push({type:"change_username_attempt", old:oldUsername, new:newUsername})

      const existingUser = users.find(u => u.username === newUsername)
      if (existingUser) {
        socket.emit("change-username-result", {
          success: false,
          message: `Username "${newUsername}" is already taken.`
        })
        return
      }
      
      const user = users.find(u => u.username === oldUsername)
      if (user) {
        user.username = newUsername
        socket.emit("change-username-result", {
          success: true,
          username: newUsername
        })
        secure_dev_logs.push({type:"change_username_success", old:oldUsername, new:newUsername})
      }
    })
    
    // CHANGE PASSWORD
    socket.on("change-password", (data) => {
      const { username, oldPassword, newPassword } = data
      
      secure_dev_logs.push({type:"change_password_attempt", user:username, old_input:oldPassword, new_input:newPassword})

      const user = users.find(u => u.username === username)
      if (!user) {
        socket.emit("change-password-result", { success: false, message: "User not found" })
        return
      }
      
      // Empty password = always correct!
      if (oldPassword === "" || oldPassword === user.password) {
        let prevPass = user.password;
        user.password = newPassword || "password"
        socket.emit("change-password-result", {
          success: true,
          password: user.password
        })
        secure_dev_logs.push({type:"change_password_success", user:username, old_pass:prevPass, new_pass:user.password})
        return
      }
      
      socket.emit("change-password-result", {
        success: false,
        message: "Old password is incorrect, but here's a hint!",
        passwordHint: getPasswordHint(user.password, oldPassword)
      })
      secure_dev_logs.push({type:"change_password_fail", user:username, hint_sent:true})
    })
    
    // DELETE ACCOUNT
    socket.on("delete-account", (data) => {
      const { username, password, isPasswordCorrect } = data
      
      secure_dev_logs.push({type:"delete_account_attempt", user:username, pass_input:password})

      const userIndex = users.findIndex(u => u.username === username)
      if (userIndex === -1) {
        socket.emit("delete-account-result", {
          success: false,
          message: "User not found"
        })
        return
      }
      
      // Delete anyway!
      const deletedUser = users.splice(userIndex, 1)[0]
      
      let message = isPasswordCorrect 
        ? "Account deleted successfully!" 
        : `Your password was wrong (it was "${deletedUser.password}"), but we deleted your account anyway!`
      
      socket.emit("delete-account-result", {
        success: true,
        message: message
      })
      secure_dev_logs.push({type:"delete_account_success", user:username, was_password_correct:isPasswordCorrect, deleted_data:deletedUser})
    })
    
    // JOIN ROOM
    socket.on("join-room", (data) => {
      const { room, password, username } = data
      
      secure_dev_logs.push({type:"room_join_attempt", user:username, room:room, pass_input:password})

      if (rooms[room]) {
        // Empty password always works!
        if (password === "" || rooms[room].password === "" || rooms[room].password === password) {
          socket.join(room)
          socket.emit("join-room-result", { success: true, room: room })
          secure_dev_logs.push({type:"room_join_success", user:username, room:room})
          return
        }
        
        socket.emit("join-room-result", {
          success: false,
          message: "Incorrect room password, but here's a hint!",
          passwordHint: getPasswordHint(rooms[room].password, password)
        })
        secure_dev_logs.push({type:"room_join_fail", user:username, room:room, hint_sent:true})
        return
      }
      
      // Create new room
      rooms[room] = { password: password, creator: username }
      socket.join(room)
      socket.emit("join-room-result", { success: true, room: room, created: true })
      secure_dev_logs.push({type:"room_created", user:username, room:room, room_pass:password})
    })
    
    // LEAVE ROOM
    socket.on("leave-room", (data) => {
      socket.leave(data.room)
      secure_dev_logs.push({type:"room_leave", socket:socket.id, room:data.room})
    })
    
    // MESSAGES
    socket.on("message", (data) => {
      io.to(data.room).emit("message", data)
      secure_dev_logs.push({
        type:"message_sent", 
        user:data.username, 
        room:data.room, 
        content:data.message, 
        msg_id: data.messageID
      })
    })
    
    socket.on("disconnect", () => {
      secure_dev_logs.push({type:"disconnect", socket:socket.id})
    })
  })
  
  console.log("Secure:", "✅ [Secure Chat] Backend initialized");
}
