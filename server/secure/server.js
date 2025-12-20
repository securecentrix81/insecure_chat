const express = require("express")
const app = express()
const http = require("http")
const server = http.createServer(app)
const io = require("socket.io")(server)

// In-memory "database" - very secure, data disappears on restart!
let users = [
  { username: "admin", password: "admin123" },
  { username: "guest", password: "password" },
  { username: "user1", password: "123456" },
  { username: "demo", password: "demo" }
]

let rooms = {
  "general": { password: "", creator: "system" },
  "secret": { password: "secret", creator: "admin" }
}

// Helper: Get password hint (very helpful for hackers!)
function getPasswordHint(actual, attempt) {
  if (!actual) return null
  if (!attempt) return `The password has ${actual.length} characters.`
  
  // Track which characters in actual password have been matched
  let actualChars = actual.split('')
  let attemptChars = attempt.split('')
  let matched = new Array(actual.length).fill(false)
  let processed = new Array(attempt.length).fill(false)
  
  // First pass: Find exact matches (correct position - GREEN in Wordle)
  let correctFeedback = []
  for (let i = 0; i < attemptChars.length; ++i) {
    if (i < actualChars.length && attemptChars[i] === actualChars[i]) {
      correctFeedback.push({letter:attemptChars[i],feedback:`✓ Position ${i + 1}: "${attemptChars[i]}" is CORRECT!`})
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
        yellowFeedback.push({letter:attemptChars[i],feedback:`⚠ Position ${i + 1}: "${attemptChars[i]}" exists but wrong position`})
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
      incorrectFeedback.push({letter:attemptChars[i],feedback:`⚠ Position ${i + 1}: "${attemptChars[i]}" is not in the password`})
    }
  }
  
  // Add length hint
  if (actual.length !== attempt.length) {
    if (actual.length > attempt.length) {
      return `Your password is longer than that`
    } else {
      return `Your password is shorter than that`
    }
  }
  let newFeedback = []
  let lettersTried = new Set()
  let feedback = incorrectFeedback.concat(yellowFeedback).concat(correctFeedback)
  for (let i of feedback.reverse()) {
    if (lettersTried.has(i.letter)) continue
    lettersTried.add(i.letter)
    newFeedback.push(i.feedback)
    if (newFeedback.length > 10) break
  }
  return newFeedback.join(". ")
}

module.exports = function initChat() {  
  io.on("connection", (socket) => {
    console.log("User connected:", socket.id)
    
    // LOGIN - The most insecure login ever
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
        console.log(`Secure: [LOGIN] Random login as ${randomUser.username}`)
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
          console.log(`Secure: [LOGIN] Empty password login for ${username}`)
          return
        }
        
        // Correct password
        if (user.password === password) {
          socket.emit("login-result", {
            success: true,
            user: user,
            message: "Login successful!"
          })
          console.log(`Secure: [LOGIN] ${username} logged in`)
          return
        }
        
        // Wrong password - give helpful hints!
        socket.emit("login-result", {
          success: false,
          message: "Incorrect password, but let us help you!",
          passwordHint: getPasswordHint(user.password, password),
          type: "warning"
        })
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
        return
      }
      
      // Nothing matches - offer signup
      socket.emit("login-result", {
        success: false,
        message: "Account not found. Would you like to sign up instead?",
        offerSignup: true,
        type: "info"
      })
    })
    
    // SIGNUP - Equally insecure
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
        return
      }
      
      // Check if password is used by another user
      const userWithPassword = users.find(u => u.password === password)
      if (userWithPassword && password !== "") {
        socket.emit("signup-result", {
          success: false,
          message: "This password is already in use!",
          existingUser: userWithPassword.username,
          password: password,
          type: "warning"
        })
        return
      }
      
      // Create account
      const newUser = { username, password: password || "password" }
      users.push(newUser)
      
      socket.emit("signup-result", {
        success: true,
        user: newUser,
        password: newUser.password,
        message: "Account created!"
      })
      console.log(`Secure: [SIGNUP] New user: ${username} with password: ${newUser.password}`)
    })
    
    // PASSWORD RECOVERY - Just tells you the password!
    socket.on("recover-password", (data) => {
      const { username, passwordAttempt } = data
      
      const user = users.find(u => u.username === username)
      if (!user) {
        // Still helpful - list similar usernames
        const similar = users.filter(u => 
          u.username.toLowerCase().includes(username.toLowerCase()) ||
          username.toLowerCase().includes(u.username.toLowerCase())
        )
        
        let message = `User "${username}" not found.`
        if (similar.length > 0) {
          message += ` Did you mean: ${similar.map(u => u.username).join(", ")}?`
        }
        
        socket.emit("recover-password-result", {
          success: false,
          message: message
        })
        return
      }
      
      // Just give them the password!
      socket.emit("recover-password-result", {
        success: true,
        username: user.username,
        password: user.password,
        message: "Here's your password!"
      })
    })
    
    // CHANGE USERNAME - No verification needed!
    socket.on("change-username", (data) => {
      const { oldUsername, newUsername } = data
      
      // Check if new username is taken
      const existingUser = users.find(u => u.username === newUsername)
      if (existingUser) {
        socket.emit("change-username-result", {
          success: false,
          message: `Username "${newUsername}" is already taken.`
        })
        return
      }
      
      // Find and update user
      const user = users.find(u => u.username === oldUsername)
      if (user) {
        user.username = newUsername
        socket.emit("change-username-result", {
          success: true,
          username: newUsername
        })
        console.log(`Secure: [CHANGE] Username: ${oldUsername} -> ${newUsername}`)
      }
    })
    
    // CHANGE PASSWORD - Empty old password always works!
    socket.on("change-password", (data) => {
      const { username, oldPassword, newPassword } = data
      
      const user = users.find(u => u.username === username)
      if (!user) {
        socket.emit("change-password-result", {
          success: false,
          message: "User not found"
        })
        return
      }
      
      // Empty password = always correct!
      if (oldPassword === "" || oldPassword === user.password) {
        user.password = newPassword || "password"
        socket.emit("change-password-result", {
          success: true,
          password: user.password
        })
        console.log(`Secure: [CHANGE] Password for ${username}: ${user.password}`)
        return
      }
      
      // Wrong password - but give hints!
      socket.emit("change-password-result", {
        success: false,
        message: "Old password is incorrect, but here's a hint!",
        passwordHint: getPasswordHint(user.password, oldPassword)
      })
    })
    
    // DELETE ACCOUNT - Deletes even with wrong password!
    socket.on("delete-account", (data) => {
      const { username, password, isPasswordCorrect } = data
      
      const userIndex = users.findIndex(u => u.username === username)
      if (userIndex === -1) {
        socket.emit("delete-account-result", {
          success: false,
          message: "User not found (already deleted?)"
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
      console.log(`Secure: [DELETE] User deleted: ${username} (password was: ${deletedUser.password})`)
    })
    
    // JOIN ROOM
    socket.on("join-room", (data) => {
      const { room, password, username } = data
      
      // Check if room exists
      if (rooms[room]) {
        // Empty password always works!
        if (password === "" || rooms[room].password === "" || rooms[room].password === password) {
          socket.join(room)
          socket.emit("join-room-result", {
            success: true,
            room: room
          })
          console.log(`Secure: [ROOM] ${username} joined ${room}`)
          return
        }
        
        // Wrong password - give hints!
        socket.emit("join-room-result", {
          success: false,
          message: "Incorrect room password, but here's a hint!",
          passwordHint: getPasswordHint(rooms[room].password, password)
        })
        return
      }
      
      // Create new room
      rooms[room] = { password: password, creator: username }
      socket.join(room)
      socket.emit("join-room-result", {
        success: true,
        room: room,
        created: true
      })
      console.log(`Secure: [ROOM] ${username} created and joined ${room}`)
    })
    
    // LEAVE ROOM
    socket.on("leave-room", (data) => {
      socket.leave(data.room)
      console.log(`Secure: [ROOM] User left ${data.room}`)
    })
    
    // MESSAGES - No rate limiting, no history!
    socket.on("message", (data) => {
      // Broadcast to room (no saving!)
      io.to(data.room).emit("message", data)
      console.log(`Secure: [MSG] ${data.username} in ${data.room}: ${data.message}`)
    })
    
    socket.on("disconnect", () => {
      console.log("User disconnected:", socket.id)
    })
  })
  
  console.log("✅ [Secure Chat] Backend initialized");
}
