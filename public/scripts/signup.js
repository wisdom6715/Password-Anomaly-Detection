// DOM elements
const signupForm = document.getElementById("signupForm")
const signupBtn = document.getElementById("signupBtn")
const btnText = document.getElementById("btnText")
const spinner = document.getElementById("spinner")
const messageDiv = document.getElementById("message")

// Backend URL
const API_BASE_URL = "http://password-anomaly-detection-3.onrender.com"

// Initialize the page
document.addEventListener("DOMContentLoaded", () => {
  // Add form submit event listener
  signupForm.addEventListener("submit", handleSignup)

  // Add real-time password validation
  const password = document.getElementById("password")
  const confirmPassword = document.getElementById("confirmPassword")

  confirmPassword.addEventListener("input", validatePasswordMatch)
  password.addEventListener("input", validatePasswordStrength)
})

// Handle signup form submission
async function handleSignup(e) {
  e.preventDefault()

  const fullName = document.getElementById("fullName").value.trim()
  const email = document.getElementById("email").value.trim()
  const username = document.getElementById("username").value.trim()
  const password = document.getElementById("password").value
  const confirmPassword = document.getElementById("confirmPassword").value
  const phoneNumber = document.getElementById("phoneNumber").value.trim() // Added phoneNumber

  // Validation
  if (!fullName || !email || !username || !password || !confirmPassword || !phoneNumber) {
    showMessage("Please fill in all fields", "error")
    return
  }

  if (password.length < 8) {
    showMessage("Password must be at least 8 characters long", "error")
    return
  }

  if (password !== confirmPassword) {
    showMessage("Passwords do not match", "error")
    return
  }

  if (!isValidEmail(email)) {
    showMessage("Please enter a valid email address", "error")
    return
  }

  setLoading(true)

  try {
    // Updated to match backend endpoint and field names
    const response = await fetch(`${API_BASE_URL}/api/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        email,
        password,
        phone_number: phoneNumber, // Backend expects phone_number
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
      }),
    })

    const result = await response.json()

    if (response.ok) {
      showMessage(result.message || "Account created successfully! Redirecting to login...", "success")

      // Clear form
      signupForm.reset()

      // Redirect to login after 2 seconds
      setTimeout(() => {
        window.location.href = "/login.html"
      }, 2000)
    } else {
      // Handle specific error messages from backend
      if (result.error) {
        showMessage(result.error, "error")
      } else {
        showMessage("Signup failed", "error")
      }
    }
  } catch (error) {
    console.error("Signup error:", error)
    showMessage("Network error. Please try again.", "error")
  } finally {
    setLoading(false)
  }
}

// Validation functions
function validatePasswordMatch() {
  const password = document.getElementById("password").value
  const confirmPassword = document.getElementById("confirmPassword")

  if (confirmPassword.value && password !== confirmPassword.value) {
    confirmPassword.classList.add("error")
  } else {
    confirmPassword.classList.remove("error")
  }
}

function validatePasswordStrength() {
  const password = document.getElementById("password")

  if (password.value.length > 0 && password.value.length < 8) {
    password.classList.add("error")
  } else {
    password.classList.remove("error")
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

// Utility functions
function setLoading(loading) {
  signupBtn.disabled = loading
  if (loading) {
    btnText.classList.add("hidden")
    spinner.classList.remove("hidden")
  } else {
    btnText.classList.remove("hidden")
    spinner.classList.add("hidden")
  }
}

function showMessage(text, type) {
  messageDiv.textContent = text
  messageDiv.className = `message ${type}`
  messageDiv.classList.remove("hidden")

  // Auto-hide after 5 seconds
  setTimeout(() => {
    messageDiv.classList.add("hidden")
  }, 5000)
}