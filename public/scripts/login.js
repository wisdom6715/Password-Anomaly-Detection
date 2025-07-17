// DOM elements
const loginForm = document.getElementById("loginForm")
const loginBtn = document.getElementById("loginBtn")
const btnText = document.getElementById("btnText")
const spinner = document.getElementById("spinner")
const messageDiv = document.getElementById("message")
const logsContainer = document.getElementById("loginLogs")

// Backend URL
const API_BASE_URL = "https://password-anomaly-detection-3.onrender.com"

// Initialize the page
document.addEventListener("DOMContentLoaded", () => {
  refreshLogs()

  // Add form submit event listener
  loginForm.addEventListener("submit", handleLogin)
})

// Handle login form submission
async function handleLogin(e) {
  e.preventDefault()

  const username = document.getElementById("username").value.trim()
  const password = document.getElementById("password").value

  if (!username || !password) {
    showMessage("Please fill in all fields", "error")
    return
  }

  setLoading(true)

  try {
    const response = await fetch(`${API_BASE_URL}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        password,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
      }),
    })

    const result = await response.json()

    if (response.ok) {
      // Store access token if needed
      if (result.access_token) {
        localStorage.setItem('access_token', result.access_token)
      }

      let message = result.message || `Welcome ${username}! Login successful.`
      
      // Check for security alerts
      if (result.security_alert) {
        message += ` ${result.security_alert}`
        showMessage(message, "warning")
      } else {
        showMessage(message, "success")
      }

      // Redirect to dashboard after 2 seconds
      setTimeout(() => {
        window.location.href = "/dashboard.html"
      }, 2000)
    } else {
      // Handle error response
      showMessage(result.error || "Login failed", "error")
    }

    // Refresh logs to show new attempt
    setTimeout(refreshLogs, 500)
  } catch (error) {
    console.error("Login error:", error)
    showMessage("Network error. Please try again.", "error")
  } finally {
    setLoading(false)
  }
}

// Utility functions
function setLoading(loading) {
  loginBtn.disabled = loading
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

async function refreshLogs() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/logs`)
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    const logs = await response.json()

    if (logs.length === 0) {
      logsContainer.innerHTML = "<p>No login attempts yet.</p>"
      return
    }

    logsContainer.innerHTML = logs
      .map((log) => {
        const timestamp = new Date(log.timestamp).toLocaleString()
        let statusClass = log.success ? "success" : "failed"
        let statusText = log.success ? "SUCCESS" : "FAILED"

        if (log.type === "signup") {
          statusClass = "signup"
          statusText = "SIGNUP"
        }

        const anomalyText = log.anomaly ? " 🚨 ANOMALY DETECTED" : ""

        return `
          <div class="log-entry ${statusClass}">
            [${timestamp}] ${log.username} - ${statusText} 
            (IP: ${log.ip_address})${anomalyText}
          </div>
        `
      })
      .join("")

    // Scroll to bottom
    logsContainer.scrollTop = logsContainer.scrollHeight
  } catch (error) {
    console.error("Error fetching logs:", error)
    logsContainer.innerHTML = "<p>Error loading logs.</p>"
  }
}