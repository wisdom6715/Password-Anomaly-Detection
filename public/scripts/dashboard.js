// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {
  refreshDashboard()
  setInterval(refreshDashboard, 30000)
})
const API_BASE_URL = "https://password-anomaly-detection-3.onrender.com"

async function refreshDashboard() {
  try {
    // Get authentication token
    const token = localStorage.getItem('access_token')
    
    if (!token) {
      window.location.href = "/login.html"
      return
    }

    // Fetch dashboard statistics
    const response = await fetch(`${API_BASE_URL}/api/stats/dashboard`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    })

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        // Token expired or invalid, redirect to login
        localStorage.removeItem('access_token')
        window.location.href = "/login.html"
        return
      }
      throw new Error(`HTTP error! status: ${response.status}`)
    }

    const stats = await response.json()
    updateStats(stats)

  } catch (error) {
    console.error("Error refreshing dashboard:", error)
    showError("Failed to refresh dashboard data")
  }
}

function updateStats(stats) {
  // Update the statistics display
  document.getElementById("totalAttempts").textContent = stats.total_login_attempts || 0
  document.getElementById("successfulLogins").textContent = stats.successful_logins || 0
  document.getElementById("failedAttempts").textContent = stats.failed_attempts || 0
  document.getElementById("securityAlerts").textContent = stats.security_alerts || 0
}

// Optional: Fetch recent activity logs if you want to show them
async function fetchRecentActivity(token) {
  try {
    // You can add this endpoint to your backend if needed
    const response = await fetch("/api/recent-activity", {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    })

    if (response.ok) {
      const logs = await response.json()
      updateActivityLogs(logs)
    }
  } catch (error) {
    console.error("Error fetching recent activity:", error)
  }
}

function updateActivityLogs(logs) {
  const logsContainer = document.getElementById("activityLogs")

  if (!logsContainer) {
    // Activity logs container doesn't exist in the UI
    return
  }

  if (!logs || logs.length === 0) {
    logsContainer.innerHTML = "<p>No recent activity.</p>"
    return
  }

  logsContainer.innerHTML = logs
    .slice(0, 20) // Show only last 20 entries
    .map((log) => {
      const timestamp = new Date(log.timestamp).toLocaleString()
      let statusClass = log.success ? "success" : "failed"
      let statusText = log.success ? "SUCCESS" : "FAILED"

      if (log.type === "signup") {
        statusClass = "signup"
        statusText = "SIGNUP"
      }

      const anomalyText = log.anomaly ? " 🚨 ANOMALY" : ""
      const extraClass = log.anomaly ? " anomaly" : ""

      return `
        <div class="log-entry ${statusClass}${extraClass}">
          [${timestamp}] ${log.username || 'Unknown'} - ${statusText} 
          (IP: ${log.ip_address || 'Unknown'})${anomalyText}
        </div>
      `
    })
    .join("")

  // Scroll to top to show latest entries
  logsContainer.scrollTop = 0
}

function showError(message) {
  // Create or update error message display
  let errorDiv = document.getElementById("errorMessage")
  
  if (!errorDiv) {
    errorDiv = document.createElement("div")
    errorDiv.id = "errorMessage"
    errorDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ff4444;
      color: white;
      padding: 10px 20px;
      border-radius: 5px;
      z-index: 1000;
      animation: fadeIn 0.3s ease-in;
    `
    document.body.appendChild(errorDiv)
  }

  errorDiv.textContent = message
  errorDiv.style.display = "block"

  // Auto-hide after 5 seconds
  setTimeout(() => {
    if (errorDiv) {
      errorDiv.style.display = "none"
    }
  }, 5000)
}

async function logout() {
  try {
    const token = localStorage.getItem('access_token')
    
    // Clear token from localStorage
    localStorage.removeItem('access_token')
    
    // Optional: Call logout endpoint if you have one
    if (token) {
      await fetch("/api/auth/logout", { 
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      })
    }
    
    window.location.href = "/login.html"
  } catch (error) {
    console.error("Logout error:", error)
    // Still redirect even if logout call fails
    window.location.href = "/login.html"
  }
}

// Optional: Add a manual refresh button handler
function manualRefresh() {
  refreshDashboard()
}

// Optional: Add connection status indicator
function updateConnectionStatus(isConnected) {
  const statusIndicator = document.getElementById("connectionStatus")
  if (statusIndicator) {
    statusIndicator.textContent = isConnected ? "Connected" : "Disconnected"
    statusIndicator.className = isConnected ? "status-connected" : "status-disconnected"
  }
}