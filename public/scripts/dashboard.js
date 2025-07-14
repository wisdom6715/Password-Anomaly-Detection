// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {
  // checkAuth()
  refreshDashboard()

  // Auto-refresh every 30 seconds
  setInterval(refreshDashboard, 30000)
})

// async function checkAuth() {
//   try {
//     const response = await fetch("/api/auth/verify")
//     const result = await response.json()

//     if (!result.authenticated) {
//       window.location.href = "/login.html"
//       return
//     }

//     document.getElementById("welcomeMessage").textContent = `Welcome, ${result.username}!`
//   } catch (error) {
//     console.error("Auth check failed:", error)
//     window.location.href = "/login.html"
//   }
// }

async function refreshDashboard() {
  try {
    // Fetch logs and calculate stats
    const response = await fetch("/api/auth/logs")
    const logs = await response.json()

    // Calculate statistics
    const stats = calculateStats(logs)
    updateStats(stats)

    // Update activity logs
    updateActivityLogs(logs)
  } catch (error) {
    console.error("Error refreshing dashboard:", error)
  }
}

function calculateStats(logs) {
  const totalAttempts = logs.length
  const successfulLogins = logs.filter((log) => log.success && log.type !== "signup").length
  const failedAttempts = logs.filter((log) => !log.success && log.type !== "signup").length
  const securityAlerts = logs.filter((log) => log.anomaly).length

  return {
    totalAttempts,
    successfulLogins,
    failedAttempts,
    securityAlerts,
  }
}

function updateStats(stats) {
  document.getElementById("totalAttempts").textContent = stats.totalAttempts
  document.getElementById("successfulLogins").textContent = stats.successfulLogins
  document.getElementById("failedAttempts").textContent = stats.failedAttempts
  document.getElementById("securityAlerts").textContent = stats.securityAlerts
}

function updateActivityLogs(logs) {
  const logsContainer = document.getElementById("activityLogs")

  if (logs.length === 0) {
    logsContainer.innerHTML = "<p>No activity yet.</p>"
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
          [${timestamp}] ${log.username} - ${statusText} 
          (IP: ${log.ip_address})${anomalyText}
        </div>
      `
    })
    .join("")

  // Scroll to top to show latest entries
  logsContainer.scrollTop = 0
}

async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST" })
    window.location.href = "/login.html"
  } catch (error) {
    console.error("Logout error:", error)
    window.location.href = "/login.html"
  }
}
