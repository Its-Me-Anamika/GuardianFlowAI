// script.js - GuardianFlow AI Dashboard
// Polls /api/dashboard-data every 5 seconds using fetch() and updates
// the DOM directly (no frontend framework, per project constraints).

const REFRESH_INTERVAL_MS = 5000;

function threatBadge(level) {
  return `<span class="threat-badge threat-${level}">${level}</span>`;
}

function renderConnectedClients(clients) {
  const container = document.getElementById("connected-clients");
  if (!clients || clients.length === 0) {
    container.innerHTML = '<div class="empty-state">No clients connected yet.</div>';
    return;
  }
  container.innerHTML = clients
    .map(c => `<span class="client-pill"><span class="dot"></span>${c.client_name}
      <small>(${c.seconds_ago}s ago)</small></span>`)
    .join("");
}

function renderRecentLogs(logs) {
  const tbody = document.getElementById("logs-tbody");
  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No logs received yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map(log => `
    <tr>
      <td>${log.timestamp || ""}</td>
      <td>${log.client_name || ""}</td>
      <td>${log.cpu_usage || 0}%</td>
      <td>${log.ram_usage || 0}%</td>
      <td>${threatBadge(log.threat_level || "Low")}</td>
      <td>${log.threat_type || "None"}</td>
    </tr>
  `).join("");
}

function renderThreatCounts(counts) {
  document.getElementById("count-low").textContent = counts.Low ?? 0;
  document.getElementById("count-medium").textContent = counts.Medium ?? 0;
  document.getElementById("count-high").textContent = counts.High ?? 0;
  document.getElementById("count-critical").textContent = counts.Critical ?? 0;
}

function renderThreatReports(reports) {
  const container = document.getElementById("threat-reports");
  if (!reports || reports.length === 0) {
    container.innerHTML = '<div class="empty-state">No threats detected yet. All clear.</div>';
    return;
  }
  container.innerHTML = reports.map(r => `
    <div class="threat-card">
      <div><strong>${r.client_name}</strong> &mdash; ${threatBadge(r.threat_level)}
        <span style="color:#8fa1bd;">(${r.threat_type})</span></div>
      <p style="margin:8px 0; font-size:13px; white-space:pre-line;">
      
      ${escapeHtml(r.explanation)}
      
      </p>
      
      ${r.recommended_actions && r.recommended_actions.length
        ? `<ul class="actions">${r.recommended_actions.map(a => `<li>${escapeHtml(a)}</li>`).join("")}</ul>`
        : ""}
      <div class="hash">SHA-256: ${r.sha256_hash}</div>
    </div>
  `).join("");
}

function renderLiveCpuRam(logs) {
  // Use the most recent log entry to show a snapshot of live CPU/RAM
  if (!logs || logs.length === 0) return;
  const latest = logs[0];
  document.getElementById("live-cpu").textContent = `${latest.cpu_usage || 0}%`;
  document.getElementById("live-ram").textContent = `${latest.ram_usage || 0}%`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

async function refreshDashboard() {
  try {
    const response = await fetch("/api/dashboard-data");
    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }
    const data = await response.json();

    renderConnectedClients(data.connected_clients);
    renderRecentLogs(data.recent_logs);
    renderThreatCounts(data.threat_counts);
    renderThreatReports(data.recent_reports);
    renderLiveCpuRam(data.recent_logs);

    document.getElementById("connection-status").textContent = "Connected";
    document.getElementById("connection-status").style.color = "#22c55e";
  } catch (err) {
    console.error("Dashboard refresh failed:", err);
    document.getElementById("connection-status").textContent = "Offline / Retrying...";
    document.getElementById("connection-status").style.color = "#ef4444";
  }
}

// Initial load, then poll on an interval
refreshDashboard();
setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
