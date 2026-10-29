/**
 * ⚡ Cyberspring — Cyber Security Audit & Governance Intelligence Controller
 * Powers the 3D dark cyber security audit & compliance console.
 */

const CyberDashboard = (function () {
  let currentActiveStage = "Planning";

  function init() {
    updateLiveClock();
    setInterval(updateLiveClock, 1000);
    loadConsoleMetrics();
  }

  function updateLiveClock() {
    const clockEl = document.getElementById("cs-live-clock");
    if (clockEl) {
      const now = new Date();
      clockEl.innerText = `SOC Guard Active • ${now.toLocaleTimeString()}`;
    }
  }

  function switchView(viewName) {
    document.querySelectorAll(".cs-subview").forEach(v => {
      v.classList.toggle("active", v.id === `cs-view-${viewName}`);
    });

    // Update sidebar buttons
    const btnMap = {
      console: 0,
      risks: 1,
      endpoints: 2,
      vulns: 3,
      reports: 4
    };

    const sidebarBtns = document.querySelectorAll(".cs-sidebar-btn");
    sidebarBtns.forEach((btn, idx) => {
      btn.classList.toggle("active", idx === btnMap[viewName]);
    });

    if (viewName === "risks") loadRisksTable();
    else if (viewName === "endpoints") loadEndpointsView();
    else if (viewName === "vulns") loadVulnsView();
    else if (viewName === "reports") loadReportsView();
    else if (viewName === "console") loadConsoleMetrics();
  }

  async function loadConsoleMetrics() {
    try {
      const res = await fetch("/api/riskguard/overview");
      const data = await res.json();
      
      const pctEl = document.getElementById("cs-donut-pct");
      if (pctEl && data.compliance_avg_score) {
        pctEl.innerText = `${Math.round(data.compliance_avg_score)}%`;
      }

      if (data.needs_attention) {
        const overdueEl = document.getElementById("cs-audits-overdue");
        if (overdueEl) overdueEl.innerText = String(data.needs_attention.length).padStart(2, '0');
      }
    } catch (err) {
      console.warn("Using baseline console metrics:", err);
    }
  }

  // Left Wing Stream Navigation
  function filterByStream(stream) {
    document.querySelectorAll(".cs-left-wing .cs-3d-wing-card").forEach(c => c.classList.remove("active"));
    if (stream === "universe") {
      switchView("endpoints");
    } else if (stream === "risks") {
      switchView("risks");
    } else if (stream === "plan") {
      switchView("risks");
    } else if (stream === "compliance") {
      switchView("reports");
    }
  }

  // Right Wing Actions Trigger
  function triggerRightAction(action) {
    if (action === "effectiveness") {
      runLocalAudit();
    } else if (action === "mitigation") {
      switchView("risks");
    } else if (action === "assurance") {
      switchView("reports");
    } else if (action === "tasks") {
      switchView("risks");
    } else if (action === "reporting") {
      window.location.href = "/api/riskguard/reports/csv";
    }
  }

  // Bottom Pipeline Lifecycle Filter
  function filterByStage(stage) {
    currentActiveStage = stage;
    document.querySelectorAll(".cs-pipeline-step-card").forEach(c => {
      const title = c.querySelector(".cs-step-title") ? c.querySelector(".cs-step-title").innerText : "";
      c.classList.toggle("active", title.toLowerCase().includes(stage.toLowerCase()));
    });
  }

  // Enterprise Risk Register
  async function loadRisksTable() {
    try {
      const res = await fetch("/api/riskguard/risks");
      const risks = await res.json();
      const tbody = document.getElementById("cs-risks-tbody");
      if (!tbody) return;

      tbody.innerHTML = risks.map(r => `
        <tr>
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: #38bdf8;">${r.risk_code}</span></td>
          <td>
            <div style="font-weight: 600; color: #fff;">${escapeHTML(r.title)}</div>
            <div style="font-size: 11px; color: var(--cs-text-muted);">${escapeHTML(r.affected_assets || 'General')}</div>
          </td>
          <td><span style="font-size: 12px; color: var(--cs-text-body);">${escapeHTML(r.category)}</span></td>
          <td>
            <span class="cs-badge ${r.inherent_rating === 'Critical' ? 'cs-badge-crit' : r.inherent_rating === 'High' ? 'cs-badge-warn' : 'cs-badge-caut'}">
              ${r.inherent_rating} (${r.inherent_score})
            </span>
          </td>
          <td><span style="font-size: 12px; font-weight: 600; color: #fff;">${r.residual_score} (${r.residual_rating})</span></td>
          <td><span style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.06); color: #fff;">${r.treatment_strategy}</span></td>
          <td><span style="font-size: 12px; font-weight: 600; color: ${r.status === 'Open' ? '#f59e0b' : '#10b981'};">${r.status}</span></td>
        </tr>
      `).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Live Local Host Audit
  async function runLocalAudit() {
    try {
      const res = await fetch("/api/riskguard/endpoints/local/inspect", { method: "POST" });
      const ep = await res.json();
      alert(`✅ Live Host Audit Complete!\n\nDevice: ${ep.device_name} (${ep.os} ${ep.os_version})\nSecurity Posture Score: ${ep.posture_score}/100\nFirewall: ${ep.firewall_status}\nDisk Encryption: ${ep.encryption_status}\nAntivirus/EDR: ${ep.antivirus_status}\nOS Patch Status: ${ep.patch_status}`);
      switchView("endpoints");
    } catch (err) {
      alert("Host audit error: " + err.message);
    }
  }

  // Endpoints Posture Cards
  async function loadEndpointsView() {
    try {
      const res = await fetch("/api/riskguard/endpoints");
      const eps = await res.json();
      const container = document.getElementById("cs-endpoints-cards");
      if (!container) return;

      container.innerHTML = eps.map(ep => `
        <div style="background: rgba(12, 23, 48, 0.65); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 18px; margin-bottom: 14px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 18px;">💻</span>
              <span style="font-size: 14.5px; font-weight: 700; color: #fff;">${escapeHTML(ep.device_name)}</span>
              <span class="cs-badge ${ep.status === 'Online' ? 'cs-badge-mon' : 'cs-badge-warn'}">${ep.status}</span>
            </div>
            <div>
              <span style="font-size: 12px; color: var(--cs-text-muted);">Posture Score:</span>
              <span style="font-size: 18px; font-weight: 800; font-family: var(--font-mono); color: ${ep.posture_score >= 75 ? '#00e5ff' : '#f59e0b'}; margin-left: 6px;">${ep.posture_score}/100</span>
            </div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0;">
            <div style="background: rgba(4, 8, 22, 0.7); padding: 10px; border-radius: 8px;">
              <div style="font-size: 10.5px; color: var(--cs-text-muted);">Firewall</div>
              <div style="font-weight: 700; color: ${ep.firewall_status === 'Pass' ? '#00ff88' : '#ef4444'}; font-size: 13px;">${ep.firewall_status}</div>
            </div>
            <div style="background: rgba(4, 8, 22, 0.7); padding: 10px; border-radius: 8px;">
              <div style="font-size: 10.5px; color: var(--cs-text-muted);">Disk Encryption</div>
              <div style="font-weight: 700; color: ${ep.encryption_status === 'Pass' ? '#00ff88' : '#f59e0b'}; font-size: 13px;">${ep.encryption_status}</div>
            </div>
            <div style="background: rgba(4, 8, 22, 0.7); padding: 10px; border-radius: 8px;">
              <div style="font-size: 10.5px; color: var(--cs-text-muted);">Antivirus / EDR</div>
              <div style="font-weight: 700; color: ${ep.antivirus_status === 'Pass' ? '#00ff88' : '#ef4444'}; font-size: 13px;">${ep.antivirus_status}</div>
            </div>
            <div style="background: rgba(4, 8, 22, 0.7); padding: 10px; border-radius: 8px;">
              <div style="font-size: 10.5px; color: var(--cs-text-muted);">Patch Status</div>
              <div style="font-weight: 700; color: ${ep.patch_status === 'Pass' ? '#00ff88' : '#f59e0b'}; font-size: 13px;">${ep.patch_status}</div>
            </div>
          </div>
          <div style="font-size: 11px; color: var(--cs-text-muted); display: flex; justify-content: space-between; border-top: 1px solid rgba(255,255,255,0.04); padding-top: 8px;">
            <span>OS: <b style="color: #fff;">${escapeHTML(ep.os)} ${escapeHTML(ep.os_version)}</b></span>
            <span>Last Audit: <b style="color: #fff; font-family: var(--font-mono);">${escapeHTML(ep.last_checkin)}</b></span>
          </div>
        </div>
      `).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Vulnerability Register
  async function loadVulnsView() {
    try {
      const res = await fetch("/api/riskguard/vulnerabilities");
      const vulns = await res.json();
      const tbody = document.getElementById("cs-vulns-tbody");
      if (!tbody) return;

      tbody.innerHTML = vulns.map(v => `
        <tr>
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: #f87171;">${escapeHTML(v.cve_id)}</span></td>
          <td>
            <div style="font-weight: 600; color: #fff;">${escapeHTML(v.title)}</div>
            <div style="font-size: 11px; color: var(--cs-text-muted);">${escapeHTML(v.affected_software)}</div>
          </td>
          <td><span class="cs-badge ${v.severity === 'Critical' ? 'cs-badge-crit' : 'cs-badge-warn'}">${v.severity} (${v.cvss_score})</span></td>
          <td><span style="font-size: 12px; color: #fff;">${escapeHTML(v.affected_asset_name || 'Production Node')}</span></td>
          <td>${v.linked_risk_id ? `<span class="cs-badge cs-badge-caut">${v.linked_risk_code || 'RSK Linked'}</span>` : `<span style="font-size: 11px; color: var(--cs-text-muted);">Unlinked</span>`}</td>
          <td>
            ${!v.linked_risk_id ? `<button class="cs-btn" style="color: #00e5ff; border-color: rgba(0, 229, 255, 0.4); padding: 4px 8px; font-size: 11px;" onclick="CyberDashboard.openEscalateModal('${v.id}', '${v.cve_id}')">⚡ Escalate to Risk</button>` : '<span style="color: #00ff88; font-size: 12px; font-weight: 600;">Linked</span>'}
          </td>
        </tr>
      `).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Reports Briefing
  async function loadReportsView() {
    try {
      const res = await fetch("/api/riskguard/reports/briefing");
      const briefing = await res.text();
      const pre = document.getElementById("cs-reports-preview");
      if (pre) pre.innerText = briefing;
    } catch (err) {
      console.error(err);
    }
  }

  // SQLite Backup
  async function backupDatabase() {
    try {
      const res = await fetch("/api/riskguard/backup", { method: "POST" });
      const data = await res.json();
      alert(`✅ Database Backup Created Successfully!\n\nBackup File: ${data.backup_file}\nSize: ${data.size_bytes} bytes\nTimestamp: ${data.timestamp}`);
    } catch (err) {
      alert("Backup error: " + err.message);
    }
  }

  // Quick Add Risk (<1 minute)
  function openAddRiskModal() {
    const modal = document.getElementById("cs-add-risk-modal");
    if (modal) modal.style.display = "flex";
  }

  async function submitAddRisk(e) {
    e.preventDefault();
    const title = document.getElementById("cs-modal-risk-title").value;
    const cat = document.getElementById("cs-modal-risk-cat").value;
    const lh = parseInt(document.getElementById("cs-modal-risk-lh").value, 10);
    const imp = parseInt(document.getElementById("cs-modal-risk-imp").value, 10);
    const owner = document.getElementById("cs-modal-risk-owner").value || "SecOps Lead";
    const assets = document.getElementById("cs-modal-risk-assets").value || "All Infrastructure";

    try {
      await fetch("/api/riskguard/risks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title, category: cat, likelihood: lh, impact: imp,
          risk_owner: owner, affected_assets: assets, treatment_strategy: "Mitigate"
        })
      });
      closeModal("cs-add-risk-modal");
      alert("✅ Risk saved to Enterprise Register!");
      switchView("risks");
    } catch (err) {
      alert("Error saving risk: " + err.message);
    }
  }

  // 1-Click Finding Escalation
  function openEscalateModal(vulnId, cveCode) {
    const modal = document.getElementById("cs-escalate-modal");
    if (!modal) return;
    document.getElementById("cs-esc-vuln-id").value = vulnId;
    document.getElementById("cs-esc-title").value = `Operational Exposure: ${cveCode} on Production Host`;
    modal.style.display = "flex";
  }

  async function submitEscalate(e) {
    e.preventDefault();
    const vulnId = document.getElementById("cs-esc-vuln-id").value;
    const title = document.getElementById("cs-esc-title").value;
    const cat = document.getElementById("cs-esc-cat").value;

    try {
      const res = await fetch("/api/riskguard/escalate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vulnerability_id: vulnId,
          custom_title: title,
          category: cat,
          assigned_owner: "SecOps Lead"
        })
      });
      if (res.ok) {
        closeModal("cs-escalate-modal");
        alert("🎉 Finding escalated to Enterprise Risk Register, mapped to CIS & ISO controls, and remediation task created!");
        switchView("risks");
      }
    } catch (err) {
      alert("Error: " + err.message);
    }
  }

  function showSupport() {
    alert("⚡ Cyberspring Global SOC & Audit Console\n\n• Architecture: Local-First Zero-CGo Monolith\n• Database: SQLite WAL mode (~/.riskguard/riskguard.db)\n• Live Audit: Stage A Endpoint Inspection\n• Hotline: +44 20 7946 0991 (24/7 Threat Response)\n• Version: v2.5.0 Cybersecurity Edition");
  }

  async function shutdownServer() {
    if (!confirm("Stop Cyberspring server?")) return;
    try {
      await fetch("/api/shutdown", { method: "POST" });
      alert("🛑 Server shutdown completed.");
    } catch (err) {
      alert("Server stopped.");
    }
  }

  function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.style.display = "none";
  }

  function escapeHTML(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  return {
    init,
    switchView,
    filterByStream,
    triggerRightAction,
    filterByStage,
    openAddRiskModal,
    submitAddRisk,
    openEscalateModal,
    submitEscalate,
    runLocalAudit,
    backupDatabase,
    showSupport,
    shutdownServer,
    closeModal
  };
})();

document.addEventListener("DOMContentLoaded", CyberDashboard.init);
