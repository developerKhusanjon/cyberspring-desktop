/**
 * 🛡️ RiskGuard Desktop — Frontend Client Application Engine
 * Complete local-first risk management, endpoint posture, compliance, and cross-module workflows.
 */

const RiskGuard = (function () {
  let currentView = "overview";
  let overviewData = null;
  let activeFilterRating = null;
  let activeFilterCell = null;
  let wizardState = {
    step: 1,
    asset: "",
    threat: "",
    vuln: "",
    likelihood: 3,
    impact: 3,
    controls: "",
    treatment: "Mitigate",
    title: "",
    category: "Technical Security",
    owner: "SecOps Lead"
  };

  async function init() {
    setupNavigation();
    setupTheme();
    await loadOverview();
    await loadSettings();
  }

  // Navigation
  function setupNavigation() {
    document.querySelectorAll(".rg-nav-item").forEach(item => {
      item.addEventListener("click", () => {
        const view = item.getAttribute("data-view");
        switchView(view);
      });
    });

    // Global Search
    const searchInput = document.getElementById("rg-global-search");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        if (currentView === "risks") loadRisks(query);
        else if (currentView === "assets") loadAssets(query);
        else if (currentView === "vulnerabilities") loadVulnerabilities(query);
      });
    }
  }

  function switchView(viewName) {
    currentView = viewName;
    document.querySelectorAll(".rg-nav-item").forEach(item => {
      item.classList.toggle("active", item.getAttribute("data-view") === viewName);
    });

    document.querySelectorAll(".rg-view-content").forEach(view => {
      view.classList.toggle("active", view.id === `rg-view-${viewName}`);
    });

    // Trigger view-specific loads
    switch (viewName) {
      case "overview": loadOverview(); break;
      case "risks": loadRisks(); break;
      case "assessment": renderWizardStep(); break;
      case "assets": loadAssets(); break;
      case "endpoints": loadEndpoints(); break;
      case "vulnerabilities": loadVulnerabilities(); break;
      case "incidents": loadIncidents(); break;
      case "compliance": loadCompliance(); break;
      case "reports": loadReports(); break;
      case "settings": loadSettings(); break;
    }
  }

  // 1. OVERVIEW
  async function loadOverview() {
    try {
      const res = await fetch("/api/riskguard/overview");
      overviewData = await res.json();
      renderOverviewKPIs(overviewData);
      renderHeatmap(overviewData.heatmap_counts || {});
      renderNeedsAttention(overviewData.needs_attention || []);
    } catch (err) {
      console.error("Failed to load overview:", err);
    }
  }

  function renderOverviewKPIs(data) {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val !== undefined ? val : "0";
    };
    setVal("rg-kpi-open-risks", data.open_risks);
    setVal("rg-kpi-crit-risks", data.critical_risks);
    setVal("rg-kpi-appetite", data.exceeding_appetite);
    setVal("rg-kpi-endpoints", `${data.healthy_endpoints}/${data.total_endpoints}`);
    setVal("rg-kpi-vulns", data.total_vulnerabilities);
    setVal("rg-kpi-incidents", data.open_incidents);
    setVal("rg-kpi-actions", data.overdue_actions);
    setVal("rg-kpi-compliance", `${Math.round(data.compliance_avg_score || 0)}%`);
  }

  function renderHeatmap(counts) {
    const grid = document.getElementById("rg-heatmap-grid");
    if (!grid) return;
    grid.innerHTML = "";

    // Y-Axis Labels (Impact 5 to 1)
    const impactLabels = ["5 (Catastrophic)", "4 (Major)", "3 (Moderate)", "2 (Minor)", "1 (Insignificant)"];
    
    for (let imp = 5; imp >= 1; imp--) {
      // Row Label
      const rowLabel = document.createElement("div");
      rowLabel.className = "text-right pr-2 text-xs text-slate-400 font-semibold flex items-center justify-end";
      rowLabel.innerText = `I:${imp}`;
      grid.appendChild(rowLabel);

      // 5 Likelihood Columns for this Impact
      for (let lh = 1; lh <= 5; lh++) {
        const score = lh * imp;
        const key = `${lh}-${imp}`;
        const count = counts[key] || 0;

        let cellClass = "rg-cell-low";
        if (score >= 20) cellClass = "rg-cell-crit";
        else if (score >= 15) cellClass = "rg-cell-high";
        else if (score >= 8) cellClass = "rg-cell-med";

        const cell = document.createElement("div");
        cell.className = `rg-heatmap-cell ${cellClass}`;
        cell.title = `Likelihood: ${lh}, Impact: ${imp} (Score: ${score})`;
        cell.innerHTML = `
          <span class="rg-cell-count">${count > 0 ? count : ""}</span>
          <span class="rg-cell-score">${score}</span>
        `;
        cell.addEventListener("click", () => {
          activeFilterCell = { lh, imp };
          switchView("risks");
        });
        grid.appendChild(cell);
      }
    }

    // Bottom X-Axis Header (Empty corner + L:1 to L:5)
    const emptyCorner = document.createElement("div");
    grid.appendChild(emptyCorner);
    for (let lh = 1; lh <= 5; lh++) {
      const colLabel = document.createElement("div");
      colLabel.className = "text-center text-xs text-slate-400 font-semibold pt-1";
      colLabel.innerText = `L:${lh}`;
      grid.appendChild(colLabel);
    }
  }

  function renderNeedsAttention(items) {
    const container = document.getElementById("rg-needs-attention-list");
    if (!container) return;
    if (items.length === 0) {
      container.innerHTML = `<div class="p-4 text-center text-slate-400 text-sm">✅ All critical risks, endpoints, and remediation tasks are currently within compliance thresholds.</div>`;
      return;
    }

    container.innerHTML = items.map(item => `
      <div class="p-3 bg-slate-800/60 border border-slate-700/80 rounded-lg flex items-center justify-between gap-4 hover:border-slate-600 transition-all">
        <div class="flex items-center gap-3">
          <span class="rg-tag rg-tag-${item.severity === 'Critical' ? 'crit' : 'high'}">${item.severity}</span>
          <div>
            <div class="font-semibold text-sm text-slate-100">${escapeHTML(item.title)}</div>
            <div class="text-xs text-slate-400">${escapeHTML(item.reason)} &bull; Owner: <span class="text-slate-300">${escapeHTML(item.owner)}</span></div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-xs font-mono text-amber-400">${escapeHTML(item.due_date)}</span>
          <button class="rg-btn rg-btn-secondary rg-btn-sm" onclick="RiskGuard.handleActionItem('${item.targetURL}')">View</button>
        </div>
      </div>
    `).join("");
  }

  function handleActionItem(target) {
    const view = target.replace("#", "");
    switchView(view);
  }

  // 2. RISK REGISTER
  async function loadRisks(query = "") {
    try {
      let url = "/api/riskguard/risks";
      const params = new URLSearchParams();
      if (query) params.append("q", query);
      if (activeFilterRating) params.append("rating", activeFilterRating);
      if (params.toString()) url += `?${params.toString()}`;

      const res = await fetch(url);
      const risks = await res.json();
      renderRiskTable(risks);
    } catch (err) {
      console.error("Failed to load risks:", err);
    }
  }

  function renderRiskTable(risks) {
    const tbody = document.getElementById("rg-risks-tbody");
    if (!tbody) return;

    if (risks.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">No risks matching the current filters. Click <b>"➕ New Risk"</b> or start the Assessment Wizard.</td></tr>`;
      return;
    }

    tbody.innerHTML = risks.map(r => {
      let ratingClass = "rg-tag-low";
      if (r.inherent_rating === "Critical") ratingClass = "rg-tag-crit";
      else if (r.inherent_rating === "High") ratingClass = "rg-tag-high";
      else if (r.inherent_rating === "Medium") ratingClass = "rg-tag-med";

      return `
        <tr>
          <td><span class="font-mono font-semibold text-blue-400">${escapeHTML(r.risk_code)}</span></td>
          <td>
            <div class="font-medium text-slate-100">${escapeHTML(r.title)}</div>
            <div class="text-xs text-slate-400 truncate max-w-md">${escapeHTML(r.vulnerability_weakness || r.description)}</div>
          </td>
          <td><span class="text-xs text-slate-300">${escapeHTML(r.category)}</span></td>
          <td>
            <span class="rg-tag ${ratingClass}">${r.inherent_rating} (${r.inherent_score})</span>
            <div class="text-[10px] text-slate-400">L:${r.likelihood} &times; I:${r.impact}</div>
          </td>
          <td>
            <span class="text-xs font-semibold text-slate-300">${r.residual_score} (${r.residual_rating})</span>
          </td>
          <td>
            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">${escapeHTML(r.treatment_strategy)}</span>
          </td>
          <td>
            <span class="text-xs ${r.status === 'Open' ? 'text-amber-400' : 'text-emerald-400'} font-semibold">${escapeHTML(r.status)}</span>
          </td>
          <td>
            <div class="flex items-center gap-1">
              <button class="rg-btn rg-btn-secondary rg-btn-sm" onclick="RiskGuard.openRiskDrawer('${r.id}')">Inspect</button>
              ${r.status !== 'Accepted' ? `<button class="rg-btn rg-btn-secondary rg-btn-sm text-amber-400" onclick="RiskGuard.openAcceptModal('${r.id}', '${escapeHTML(r.risk_code)}')">Accept</button>` : ''}
              <button class="rg-btn rg-btn-danger rg-btn-sm" onclick="RiskGuard.deleteRisk('${r.id}')">Delete</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  // Quick Create Risk Modal (< 1 minute creation)
  function openQuickCreateRisk() {
    const modal = document.getElementById("rg-quick-risk-modal");
    if (modal) modal.style.display = "flex";
  }

  async function submitQuickRisk(e) {
    e.preventDefault();
    const title = document.getElementById("rg-quick-title").value;
    const category = document.getElementById("rg-quick-cat").value;
    const likelihood = parseInt(document.getElementById("rg-quick-lh").value, 10);
    const impact = parseInt(document.getElementById("rg-quick-imp").value, 10);
    const owner = document.getElementById("rg-quick-owner").value || "SecOps Analyst";
    const assets = document.getElementById("rg-quick-assets").value || "All Infrastructure";
    const treatment = document.getElementById("rg-quick-treatment").value;

    try {
      const res = await fetch("/api/riskguard/risks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title, category, likelihood, impact,
          risk_owner: owner, affected_assets: assets,
          treatment_strategy: treatment
        })
      });
      if (res.ok) {
        closeModal("rg-quick-risk-modal");
        loadRisks();
        loadOverview();
      }
    } catch (err) {
      alert("Error saving risk: " + err.message);
    }
  }

  // 3. GUIDED 8-STEP RISK ASSESSMENT WIZARD
  function renderWizardStep() {
    const step = wizardState.step;
    document.querySelectorAll(".rg-stepper-step").forEach((el, idx) => {
      el.classList.toggle("active", idx + 1 === step);
      el.classList.toggle("completed", idx + 1 < step);
    });

    const stepContainer = document.getElementById("rg-wizard-body");
    if (!stepContainer) return;

    // Calculate live score
    const score = wizardState.likelihood * wizardState.impact;
    let rating = "Low";
    if (score >= 20) rating = "Critical";
    else if (score >= 15) rating = "High";
    else if (score >= 8) rating = "Medium";

    let stepHTML = "";
    switch (step) {
      case 1:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 1: What asset, process, or business activity is affected?</h3>
          <p class="text-xs text-slate-400 mb-4">Identify the specific systems, services, or business activities under evaluation.</p>
          <div class="rg-form-group">
            <label>Asset or Business Process Name</label>
            <input type="text" id="wz-asset" value="${escapeHTML(wizardState.asset)}" placeholder="e.g. Primary Customer Database Cluster / VPN Gateway" />
          </div>
          <div class="rg-form-group mt-3">
            <label>Category</label>
            <select id="wz-cat">
              <option ${wizardState.category === 'Technical Security' ? 'selected' : ''}>Technical Security</option>
              <option ${wizardState.category === 'Identity & Access' ? 'selected' : ''}>Identity & Access</option>
              <option ${wizardState.category === 'Cloud Security' ? 'selected' : ''}>Cloud Security</option>
              <option ${wizardState.category === 'Compliance & Governance' ? 'selected' : ''}>Compliance & Governance</option>
            </select>
          </div>
        `;
        break;
      case 2:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 2: What could go wrong?</h3>
          <p class="text-xs text-slate-400 mb-4">Describe the realistic threat scenario or adversary action.</p>
          <div class="rg-form-group">
            <label>Threat Scenario</label>
            <textarea id="wz-threat" rows="3" placeholder="e.g. An external attacker conducts brute-force authentication against staff VPN logins.">${escapeHTML(wizardState.threat)}</textarea>
          </div>
        `;
        break;
      case 3:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 3: What would cause the event?</h3>
          <p class="text-xs text-slate-400 mb-4">Identify the underlying technical weakness or operational vulnerability.</p>
          <div class="rg-form-group">
            <label>Root Vulnerability or Weakness</label>
            <textarea id="wz-vuln" rows="3" placeholder="e.g. Unpatched OpenSSL CVE or missing multi-factor authentication (MFA).">${escapeHTML(wizardState.vuln)}</textarea>
          </div>
        `;
        break;
      case 4:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 4: How likely is the event?</h3>
          <p class="text-xs text-slate-400 mb-4">Estimate the frequency and probability of an exploit attempt.</p>
          <div class="grid grid-cols-5 gap-3">
            ${[1, 2, 3, 4, 5].map(v => `
              <button class="p-3 rounded-lg border text-center transition-all ${wizardState.likelihood === v ? 'border-blue-500 bg-blue-500/20 text-white font-bold' : 'border-slate-700 bg-slate-800 text-slate-400'}"
                onclick="RiskGuard.setWizardLikelihood(${v})">
                <div class="text-lg">${v}</div>
                <div class="text-[10px] uppercase font-semibold">${['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][v-1]}</div>
              </button>
            `).join("")}
          </div>
        `;
        break;
      case 5:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 5: What would the business impact be?</h3>
          <p class="text-xs text-slate-400 mb-4">Estimate potential financial, operational, or legal consequences.</p>
          <div class="grid grid-cols-5 gap-3">
            ${[1, 2, 3, 4, 5].map(v => `
              <button class="p-3 rounded-lg border text-center transition-all ${wizardState.impact === v ? 'border-amber-500 bg-amber-500/20 text-white font-bold' : 'border-slate-700 bg-slate-800 text-slate-400'}"
                onclick="RiskGuard.setWizardImpact(${v})">
                <div class="text-lg">${v}</div>
                <div class="text-[10px] uppercase font-semibold">${['Insignificant', 'Minor', 'Moderate', 'Major', 'Catastrophic'][v-1]}</div>
              </button>
            `).join("")}
          </div>
        `;
        break;
      case 6:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 6: What controls are already in place?</h3>
          <p class="text-xs text-slate-400 mb-4">Document defensive controls that reduce inherent likelihood or impact.</p>
          <div class="rg-form-group">
            <label>Existing Protective Controls</label>
            <textarea id="wz-controls" rows="3" placeholder="e.g. Edge firewall rate-limiting, daily encrypted snapshots, SIEM alert rule.">${escapeHTML(wizardState.controls)}</textarea>
          </div>
        `;
        break;
      case 7:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 7: What action should be taken?</h3>
          <p class="text-xs text-slate-400 mb-4">Select the organizational risk treatment strategy.</p>
          <div class="grid grid-cols-4 gap-3">
            ${['Mitigate', 'Accept', 'Transfer', 'Avoid'].map(t => `
              <button class="p-3 rounded-lg border text-center transition-all ${wizardState.treatment === t ? 'border-emerald-500 bg-emerald-500/20 text-white font-bold' : 'border-slate-700 bg-slate-800 text-slate-400'}"
                onclick="RiskGuard.setWizardTreatment('${t}')">
                <div class="text-sm font-bold">${t}</div>
                <div class="text-[10px] text-slate-400">${t === 'Mitigate' ? 'Implement security controls' : t === 'Accept' ? 'Formal approval & justification' : t === 'Transfer' ? 'Insurance or vendor SLA' : 'Cease activity'}</div>
              </button>
            `).join("")}
          </div>
        `;
        break;
      case 8:
        stepHTML = `
          <h3 class="text-base font-bold text-slate-100 mb-2">Step 8: Review & Save Assessment</h3>
          <div class="p-4 rounded-lg bg-slate-800/80 border border-slate-700 flex flex-col gap-3">
            <div class="flex items-center justify-between">
              <span class="text-sm text-slate-400">Affected Asset:</span>
              <span class="font-semibold text-slate-200">${escapeHTML(wizardState.asset || "Unspecified")}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-sm text-slate-400">Threat Scenario:</span>
              <span class="text-xs text-slate-300 max-w-sm text-right">${escapeHTML(wizardState.threat || "None")}</span>
            </div>
            <div class="flex items-center justify-between border-t border-slate-700/60 pt-2">
              <span class="text-sm text-slate-400">Inherent Risk Score:</span>
              <span class="rg-tag rg-tag-${rating.toLowerCase()} text-sm font-bold">${rating} (${score} pts)</span>
            </div>
            <div class="text-xs text-slate-400 italic">
              Calculation Rationale: Likelihood (${wizardState.likelihood}) &times; Impact (${wizardState.impact}) = Score ${score}.
            </div>
            <div class="flex items-center justify-between border-t border-slate-700/60 pt-2">
              <span class="text-sm text-slate-400">Treatment Plan:</span>
              <span class="text-sm font-semibold text-emerald-400">${wizardState.treatment}</span>
            </div>
          </div>
        `;
        break;
    }

    stepContainer.innerHTML = stepHTML;
    document.getElementById("rg-wizard-score-preview").innerText = `${rating} (${score} pts) — L:${wizardState.likelihood} × I:${wizardState.impact}`;
  }

  function nextWizardStep() {
    saveCurrentWizardInputs();
    if (wizardState.step < 8) {
      wizardState.step++;
      renderWizardStep();
    } else {
      finishWizardAssessment();
    }
  }

  function prevWizardStep() {
    saveCurrentWizardInputs();
    if (wizardState.step > 1) {
      wizardState.step--;
      renderWizardStep();
    }
  }

  function saveCurrentWizardInputs() {
    const assetEl = document.getElementById("wz-asset");
    if (assetEl) wizardState.asset = assetEl.value;
    const catEl = document.getElementById("wz-cat");
    if (catEl) wizardState.category = catEl.value;
    const threatEl = document.getElementById("wz-threat");
    if (threatEl) wizardState.threat = threatEl.value;
    const vulnEl = document.getElementById("wz-vuln");
    if (vulnEl) wizardState.vuln = vulnEl.value;
    const ctrlEl = document.getElementById("wz-controls");
    if (ctrlEl) wizardState.controls = ctrlEl.value;
  }

  function setWizardLikelihood(val) { wizardState.likelihood = val; renderWizardStep(); }
  function setWizardImpact(val) { wizardState.impact = val; renderWizardStep(); }
  function setWizardTreatment(val) { wizardState.treatment = val; renderWizardStep(); }

  async function finishWizardAssessment() {
    const title = `Risk to ${wizardState.asset || 'Infrastructure'}: ${wizardState.threat.substring(0, 45) || 'Operational Disruption'}`;
    try {
      const res = await fetch("/api/riskguard/risks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          category: wizardState.category,
          affected_assets: wizardState.asset,
          threat_scenario: wizardState.threat,
          vulnerability_weakness: wizardState.vuln,
          existing_controls: wizardState.controls,
          treatment_strategy: wizardState.treatment,
          likelihood: wizardState.likelihood,
          impact: wizardState.impact,
          risk_owner: "SecOps Lead"
        })
      });
      if (res.ok) {
        alert("🎉 Risk Assessment successfully saved to the Risk Register!");
        wizardState.step = 1;
        switchView("risks");
      }
    } catch (err) {
      alert("Error: " + err.message);
    }
  }

  // 4. ENDPOINTS & LOCAL POSTURE
  async function loadEndpoints() {
    try {
      const res = await fetch("/api/riskguard/endpoints");
      const endpoints = await res.json();
      renderEndpoints(endpoints);
    } catch (err) {
      console.error("Failed to load endpoints:", err);
    }
  }

  function renderEndpoints(endpoints) {
    const container = document.getElementById("rg-endpoints-list");
    if (!container) return;

    container.innerHTML = endpoints.map(ep => `
      <div class="rg-card">
        <div class="rg-card-header">
          <div class="rg-card-title">
            <span>💻</span>
            <span>${escapeHTML(ep.device_name)}</span>
            <span class="rg-tag ${ep.status === 'Online' ? 'rg-tag-low' : 'rg-tag-high'}">${ep.status}</span>
          </div>
          <div class="text-right">
            <span class="text-xs text-slate-400">Security Score:</span>
            <span class="font-mono font-bold text-lg ${ep.posture_score >= 75 ? 'text-emerald-400' : 'text-amber-400'}">${ep.posture_score}/100</span>
          </div>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 my-3">
          <div class="p-3 bg-slate-900/60 rounded border border-slate-800">
            <div class="text-xs text-slate-400">Firewall</div>
            <div class="font-bold text-sm ${ep.firewall_status === 'Pass' ? 'text-emerald-400' : 'text-red-400'}">${ep.firewall_status}</div>
          </div>
          <div class="p-3 bg-slate-900/60 rounded border border-slate-800">
            <div class="text-xs text-slate-400">Disk Encryption</div>
            <div class="font-bold text-sm ${ep.encryption_status === 'Pass' ? 'text-emerald-400' : 'text-amber-400'}">${ep.encryption_status}</div>
          </div>
          <div class="p-3 bg-slate-900/60 rounded border border-slate-800">
            <div class="text-xs text-slate-400">Antivirus / EDR</div>
            <div class="font-bold text-sm ${ep.antivirus_status === 'Pass' ? 'text-emerald-400' : 'text-red-400'}">${ep.antivirus_status}</div>
          </div>
          <div class="p-3 bg-slate-900/60 rounded border border-slate-800">
            <div class="text-xs text-slate-400">Patch Level</div>
            <div class="font-bold text-sm ${ep.patch_status === 'Pass' ? 'text-emerald-400' : 'text-amber-400'}">${ep.patch_status}</div>
          </div>
        </div>
        <div class="text-xs text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-2">
          <span>OS: <b class="text-slate-300">${escapeHTML(ep.os)} ${escapeHTML(ep.os_version)} (${escapeHTML(ep.arch)})</b></span>
          <span>Last Check-in: <b class="text-slate-300 font-mono">${escapeHTML(ep.last_checkin)}</b></span>
        </div>
      </div>
    `).join("");
  }

  async function runLocalMachineInspection() {
    const btn = document.getElementById("rg-btn-inspect-local");
    if (btn) btn.innerText = "⏳ Running Audit...";
    try {
      const res = await fetch("/api/riskguard/endpoints/local/inspect", { method: "POST" });
      const ep = await res.json();
      alert(`✅ Local Endpoint Audit Complete!\nDevice: ${ep.device_name} (${ep.os})\nScore: ${ep.posture_score}/100\nFirewall: ${ep.firewall_status}\nEncryption: ${ep.encryption_status}`);
      loadEndpoints();
      loadOverview();
    } catch (err) {
      alert("Inspection error: " + err.message);
    } finally {
      if (btn) btn.innerText = "🔄 Run Local Posture Audit";
    }
  }

  // 5. VULNERABILITIES & CROSS-MODULE WORKFLOW
  async function loadVulnerabilities(query = "") {
    try {
      let url = "/api/riskguard/vulnerabilities";
      if (query) url += `?q=${encodeURIComponent(query)}`;
      const res = await fetch(url);
      const vulns = await res.json();
      renderVulnerabilities(vulns);
    } catch (err) {
      console.error("Failed to load vulns:", err);
    }
  }

  function renderVulnerabilities(vulns) {
    const tbody = document.getElementById("rg-vulns-tbody");
    if (!tbody) return;

    tbody.innerHTML = vulns.map(v => `
      <tr>
        <td><span class="font-mono font-bold text-red-400">${escapeHTML(v.cve_id)}</span></td>
        <td>
          <div class="font-medium text-slate-100">${escapeHTML(v.title)}</div>
          <div class="text-xs text-slate-400">${escapeHTML(v.affected_software)}</div>
        </td>
        <td>
          <span class="rg-tag rg-tag-${v.severity === 'Critical' ? 'crit' : v.severity === 'High' ? 'high' : 'med'}">${v.severity} (${v.cvss_score})</span>
        </td>
        <td><span class="text-xs text-slate-300 font-medium">${escapeHTML(v.affected_asset_name || 'Unassigned')}</span></td>
        <td>
          ${v.linked_risk_id ? `<span class="rg-tag rg-tag-med font-mono">Linked: ${escapeHTML(v.linked_risk_code || 'RSK')}</span>` : `<span class="text-xs text-slate-500">Unlinked</span>`}
        </td>
        <td><span class="text-xs font-semibold text-slate-300">${escapeHTML(v.status)}</span></td>
        <td>
          <div class="flex items-center gap-1">
            ${!v.linked_risk_id ? `<button class="rg-btn rg-btn-primary rg-btn-sm" onclick="RiskGuard.openEscalateModal('${v.id}', '${escapeHTML(v.cve_id)}', '${escapeHTML(v.title)}')">⚡ Escalate to Risk</button>` : ''}
            <button class="rg-btn rg-btn-secondary rg-btn-sm" onclick="RiskGuard.markVulnPatched('${v.id}')">Mark Patched</button>
          </div>
        </td>
      </tr>
    `).join("");
  }

  function openEscalateModal(vulnId, cve, title) {
    document.getElementById("rg-esc-vuln-id").value = vulnId;
    document.getElementById("rg-esc-title").value = `Operational Exposure: ${cve} (${title.substring(0, 35)}...)`;
    document.getElementById("rg-escalate-modal").style.display = "flex";
  }

  async function submitEscalate(e) {
    e.preventDefault();
    const vulnId = document.getElementById("rg-esc-vuln-id").value;
    const title = document.getElementById("rg-esc-title").value;
    const cat = document.getElementById("rg-esc-cat").value;
    const owner = document.getElementById("rg-esc-owner").value || "SecOps Lead";

    try {
      const res = await fetch("/api/riskguard/escalate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vulnerability_id: vulnId,
          custom_title: title,
          category: cat,
          assigned_owner: owner
        })
      });
      if (res.ok) {
        closeModal("rg-escalate-modal");
        alert("🎉 Cross-Module Flow Complete! Finding has been linked to a new Business Risk, compliance controls (CIS/ISO) were mapped, and a mitigation task was generated.");
        switchView("risks");
      }
    } catch (err) {
      alert("Escalation failed: " + err.message);
    }
  }

  async function markVulnPatched(id) {
    if (!confirm("Confirm that this vulnerability has been verified and patched on the host?")) return;
    try {
      await fetch(`/api/riskguard/vulnerabilities/${id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "Patched" })
      });
      loadVulnerabilities();
      loadOverview();
    } catch (err) {
      console.error(err);
    }
  }

  // 6. ASSETS INVENTORY
  async function loadAssets(query = "") {
    try {
      let url = "/api/riskguard/assets";
      if (query) url += `?q=${encodeURIComponent(query)}`;
      const res = await fetch(url);
      const assets = await res.json();
      renderAssets(assets);
    } catch (err) {
      console.error("Failed to load assets:", err);
    }
  }

  function renderAssets(assets) {
    const tbody = document.getElementById("rg-assets-tbody");
    if (!tbody) return;

    tbody.innerHTML = assets.map(a => `
      <tr>
        <td>
          <div class="font-bold text-slate-100">${escapeHTML(a.name)}</div>
          <div class="text-xs text-slate-400 font-mono">${escapeHTML(a.hostname || a.ip_address || 'N/A')}</div>
        </td>
        <td><span class="text-xs text-slate-300">${escapeHTML(a.type)}</span></td>
        <td>
          <span class="rg-tag rg-tag-${a.criticality === 'Critical' ? 'crit' : a.criticality === 'High' ? 'high' : 'med'}">${a.criticality}</span>
        </td>
        <td><span class="text-xs text-slate-300">${escapeHTML(a.owner || 'Unassigned')}</span></td>
        <td><span class="text-xs text-slate-400">${escapeHTML(a.environment)}</span></td>
        <td>
          <span class="text-xs font-mono text-slate-300">Vulns: ${a.linked_vulns} | Inc: ${a.linked_incidents}</span>
        </td>
      </tr>
    `).join("");
  }

  // 7. COMPLIANCE & FRAMEWORKS
  async function loadCompliance() {
    try {
      const res = await fetch("/api/riskguard/compliance/frameworks");
      const fws = await res.json();
      renderFrameworks(fws);
      if (fws.length > 0) loadControls(fws[0].id);
    } catch (err) {
      console.error("Failed to load compliance:", err);
    }
  }

  function renderFrameworks(fws) {
    const container = document.getElementById("rg-frameworks-tabs");
    if (!container) return;

    container.innerHTML = fws.map((fw, idx) => `
      <button class="rg-btn ${idx === 0 ? 'rg-btn-primary' : 'rg-btn-secondary'}" onclick="RiskGuard.selectFramework('${fw.id}', this)">
        <span>${escapeHTML(fw.code)} (${Math.round(fw.coverage_pct)}%)</span>
      </button>
    `).join("");
  }

  function selectFramework(fwId, btn) {
    document.querySelectorAll("#rg-frameworks-tabs button").forEach(b => {
      b.className = "rg-btn rg-btn-secondary";
    });
    btn.className = "rg-btn rg-btn-primary";
    loadControls(fwId);
  }

  async function loadControls(fwId) {
    try {
      const res = await fetch(`/api/riskguard/compliance/controls?framework_id=${fwId}`);
      const controls = await res.json();
      renderControls(controls);
    } catch (err) {
      console.error("Failed to load controls:", err);
    }
  }

  function renderControls(controls) {
    const tbody = document.getElementById("rg-controls-tbody");
    if (!tbody) return;

    tbody.innerHTML = controls.map(c => `
      <tr>
        <td><span class="font-mono font-bold text-blue-400">${escapeHTML(c.control_id)}</span></td>
        <td>
          <div class="font-medium text-slate-100">${escapeHTML(c.title)}</div>
          <div class="text-xs text-slate-400">${escapeHTML(c.description)}</div>
        </td>
        <td><span class="text-xs text-slate-300">${escapeHTML(c.category)}</span></td>
        <td>
          <span class="rg-tag ${c.implementation_status === 'Implemented' ? 'rg-tag-low' : 'rg-tag-med'}">${escapeHTML(c.implementation_status)}</span>
        </td>
        <td>
          ${c.mapped_risk_ids && c.mapped_risk_ids.length > 0 ? c.mapped_risk_ids.map(r => `<span class="rg-tag rg-tag-neutral text-[10px] block my-0.5">${escapeHTML(r)}</span>`).join("") : '<span class="text-xs text-slate-500">None</span>'}
        </td>
      </tr>
    `).join("");
  }

  // 8. INCIDENTS
  async function loadIncidents() {
    try {
      const res = await fetch("/api/riskguard/incidents");
      const incidents = await res.json();
      renderIncidents(incidents);
    } catch (err) {
      console.error("Failed to load incidents:", err);
    }
  }

  function renderIncidents(incidents) {
    const tbody = document.getElementById("rg-incidents-tbody");
    if (!tbody) return;

    tbody.innerHTML = incidents.map(i => `
      <tr>
        <td><span class="font-mono font-bold text-amber-400">${escapeHTML(i.incident_code)}</span></td>
        <td>
          <div class="font-medium text-slate-100">${escapeHTML(i.title)}</div>
          <div class="text-xs text-slate-400">${escapeHTML(i.description)}</div>
        </td>
        <td><span class="rg-tag rg-tag-${i.severity === 'Critical' ? 'crit' : 'high'}">${i.severity}</span></td>
        <td><span class="text-xs font-semibold text-slate-200">${escapeHTML(i.status)}</span></td>
        <td><span class="text-xs text-emerald-400 font-medium">${escapeHTML(i.containment_status)}</span></td>
        <td><span class="text-xs text-slate-300">${escapeHTML(i.lead_investigator)}</span></td>
      </tr>
    `).join("");
  }

  // 9. REPORTS
  async function loadReports() {
    // Generates preview
    try {
      const res = await fetch("/api/riskguard/reports/markdown");
      const md = await res.text();
      const preview = document.getElementById("rg-reports-preview");
      if (preview) preview.innerText = md;
    } catch (err) {
      console.error(err);
    }
  }

  // 10. SETTINGS & BACKUP
  async function loadSettings() {
    try {
      const res = await fetch("/api/riskguard/settings");
      const s = await res.json();
      const nameInput = document.getElementById("rg-set-product-name");
      if (nameInput) nameInput.value = s.product_name;
      const titleEl = document.getElementById("rg-top-product-title");
      if (titleEl) titleEl.innerText = s.product_name;

      const appVal = document.getElementById("rg-set-appetite");
      if (appVal) appVal.value = s.risk_appetite_threshold;
    } catch (err) {
      console.error(err);
    }
  }

  async function saveSettings(e) {
    e.preventDefault();
    const productName = document.getElementById("rg-set-product-name").value;
    const appetite = parseInt(document.getElementById("rg-set-appetite").value, 10);

    try {
      await fetch("/api/riskguard/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ product_name: productName, risk_appetite_threshold: appetite })
      });
      alert("✅ Settings saved successfully!");
      loadSettings();
      loadOverview();
    } catch (err) {
      alert("Save failed: " + err.message);
    }
  }

  async function triggerBackup() {
    try {
      const res = await fetch("/api/riskguard/backup", { method: "POST" });
      const data = await res.json();
      alert(`💾 Online SQLite Backup Complete!\nSaved to: ${data.backup_path}`);
    } catch (err) {
      alert("Backup error: " + err.message);
    }
  }

  async function clearSampleWorkspace() {
    if (!confirm("Are you sure you want to clear the sample workspace and switch to a blank production workspace?")) return;
    try {
      await fetch("/api/riskguard/workspace/clear", { method: "POST" });
      alert("✅ Sample workspace cleared. Clean production workspace active.");
      location.reload();
    } catch (err) {
      alert("Error: " + err.message);
    }
  }

  async function seedSampleWorkspace() {
    try {
      await fetch("/api/riskguard/workspace/seed", { method: "POST" });
      alert("✅ Sample demonstration workspace reloaded!");
      location.reload();
    } catch (err) {
      alert("Error: " + err.message);
    }
  }

  // Helper Utilities
  function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.style.display = "none";
  }

  function setupTheme() {
    const toggle = document.getElementById("rg-theme-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        toggle.innerText = next === "dark" ? "🌙" : "☀️";
      });
    }
  }

  function escapeHTML(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  return {
    init,
    switchView,
    openQuickCreateRisk,
    submitQuickRisk,
    nextWizardStep,
    prevWizardStep,
    setWizardLikelihood,
    setWizardImpact,
    setWizardTreatment,
    runLocalMachineInspection,
    openEscalateModal,
    submitEscalate,
    markVulnPatched,
    selectFramework,
    saveSettings,
    triggerBackup,
    clearSampleWorkspace,
    seedSampleWorkspace,
    closeModal,
    handleActionItem
  };
})();

document.addEventListener("DOMContentLoaded", RiskGuard.init);
