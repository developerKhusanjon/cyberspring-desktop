/**
 * CyberSpring — Main Application Orchestrator & State Manager
 * Coordinates navigation, live telemetry radar, incident investigation, SOAR playbooks, and modal workflows.
 */

class CyberSpringApp {
  constructor() {
    this.status = null;
    this.radar = null;
    this.terminal = null;
    this.sast = null;

    this.selectedIncident = null;
    this.selectedNode = null;

    this.initNavigation();
    this.initControllers();
    this.fetchSystemStatus();
    this.fetchPlaybooks();
  }

  initNavigation() {
    const pills = document.querySelectorAll('.nav-pill');
    pills.forEach((pill) => {
      pill.addEventListener('click', () => {
        pills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');

        const targetView = pill.getAttribute('data-view');
        this.switchView(targetView);
      });
    });
  }

  switchView(viewId) {
    document.querySelectorAll('.view-section').forEach((section) => {
      section.classList.remove('active-view');
    });

    const activeSec = document.getElementById(viewId);
    if (activeSec) {
      activeSec.classList.add('active-view');
    }

    // Trigger radar redraw if returning to overview
    if (viewId === 'view-overview' && this.radar) {
      setTimeout(() => {
        this.radar.initSize();
        this.radar.render();
      }, 50);
    }
  }

  initControllers() {
    // 1. Radar
    this.radar = new window.ThreatRadar('radarCanvas', 'radarContainer');

    // 2. Terminal Studio
    this.terminal = new window.TerminalStudio();

    // 3. SAST Scanner
    this.sast = new window.SASTScannerUI();
  }

  async fetchSystemStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      this.status = data;

      // Update Hero Metrics
      const blockedEl = document.getElementById('threatsBlockedVal');
      if (blockedEl) blockedEl.textContent = `${data.threatsBlockedPercent}%`;

      const incidentEl = document.getElementById('openIncidentsCount');
      if (incidentEl) incidentEl.textContent = data.openIncidentsTotal;

      const trendEl = document.getElementById('incidentTrendPercent');
      if (trendEl) trendEl.textContent = `+${data.incidentTrendPercent}%`;

      const critChip = document.getElementById('chipCritCount');
      if (critChip) critChip.textContent = data.highSeverityCount;

      const medChip = document.getElementById('chipMedCount');
      if (medChip) medChip.textContent = data.mediumSeverityCount;

      const lowChip = document.getElementById('chipLowCount');
      if (lowChip) lowChip.textContent = data.lowSeverityCount;

      // Feed radar with cloud/identity nodes
      if (this.radar && data.integrations) {
        this.radar.setTelemetry(data.integrations, data.threatsBlockedPercent);
      }

      // Populate Incident list and Alerts stream
      this.renderIncidents(data.incidents);
      this.renderAlertsStream(data.incidents);
    } catch (e) {
      console.error('Failed fetching status:', e);
    }
  }

  async fetchPlaybooks() {
    try {
      const res = await fetch('/api/playbooks');
      const playbooks = await res.json();
      this.renderPlaybooks(playbooks);
      this.renderExecutionsGrid(playbooks);
    } catch (e) {
      console.error('Failed fetching playbooks:', e);
    }
  }

  renderPlaybooks(list) {
    const container = document.getElementById('playbooksListContainer');
    if (!container) return;
    container.innerHTML = '';

    list.forEach((pb) => {
      const item = document.createElement('div');
      item.className = 'playbook-item';

      const isCompleted = pb.status === 'Completed';
      const isRunning = pb.status === 'Running';
      const iconClass = isCompleted ? 'completed' : isRunning ? 'running' : '';
      const iconChar = isCompleted ? '✓' : isRunning ? '⚡' : '▶';

      const metaText = isCompleted
        ? `Completed • ${pb.execCount} times`
        : isRunning
        ? `Running • ${pb.activeItems} active`
        : `Idle • Last: ${new Date(pb.lastRun).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

      item.innerHTML = `
        <div class="playbook-info-left">
          <div class="playbook-status-icon ${iconClass}">${iconChar}</div>
          <div>
            <div class="playbook-name">${pb.name}</div>
            <div class="playbook-meta">${metaText}</div>
          </div>
        </div>
        <button class="playbook-action-btn" onclick="window.CyberApp.triggerPlaybook('${pb.id}')">
          ${isRunning ? 'Active' : 'Trigger'}
        </button>
      `;

      container.appendChild(item);
    });
  }

  renderExecutionsGrid(list) {
    const grid = document.getElementById('executionsPlaybookGrid');
    if (!grid) return;
    grid.innerHTML = '';

    list.forEach((pb) => {
      const card = document.createElement('div');
      card.className = 'glass-widget';
      card.style.background = '#ffffff';

      const isRunning = pb.status === 'Running';
      const badgeBg = isRunning ? '#e0f2fe' : '#e8f5e9';
      const badgeColor = isRunning ? '#0284c7' : '#10b981';

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
          <div>
            <strong style="font-size: 15px; color: #0f172a;">${pb.name}</strong>
            <div style="font-size: 11px; font-family: var(--font-mono); color: #64748b; margin-top: 2px;">ID: ${pb.id}</div>
          </div>
          <span class="asset-badge" style="background: ${badgeBg}; color: ${badgeColor};">
            ${isRunning ? '⚡ Running' : '✓ ' + pb.status}
          </span>
        </div>
        <p style="font-size: 12.5px; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.5;">${pb.description}</p>
        <div style="font-size: 11px; font-family: var(--font-mono); color: #64748b; margin-bottom: 14px;">Target: ${pb.target} • Executions: ${pb.execCount}</div>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <button class="btn-secondary" style="font-size: 11px;" onclick="window.CyberApp.inspectPlaybookLogs('${pb.id}')">📜 View Execution Logs</button>
          <button class="btn-primary" style="font-size: 11px;" onclick="window.CyberApp.triggerPlaybook('${pb.id}')">⚡ Trigger Playbook</button>
        </div>
      `;

      grid.appendChild(card);
    });
  }

  async triggerPlaybook(id) {
    try {
      this.showToast(`Initiating SOAR Playbook: ${id}...`);
      const res = await fetch('/api/playbooks/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id, target: 'SOC Perimeter Gateway' }),
      });
      const updated = await res.json();
      this.showToast(`✅ Playbook ${updated.name} executed successfully.`);
      this.fetchPlaybooks();
    } catch (e) {
      alert('Error triggering playbook: ' + e);
    }
  }

  renderIncidents(incidents) {
    const listEl = document.getElementById('incidentsFeedList');
    if (!listEl || !incidents) return;
    listEl.innerHTML = '';

    incidents.forEach((inc) => {
      const row = document.createElement('div');
      row.className = 'incident-feed-row';
      const sevClass = inc.severity.toLowerCase();

      row.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="finding-sev-badge ${sevClass}">${inc.severity}</span>
          <span style="font-size: 11px; color: var(--text-muted);">${inc.createdAt}</span>
        </div>
        <div style="font-weight: 600; font-size: 13px; margin: 4px 0; color: #0f172a;">${inc.title}</div>
        <div style="font-size: 11px; color: var(--text-secondary);">Source: ${inc.source} • Status: <strong>${inc.status}</strong></div>
      `;

      row.addEventListener('click', () => {
        this.openIncidentModal(inc);
      });

      listEl.appendChild(row);
    });
  }

  renderAlertsStream(incidents) {
    const container = document.getElementById('alertsStreamContainer');
    if (!container || !incidents) return;
    container.innerHTML = '';

    incidents.forEach((inc) => {
      const card = document.createElement('div');
      card.className = 'playbook-item';
      card.style.background = 'rgba(255,255,255,0.85)';
      card.style.color = '#0f172a';
      card.style.borderLeft = inc.severity === 'High' ? '4px solid #ef4444' : inc.severity === 'Medium' ? '4px solid #f59e0b' : '4px solid #3b82f6';

      card.innerHTML = `
        <div style="flex: 1; cursor: pointer;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="finding-sev-badge ${inc.severity.toLowerCase()}">${inc.severity}</span>
            <span style="font-weight: 700; font-size: 14px;">[${inc.ID}] ${inc.title}</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Source: ${inc.source} · Asset: <code>${inc.asset || 'N/A'}</code> · Status: <strong>${inc.status}</strong></div>
        </div>
        <div style="display: flex; gap: 6px;">
          <button class="btn-secondary" style="font-size: 11px;" onclick="window.CyberApp.openIncidentModalFromId('${inc.ID}')">Investigate</button>
          <button class="btn-primary" style="font-size: 11px;" onclick="window.CyberApp.performIncidentAction('${inc.ID}', 'contain')">Contain</button>
        </div>
      `;

      container.appendChild(card);
    });
  }

  openIncidentModal(inc) {
    this.selectedIncident = inc;
    const modal = document.getElementById('incidentModal');
    const titleEl = document.getElementById('incidentModalTitle');
    const contentEl = document.getElementById('incidentModalContent');

    if (!modal || !contentEl) return;

    if (titleEl) titleEl.textContent = `[${inc.ID}] ${inc.title}`;

    const sevClass = inc.severity.toLowerCase();

    contentEl.innerHTML = `
      <div style="display: flex; gap: 8px; margin-bottom: 14px;">
        <span class="finding-sev-badge ${sevClass}">${inc.severity} Severity</span>
        <span class="detail-tag">Status: ${inc.status}</span>
        <span class="detail-tag">${inc.createdAt}</span>
      </div>
      <p style="margin-bottom: 14px; color: #1e293b; font-size: 14px;">${inc.description || inc.title}</p>
      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; margin-bottom: 14px; font-size: 12px;">
        <div><strong>Affected Asset:</strong> <code>${inc.asset || 'Internal Network'}</code></div>
        <div style="margin-top: 4px;"><strong>Threat Indicator / IP:</strong> <code>${inc.attackerIP || 'N/A'}</code></div>
        <div style="margin-top: 4px;"><strong>Telemetry Feed:</strong> ${inc.source}</div>
      </div>
      <div style="font-weight: 700; font-size: 12px; color: #475569; text-transform: uppercase; margin-bottom: 6px;">Recommended SOAR Response:</div>
      <p style="font-size: 12px; color: #64748b;">Execute host containment via EDR and drop attacker subnet at the perimeter edge firewall.</p>
    `;

    // Wire action buttons
    const triageBtn = document.getElementById('incidentTriageBtn');
    if (triageBtn) {
      triageBtn.onclick = () => this.performIncidentAction(inc.ID, 'triage');
    }
    const isolateBtn = document.getElementById('incidentIsolateBtn');
    if (isolateBtn) {
      isolateBtn.onclick = () => this.performIncidentAction(inc.ID, 'contain');
    }

    modal.classList.add('active');
  }

  openIncidentModalFromId(id) {
    if (this.status && this.status.incidents) {
      const inc = this.status.incidents.find((i) => i.ID === id);
      if (inc) this.openIncidentModal(inc);
    }
  }

  async performIncidentAction(id, action) {
    try {
      this.showToast(`Executing action '${action}' for incident ${id}...`);
      const res = await fetch('/api/incidents/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id, action: action }),
      });
      const data = await res.json();
      this.closeModals();
      this.showToast(`Incident ${id} successfully updated to status: ${data.incident.status}.`);
      this.fetchSystemStatus();
      this.fetchPlaybooks();
    } catch (e) {
      alert('Error updating incident: ' + e);
    }
  }

  showTelemetryDetails(node) {
    this.selectedNode = node;
    const modal = document.getElementById('telemetryModal');
    const titleEl = document.getElementById('telemetryModalTitle');
    const contentEl = document.getElementById('telemetryModalContent');
    const actionBtn = document.getElementById('telemetryActionBtn');

    if (!modal || !contentEl) return;

    if (titleEl) titleEl.textContent = `Perimeter Telemetry Node: ${node.name}`;

    let logsHtml = '';
    if (node.recentLogs && node.recentLogs.length > 0) {
      logsHtml = node.recentLogs.map((l) => `<div class="log-stream-entry">${l}</div>`).join('');
    } else {
      logsHtml = `<div class="log-stream-entry">${node.eventCount} telemetry events streaming nominally.</div>`;
    }

    contentEl.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <div>
          <strong style="font-size: 16px;">${node.name}</strong>
          <div style="font-size: 12px; color: var(--text-secondary);">${node.category}</div>
        </div>
        <span class="finding-sev-badge ${node.hasWarning ? 'high' : 'low'}">
          ${node.hasWarning ? '⚠️ Warning' : '✅ Healthy'}
        </span>
      </div>
      <p style="font-size: 13px; margin-bottom: 10px;">Ingested <strong>${node.eventCount} security events</strong> across orbital tier ${node.orbitTier}.</p>
      <div style="font-weight: 700; font-size: 11px; text-transform: uppercase; color: #475569;">Live Telemetry Stream:</div>
      <div class="log-stream-box">
        ${logsHtml}
      </div>
    `;

    if (actionBtn) {
      actionBtn.onclick = () => {
        this.closeModals();
        this.triggerPlaybook('pb-ipblock');
      };
    }

    modal.classList.add('active');
  }

  inspectPlaybookLogs(id) {
    this.showToast(`Loading forensic execution history for ${id}...`);
    // Switch to terminal CLI and execute soar list
    document.querySelector('[data-view=view-terminal]').click();
    if (this.terminal) {
      this.terminal.switchTerminalMode('cli');
      this.terminal.runCliPreset(`soar list`);
    }
  }

  openCustomRuleModal() {
    const modal = document.getElementById('customRuleModal');
    if (modal) modal.classList.add('active');
  }

  async submitCustomRule() {
    const id = document.getElementById('ruleFormId').value.trim();
    const name = document.getElementById('ruleFormName').value.trim();
    const severity = document.getElementById('ruleFormSeverity').value;
    const cwe = document.getElementById('ruleFormCWE').value.trim();
    const regex = document.getElementById('ruleFormRegex').value.trim();
    const remedy = document.getElementById('ruleFormRemedy').value.trim();

    if (!id || !name || !regex) {
      alert('Please fill in Rule ID, Title, and Regex pattern.');
      return;
    }

    try {
      const res = await fetch('/api/sast/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id,
          name,
          category: 'Custom Rule',
          severity,
          cwe: cwe || 'CWE-Other',
          owasp: 'A05:2021-Security Misconfiguration',
          regex,
          languages: ['all'],
          remedy: remedy || 'Remediate according to security guidelines.',
          description: name,
        }),
      });

      if (!res.ok) {
        const txt = await res.text();
        alert('Error adding rule: ' + txt);
        return;
      }

      this.closeModals();
      this.showToast(`✅ Custom SAST Rule ${id} registered successfully.`);
      if (this.sast) this.sast.runScan();
    } catch (e) {
      alert('Failed registering rule: ' + e);
    }
  }

  closeModals() {
    document.querySelectorAll('.cyber-modal-backdrop').forEach((m) => m.classList.remove('active'));
  }

  filterIncidentsBySev(sev) {
    document.querySelector('[data-view=view-alerts]').click();
    this.showToast(`Filtered alert signals by ${sev} severity.`);
  }

  async shutdownServer() {
    if (!confirm('🛑 Are you sure you want to shut down the CyberSpring server?')) return;
    try {
      this.showToast('🛑 Shutting down CyberSpring server...');
      await fetch('/api/shutdown', { method: 'POST' });
      setTimeout(() => {
        document.body.innerHTML = `
          <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #f8fafc; background: #090d16; text-align: center; padding: 20px;">
            <div style="font-size: 52px; margin-bottom: 16px;">🛑</div>
            <h1 style="font-size: 26px; margin-bottom: 8px; color: #f87171;">CyberSpring Server is Down</h1>
            <p style="color: #94a3b8; font-size: 15px; max-width: 500px; line-height: 1.5;">The controlling center server process has been safely stopped.</p>
            <div style="margin-top: 24px; padding: 14px 24px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px;">
              <p style="color: #cbd5e1; font-size: 13px; margin-bottom: 6px;">To bring the server back up, run:</p>
              <code style="font-family: monospace; font-size: 14px; color: #38bdf8; font-weight: bold;">make up &nbsp;OR&nbsp; ./up.sh</code>
            </div>
          </div>
        `;
      }, 400);
    } catch (e) {
      alert('Shutdown signal sent: ' + e);
    }
  }

  showToast(msg) {
    const toast = document.getElementById('globalToast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 3800);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.CyberApp = new CyberSpringApp();
});
