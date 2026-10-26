/**
 * CyberSpring — SAST Source Code Weak Point & Vulnerability Scanner Controller
 * Interactively audits repositories, highlights contextual snippets, applies safe auto-remediation patches, and reverts backups.
 */

class SASTScannerUI {
  constructor() {
    this.targetPathInput = document.getElementById('sastTargetPath');
    this.searchInput = document.getElementById('sastSearchInput');
    this.scanBtn = document.getElementById('sastScanBtn');
    this.sarifBtn = document.getElementById('sastSarifBtn');
    this.htmlReportBtn = document.getElementById('sastHtmlReportBtn');

    this.findingsListContainer = document.getElementById('sastFindingsList');
    this.detailContainer = document.getElementById('sastDetailView');

    this.critCountEl = document.getElementById('sastCritCount');
    this.highCountEl = document.getElementById('sastHighCount');
    this.medCountEl = document.getElementById('sastMedCount');
    this.filesCountEl = document.getElementById('sastFilesCount');
    this.durationEl = document.getElementById('sastDuration');
    this.navBadge = document.getElementById('sastNavBadge');
    this.filterAllCount = document.getElementById('filterAllCount');

    this.currentFindings = [];
    this.activeFilter = 'ALL';
    this.searchQuery = '';
    this.selectedFinding = null;

    this.bindEvents();
    // Auto-run initial scan on sample app
    this.runScan('test_samples/vulnerable_app');
  }

  bindEvents() {
    if (this.scanBtn) {
      this.scanBtn.addEventListener('click', () => {
        const path = this.targetPathInput ? this.targetPathInput.value.trim() : '';
        this.runScan(path || '.');
      });
    }

    if (this.targetPathInput) {
      this.targetPathInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.runScan(this.targetPathInput.value.trim() || '.');
        }
      });
    }

    if (this.searchInput) {
      this.searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderFindingsList();
      });
    }

    if (this.sarifBtn) {
      this.sarifBtn.addEventListener('click', () => {
        window.open('/api/report/sarif', '_blank');
      });
    }

    if (this.htmlReportBtn) {
      this.htmlReportBtn.addEventListener('click', () => {
        window.open('/api/report/html', '_blank');
      });
    }

    // Filter pills
    document.querySelectorAll('.sast-filter-pill').forEach((pill) => {
      pill.addEventListener('click', (e) => {
        document.querySelectorAll('.sast-filter-pill').forEach((p) => p.classList.remove('active'));
        e.target.classList.add('active');
        this.activeFilter = e.target.getAttribute('data-filter') || 'ALL';
        this.renderFindingsList();
      });
    });
  }

  setTarget(path) {
    if (this.targetPathInput) {
      this.targetPathInput.value = path;
    }
    this.runScan(path);
  }

  async runScan(path) {
    const target = path || (this.targetPathInput ? this.targetPathInput.value.trim() : 'test_samples/vulnerable_app');

    if (this.scanBtn) {
      this.scanBtn.disabled = true;
      this.scanBtn.textContent = 'Auditing...';
    }

    try {
      const res = await fetch('/api/sast/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: target }),
      });
      const data = await res.json();
      this.currentFindings = data.findings || [];

      // Update Metric Badges
      if (this.critCountEl) this.critCountEl.textContent = data.criticalCount || 0;
      if (this.highCountEl) this.highCountEl.textContent = data.highCount || 0;
      if (this.medCountEl) this.medCountEl.textContent = data.mediumCount || 0;
      if (this.filesCountEl) this.filesCountEl.textContent = data.scannedFiles || 0;
      if (this.durationEl) this.durationEl.textContent = `${data.durationMs}ms`;
      if (this.navBadge) this.navBadge.textContent = `${data.findingsCount} Vulns`;
      if (this.filterAllCount) this.filterAllCount.textContent = data.findingsCount || 0;

      this.renderFindingsList();

      if (this.currentFindings.length > 0) {
        this.renderFindingDetail(this.currentFindings[0]);
      } else {
        if (this.detailContainer) {
          this.detailContainer.innerHTML = `
            <div class="detail-header-card" style="text-align: center; padding: 40px;">
              <div style="font-size: 32px; margin-bottom: 12px;">✅</div>
              <h2 style="font-size: 18px; color: #10b981;">No Security Weaknesses Discovered</h2>
              <p style="color: var(--text-secondary); margin-top: 6px;">Target codebase passed all active SAST vulnerability patterns.</p>
            </div>
          `;
        }
      }

      if (window.CyberApp) {
        window.CyberApp.showToast(`SAST Scan complete: ${data.findingsCount} security weaknesses identified in ${data.scannedFiles} files.`);
      }
    } catch (e) {
      alert('Scan error: ' + e);
    } finally {
      if (this.scanBtn) {
        this.scanBtn.disabled = false;
        this.scanBtn.textContent = '⚡ Run Vulnerability Audit';
      }
    }
  }

  renderFindingsList() {
    if (!this.findingsListContainer) return;
    this.findingsListContainer.innerHTML = '';

    const filtered = this.currentFindings.filter((f) => {
      // 1. Severity filter
      if (this.activeFilter !== 'ALL' && f.severity !== this.activeFilter) {
        return false;
      }
      // 2. Search query filter
      if (this.searchQuery) {
        const text = `${f.title} ${f.ruleId} ${f.cwe} ${f.filePath} ${f.description}`.toLowerCase();
        if (!text.includes(this.searchQuery)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      this.findingsListContainer.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-muted);">No findings match the active criteria.</div>`;
      return;
    }

    filtered.forEach((f, idx) => {
      const card = document.createElement('div');
      const isSelected = this.selectedFinding && this.selectedFinding.id === f.id && this.selectedFinding.filePath === f.filePath;
      card.className = `finding-item-row ${isSelected || (!this.selectedFinding && idx === 0) ? 'active' : ''}`;

      const sevClass = f.severity.toLowerCase();

      card.innerHTML = `
        <div class="finding-row-header">
          <span class="finding-sev-badge ${sevClass}">${f.severity}</span>
          <span class="finding-rule-id">${f.ruleId}</span>
        </div>
        <div class="finding-row-title">${f.title}</div>
        <div class="finding-row-loc">${f.filePath}:${f.lineNumber}</div>
      `;

      card.addEventListener('click', () => {
        document.querySelectorAll('.finding-item-row').forEach((r) => r.classList.remove('active'));
        card.classList.add('active');
        this.selectedFinding = f;
        this.renderFindingDetail(f);
      });

      this.findingsListContainer.appendChild(card);
    });
  }

  renderFindingDetail(f) {
    if (!this.detailContainer || !f) return;
    this.selectedFinding = f;

    const sevClass = f.severity.toLowerCase();

    this.detailContainer.innerHTML = `
      <div class="detail-header-card">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;">
          <div>
            <div style="display: flex; gap: 8px; margin-bottom: 6px;">
              <span class="finding-sev-badge ${sevClass}">${f.severity}</span>
              <span class="detail-tag">${f.cwe}</span>
              <span class="detail-tag">${f.owasp}</span>
            </div>
            <h2 class="detail-title">${f.title}</h2>
          </div>
          <div style="display: flex; gap: 6px;">
            <button class="btn-primary" style="font-size: 11px;" onclick="window.CyberApp.sast.applyPatch('${f.filePath}', ${f.lineNumber}, '${f.ruleId}')">⚡ Apply Auto-Fix</button>
            <button class="btn-secondary" style="font-size: 11px;" onclick="window.CyberApp.sast.revertPatch('${f.filePath}')">↩️ Revert</button>
          </div>
        </div>
        <div class="detail-meta-loc">
          <span>📂 <strong>File:</strong> <code>${f.filePath}</code></span>
          <span style="margin-left: 14px;">📍 <strong>Line:</strong> ${f.lineNumber}</span>
          <span style="margin-left: 14px;">🏷️ <strong>Category:</strong> ${f.category}</span>
        </div>
        <p class="detail-desc">${f.description}</p>
      </div>

      <div class="code-snippet-box">
        <div class="snippet-header">Context Snippet (${f.filePath}:${f.lineNumber})</div>
        <pre class="snippet-pre"><code>${this.escapeHtml(f.contextSnippet)}</code></pre>
      </div>

      <div class="remedy-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <div class="remedy-header" style="margin-bottom: 0;">🛡️ Remediation Strategy & Auto-Patch</div>
          <button class="btn-secondary" style="padding: 2px 8px; font-size: 10px;" onclick="window.CyberApp.sast.copyFix('${f.remedyDiff ? this.escapeHtml(f.remedyDiff) : ''}')">📋 Copy Patch</button>
        </div>
        <p style="font-size: 13px; color: #334155; margin-bottom: 10px;">${f.remedy}</p>
        <div class="remedy-diff-title">Automated Remediation Diff:</div>
        <pre class="diff-pre"><code>${this.escapeHtml(f.remedyDiff)}</code></pre>
      </div>
    `;
  }

  async applyPatch(filePath, lineNumber, ruleId) {
    try {
      if (window.CyberApp) window.CyberApp.showToast(`Applying automated security patch for ${ruleId}...`);

      const res = await fetch('/api/sast/apply-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath, lineNumber, ruleId }),
      });
      const data = await res.json();

      if (data.patchResult && data.patchResult.success) {
        if (window.CyberApp) {
          window.CyberApp.showToast(`✅ ${data.patchResult.message}`);
        }
        // Refresh scan to reflect resolved vulnerability
        this.runScan(this.targetPathInput ? this.targetPathInput.value.trim() : '');
      } else {
        alert('Patch could not be applied automatically.');
      }
    } catch (e) {
      alert('Error applying patch: ' + e);
    }
  }

  async revertPatch(filePath) {
    try {
      const res = await fetch('/api/sast/revert-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath }),
      });
      const data = await res.json();

      if (data.patchResult && data.patchResult.success) {
        if (window.CyberApp) {
          window.CyberApp.showToast(`✅ ${data.patchResult.message}`);
        }
        // Refresh scan
        this.runScan(this.targetPathInput ? this.targetPathInput.value.trim() : '');
      } else {
        alert('No backup file found to revert.');
      }
    } catch (e) {
      alert('Error reverting patch: ' + e);
    }
  }

  copyFix(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (window.CyberApp) window.CyberApp.showToast('Copied remediation patch diff to clipboard.');
    });
  }

  escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

window.SASTScannerUI = SASTScannerUI;
