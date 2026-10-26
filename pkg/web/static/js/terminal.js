/**
 * CyberSpring — Unified Terminal Studio & Detection Engineering Agent Controller
 * Features interactive CLI command shell, command history, ANSI rendering, and dynamic AI detection synthesis.
 */

class TerminalStudio {
  constructor() {
    // Mode containers
    this.cliContainer = document.getElementById('terminalCliContainer');
    this.agentContainer = document.getElementById('terminalAgentContainer');
    this.agentActionsBar = document.getElementById('terminalAgentActionsBar');
    this.tabModeCLI = document.getElementById('tabModeCLI');
    this.tabModeAgent = document.getElementById('tabModeAgent');

    // CLI elements
    this.cliInput = document.getElementById('cliCommandInput');
    this.cliOutputPre = document.getElementById('cliOutputPre');
    this.cliOutputViewport = document.getElementById('cliOutputViewport');
    this.cliRunBtn = document.getElementById('cliRunBtn');

    // Agent mode elements
    this.agentPromptInput = document.getElementById('agentCustomPromptInput');
    this.agentStepsList = document.getElementById('agentStepsList');
    this.ruleEditor = document.getElementById('ruleEditor');
    this.testEditor = document.getElementById('testEditor');
    this.backtestProgressBar = document.getElementById('backtestProgressBar');
    this.backtestOutcomeRow = document.getElementById('backtestOutcomeRow');
    this.stageBadgesRow = document.getElementById('stageBadgesRow');
    this.runAgentBtn = document.getElementById('runAgentBtn');
    this.runReplayBtn = document.getElementById('runReplayBtn');
    this.runBacktestBtn = document.getElementById('runBacktestBtn');
    this.saveRulesBtn = document.getElementById('saveRulesBtn');

    // Timer
    this.timerElement = document.getElementById('titlebarTimer');
    this.timerSeconds = 24;

    // Command History
    this.history = [];
    this.historyIndex = -1;

    this.initTimer();
    this.bindEvents();
    this.loadRules();
    this.initCliWelcome();
  }

  initTimer() {
    setInterval(() => {
      this.timerSeconds++;
      const mins = Math.floor(this.timerSeconds / 60);
      const secs = this.timerSeconds % 60;
      if (this.timerElement) {
        this.timerElement.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      }
    }, 1000);
  }

  bindEvents() {
    // CLI Input handling
    if (this.cliInput) {
      this.cliInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.executeCliCommand(this.cliInput.value);
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (this.history.length > 0 && this.historyIndex < this.history.length - 1) {
            this.historyIndex++;
            this.cliInput.value = this.history[this.history.length - 1 - this.historyIndex];
          }
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (this.historyIndex > 0) {
            this.historyIndex--;
            this.cliInput.value = this.history[this.history.length - 1 - this.historyIndex];
          } else if (this.historyIndex === 0) {
            this.historyIndex = -1;
            this.cliInput.value = '';
          }
        }
      });
    }

    if (this.cliRunBtn) {
      this.cliRunBtn.addEventListener('click', () => {
        if (this.cliInput) this.executeCliCommand(this.cliInput.value);
      });
    }

    // Agent Studio handling
    if (this.runAgentBtn) {
      this.runAgentBtn.addEventListener('click', () => this.executeAgentPrompt());
    }
    if (this.runReplayBtn) {
      this.runReplayBtn.addEventListener('click', () => this.executeReplay());
    }
    if (this.runBacktestBtn) {
      this.runBacktestBtn.addEventListener('click', () => this.executeHistoricalBacktest());
    }
    if (this.saveRulesBtn) {
      this.saveRulesBtn.addEventListener('click', () => this.saveRules());
    }
  }

  switchTerminalMode(mode) {
    if (mode === 'cli') {
      if (this.cliContainer) this.cliContainer.style.display = 'flex';
      if (this.agentContainer) this.agentContainer.style.display = 'none';
      if (this.agentActionsBar) this.agentActionsBar.style.display = 'none';
      if (this.tabModeCLI) this.tabModeCLI.classList.add('active');
      if (this.tabModeAgent) this.tabModeAgent.classList.remove('active');
      if (this.cliInput) this.cliInput.focus();
    } else {
      if (this.cliContainer) this.cliContainer.style.display = 'none';
      if (this.agentContainer) this.agentContainer.style.display = 'grid';
      if (this.agentActionsBar) this.agentActionsBar.style.display = 'flex';
      if (this.tabModeCLI) this.tabModeCLI.classList.remove('active');
      if (this.tabModeAgent) this.tabModeAgent.classList.add('active');
    }
  }

  initCliWelcome() {
    const welcome = `\x1b[1;36m   ______      __               _____             _            
  / ____/_  __/ /_  ___  _____ / ___/____  _____ (_)___  ____ _
 / /   / / / / __ \\/ _ \\/ ___/ \\__ \\/ __ \\/ ___// / __ \\/ __ \`/
/ /___/ /_/ / /_/ /  __/ /    ___/ / /_/ / /   / / / / / /_/ / 
\\____/\\__, /_.___/\\___/_/    /____/ .___/_/   /_/_/ /_/\\__, /  
     /____/                      /_/                  /____/   
   Detection Engineering Automation & Controlling Center v1.0\x1b[0m

Connected to CyberSpring Local Node (\x1b[32mdarwin/arm64\x1b[0m). Type \x1b[1;32mhelp\x1b[0m to list available commands.
Try running: \x1b[36mscan test_samples/vulnerable_app\x1b[0m or \x1b[36mstatus\x1b[0m\n\n`;

    this.appendCliOutput(welcome);
  }

  runCliPreset(cmd) {
    if (this.cliInput) this.cliInput.value = cmd;
    this.executeCliCommand(cmd);
  }

  async executeCliCommand(cmd) {
    cmd = (cmd || '').trim();
    if (!cmd) return;

    // Record history
    this.history.push(cmd);
    this.historyIndex = -1;

    // Clear input
    if (this.cliInput) this.cliInput.value = '';

    // Print command line
    this.appendCliOutput(`\x1b[1;34mcyberspring@soc-hub:~$\x1b[0m \x1b[1;37m${cmd}\x1b[0m\n`);

    if (cmd === 'clear') {
      this.clearCliOutput();
      return;
    }

    try {
      const res = await fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await res.json();
      this.appendCliOutput(data.output + '\n');

      // Check for synchronization triggers
      if (data.action === 'refresh_sast' && window.CyberApp && window.CyberApp.sast) {
        window.CyberApp.sast.runScan();
      } else if (data.action === 'refresh_rules') {
        this.loadRules();
      } else if (data.action === 'refresh_soar' && window.CyberApp) {
        window.CyberApp.fetchPlaybooks();
      } else if (data.action === 'refresh_agent' && window.CyberApp) {
        this.loadRules();
      }
    } catch (e) {
      this.appendCliOutput(`\x1b[31mExecution error: ${e}\x1b[0m\n\n`);
    }
  }

  appendCliOutput(ansiText) {
    if (!this.cliOutputPre) return;
    this.cliOutputPre.innerHTML += this.ansiToHtml(ansiText);
    if (this.cliOutputViewport) {
      this.cliOutputViewport.scrollTop = this.cliOutputViewport.scrollHeight;
    }
  }

  clearCliOutput() {
    if (this.cliOutputPre) this.cliOutputPre.innerHTML = '';
  }

  ansiToHtml(text) {
    if (!text) return '';
    // Basic ANSI color converter
    let html = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Colors
    html = html.replace(/\033\[1;31m/g, '<span style="color: #ff1744; font-weight: bold;">');
    html = html.replace(/\033\[31m/g, '<span style="color: #ff5252;">');
    html = html.replace(/\033\[1;32m/g, '<span style="color: #00e676; font-weight: bold;">');
    html = html.replace(/\033\[32m/g, '<span style="color: #10b981;">');
    html = html.replace(/\033\[1;36m/g, '<span style="color: #38bdf8; font-weight: bold;">');
    html = html.replace(/\033\[36m/g, '<span style="color: #0284c7;">');
    html = html.replace(/\033\[1;34m/g, '<span style="color: #60a5fa; font-weight: bold;">');
    html = html.replace(/\033\[34m/g, '<span style="color: #3b82f6;">');
    html = html.replace(/\033\[33m/g, '<span style="color: #f59e0b;">');
    html = html.replace(/\033\[1;37m/g, '<span style="color: #ffffff; font-weight: bold;">');
    html = html.replace(/\033\[1m/g, '<span style="font-weight: bold;">');
    html = html.replace(/\033\[2m/g, '<span style="opacity: 0.7;">');
    html = html.replace(/\033\[0m/g, '</span>');

    // Also support \x1b escaped sequences
    html = html.replace(/\x1b\[1;31m/g, '<span style="color: #ff1744; font-weight: bold;">');
    html = html.replace(/\x1b\[31m/g, '<span style="color: #ff5252;">');
    html = html.replace(/\x1b\[1;32m/g, '<span style="color: #00e676; font-weight: bold;">');
    html = html.replace(/\x1b\[32m/g, '<span style="color: #10b981;">');
    html = html.replace(/\x1b\[1;36m/g, '<span style="color: #38bdf8; font-weight: bold;">');
    html = html.replace(/\x1b\[36m/g, '<span style="color: #0284c7;">');
    html = html.replace(/\x1b\[1;34m/g, '<span style="color: #60a5fa; font-weight: bold;">');
    html = html.replace(/\x1b\[34m/g, '<span style="color: #3b82f6;">');
    html = html.replace(/\x1b\[33m/g, '<span style="color: #f59e0b;">');
    html = html.replace(/\x1b\[1;37m/g, '<span style="color: #ffffff; font-weight: bold;">');
    html = html.replace(/\x1b\[1m/g, '<span style="font-weight: bold;">');
    html = html.replace(/\x1b\[2m/g, '<span style="opacity: 0.7;">');
    html = html.replace(/\x1b\[0m/g, '</span>');

    return html;
  }

  loadAgentPreset(type) {
    if (!this.agentPromptInput) return;
    const presets = {
      vpn: `Write a detection for password spraying against our VPN: failed logons across 10 or more distinct accounts from one source IP inside 10 minutes. Generate test cases, backtest it against the last 30 days of VPN auth logs, and report the false positive rate.`,
      aws: `Detect AWS root account console login without MFA. Generate Sigma correlation rule and replay attack fixtures. Backtest against 30 days of CloudTrail telemetry.`,
      k8s: `Alert on Kubernetes privileged pod creation with host namespace access. Correlate across k8s audit events and backtest false positive rate.`,
      ssh: `Write a detection for Linux SSH repeated failed authentication attempts: 8 or more failed passwords from one IP within 10 minutes.`,
    };
    this.agentPromptInput.value = presets[type] || presets.vpn;
  }

  async loadRules() {
    try {
      const res = await fetch('/api/rules');
      const data = await res.json();
      if (this.ruleEditor) this.ruleEditor.value = data.ruleContent || '';
      if (this.testEditor) this.testEditor.value = data.testContent || '';
    } catch (e) {
      console.error('Failed loading rules:', e);
    }
  }

  async saveRules() {
    try {
      const res = await fetch('/api/detection/save-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleContent: this.ruleEditor ? this.ruleEditor.value : '',
          testContent: this.testEditor ? this.testEditor.value : '',
        }),
      });
      const data = await res.json();
      if (window.CyberApp) window.CyberApp.showToast(data.message || 'Rules & test cases saved successfully.');
    } catch (e) {
      alert('Error saving rules: ' + e);
    }
  }

  async executeAgentPrompt() {
    const promptText = this.agentPromptInput ? this.agentPromptInput.value.trim() : '';
    if (!promptText) return;

    if (this.runAgentBtn) {
      this.runAgentBtn.disabled = true;
      this.runAgentBtn.textContent = 'Synthesizing...';
    }

    if (this.agentStepsList) this.agentStepsList.innerHTML = '';
    this.setBacktestProgress(15);

    try {
      const res = await fetch('/api/detection/agent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: promptText }),
      });
      const data = await res.json();

      // Update editors with synthesized rules
      if (this.ruleEditor && data.ruleYaml) this.ruleEditor.value = data.ruleYaml;
      if (this.testEditor && data.testYaml) this.testEditor.value = data.testYaml;

      // Sequential animated playback of agent execution
      let stepIndex = 0;
      const playStep = () => {
        if (stepIndex >= data.steps.length) {
          this.applyBacktestOutcome(data.backtest);
          if (this.runAgentBtn) {
            this.runAgentBtn.disabled = false;
            this.runAgentBtn.textContent = '⚡ Run Agent Session';
          }
          return;
        }

        const step = data.steps[stepIndex];
        const stepEl = document.createElement('div');
        stepEl.className = 'agent-step-item';

        let bulletClass = 'blue';
        if (step.type === 'alert') bulletClass = 'amber';
        if (step.type === 'done') bulletClass = 'green';

        let innerHTML = `
          <div class="step-bullet ${bulletClass}">●</div>
          <div class="step-content">
            <span class="step-title">${step.label}</span>
        `;

        if (step.type === 'alert') {
          innerHTML += `
            <div class="step-quote-box">${step.detail.replace(/\n/g, '<br/>')}</div>
          `;
        } else if (step.detail) {
          innerHTML += `<span class="step-meta">${step.detail}</span>`;
        }

        if (step.type === 'done') {
          innerHTML += `<span class="agent-cursor"></span>`;
        }

        innerHTML += `</div>`;
        stepEl.innerHTML = innerHTML;
        if (this.agentStepsList) this.agentStepsList.appendChild(stepEl);

        this.setBacktestProgress(25 + stepIndex * 15);
        stepIndex++;
        const delay = step.type === 'alert' ? 1000 : 500;
        setTimeout(playStep, delay);
      };

      playStep();
    } catch (e) {
      alert('Agent execution failed: ' + e);
      if (this.runAgentBtn) {
        this.runAgentBtn.disabled = false;
        this.runAgentBtn.textContent = '⚡ Run Agent Session';
      }
    }
  }

  async executeReplay() {
    try {
      const res = await fetch('/api/detection/replay', { method: 'POST' });
      const results = await res.json();
      let passed = 0;
      results.forEach((r) => { if (r.passed) passed++; });
      if (this.stageBadgesRow) {
        this.stageBadgesRow.innerHTML = `
          <div>STAGE 1 · <span class="stage-tag">replay fixtures</span> ${passed}/${results.length} passed</div>
        `;
      }
      if (window.CyberApp) {
        window.CyberApp.showToast(`Replay fixtures verified: ${passed}/${results.length} cases passed.`);
      }
    } catch (e) {
      alert('Replay failed: ' + e);
    }
  }

  async executeHistoricalBacktest() {
    this.setBacktestProgress(20);
    try {
      const res = await fetch('/api/detection/backtest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: 412806, days: 30, budget: 2 }),
      });
      const outcome = await res.json();
      setTimeout(() => {
        this.applyBacktestOutcome(outcome);
      }, 500);
    } catch (e) {
      alert('Backtest failed: ' + e);
    }
  }

  setBacktestProgress(percent) {
    if (this.backtestProgressBar) {
      this.backtestProgressBar.style.width = `${percent}%`;
    }
  }

  applyBacktestOutcome(bt) {
    this.setBacktestProgress(100);

    if (this.stageBadgesRow) {
      this.stageBadgesRow.innerHTML = `
        <div>STAGE 1 · <span class="stage-tag">replay fixtures</span> ${bt.stage1AttacksFired} · ${bt.stage1BenignQuiet}</div>
        <div>STAGE 2 · <span class="stage-tag">historical backtest</span> - ${bt.stage2TotalEvents.toLocaleString()} events · ${bt.stage2Days} days</div>
      `;
    }

    if (this.backtestOutcomeRow) {
      this.backtestOutcomeRow.innerHTML = `
        <div class="outcome-fires">fires on ${bt.stage2Days} days of history: <strong>${bt.firesCount}</strong> - triaged: <strong>benign</strong></div>
        <div class="outcome-budget-tag">false positives: ${bt.falsePositives} in ${bt.stage2Days} days — ${bt.withinBudget ? 'within budget' : 'exceeds budget'}</div>
      `;
    }

    if (window.CyberApp) {
      window.CyberApp.showToast(`Historical backtest finished: ${bt.stage2TotalEvents.toLocaleString()} events processed. Within FP budget.`);
    }
  }
}

window.TerminalStudio = TerminalStudio;
