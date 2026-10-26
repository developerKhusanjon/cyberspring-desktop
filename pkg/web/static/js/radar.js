/**
 * CyberSpring — Radial Threat Defense Radar HUD (Image 3 Inspiration)
 * Renders high-precision orbital arcs, concentric radar rings, and telemetry nodes.
 */

class ThreatRadar {
  constructor(canvasId, containerId) {
    this.canvas = document.getElementById(canvasId);
    this.container = document.getElementById(containerId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');

    this.blockedPercent = 68;
    this.nodes = [];
    this.pulsePhase = 0;
    this.animationId = null;

    this.initSize();
    window.addEventListener('resize', () => {
      this.initSize();
      this.render();
    });
  }

  initSize() {
    const rect = this.container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.width = rect.width || 750;
    this.height = 380;

    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;

    this.ctx.scale(dpr, dpr);
    this.centerX = this.width / 2;
    this.centerY = this.height - 20;
  }

  setTelemetry(nodes, blockedPercent) {
    this.nodes = nodes || [];
    if (blockedPercent !== undefined) {
      this.blockedPercent = blockedPercent;
    }
    this.renderNodeElements();
    this.startAnimation();
  }

  startAnimation() {
    const loop = () => {
      this.pulsePhase += 0.02;
      this.render();
      this.animationId = requestAnimationFrame(loop);
    };
    if (this.animationId) cancelAnimationFrame(this.animationId);
    this.animationId = requestAnimationFrame(loop);
  }

  render() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    const cx = this.centerX;
    const cy = this.centerY;

    // 1. Outer Concentric Orbital Arcs
    const radii = [320, 260, 200, 140];

    radii.forEach((r, idx) => {
      ctx.beginPath();
      ctx.arc(cx, cy, r, Math.PI, 0, false);
      ctx.strokeStyle = `rgba(203, 213, 225, ${0.45 - idx * 0.08})`;
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 6]);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    // 2. Decorative Outer Tick Ring (Radar Graduation)
    const tickRadius = 310;
    const tickCount = 60;
    for (let i = 0; i <= tickCount; i++) {
      const angle = Math.PI + (i / tickCount) * Math.PI;
      const x1 = cx + Math.cos(angle) * tickRadius;
      const y1 = cy + Math.sin(angle) * tickRadius;
      const len = i % 5 === 0 ? 8 : 4;
      const x2 = cx + Math.cos(angle) * (tickRadius - len);
      const y2 = cy + Math.sin(angle) * (tickRadius - len);

      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = i % 5 === 0 ? 'rgba(244, 63, 94, 0.4)' : 'rgba(203, 213, 225, 0.3)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // 3. Central Solid Crimson Arc (68% Threats Blocked)
    const innerRadius = 130;
    const arcThickness = 28;

    // Background track
    ctx.beginPath();
    ctx.arc(cx, cy, innerRadius, Math.PI, 0, false);
    ctx.lineWidth = arcThickness;
    ctx.strokeStyle = 'rgba(241, 245, 249, 0.6)';
    ctx.stroke();

    // Active Gradient Arc
    const startAngle = Math.PI;
    const endAngle = Math.PI + (this.blockedPercent / 100) * Math.PI;

    const grad = ctx.createLinearGradient(cx - innerRadius, cy, cx + innerRadius, cy);
    grad.addColorStop(0, '#ff1744');
    grad.addColorStop(0.5, '#e10050');
    grad.addColorStop(1, '#ff5252');

    ctx.beginPath();
    ctx.arc(cx, cy, innerRadius, startAngle, endAngle, false);
    ctx.lineWidth = arcThickness;
    ctx.strokeStyle = grad;
    ctx.lineCap = 'round';
    ctx.shadowColor = 'rgba(255, 23, 68, 0.45)';
    ctx.shadowBlur = 16;
    ctx.stroke();

    // Reset shadow
    ctx.shadowColor = 'transparent';
    ctx.shadowBlur = 0;

    // 4. Subtle Animated Pulse Ripple
    const rippleRadius = 140 + (Math.sin(this.pulsePhase) + 1) * 20;
    ctx.beginPath();
    ctx.arc(cx, cy, rippleRadius, Math.PI, 0, false);
    ctx.strokeStyle = `rgba(255, 23, 68, ${0.15 - (Math.sin(this.pulsePhase) + 1) * 0.05})`;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  renderNodeElements() {
    // Remove old dynamic node badges if any
    const existing = this.container.querySelectorAll('.telemetry-node');
    existing.forEach((el) => el.remove());

    const cx = this.centerX;
    const cy = this.centerY;

    // Distance mapped to tier
    const tierDistance = { 1: 195, 2: 255, 3: 310 };

    this.nodes.forEach((node) => {
      const radius = tierDistance[node.orbitTier] || 250;
      // Angle in radians (180deg is left, 90deg is top, 0deg is right)
      const rad = (node.orbitAngle * Math.PI) / 180;
      const x = cx - Math.cos(rad) * radius;
      const y = cy - Math.sin(rad) * radius;

      const el = document.createElement('div');
      el.className = 'telemetry-node';
      el.style.left = `${x - 60}px`;
      el.style.top = `${y - 20}px`;

      const warningIcon = node.hasWarning ? '<span class="node-warning-flag">⚠️</span>' : '';

      el.innerHTML = `
        <div class="node-icon ${node.id}">${this.getVendorLogo(node.id)}</div>
        <div class="node-info">
          <div class="node-title">${node.name} ${warningIcon}</div>
          <div class="node-events">${node.eventCount} events</div>
        </div>
      `;

      el.addEventListener('click', () => {
        if (window.CyberApp) {
          window.CyberApp.showTelemetryDetails(node);
        }
      });

      this.container.appendChild(el);
    });
  }

  getVendorLogo(id) {
    const svgs = {
      okta: '🔵',
      azure: '🔷',
      aws: '🟧',
      gcp: '🌈',
      github: '🐙',
      fortinet: '🛡️',
      cisco: '📡',
    };
    return svgs[id] || '⚡';
  }
}

window.ThreatRadar = ThreatRadar;
