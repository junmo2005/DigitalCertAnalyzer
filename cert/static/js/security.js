// ====================== tech-effects.js 合并内容开始 ======================
/**
 * 证链智审 - 科技风特效库 (jiejoe风格增强版)
 * 特效：旋转笑脸徽章 / 3D动态线框三角形
 */

// ==================== 粒子系统 ====================
class ParticleSystem {
    constructor(canvas, options = {}) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.particles = [];
        this.options = {
            count: options.count || 80,
            color: options.color || '#1A5F4A',
            connectionDistance: options.connectionDistance || 120,
            speed: options.speed || 0.5,
            ...options
        };
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.init();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    init() {
        this.particles = [];
        for (let i = 0; i < this.options.count; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * this.options.speed,
                vy: (Math.random() - 0.5) * this.options.speed,
                size: Math.random() * 2 + 0.5,
                opacity: Math.random() * 0.5 + 0.2
            });
        }
    }

    update() {
        this.particles.forEach(p => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0 || p.x > this.canvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > this.canvas.height) p.vy *= -1;
        });
    }

    draw() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        for (let i = 0; i < this.particles.length; i++) {
            for (let j = i + 1; j < this.particles.length; j++) {
                const dx = this.particles[i].x - this.particles[j].x;
                const dy = this.particles[i].y - this.particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < this.options.connectionDistance) {
                    this.ctx.beginPath();
                    this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
                    this.ctx.lineTo(this.particles[j].x, this.particles[j].y);
                    const alpha = 0.1 * (1 - dist / this.options.connectionDistance);
                    this.ctx.strokeStyle = this.hexToRgba(this.options.color, alpha);
                    this.ctx.lineWidth = 0.5;
                    this.ctx.stroke();
                }
            }
        }

        this.particles.forEach(p => {
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            this.ctx.fillStyle = this.hexToRgba(this.options.color, p.opacity);
            this.ctx.fill();
        });
    }

    hexToRgba(hex, alpha) {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    animate() {
        this.update();
        this.draw();
        requestAnimationFrame(() => this.animate());
    }
}

// ==================== 旋转笑脸徽章特效 ====================
class CircularTextBadge {
    constructor(container, options = {}) {
        this.container = typeof container === 'string' ? document.querySelector(container) : container;
        this.options = {
            text: options.text || 'SECURITY ANALYSIS • CERTIFICATE GUARD • ',
            size: options.size || 120,
            duration: options.duration || 20,
            color: options.color || '#1A5F4A',
            smileyColor: options.smileyColor || '#1A5F4A',
            fontSize: options.fontSize || 10,
            letterSpacing: options.letterSpacing || 4,
            dotColor: options.dotColor || '#4A8C78',
            ...options
        };
        this.angle = 0;
        this.animationId = null;
        this.svg = null;
        this.textPath = null;
        this.init();
    }

    init() {
        if (!this.container) return;
        const s = this.options.size;
        const r = s / 2 - 12;

        this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        this.svg.setAttribute('width', s);
        this.svg.setAttribute('height', s);
        this.svg.setAttribute('viewBox', `0 0 ${s} ${s}`);
        const rotationCSS = this.options.selfRotation
            ? `animation: badgeSelfRotate ${this.options.duration * 2}s linear infinite;`
            : '';
        this.svg.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            overflow: visible;
            pointer-events: none;
            ${rotationCSS}
        `;

        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const pathId = `circlePath_${Math.random().toString(36).substr(2, 9)}`;
        path.setAttribute('id', pathId);
        path.setAttribute('d', this.describeArc(s / 2, s / 2, r, 0, 360));
        path.style.fill = 'none';
        defs.appendChild(path);
        this.svg.appendChild(defs);

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('fill', this.options.color);
        text.setAttribute('font-size', this.options.fontSize);
        text.setAttribute('font-family', "'Inter', -apple-system, sans-serif");
        text.setAttribute('font-weight', '700');
        text.setAttribute('letter-spacing', this.options.letterSpacing);
        text.style.textTransform = 'uppercase';

        this.textPath = document.createElementNS('http://www.w3.org/2000/svg', 'textPath');
        this.textPath.setAttribute('href', `#${pathId}`);
        this.textPath.setAttribute('startOffset', '0%');
        this.textPath.textContent = this.options.text;
        text.appendChild(this.textPath);
        this.svg.appendChild(text);

        const centerG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        centerG.style.cssText = `transform-origin: center;`;

        for (let i = 0; i < 12; i++) {
            const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            const angle = (i / 12) * Math.PI * 2;
            const dotR = 26;
            dot.setAttribute('cx', s / 2 + Math.cos(angle) * dotR);
            dot.setAttribute('cy', s / 2 + Math.sin(angle) * dotR);
            dot.setAttribute('r', i % 2 === 0 ? 1.5 : 1);
            dot.setAttribute('fill', this.options.dotColor);
            dot.setAttribute('opacity', i % 2 === 0 ? '0.6' : '0.3');
            centerG.appendChild(dot);
        }

        const outerRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        outerRing.setAttribute('cx', s / 2);
        outerRing.setAttribute('cy', s / 2);
        outerRing.setAttribute('r', 32);
        outerRing.setAttribute('fill', 'none');
        outerRing.setAttribute('stroke', this.options.smileyColor);
        outerRing.setAttribute('stroke-width', '0.8');
        outerRing.setAttribute('opacity', '0.2');
        outerRing.setAttribute('stroke-dasharray', '3 3');
        centerG.appendChild(outerRing);

        const glowCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        glowCircle.setAttribute('cx', s / 2);
        glowCircle.setAttribute('cy', s / 2);
        glowCircle.setAttribute('r', 22);
        glowCircle.setAttribute('fill', this.options.smileyColor);
        glowCircle.setAttribute('opacity', '0.06');
        glowCircle.setAttribute('filter', 'blur(4px)');
        centerG.appendChild(glowCircle);

        const faceCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        faceCircle.setAttribute('cx', s / 2);
        faceCircle.setAttribute('cy', s / 2);
        faceCircle.setAttribute('r', 19);
        faceCircle.setAttribute('fill', 'none');
        faceCircle.setAttribute('stroke', this.options.smileyColor);
        faceCircle.setAttribute('stroke-width', '2.2');
        faceCircle.setAttribute('opacity', '0.95');
        centerG.appendChild(faceCircle);

        const leftEye = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        leftEye.setAttribute('cx', s / 2 - 6.5);
        leftEye.setAttribute('cy', s / 2 - 4);
        leftEye.setAttribute('r', 2.2);
        leftEye.setAttribute('fill', this.options.smileyColor);
        leftEye.setAttribute('opacity', '0.9');
        centerG.appendChild(leftEye);

        const rightEye = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        rightEye.setAttribute('cx', s / 2 + 6.5);
        rightEye.setAttribute('cy', s / 2 - 4);
        rightEye.setAttribute('r', 2.2);
        rightEye.setAttribute('fill', this.options.smileyColor);
        rightEye.setAttribute('opacity', '0.9');
        centerG.appendChild(rightEye);

        const mouth = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        mouth.setAttribute('d', `M ${s / 2 - 9} ${s / 2 + 3} Q ${s / 2 - 4} ${s / 2 + 11} ${s / 2} ${s / 2 + 9} Q ${s / 2 + 4} ${s / 2 + 11} ${s / 2 + 9} ${s / 2 + 3}`);
        mouth.setAttribute('fill', 'none');
        mouth.setAttribute('stroke', this.options.smileyColor);
        mouth.setAttribute('stroke-width', '2');
        mouth.setAttribute('stroke-linecap', 'round');
        centerG.appendChild(mouth);

        for (let i = 0; i < 6; i++) {
            const decoDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            const angle = (i / 6) * Math.PI * 2 + Math.PI / 6;
            const decoR = 10;
            decoDot.setAttribute('cx', s / 2 + Math.cos(angle) * decoR);
            decoDot.setAttribute('cy', s / 2 + Math.sin(angle) * decoR);
            decoDot.setAttribute('r', 0.8);
            decoDot.setAttribute('fill', this.options.dotColor);
            decoDot.setAttribute('opacity', '0.4');
            centerG.appendChild(decoDot);
        }

        this.svg.appendChild(centerG);
        this.container.appendChild(this.svg);
        this.startAnimation();
    }

    describeArc(cx, cy, r, startAngle, endAngle) {
        const start = this.polarToCartesian(cx, cy, r, endAngle);
        const end = this.polarToCartesian(cx, cy, r, startAngle);
        const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1';
        return ['M', start.x, start.y, 'A', r, r, 0, largeArcFlag, 0, end.x, end.y].join(' ');
    }

    polarToCartesian(centerX, centerY, radius, angleInDegrees) {
        const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0;
        return {
            x: centerX + (radius * Math.cos(angleInRadians)),
            y: centerY + (radius * Math.sin(angleInRadians))
        };
    }

    startAnimation() {
        let offset = 0;
        const animate = () => {
            offset = (offset + 0.12) % 100;
            if (this.textPath) {
                this.textPath.setAttribute('startOffset', `${offset}%`);
            }
            this.animationId = requestAnimationFrame(animate);
        };
        animate();
    }

    destroy() {
        if (this.animationId) cancelAnimationFrame(this.animationId);
        if (this.svg && this.svg.parentNode) {
            this.svg.parentNode.removeChild(this.svg);
        }
    }
}

// ==================== 3D动态线框三角形 ====================
class DynamicTriangle {
    constructor(canvas, options = {}) {
        this.canvas = typeof canvas === 'string' ? document.querySelector(canvas) : canvas;
        this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
        this.options = {
            size: options.size || 320,
            lineColor: options.lineColor || 'rgba(203, 213, 225, 0.6)',
            lineWidth: options.lineWidth || 2,
            innerFrameOffset: options.innerFrameOffset || 14,
            horizontalLines: options.horizontalLines || 5,
            cornerDotSize: options.cornerDotSize || 4,
            sideDotCount: options.sideDotCount || 6,
            dotColors: options.dotColors || ['#c07070', '#5a90a0', '#c4a050', '#8a6a9a', '#4A8C78', '#e0a0a0'],
            dotCount: options.dotCount || 12,
            rotationSpeed: options.rotationSpeed || 0.006,
            pulseSpeed: options.pulseSpeed || 0.0015,
            interactive: options.interactive !== false,
            ...options
        };
        this.rotation = 0;
        this.pulsePhase = 0;
        this.dots = [];
        this.sideDots = [];
        this.animationId = null;
        this.width = 0;
        this.height = 0;
        this.mouseX = 0;
        this.mouseY = 0;
        this.targetRotationX = 0;
        this.currentRotationX = 0;
        this.init();
    }

    init() {
        if (!this.canvas || !this.ctx) return;
        this.resize();
        window.addEventListener('resize', () => this.resize());
        if (this.options.interactive) {
            const parent = this.canvas.parentElement;
            if (parent) {
                parent.addEventListener('mousemove', (e) => {
                    const rect = parent.getBoundingClientRect();
                    this.mouseX = (e.clientX - rect.left - rect.width / 2) / (rect.width / 2);
                    this.mouseY = (e.clientY - rect.top - rect.height / 2) / (rect.height / 2);
                });
            }
        }
        this.initDots();
        this.initSideDots();
        this.animate();
    }

    resize() {
        const parent = this.canvas.parentElement;
        if (parent) {
            this.width = parent.clientWidth;
            this.height = parent.clientHeight;
        } else {
            this.width = this.options.size;
            this.height = this.options.size;
        }
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = this.width * dpr;
        this.canvas.height = this.height * dpr;
        this.canvas.style.width = this.width + 'px';
        this.canvas.style.height = this.height + 'px';
        this.ctx.setTransform(1, 0, 0, 1, 0, 0);
        this.ctx.scale(dpr, dpr);
    }

    initDots() {
        this.dots = [];
        const { dotCount, dotColors } = this.options;
        for (let i = 0; i < dotCount; i++) {
            this.dots.push({
                t: Math.random(),
                u: Math.random() * 0.9,
                v: Math.random() * 0.9,
                vx: (Math.random() - 0.5) * 0.002,
                vy: (Math.random() - 0.5) * 0.002,
                radius: Math.random() * 2.5 + 1.8,
                color: dotColors[i % dotColors.length],
                alpha: Math.random() * 0.3 + 0.7
            });
        }
    }

    initSideDots() {
        this.sideDots = [];
        const { sideDotCount, dotColors } = this.options;
        for (let edge = 0; edge < 3; edge++) {
            for (let i = 0; i < sideDotCount; i++) {
                this.sideDots.push({
                    edge: edge,
                    pos: Math.random(),
                    speed: (Math.random() * 0.3 + 0.15) * (Math.random() > 0.5 ? 1 : -1),
                    radius: Math.random() * 2.5 + 2.5,
                    color: dotColors[(edge * sideDotCount + i) % dotColors.length],
                    alpha: Math.random() * 0.25 + 0.75
                });
            }
        }
    }

    getVertices(cx, cy, size, rotation, tiltX) {
        const v = [];
        const perspective = 0.85 + Math.cos(tiltX) * 0.15;
        for (let i = 0; i < 3; i++) {
            const angle = rotation + (i * Math.PI * 2) / 3 - Math.PI / 2;
            const x = cx + Math.cos(angle) * size * perspective;
            const y = cy + Math.sin(angle) * size;
            v.push({ x, y });
        }
        return v;
    }

    getInnerVertices(vertices, offset) {
        const cx = (vertices[0].x + vertices[1].x + vertices[2].x) / 3;
        const cy = (vertices[0].y + vertices[1].y + vertices[2].y) / 3;
        return vertices.map(v => ({
            x: cx + (v.x - cx) * (1 - offset / 100),
            y: cy + (v.y - cy) * (1 - offset / 100)
        }));
    }

    drawDoubleFrame(cx, cy, size, rotation, tiltX) {
        const ctx = this.ctx;
        const { lineWidth, innerFrameOffset } = this.options;
        const pulse = Math.sin(this.pulsePhase) * 0.025;
        const s = size * (1 + pulse);
        const outer = this.getVertices(cx, cy, s, rotation, tiltX);
        const inner = this.getInnerVertices(outer, innerFrameOffset);

        ctx.save();
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';

        const thickOffset = 10;
        ctx.globalAlpha = 0.06;
        ctx.strokeStyle = this.options.lineColor;
        ctx.lineWidth = lineWidth * 0.8;
        ctx.beginPath();
        ctx.moveTo(outer[0].x + thickOffset, outer[0].y - thickOffset);
        ctx.lineTo(outer[1].x + thickOffset, outer[1].y - thickOffset);
        ctx.lineTo(outer[2].x + thickOffset, outer[2].y - thickOffset);
        ctx.closePath();
        ctx.stroke();

        ctx.globalAlpha = 0.04;
        ctx.lineWidth = lineWidth * 0.5;
        for (let i = 0; i < 3; i++) {
            ctx.beginPath();
            ctx.moveTo(outer[i].x, outer[i].y);
            ctx.lineTo(outer[i].x + thickOffset, outer[i].y - thickOffset);
            ctx.stroke();
        }

        ctx.globalAlpha = 0.85;
        ctx.strokeStyle = this.options.lineColor;
        ctx.lineWidth = lineWidth;
        ctx.beginPath();
        ctx.moveTo(outer[0].x, outer[0].y);
        ctx.lineTo(outer[1].x, outer[1].y);
        ctx.lineTo(outer[2].x, outer[2].y);
        ctx.closePath();
        ctx.stroke();

        ctx.globalAlpha = 0.5;
        ctx.lineWidth = lineWidth * 0.7;
        ctx.beginPath();
        ctx.moveTo(inner[0].x, inner[0].y);
        ctx.lineTo(inner[1].x, inner[1].y);
        ctx.lineTo(inner[2].x, inner[2].y);
        ctx.closePath();
        ctx.stroke();

        ctx.globalAlpha = 0.15;
        ctx.lineWidth = lineWidth * 0.5;
        for (let i = 0; i < 3; i++) {
            ctx.beginPath();
            ctx.moveTo(outer[i].x, outer[i].y);
            ctx.lineTo(inner[i].x, inner[i].y);
            ctx.stroke();
        }

        const hLines = this.options.horizontalLines;
        ctx.globalAlpha = 0.18;
        ctx.lineWidth = lineWidth * 0.5;
        for (let i = 1; i <= hLines; i++) {
            const t = i / (hLines + 1);
            const left = {
                x: outer[0].x + (outer[1].x - outer[0].x) * t * 0.5,
                y: outer[0].y + (outer[1].y - outer[0].y) * t
            };
            const right = {
                x: outer[0].x + (outer[2].x - outer[0].x) * t * 0.5,
                y: outer[0].y + (outer[2].y - outer[0].y) * t
            };
            const innerLeft = {
                x: inner[0].x + (inner[1].x - inner[0].x) * t * 0.5,
                y: inner[0].y + (inner[1].y - inner[0].y) * t
            };
            const innerRight = {
                x: inner[0].x + (inner[2].x - inner[0].x) * t * 0.5,
                y: inner[0].y + (inner[2].y - inner[0].y) * t
            };
            ctx.beginPath();
            ctx.moveTo(innerLeft.x, innerLeft.y);
            ctx.lineTo(innerRight.x, innerRight.y);
            ctx.stroke();
        }

        ctx.globalAlpha = 0.12;
        ctx.lineWidth = lineWidth * 0.4;
        for (let i = 1; i <= 2; i++) {
            const t = i / 3;
            const bottom = {
                x: outer[1].x + (outer[2].x - outer[1].x) * t,
                y: outer[1].y + (outer[2].y - outer[1].y) * t
            };
            const top = { x: inner[0].x, y: inner[0].y };
            ctx.beginPath();
            ctx.moveTo(bottom.x, bottom.y);
            ctx.lineTo(top.x, top.y);
            ctx.stroke();
        }

        ctx.globalAlpha = 1;
        ctx.restore();

        return { outer, inner };
    }

    drawCornerDots(vertices) {
        const ctx = this.ctx;
        const size = this.options.cornerDotSize;
        const colors = this.options.dotColors;
        vertices.forEach((v, i) => {
            const color = colors[i % colors.length];
            ctx.save();
            ctx.globalAlpha = 0.3;
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(v.x, v.y, size * 3, 0, Math.PI * 2);
            ctx.fill();
            ctx.globalAlpha = 0.9;
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(v.x, v.y, size, 0, Math.PI * 2);
            ctx.fill();
            ctx.globalAlpha = 0.6;
            ctx.fillStyle = '#fff';
            ctx.beginPath();
            ctx.arc(v.x - size * 0.2, v.y - size * 0.2, size * 0.35, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        });
    }

    drawSideDots(vertices) {
        const ctx = this.ctx;
        this.sideDots.forEach(dot => {
            dot.pos += dot.speed * 0.008;
            if (dot.pos > 1) { dot.pos = 1; dot.speed *= -1; }
            if (dot.pos < 0) { dot.pos = 0; dot.speed *= -1; }

            const v0 = vertices[dot.edge];
            const v1 = vertices[(dot.edge + 1) % 3];
            const x = v0.x + (v1.x - v0.x) * dot.pos;
            const y = v0.y + (v1.y - v0.y) * dot.pos;

            ctx.save();
            ctx.globalAlpha = dot.alpha * 0.25;
            ctx.fillStyle = dot.color;
            ctx.beginPath();
            ctx.arc(x, y, dot.radius * 2.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.globalAlpha = dot.alpha;
            ctx.fillStyle = dot.color;
            ctx.beginPath();
            ctx.arc(x, y, dot.radius, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        });
    }

    drawInnerDots(vertices) {
        const ctx = this.ctx;
        const cx = (vertices[0].x + vertices[1].x + vertices[2].x) / 3;
        const cy = (vertices[0].y + vertices[1].y + vertices[2].y) / 3;

        this.dots.forEach(dot => {
            dot.t += dot.vx;
            dot.u += dot.vy;
            if (dot.u < 0 || dot.u > 0.9) dot.vy *= -1;
            if (dot.v < 0 || dot.v > 0.9) dot.vx *= -1;

            const pu = Math.abs(dot.u);
            const pv = Math.abs(dot.v);
            const w = 1 - pu - pv;
            if (w < 0) return;

            const x = cx + (vertices[0].x - cx) * pu * 0.6 + (vertices[1].x - cx) * pv * 0.6 + (vertices[2].x - cx) * w * 0.6;
            const y = cy + (vertices[0].y - cy) * pu * 0.6 + (vertices[1].y - cy) * pv * 0.6 + (vertices[2].y - cy) * w * 0.6;

            ctx.save();
            ctx.globalAlpha = dot.alpha * 0.7;
            ctx.fillStyle = dot.color;
            ctx.beginPath();
            ctx.arc(x, y, dot.radius, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        });
    }

    animate() {
        if (!this.ctx) return;
        this.ctx.clearRect(0, 0, this.width, this.height);

        const cx = this.width / 2;
        const cy = this.height / 2;
        const baseSize = Math.min(this.width, this.height) * 0.38;

        this.targetRotationX = this.mouseY * 0.25;
        this.currentRotationX += (this.targetRotationX - this.currentRotationX) * 0.04;

        this.rotation += this.options.rotationSpeed;
        this.pulsePhase += this.options.pulseSpeed;

        const { outer, inner } = this.drawDoubleFrame(cx, cy, baseSize, this.rotation, this.currentRotationX);

        this.drawInnerDots(inner);
        this.drawSideDots(outer);
        this.drawCornerDots(outer);

        this.animationId = requestAnimationFrame(() => this.animate());
    }

    destroy() {
        if (this.animationId) cancelAnimationFrame(this.animationId);
    }
}

// ==================== Hero 浮动粒子 ====================
class HeroFloatingParticles {
    constructor(container, options = {}) {
        this.container = typeof container === 'string' ? document.querySelector(container) : container;
        this.options = {
            count: options.count || 18,
            colors: options.colors || ['#1A5F4A', '#4A8C78', '#1d4ed8', '#5a90a0', '#c4a050'],
            minSize: options.minSize || 2,
            maxSize: options.maxSize || 5,
            minDuration: options.minDuration || 12,
            maxDuration: options.maxDuration || 25,
            ...options
        };
        this.particles = [];
        this.init();
    }

    init() {
        if (!this.container) return;
        for (let i = 0; i < this.options.count; i++) {
            this.createParticle(i);
        }
    }

    createParticle(index) {
        const particle = document.createElement('div');
        particle.className = 'hero-particle';

        const size = this.options.minSize + Math.random() * (this.options.maxSize - this.options.minSize);
        const color = this.options.colors[Math.floor(Math.random() * this.options.colors.length)];
        const left = Math.random() * 100;
        const duration = this.options.minDuration + Math.random() * (this.options.maxDuration - this.options.minDuration);
        const delay = Math.random() * duration;
        const opacity = 0.15 + Math.random() * 0.35;

        particle.style.cssText = `
            width: ${size}px;
            height: ${size}px;
            left: ${left}%;
            background: ${color};
            box-shadow: 0 0 ${size * 2}px ${color}40;
            opacity: ${opacity};
            animation-duration: ${duration}s;
            animation-delay: -${delay}s;
        `;

        this.container.appendChild(particle);
        this.particles.push(particle);
    }

    destroy() {
        this.particles.forEach(p => p.remove());
        this.particles = [];
    }
}

// ==================== Hero区域特效初始化 ====================
function initHeroEffects() {
    console.log('初始化Hero区域特效...');
    const isMobile = window.innerWidth < 768;

    const badgeContainer = document.getElementById('heroBadge');
    if (badgeContainer && typeof CircularTextBadge !== 'undefined') {
        badgeContainer.innerHTML = '';
        window._heroBadge = new CircularTextBadge(badgeContainer, {
            text: 'SECURITY ANALYSIS • CERTIFICATE GUARD • DOMAIN SAFE • ',
            size: isMobile ? 200 : (window.innerWidth < 992 ? 280 : 363),
            duration: 20,
            color: '#CBD5E1',
            smileyColor: '#1A5F4A',
            fontSize: isMobile ? 12 : (window.innerWidth < 992 ? 16 : 20),
            letterSpacing: isMobile ? 5 : (window.innerWidth < 992 ? 6 : 8),
            dotColor: '#4A8C78',
            selfRotation: true
        });
        console.log('旋转笑脸徽章已启动 (3x放大 + 自旋转)');
    } else {
        console.warn('徽章容器或CircularTextBadge未找到');
    }

    const triangleCanvas = document.getElementById('heroTriangle');
    if (triangleCanvas && typeof DynamicTriangle !== 'undefined') {
        if (window._heroTriangle) window._heroTriangle.destroy();
        window._heroTriangle = new DynamicTriangle(triangleCanvas, {
            size: isMobile ? 200 : (window.innerWidth < 992 ? 280 : 363),
            lineColor: 'rgba(203, 213, 225, 0.5)',
            lineWidth: 2.2,
            dotColors: ['#c07070', '#5a90a0', '#c4a050', '#8a6a9a', '#6a9a8a', '#4A8C78', '#e0a0a0'],
            dotCount: 14,
            rotationSpeed: 0.006,
            pulseSpeed: 0.0015,
            interactive: true,
            innerFrameOffset: 16,
            horizontalLines: 5,
            cornerDotSize: 4.5,
            sideDotCount: 6
        });
        console.log('3D动态三角形已启动 (jiejoe风格)');
    } else {
        console.warn('三角形容器或DynamicTriangle未找到');
    }

    const heroParticlesContainer = document.getElementById('heroParticles');
    if (heroParticlesContainer && typeof HeroFloatingParticles !== 'undefined') {
        heroParticlesContainer.innerHTML = '';
        new HeroFloatingParticles(heroParticlesContainer, {
            count: 16,
            colors: ['#1A5F4A', '#4A8C78', '#1d4ed8', '#1A5F4A', '#5a90a0'],
            minSize: 2,
            maxSize: 5,
            minDuration: 14,
            maxDuration: 28
        });
        console.log('Hero浮动粒子已启动');
    }
}

function initTechEffects() {
    console.log('初始化科技风特效...');

    const particleCanvas = document.getElementById('particleCanvas');
    if (particleCanvas) {
        const ps = new ParticleSystem(particleCanvas, {
            count: 60,
            color: '#CBD5E1',
            connectionDistance: 130,
            speed: 0.4
        });
        ps.animate();
        console.log('粒子网络已启动');
    }

    initHeroEffects();

    console.log('科技风特效初始化完成');
}

// 全局导出特效类
window.ParticleSystem = ParticleSystem;
window.CircularTextBadge = CircularTextBadge;
window.DynamicTriangle = DynamicTriangle;
window.HeroFloatingParticles = HeroFloatingParticles;
window.initTechEffects = initTechEffects;
window.initHeroEffects = initHeroEffects;

// ====================== tech-effects.js 合并内容结束 ======================
// ====================== security.js 原始内容开始 ======================

var currentDomainFileName = null;

// ====================== 页面加载动画控制 ======================
(function() {
    const pageLoader = document.getElementById('pageLoader');

    function hideLoader() {
        if (!pageLoader) return;
        pageLoader.classList.add('fade-out');
        setTimeout(function() {
            if (pageLoader && pageLoader.parentNode) {
                pageLoader.parentNode.removeChild(pageLoader);
            }
            document.body.classList.add('content-loaded');
        }, 800);
    }

    if (document.readyState === 'complete') {
        setTimeout(hideLoader, 1200);
    } else {
        window.addEventListener('load', function() {
            setTimeout(hideLoader, 800);
        });
        setTimeout(hideLoader, 5000);
    }
})();

// ====================== 全局变量 ======================
let securityChartInstance = null;
let featuresChartInstance = null;
let reportTimeout = null;
let currentTaskId = null;
let pollInterval = null;
let reportData = null;
let statusTimer = 0;
let timerInterval = null;
let currentSecurityReport = null;

let pcapPollInterval = null;
let currentPcapTaskId = null;

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_COUNT = 2000;

// ====================== DOM 安全操作函数 ======================
function safeGetElement(id) {
    return document.getElementById(id);
}

function getApiBaseUrl() {
    return window.location.protocol === 'file:' ? 'http://127.0.0.1:5000' : '';
}

function getApiUrl(path) {
    return `${getApiBaseUrl()}${path}`;
}

function safeToggleDisplay(elementId, show) {
    const element = safeGetElement(elementId);
    if (element) {
        element.style.display = show ? 'block' : 'none';
        return true;
    }
    return false;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ====================== 页面初始化 ======================
document.addEventListener('DOMContentLoaded', function() {
    console.log('安全分析页面初始化...');
    
    try {
        initializeSecurityFeatures();
    } catch (e) {
        console.error('initializeSecurityFeatures 失败:', e);
    }
    
    try {
        initializeFileAnalysisEvents();
    } catch (e) {
        console.error('initializeFileAnalysisEvents 失败:', e);
    }
    
    try {
        initializeEventListeners();
    } catch (e) {
        console.error('initializeEventListeners 失败:', e);
    }
    
    safeToggleDisplay('quickStartGuide', true);
    safeToggleDisplay('analysisEntrance', false);
    safeToggleDisplay('analysisResults', false);
    safeToggleDisplay('quickStartBody', true);
    
    // 初始化科技风特效
    try {
        initTechEffects();
    } catch (e) {
        console.error('initTechEffects 失败:', e);
    }
    
    console.log('安全分析页面初始化完成');
});

function initializeSecurityFeatures() {
    initializeChartsConfig();
    initializeQuickStartGuide();
}

function initializeChartsConfig() {
    if (typeof Chart !== 'undefined') {
        Chart.defaults.font.family = 'Inter, sans-serif';
        Chart.defaults.color = '#4E5165';
        Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(56, 58, 122, 0.8)';
    }
}

function initializeQuickStartGuide() {
    const isCollapsed = localStorage.getItem('quickStartCollapsed') === 'true';
    if (isCollapsed) {
        collapseQuickStart();
    } else {
        expandQuickStart();
    }
}

function collapseQuickStart() {
    const quickStartCard = safeGetElement('quickStartCard');
    const quickStartBody = safeGetElement('quickStartBody');
    if (quickStartCard) quickStartCard.classList.add('quick-start-collapsed');
    if (quickStartBody) quickStartBody.style.display = 'none';
    localStorage.setItem('quickStartCollapsed', 'true');
}

function expandQuickStart() {
    const quickStartCard = safeGetElement('quickStartCard');
    const quickStartBody = safeGetElement('quickStartBody');
    if (quickStartCard) quickStartCard.classList.remove('quick-start-collapsed');
    if (quickStartBody) quickStartBody.style.display = 'block';
    localStorage.setItem('quickStartCollapsed', 'false');
}

function toggleQuickStart() {
    const quickStartCard = safeGetElement('quickStartCard');
    if (quickStartCard && quickStartCard.classList.contains('quick-start-collapsed')) {
        expandQuickStart();
    } else {
        collapseQuickStart();
    }
}

// ====================== 文件事件初始化 ======================
function initializeFileAnalysisEvents() {
    const pcapFileInput = safeGetElement('pcapFile');
    if (pcapFileInput) {
        pcapFileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                console.log('PCAP文件已选择:', file.name, formatFileSize(file.size));
            }
        });
    }
    
    const certZipFileInput = safeGetElement('certZipFile');
    const certDerFileInput = safeGetElement('certDerFile');
    
    if (certZipFileInput) {
        certZipFileInput.addEventListener('change', function(e) {
            console.log('证书压缩包已选择:', e.target.files[0]?.name);
        });
    }
    
    if (certDerFileInput) {
        certDerFileInput.addEventListener('change', function(e) {
            console.log('DER证书文件已选择:', e.target.files[0]?.name);
        });
    }
    
    const certTabs = document.querySelectorAll('#certTab .nav-link');
    certTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            if (this.id === 'zip-tab' && certDerFileInput) {
                certDerFileInput.value = '';
            } else if (this.id === 'single-tab' && certZipFileInput) {
                certZipFileInput.value = '';
            }
        });
    });
}

// ====================== 事件监听器初始化 ======================
function initializeEventListeners() {
    const startUsingBtn = safeGetElement('startUsingBtn');
    if (startUsingBtn) {
        startUsingBtn.addEventListener('click', function() {
            safeToggleDisplay('analysisEntrance', true);
            const entrance = safeGetElement('analysisEntrance');
            if (entrance) entrance.scrollIntoView({ behavior: 'smooth' });
        });
    }
    
    const toggleGuideBtn = safeGetElement('toggleGuideBtn');
    if (toggleGuideBtn) {
        toggleGuideBtn.addEventListener('click', function() {
            const quickStartBody = safeGetElement('quickStartBody');
            if (quickStartBody) {
                if (quickStartBody.style.display === 'none') {
                    quickStartBody.style.display = 'block';
                    this.innerHTML = '<i class="fas fa-times"></i> 折叠';
                } else {
                    quickStartBody.style.display = 'none';
                    this.innerHTML = '<i class="fas fa-chevron-down"></i> 展开';
                }
            }
        });
    }
    
    const analyzePcapBtn = safeGetElement('analyzePcapBtn');
    if (analyzePcapBtn) {
        analyzePcapBtn.addEventListener('click', function() {
            const fileInput = safeGetElement('pcapFile');
            if (fileInput) {
                fileInput.click();
            }
        });
    }
    
    const analyzeCertBtn = safeGetElement('analyzeCertBtn');
    if (analyzeCertBtn) {
        analyzeCertBtn.addEventListener('click', function() {
            const zipFileInput = safeGetElement('certZipFile');
            const derFileInput = safeGetElement('certDerFile');
            
            let fileToAnalyze = null;
            let analysisType = '';
            
            if (zipFileInput && zipFileInput.files.length) {
                fileToAnalyze = zipFileInput.files[0];
                analysisType = 'zip';
            } else if (derFileInput && derFileInput.files.length) {
                fileToAnalyze = derFileInput.files[0];
                analysisType = 'der';
            } else {
                alert('请选择证书文件');
                return;
            }
            
            processCertificateAnalysis(fileToAnalyze, analysisType);
        });
    }
    
    const generateReportBtn = safeGetElement('generateReportBtn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', generateSecurityReport);
    }
    
    const copyReportBtn = safeGetElement('copyReportBtn');
    if (copyReportBtn) {
        copyReportBtn.addEventListener('click', copyReport);
    }
    
    const downloadReportBtn = safeGetElement('downloadReportBtn');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', downloadReport);
    }
    
    window.addEventListener('beforeunload', function() {
        clearPcapPolling();
        if (pollInterval) clearInterval(pollInterval);
        if (timerInterval) clearInterval(timerInterval);
        destroyAllChartInstances();
    });
}

// ====================== PCAP分析（异步版本） ======================
function clearPcapPolling() {
    if (pcapPollInterval) {
        clearInterval(pcapPollInterval);
        pcapPollInterval = null;
    }
    currentPcapTaskId = null;
}

function updateLoadingStatus(message, progress) {
    const statusElement = safeGetElement('loadingStatusText');
    const progressBar = safeGetElement('loadingProgressBar');
    const progressPercent = safeGetElement('progressPercent');
    
    if (statusElement) {
        statusElement.innerHTML = message.replace(/\n/g, '<br>');
    }
    if (progressBar) {
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
    }
    if (progressPercent) {
        progressPercent.textContent = `${Math.round(progress)}%`;
    }
}

function showEnhancedLoading(message, fileSizeMB = null) {
    const loadingTitle = document.querySelector('#loadingSkeleton .skeleton-title');
    if (loadingTitle) {
        loadingTitle.textContent = message;
    }
    
    const skeletonBody = document.querySelector('#loadingSkeleton .skeleton-body');
    if (skeletonBody) {
        let statusDiv = safeGetElement('loadingStatusContainer');
        if (!statusDiv) {
            statusDiv = document.createElement('div');
            statusDiv.id = 'loadingStatusContainer';
            statusDiv.className = 'mt-4';
            statusDiv.innerHTML = `
                <div class="d-flex align-items-center mb-2">
                    <div class="spinner-border spinner-border-sm text-primary me-2" role="status"></div>
                    <span id="loadingStatusText">${message}</span>
                    <span id="progressPercent" class="ms-auto small text-muted">0%</span>
                </div>
                <div class="progress" style="height: 8px;">
                    <div id="loadingProgressBar" class="progress-bar progress-bar-striped progress-bar-animated" 
                         style="width: 5%" role="progressbar"></div>
                </div>
                ${fileSizeMB ? `<div class="small text-muted mt-2">文件大小: ${fileSizeMB} MB</div>` : ''}
            `;
            skeletonBody.appendChild(statusDiv);
        }
    }
    
    showSkeletonLoading();
    safeToggleDisplay('analysisResults', true);
}

async function processPcapAnalysis(file) {
    console.log('开始分析PCAP文件:', file.name);
    
    const maxSize = 520 * 1024 * 1024;
    if (file.size > maxSize) {
        alert(`文件过大: ${formatFileSize(file.size)}，最大支持 520MB`);
        return;
    }
    
    clearPcapPolling();
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
        
        showEnhancedLoading('正在上传PCAP文件...', fileSizeMB);
        updateLoadingStatus('正在上传并提交分析任务...', 5);
        
        const response = await fetch('/api/security/analyze-pcap-async', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('PCAP任务提交响应:', data);
        
        if (data.status === 'processing' && data.task_id) {
            currentPcapTaskId = data.task_id;
            
            let statusMessage = `任务已提交，正在提取PCAP域名...`;
            if (data.file_size_mb) {
                statusMessage += `<br><small>文件大小: ${data.file_size_mb} MB</small>`;
            }
            updateLoadingStatus(statusMessage, 10);
            
            pollPcapTaskStatus(currentPcapTaskId);
            
        } else if (data.status === 'success') {
            hideSkeletonLoading();
            if (data.security_report) {
                displaySecurityReport(data.security_report);
                safeToggleDisplay('analysisResults', true);
            }
        } else {
            throw new Error(data.error || '提交任务失败');
        }
        
    } catch (error) {
        console.error('PCAP分析错误:', error);
        hideSkeletonLoading();
        clearPcapPolling();
        showPcapAnalysisError(error, file);
    }
}

// ====================== 安全分析结果显示函数 ======================
function showSecurityAnalysisResult(resultData) {
    console.log('显示安全分析结果:', resultData);
    
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const actualResults = document.getElementById('actualResultsContent');
    
    if (loadingSkeleton) loadingSkeleton.style.display = 'none';
    if (!actualResults) {
        console.error('actualResultsContent 元素不存在');
        return;
    }
    
    actualResults.style.display = 'block';
    
    const report = resultData?.security_report || resultData;
    if (!report) {
        actualResults.innerHTML = '<div class="alert alert-warning">分析结果为空</div>';
        return;
    }
    
    window.lastSecurityReport = report;
    
    const resultId = 'securityResult_' + Date.now();
    actualResults.innerHTML = generateResultsWithTabsHTML(resultId, false);
    
    setTimeout(() => {
        const scoreCardEl = document.getElementById('scoreCard');
        const detailedFindingsEl = document.getElementById('detailedFindings');
        const chartSectionEl = document.getElementById('chartSection');
        const domainDetailsEl = document.getElementById('domainDetails');
        
        console.log('DOM 元素检查:', {
            scoreCard: !!scoreCardEl,
            detailedFindings: !!detailedFindingsEl,
            chartSection: !!chartSectionEl,
            domainDetails: !!domainDetailsEl
        });
        
        if (scoreCardEl) renderScoreCardFixed(report);
        else console.error('scoreCard 元素未找到');
        
        if (detailedFindingsEl) renderDetailedFindingsFixed(report);
        else console.error('detailedFindings 元素未找到');
        
        if (chartSectionEl) renderChartSectionFixed(report);
        else console.error('chartSection 元素未找到');
        
        if (domainDetailsEl) renderDomainDetailsFixed(report);
        else console.error('domainDetails 元素未找到');
        
        setTimeout(() => {
            initializeResultCharts(report);
        }, 100);
        
        setTimeout(() => {
            generateAiReport(report, 'security');
        }, 200);
    }, 50);
}

function renderScoreCardFixed(report) {
    const summary = report.summary || {};
    const score = summary.security_score || 0;
    const analyzedCount = summary.analyzed_domains || 0;
    const grade = getSecurityGrade(score);

    const scoreCard = document.getElementById('scoreCard');
    if (!scoreCard) return;

    const getGradeColor = (g) => {
        if (g === '优秀') return '#34D399';
        if (g === '良好') return '#60A5FA';
        if (g === '一般') return '#FBBF24';
        return '#F87171';
    };

    scoreCard.innerHTML = `
        <div class="card" style="background: linear-gradient(135deg, rgba(13,25,42,0.9), rgba(10,22,40,0.95)); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; overflow: hidden;">
            <div class="card-body p-4">
                <div class="row align-items-center">
                    <div class="col-md-4 text-center mb-3 mb-md-0">
                        <div style="font-size: 3rem; font-weight: 700; color: ${getGradeColor(grade)}; text-shadow: 0 0 20px ${getGradeColor(grade)}40;">${grade}</div>
                        <div style="font-size: 2.5rem; font-weight: 700; color: #FFFFFF;">${score}<small class="fs-6" style="color: #64748B;">/100</small></div>
                        <div class="mt-2" style="color: #64748B; font-size: 0.85rem;">安全评分</div>
                        <div class="mt-1" style="color: #94A3B8; font-size: 0.8rem;">基于 ${analyzedCount} 个域名</div>
                    </div>
                    <div class="col-md-8">
                        <h5 class="mb-3" style="color: #FFFFFF;">详细评分</h5>
                        <div class="row g-3">
                            <div class="col-6">
                                <div class="d-flex align-items-center gap-2 p-2 rounded" style="background: rgba(255,255,255,0.03);">
                                    ${summary.domains_with_https_enforcement > 0 ? '<i class="fas fa-check-circle" style="color: #34D399;"></i>' : '<i class="fas fa-times-circle" style="color: #F87171;"></i>'}
                                    <span style="color: #CBD5E1; font-size: 0.85rem;">HTTPS强制 (${summary.domains_with_https_enforcement || 0}个)</span>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="d-flex align-items-center gap-2 p-2 rounded" style="background: rgba(255,255,255,0.03);">
                                    ${summary.domains_with_hsts > 0 ? '<i class="fas fa-check-circle" style="color: #34D399;"></i>' : '<i class="fas fa-times-circle" style="color: #F87171;"></i>'}
                                    <span style="color: #CBD5E1; font-size: 0.85rem;">HSTS保护 (${summary.domains_with_hsts || 0}个)</span>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="d-flex align-items-center gap-2 p-2 rounded" style="background: rgba(255,255,255,0.03);">
                                    ${summary.domains_with_good_security_headers > 0 ? '<i class="fas fa-check-circle" style="color: #34D399;"></i>' : '<i class="fas fa-times-circle" style="color: #F87171;"></i>'}
                                    <span style="color: #CBD5E1; font-size: 0.85rem;">安全响应头 (${summary.domains_with_good_security_headers || 0}个)</span>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="d-flex align-items-center gap-2 p-2 rounded" style="background: rgba(255,255,255,0.03);">
                                    ${summary.domains_with_valid_certificate_chains > 0 ? '<i class="fas fa-check-circle" style="color: #34D399;"></i>' : '<i class="fas fa-times-circle" style="color: #F87171;"></i>'}
                                    <span style="color: #CBD5E1; font-size: 0.85rem;">证书链完整 (${summary.domains_with_valid_certificate_chains || 0}个)</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderDetailedFindingsFixed(report) {
    const detailedFindings = document.getElementById('detailedFindings');
    if (!detailedFindings) return;

    const summary = report.summary || {};
    const domainStats = report.domain_stats || {};
    const analyzedCount = summary.analyzed_domains || 0;
    const successfulCount = summary.successful_domains || analyzedCount;
    const failedCount = summary.failed_domains || 0;

    let findingsHtml = `
        <div class="card mb-3" style="background: rgba(13,25,42,0.6); border: 1px solid rgba(255,255,255,0.08);">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 style="color: #FFFFFF; margin-bottom: 12px;"><i class="fas fa-chart-pie me-2"></i>域名提取统计</h6>
                        <ul class="list-unstyled" style="color: #94A3B8; font-size: 0.9rem;">
                            <li class="mb-2"><i class="fas fa-file-export me-2" style="color: #60A5FA;"></i> 提取域名总数: <strong style="color: #FFFFFF;">${domainStats.total_extracted || 0}</strong></li>
                            <li class="mb-2"><i class="fas fa-filter me-2" style="color: #60A5FA;"></i> 过滤后域名: <strong style="color: #FFFFFF;">${domainStats.after_filtering || 0}</strong></li>
                            <li class="mb-2"><i class="fas fa-chart-line me-2" style="color: #60A5FA;"></i> 实际分析: <strong style="color: #FFFFFF;">${domainStats.to_analyze || analyzedCount}</strong></li>
                            <li class="mb-2"><i class="fas fa-check-circle me-2" style="color: #34D399;"></i> 成功分析: <strong style="color: #34D399;">${successfulCount}</strong></li>
                            ${failedCount > 0 ? `<li class="mb-2"><i class="fas fa-times-circle me-2" style="color: #F87171;"></i> 分析失败: <strong style="color: #F87171;">${failedCount}</strong></li>` : ''}
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6 style="color: #FFFFFF; margin-bottom: 12px;"><i class="fas fa-shield-alt me-2"></i>安全特性统计</h6>
                        <ul class="list-unstyled" style="color: #94A3B8; font-size: 0.9rem;">
                            <li class="mb-2"><i class="fas fa-lock me-2" style="color: #34D399;"></i> HTTPS强制: <strong style="color: #FFFFFF;">${summary.domains_with_https_enforcement || 0}</strong></li>
                            <li class="mb-2"><i class="fas fa-shield-alt me-2" style="color: #34D399;"></i> HSTS保护: <strong style="color: #FFFFFF;">${summary.domains_with_hsts || 0}</strong></li>
                            <li class="mb-2"><i class="fas fa-header me-2" style="color: #34D399;"></i> 安全头良好: <strong style="color: #FFFFFF;">${summary.domains_with_good_security_headers || 0}</strong></li>
                            <li class="mb-2"><i class="fas fa-certificate me-2" style="color: #34D399;"></i> 证书链完整: <strong style="color: #FFFFFF;">${summary.domains_with_valid_certificate_chains || 0}</strong></li>
                        </ul>
                    </div>
                </div>
                ${report.performance_stats ? `
                <hr style="border-color: rgba(255,255,255,0.06);">
                <div class="mt-3">
                    <h6 style="color: #FFFFFF; margin-bottom: 8px;"><i class="fas fa-tachometer-alt me-2"></i>性能统计</h6>
                    <div class="row small" style="color: #94A3B8;">
                        <div class="col-md-3 mb-1"><span class="text-muted">提取耗时:</span> <strong>${report.performance_stats.extract_time || 0}s</strong></div>
                        <div class="col-md-3 mb-1"><span class="text-muted">分析耗时:</span> <strong>${report.performance_stats.analyze_time || 0}s</strong></div>
                        <div class="col-md-3 mb-1"><span class="text-muted">总耗时:</span> <strong>${report.performance_stats.total_time || 0}s</strong></div>
                        <div class="col-md-3 mb-1"><span class="text-muted">平均/域名:</span> <strong>${report.performance_stats.avg_per_domain || 0}s</strong></div>
                    </div>
                </div>
                ` : ''}
                ${report.saved_files && (report.saved_files.json || report.saved_files.txt) ? `
                <hr style="border-color: rgba(255,255,255,0.06);">
                <div class="mt-3">
                    <h6 style="color: #FFFFFF; margin-bottom: 8px;"><i class="fas fa-save me-2"></i>保存的文件</h6>
                    <ul class="list-unstyled small" style="color: #94A3B8;">
                        ${report.saved_files.json ? `<li><i class="fas fa-file-code me-2"></i> JSON: ${escapeHtml(report.saved_files.json.split(/[\\/]/).pop())}</li>` : ''}
                        ${report.saved_files.txt ? `<li><i class="fas fa-file-alt me-2"></i> TXT: ${escapeHtml(report.saved_files.txt.split(/[\\/]/).pop())}</li>` : ''}
                    </ul>
                </div>
                ` : ''}
            </div>
        </div>
    `;

    detailedFindings.innerHTML = findingsHtml;
}

function renderChartSectionFixed(report) {
    const chartSection = document.getElementById('chartSection');
    if (!chartSection) return;

    const summary = report.summary || {};
    const scoreDistribution = report.scoreDistribution || [0, 0, 0, 0];
    const total = summary.analyzed_domains || 1;

    const hasScoreData = scoreDistribution.some(v => v > 0);
    const featureStats = report.featureStats || {};
    const hasFeatureData = featureStats.https > 0 || featureStats.hsts > 0 || featureStats.good_headers > 0 || featureStats.valid_chains > 0;

    if (!hasScoreData && !hasFeatureData) {
        chartSection.innerHTML = '<div class="text-center py-4" style="color: #64748B;">暂无图表数据</div>';
        return;
    }

    chartSection.innerHTML = `
        <div class="row g-4">
            <div class="col-md-6">
                <div class="p-3 rounded" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);">
                    <h6 class="mb-3" style="color: #FFFFFF; text-align: center;">安全分数分布</h6>
                    <div style="position: relative; height: 280px;">
                        <canvas id="securityChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="p-3 rounded" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);">
                    <h6 class="mb-3" style="color: #FFFFFF; text-align: center;">安全特性覆盖率</h6>
                    <div style="position: relative; height: 280px;">
                        <canvas id="featuresChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderDomainDetailsFixed(report) {
    const domainDetails = document.getElementById('domainDetails');
    if (!domainDetails) return;

    const detailedResults = report.detailed_results || [];
    
    if (!detailedResults.length) {
        domainDetails.innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i> 
                未收到任何域名分析结果。可能原因：<br>
                1. PCAP 中未提取到有效域名<br>
                2. 所有域名分析均超时或失败<br>
                3. 后端未正确返回 detailed_results 字段<br>
                请检查后端日志。
            </div>`;
        return;
    }

    const sortedResults = [...detailedResults].sort((a, b) => (b.security_score || 0) - (a.security_score || 0));

    let html = `
        <div class="table-responsive">
            <table class="table table-sm" style="color: #94A3B8; font-size: 0.85rem;">
                <thead style="background: rgba(255,255,255,0.03);">
                    <tr>
                        <th style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">域名</th>
                        <th class="text-center" style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">HTTPS</th>
                        <th class="text-center" style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">HSTS</th>
                        <th class="text-center" style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">安全头</th>
                        <th class="text-center" style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">证书链</th>
                        <th class="text-center" style="color: #CBD5E1; border-color: rgba(255,255,255,0.06);">分数</th>
                    </tr>
                </thead>
                <tbody>
    `;

    sortedResults.slice(0, 50).forEach(result => {
        if (result.error || result.status === 'failed' || result.status === 'timeout') {
            html += `
                <tr style="border-color: rgba(255,255,255,0.04);">
                    <td style="border-color: rgba(255,255,255,0.04);"><code style="color: #F87171;">${escapeHtml(result.domain)}</code></td>
                    <td colspan="5" class="text-center" style="border-color: rgba(255,255,255,0.04); color: #F87171;">
                        <i class="fas fa-exclamation-circle me-1"></i> ${escapeHtml(result.error || result.status || '分析失败')}
                    </td>
                </tr>
            `;
        } else {
            const score = result.security_score || 0;
            const scoreColor = score >= 80 ? '#34D399' : score >= 60 ? '#60A5FA' : score >= 40 ? '#FBBF24' : '#F87171';
            
            html += `
                <tr style="border-color: rgba(255,255,255,0.04);">
                    <td style="border-color: rgba(255,255,255,0.04);"><strong style="color: #FFFFFF;">${escapeHtml(result.domain)}</strong></td>
                    <td class="text-center" style="border-color: rgba(255,255,255,0.04);">
                        ${result.https_enforcement?.enforced ? '<i class="fas fa-check" style="color: #34D399;"></i>' : '<i class="fas fa-times" style="color: #F87171;"></i>'}
                    </td>
                    <td class="text-center" style="border-color: rgba(255,255,255,0.04);">
                        ${result.hsts?.enabled ? '<i class="fas fa-check" style="color: #34D399;"></i>' : '<i class="fas fa-times" style="color: #F87171;"></i>'}
                    </td>
                    <td class="text-center" style="border-color: rgba(255,255,255,0.04);">
                        ${getSecurityHeadersIcon(result.security_headers)}
                    </td>
                    <td class="text-center" style="border-color: rgba(255,255,255,0.04);">
                        ${result.certificate_chain_valid ? '<i class="fas fa-check" style="color: #34D399;"></i>' : '<i class="fas fa-times" style="color: #F87171;"></i>'}
                    </td>
                    <td class="text-center" style="border-color: rgba(255,255,255,0.04);">
                        <span style="display: inline-block; padding: 2px 10px; border-radius: 10px; background: ${scoreColor}20; color: ${scoreColor}; font-weight: 600; font-size: 0.8rem;">${score}</span>
                    </td>
                </tr>
            `;
        }
    });

    if (detailedResults.length > 50) {
        html += `
            <tr>
                <td colspan="6" class="text-center" style="border-color: rgba(255,255,255,0.04); color: #64748B; padding: 16px;">
                    ... 还有 ${detailedResults.length - 50} 个域名未显示
                </td>
            </tr>
        `;
    }

    html += `
                </tbody>
            </table>
        </div>
    `;

    domainDetails.innerHTML = html;
}

function pollPcapTaskStatus(taskId) {
    clearPcapPolling();
    
    let pollCount = 0;
    
    pcapPollInterval = setInterval(async () => {
        pollCount++;
        
        try {
            const response = await fetch(`/api/security/task-status/${taskId}`);
            
            if (!response.ok) {
                console.error(`轮询失败: ${response.status}`);
                return;
            }
            
            const result = await response.json();
            
            let progress = 15;
            let statusMessage = result.message || '正在处理中...';
            
            if (result.status === 'processing') {
                if (result.total_domains && result.analyzed_count !== undefined) {
                    const analyzeProgress = (result.analyzed_count / result.total_domains) * 80;
                    progress = Math.min(15 + analyzeProgress, 95);
                    statusMessage = `正在分析域名: ${result.analyzed_count}/${result.total_domains}`;
                }
                updateLoadingStatus(statusMessage, progress);
            }
                
            if (result.status === 'completed' || result.status === 'success') {
                clearPcapPolling();
                hideSkeletonLoading();

                if (result.security_report) {
                    console.log('✅ 任务完成，保存并渲染报告');
                    window.lastSecurityReport = result.security_report;

                    if (typeof showSecurityAnalysisResult === 'function') {
                        showSecurityAnalysisResult(result.security_report);
                    } else {
                        displaySecurityReport(result.security_report);
                    }

                    safeToggleDisplay('analysisResultsSection', true);
                    const actualDiv = document.getElementById('actualResultsContent');
                    if (actualDiv) actualDiv.style.display = 'block';
                    const loadingDiv = document.getElementById('loadingSkeleton');
                    if (loadingDiv) loadingDiv.style.display = 'none';

                } else {
                    console.error('❌ 任务完成但没有 security_report 数据');
                    showPcapAnalysisError(new Error('分析完成但未返回结果'), null);
                }
            } 
            
            if (pollCount >= MAX_POLL_COUNT) {
                clearPcapPolling();
                hideSkeletonLoading();
                showPcapAnalysisError(new Error('分析超时，请稍后重试'), null);
            }
            
        } catch (error) {
            console.error('轮询失败:', error);
            if (pollCount >= 10) {
                clearPcapPolling();
                hideSkeletonLoading();
                showPcapAnalysisError(error, null);
            }
        }
    }, POLL_INTERVAL_MS);
}

function showPcapAnalysisError(error, file) {
    const actualResults = safeGetElement('actualResults');
    
    let suggestions = '';
    let errorMessage = error.message || '未知错误';
    
    if (error.name === 'AbortError' || errorMessage.includes('timeout') || errorMessage.includes('超时')) {
        suggestions = `
            <li>PCAP文件较大，分析超时</li>
            <li>建议尝试较小的PCAP文件</li>
        `;
    } else if (errorMessage.includes('Network') || errorMessage.includes('fetch')) {
        suggestions = '<li>网络连接问题，请检查网络后重试</li>';
    } else if (errorMessage.includes('未检测到TLS证书') || errorMessage.includes('提取')) {
        suggestions = `
            <li>PCAP文件中不包含DNS查询或TLS握手流量</li>
            <li>流量被加密或使用非标准端口</li>
        `;
    } else {
        suggestions = '<li>请检查PCAP文件格式是否正确</li>';
    }
    
    const html = `
        <div class="alert alert-danger">
            <h5><i class="fas fa-times-circle me-2"></i>PCAP分析失败</h5>
            <p>${escapeHtml(errorMessage)}</p>
            <hr>
            <h6>可能的原因：</h6>
            <ul>
                ${suggestions}
                <li>文件中不包含DNS或TLS流量</li>
                <li>需要的依赖库未安装（tshark/scapy）</li>
            </ul>
            <div class="mt-3">
                <button class="btn btn-primary me-2" onclick="resetSecurityAnalysis()">
                    <i class="fas fa-redo me-2"></i>重新分析
                </button>
            </div>
        </div>
    `;
    
    if (actualResults) actualResults.innerHTML = html;
    safeToggleDisplay('actualResults', true);
    safeToggleDisplay('analysisResults', true);
}

// ====================== 证书分析 ======================
async function processCertificateAnalysis(file, type) {
    console.log('开始分析证书文件:', file.name, '类型:', type);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('analysis_type', type);
        
        showSkeletonLoading();
        safeToggleDisplay('analysisResults', true);
        
        const response = await fetch('/api/security/analyze-certificates', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('证书分析响应:', data);
        
        hideSkeletonLoading();
        
        if (data.status === 'success') {
            displaySecurityReport(data.security_report);
        } else if (data.status === 'info') {
            showCertificateInfo(data);
        } else if (data.status === 'warning') {
            showCertificateWarning(data.message, data.certificate_analysis);
        } else {
            throw new Error(data.error || '分析失败');
        }
        
    } catch (error) {
        console.error('证书分析错误:', error);
        hideSkeletonLoading();
        alert('分析失败: ' + error.message);
    }
}

function showCertificateInfo(data) {
    hideSkeletonLoading();
    
    const resultsSection = safeGetElement('analysisResults');
    if (!resultsSection) return;
    
    resultsSection.style.display = 'block';
    
    let analysisHtml = `
        <div class="alert alert-info">
            <div class="d-flex align-items-center">
                <i class="fas fa-info-circle fa-2x me-3"></i>
                <div>
                    <h5 class="alert-heading mb-2">证书分析结果</h5>
                    <p class="mb-0" style="white-space: pre-line;">${escapeHtml(data.message)}</p>
                </div>
            </div>
        </div>
    `;
    
    if (data.certificate_analysis && data.certificate_analysis.length > 0) {
        const certInfo = data.certificate_analysis[0];
        
        analysisHtml += `
            <div class="card mt-4">
                <div class="card-header bg-light">
                    <h6 class="mb-0"><i class="fas fa-search me-2"></i>证书详细信息</h6>
                </div>
                <div class="card-body">
                    <div class="row">
                        ${certInfo.type ? `
                        <div class="col-md-6 mb-3">
                            <strong>证书类型:</strong>
                            <span class="ms-2 badge ${certInfo.is_ca ? 'bg-warning' : 'bg-info'}">${escapeHtml(certInfo.type)}</span>
                        </div>` : ''}
                        ${certInfo.subject ? `
                        <div class="col-12 mb-3">
                            <strong>证书主题:</strong>
                            <code class="ms-2 bg-light p-2 rounded d-block mt-1">${escapeHtml(certInfo.subject)}</code>
                        </div>` : ''}
                        ${certInfo.issuer ? `
                        <div class="col-12 mb-3">
                            <strong>颁发机构:</strong>
                            <code class="ms-2 bg-light p-2 rounded d-block mt-1">${escapeHtml(certInfo.issuer)}</code>
                        </div>` : ''}
                    </div>
                </div>
            </div>
        `;
    }
    
    analysisHtml += `
        <div class="card mt-4">
            <div class="card-header bg-light">
                <h6 class="mb-0"><i class="fas fa-lightbulb me-2"></i>下一步操作</h6>
            </div>
            <div class="card-body">
                <div class="text-center">
                    <button class="btn btn-primary me-3" onclick="resetSecurityAnalysis()">
                        <i class="fas fa-upload me-2"></i>重新上传证书
                    </button>
                </div>
            </div>
        </div>
    `;
    
    resultsSection.innerHTML = analysisHtml;
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function showCertificateWarning(message, certificateAnalysis) {
    hideSkeletonLoading();
    
    const resultsSection = safeGetElement('analysisResults');
    if (!resultsSection) {
        alert("证书分析提示:\n\n" + message);
        return;
    }
    
    resultsSection.style.display = 'block';
    
    let analysisHtml = `
        <div class="alert alert-warning">
            <div class="d-flex align-items-center">
                <i class="fas fa-exclamation-triangle fa-2x me-3"></i>
                <div>
                    <h5 class="alert-heading mb-2">证书分析提示</h5>
                    <p class="mb-0" style="white-space: pre-line;">${escapeHtml(message)}</p>
                </div>
            </div>
        </div>
        <div class="text-center mt-4">
            <button class="btn btn-primary me-3" onclick="resetSecurityAnalysis()">
                <i class="fas fa-upload me-2"></i>重新上传证书
            </button>
        </div>
    `;
    
    resultsSection.innerHTML = analysisHtml;
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// ====================== 结果显示 ======================
function displaySecurityReport(report) {
    console.log('显示安全报告:', report);

    if (typeof showSecurityAnalysisResult === 'function') {
        showSecurityAnalysisResult(report);
        return;
    }

    const actualReport = report?.security_report || report;
    if (!actualReport) {
        console.error('报告数据为空');
        return;
    }

    setCurrentSecurityReport(actualReport);
    destroyAllChartInstances();

    safeToggleDisplay('analysisResults', true);
    safeToggleDisplay('actualResults', true);
    hideSkeletonLoading();

    const container = document.getElementById('actualResultsContent');
    if (container) {
        const summary = actualReport.summary || {};
        container.innerHTML = `
            <div class="alert alert-success">
                <h5>分析完成</h5>
                <p>安全评分：${summary.security_score || 0}</p>
                <p>成功分析域名数：${summary.successful_domains || summary.analyzed_domains || 0}</p>
            </div>
        `;
    }
}

function getSecurityHeadersIcon(securityHeaders) {
    if (!securityHeaders?.assessment) return '❌';
    const a = securityHeaders.assessment;
    const good = [a.has_csp, a.has_x_content_type_options, a.has_x_frame_options, a.has_referrer_policy].filter(Boolean).length;
    if (good >= 3) return '✅';
    if (good >= 1) return '⚠️';
    return '❌';
}

// ====================== 图表函数 ======================
function destroyAllChartInstances() {
    if (securityChartInstance) {
        try { securityChartInstance.destroy(); } catch (e) {}
        securityChartInstance = null;
    }
    if (featuresChartInstance) {
        try { featuresChartInstance.destroy(); } catch (e) {}
        featuresChartInstance = null;
    }
}

function showSkeletonLoading() {
    safeToggleDisplay('loadingSkeleton', true);
    safeToggleDisplay('actualResults', false);
}

function hideSkeletonLoading() {
    const loadingSkeleton = safeGetElement('loadingSkeleton');
    if (loadingSkeleton) {
        loadingSkeleton.style.display = 'none';
    }
    
    const actualResults = safeGetElement('actualResults') || safeGetElement('actualResultsContent');
    if (actualResults) {
        actualResults.style.display = 'block';
    }
    
    safeToggleDisplay('analysisResults', true);
    safeToggleDisplay('analysisResultsSection', true);
}

function resetSecurityAnalysis() {
    clearPcapPolling();
    safeToggleDisplay('analysisResults', false);
    safeToggleDisplay('analysisEntrance', true);
    
    const pcapFile = safeGetElement('pcapFile');
    if (pcapFile) pcapFile.value = '';
    
    destroyAllChartInstances();
}

function getSecurityGrade(score) {
    if (score >= 90) return '优秀';
    if (score >= 70) return '良好';
    if (score >= 50) return '一般';
    return '需改进';
}

function setCurrentSecurityReport(reportData) {
    if (!reportData) return;
    
    const completeReport = {
        ...reportData,
        summary: reportData.summary || {},
        detailed_results: reportData.detailed_results || [],
        timestamp: new Date().toISOString()
    };
    
    window.lastSecurityReport = completeReport;
    
    try {
        sessionStorage.setItem('lastSecurityReport', JSON.stringify(completeReport));
    } catch (e) {}
}

function getCurrentSecurityReport() {
    if (window.lastSecurityReport) return window.lastSecurityReport;
    
    try {
        const stored = sessionStorage.getItem('lastSecurityReport');
        if (stored) {
            window.lastSecurityReport = JSON.parse(stored);
            return window.lastSecurityReport;
        }
    } catch (e) {}
    
    return null;
}

// ====================== 报告生成 ======================
async function generateSecurityReport() {
    const currentReport = getCurrentSecurityReport();
    if (!currentReport) {
        alert('请先完成安全分析');
        return;
    }
    
    const generateBtn = safeGetElement('generateReportBtn');
    const loadingDiv = safeGetElement('reportLoading');
    const reportError = safeGetElement('reportError');
    
    if (reportError) reportError.style.display = 'none';
    safeToggleDisplay('reportContent', false);
    
    if (generateBtn) {
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>生成中...';
    }
    if (loadingDiv) loadingDiv.style.display = 'block';
    
    try {
        const requestData = {
            source_type: 'security',
            report_type: 'security',
            analysis_data: {
                summary: currentReport.summary || {},
                detailed_results: currentReport.detailed_results || [],
                scoreDistribution: currentReport.scoreDistribution || [0, 0, 0, 0],
                featureStats: currentReport.featureStats || {},
                timestamp: new Date().toISOString()
            },
            original_file: '安全分析报告_' + new Date().toLocaleDateString()
        };
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);
        
        const response = await fetch('/api/security/generate-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const result = await response.json();
        
        if (result.status === 'processing' && result.task_id) {
            currentTaskId = result.task_id;
            const taskIdDisplay = safeGetElement('taskIdDisplay');
            if (taskIdDisplay) taskIdDisplay.textContent = currentTaskId;
            pollReportStatus(currentTaskId);
        } else if (result.status === 'success' && result.report_content) {
            currentSecurityReport = {
                content: result.report_content,
                generated_at: result.generated_at || new Date().toISOString(),
                analysis_data: currentReport
            };
            displayGeneratedReport(result.report_content, result.generated_at);
            safeToggleDisplay('reportStatus', false);
        } else {
            throw new Error(result.error || '报告生成失败');
        }
        
    } catch (error) {
        console.error('报告生成失败:', error);
        showReportError('报告生成失败: ' + error.message);
    } finally {
        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<i class="fas fa-magic me-2"></i>生成AI报告';
        }
        if (loadingDiv) loadingDiv.style.display = 'none';
    }
}

function pollReportStatus(taskId) {
    if (pollInterval) clearInterval(pollInterval);
    
    let pollCount = 0;
    const maxPollCount = 60;
    
    pollInterval = setInterval(async () => {
        pollCount++;
        
        try {
            const response = await fetch(`/api/security/report-status/${taskId}`);
            if (!response.ok) return;
            
            const result = await response.json();
            
            if (result.status === 'completed' || result.status === 'success') {
                clearInterval(pollInterval);
                pollInterval = null;
                
                currentSecurityReport = {
                    content: result.report_content,
                    generated_at: result.generated_at || new Date().toISOString()
                };
                
                displayGeneratedReport(result.report_content, result.generated_at);
                safeToggleDisplay('reportStatus', false);
                safeToggleDisplay('copyReportBtn', true);
                safeToggleDisplay('downloadReportBtn', true);
                
            } else if (result.status === 'error' || result.status === 'failed') {
                clearInterval(pollInterval);
                pollInterval = null;
                showReportError(result.error || '报告生成失败');
            }
            
            if (pollCount >= maxPollCount) {
                clearInterval(pollInterval);
                pollInterval = null;
                showReportError('报告生成超时');
            }
            
        } catch (error) {
            console.error('轮询失败:', error);
        }
    }, 3000);
}

function displayGeneratedReport(reportContent, generatedAt) {
    const reportText = safeGetElement('reportText');
    const reportContentDiv = safeGetElement('reportContent');
    const reportTime = safeGetElement('reportTime');
    
    if (reportTime) {
        reportTime.textContent = generatedAt ? new Date(generatedAt).toLocaleString() : new Date().toLocaleString();
    }
    
    if (reportText) {
        reportText.innerHTML = `<pre class="bg-light p-3 rounded" style="white-space: pre-wrap; word-break: break-word;">${escapeHtml(reportContent)}</pre>`;
    }
    
    if (reportContentDiv) reportContentDiv.style.display = 'block';
    
    const reportError = safeGetElement('reportError');
    if (reportError) reportError.style.display = 'none';
}

function showReportError(message) {
    const reportError = safeGetElement('reportError');
    const errorMessage = safeGetElement('errorMessage');
    
    if (errorMessage) errorMessage.textContent = message;
    if (reportError) reportError.style.display = 'block';
    
    safeToggleDisplay('reportLoading', false);
    safeToggleDisplay('reportContent', false);
    safeToggleDisplay('generateReportBtn', true);
}

function copyReport() {
    if (!currentSecurityReport?.content) {
        alert('没有可复制的报告内容');
        return;
    }
    
    navigator.clipboard.writeText(currentSecurityReport.content).then(() => {
        alert('报告已复制到剪贴板');
    }).catch(() => {
        alert('复制失败，请手动复制');
    });
}

function downloadReport() {
    if (!currentSecurityReport?.content) {
        alert('没有可下载的报告内容');
        return;
    }
    
    const blob = new Blob([currentSecurityReport.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `安全分析报告_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ====================== 域名分析相关函数 ======================
function normalizeSingleDomainResult(rawData) {
    const data = rawData && rawData.security_report ? rawData.security_report : rawData;
    
    let chain = [];
    if (Array.isArray(data?.chain_data)) {
        chain = data.chain_data;
    } else if (data?.certificate_chain && Array.isArray(data.certificate_chain)) {
        chain = data.certificate_chain;
    }
    
    let chartData = data?.chart_data;
    if (!chartData || !chartData.labels || chartData.labels.length === 0) {
        chartData = buildCountryChartDataFromChain(chain);
    }
    
    return {
        domain: data?.domain || '未知域名',
        chain_data: chain,
        chart_data: chartData,
        status: data?.status || 'success',
        error: data?.error || null
    };
}

function buildCountryChartDataFromChain(chain = []) {
    const stats = {};
    
    function normalizeCountryName(country) {
        const map = {
            'CN': '中国', 'US': '美国', 'BE': '比利时', 'GB': '英国',
            'DE': '德国', 'FR': '法国', 'JP': '日本', 'KR': '韩国',
            'SG': '新加坡', 'CA': '加拿大', 'AU': '澳大利亚', 'CH': '瑞士', 'NL': '荷兰'
        };
        return map[country] || country || '未知';
    }

    chain.forEach(cert => {
        const country = normalizeCountryName(cert.issuer_country);
        stats[country] = (stats[country] || 0) + 1;
    });

    const entries = Object.entries(stats)
        .filter(([name, count]) => name && count > 0)
        .sort((a, b) => b[1] - a[1]);

    return {
        labels: entries.map(([name]) => name),
        values: entries.map(([, count]) => count)
    };
}

function buildSingleDomainResultHtml(data) {
    const chain = data.chain_data || [];
    let outputText = `================================================================================\n`;
    outputText += `                 详细分析结果\n`;
    outputText += `================================================================================\n\n`;
    outputText += `1. 域名: ${data.domain}\n`;
    outputText += `   分析时间: ${new Date().toLocaleString()}\n`;
    outputText += `   分析状态: 成功\n`;
    outputText += `   证书链长度: ${chain.length}\n`;
    outputText += `   证书链详情:\n`;

    chain.forEach((cert) => {
        outputText += `     - ${cert.type} (#${cert.index})\n`;
        outputText += `       主题: ${cert.common_name || 'N/A'}\n`;
        outputText += `       颁发者: ${cert.issuer_common_name || 'N/A'}\n`;
        outputText += `       国家: ${normalizeCountryName(cert.issuer_country)}\n`;
        outputText += `       有效期: ${cert.not_before || 'N/A'} 至 ${cert.not_after || 'N/A'}\n`;
        outputText += `       序列号: ${cert.serial || 'N/A'}\n`;
    });
    outputText += `\n------------------------------------------------------------\n`;

    function normalizeCountryName(country) {
        const map = {
            'CN': '中国', 'US': '美国', 'BE': '比利时', 'GB': '英国',
            'DE': '德国', 'FR': '法国', 'JP': '日本', 'KR': '韩国',
            'SG': '新加坡', 'CA': '加拿大', 'AU': '澳大利亚', 'CH': '瑞士', 'NL': '荷兰'
        };
        return map[country] || country || '未知';
    }

    return `
        <div class="row">
            <div class="col-xl-8 col-lg-7 mb-4">
                <div class="card shadow h-100 border-left-primary">
                    <div class="card-header py-3">
                        <h6 class="m-0 font-weight-bold text-primary"><i class="fas fa-file-alt me-2"></i>证书链分析报告</h6>
                    </div>
                    <div class="card-body p-0">
                        <pre class="p-4 m-0 text-light" style="background-color: #2d2d2d; max-height: 500px; overflow-y: auto; font-size: 0.9rem; border-radius: 0 0 0.35rem 0.35rem; font-family: Consolas, monospace;">${escapeHtml(outputText)}</pre>
                    </div>
                </div>
            </div>
            <div class="col-xl-4 col-lg-5 mb-4">
                <div class="card shadow h-100 border-left-info">
                    <div class="card-header py-3">
                        <h6 class="m-0 font-weight-bold text-info"><i class="fas fa-chart-pie me-2"></i>证书颁发国家分布</h6>
                    </div>
                    <div class="card-body">
                        <div style="position: relative; height: 320px;">
                            <canvas id="certCountryPieChart"></canvas>
                        </div>
                        <div id="domainChartNoData" class="text-center py-4 text-muted" style="display:none;">暂无国家统计数据</div>
                        <div class="mt-4 text-center small text-muted">
                            基于提取到的 ${chain.length} 级证书颁发机构所在国家进行统计
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function initializeDomainCharts(chartData) {
    if (window.domainSecurityChart instanceof Chart) window.domainSecurityChart.destroy();
    if (window.domainFeaturesChart instanceof Chart) window.domainFeaturesChart.destroy();
    if (window.certCountryPieChart instanceof Chart) window.certCountryPieChart.destroy();

    const canvas = document.getElementById('certCountryPieChart');
    const noData = document.getElementById('domainChartNoData');

    if (!canvas) return;

    if (typeof Chart === 'undefined') {
        canvas.style.display = 'none';
        if (noData) {
            noData.style.display = 'block';
            noData.textContent = 'Chart.js 未加载，无法渲染图表';
        }
        return;
    }

    if (!chartData || !Array.isArray(chartData.labels) || chartData.labels.length === 0) {
        canvas.style.display = 'none';
        if (noData) noData.style.display = 'block';
        return;
    }

    canvas.style.display = 'block';
    if (noData) noData.style.display = 'none';

    window.certCountryPieChart = new Chart(canvas.getContext('2d'), {
        type: 'pie',
        data: {
            labels: chartData.labels,
            datasets: [{
                data: chartData.values,
                backgroundColor: ['#88D8C0', '#D6E95B', '#FFE666', '#4e73df', '#36b9cc', '#f6c23e', '#e74a3b'],
                hoverOffset: 6,
                borderWidth: 1,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { font: { size: 13 } }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round(value / total * 100) : 0;
                            return `${context.label}: ${value}个 (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// ====================== 结果Tab切换 ======================
function switchResultTab(tabName, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const buttons = container.querySelectorAll('.result-tab-btn');
    buttons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    const contents = container.querySelectorAll('.results-tab-content');
    contents.forEach(content => {
        content.classList.toggle('active', content.dataset.tabContent === tabName);
    });
}

function generateResultsWithTabsHTML(resultId, isLoading = false) {
    const chartTabDisplay = isLoading ? 'style="display:none;"' : '';
    const domainTabDisplay = isLoading ? 'style="display:none;"' : '';
    const reportTabDisplay = isLoading ? 'style="display:none;"' : '';
    
    return `
    <div class="row">
        <div class="col-12 mb-4">
            <div id="scoreCard"></div>
        </div>
    </div>
    <div class="row mb-4">
        <div class="col-12">
            <div id="${resultId}" data-result-type="security">
                <div class="results-tabs" id="${resultId}_tabs">
                    <button class="result-tab-btn active" data-tab="basic" onclick="switchResultTab('basic', '${resultId}')">
                        <i class="fas fa-info-circle"></i> 基本信息
                    </button>
                    <button class="result-tab-btn" data-tab="chart" onclick="switchResultTab('chart', '${resultId}')" ${chartTabDisplay}>
                        <i class="fas fa-chart-bar"></i> 图表分析
                    </button>
                    <button class="result-tab-btn" data-tab="domain" onclick="switchResultTab('domain', '${resultId}')" ${domainTabDisplay}>
                        <i class="fas fa-globe"></i> 域名详情
                    </button>
                    <button class="result-tab-btn" data-tab="report" onclick="switchResultTab('report', '${resultId}')" ${reportTabDisplay}>
                        <i class="fas fa-file-alt"></i> 智能分析报告
                    </button>
                </div>
                <div class="results-tab-content active" data-tab-content="basic" id="${resultId}_basic">
                    <div class="tab-content-title"><i class="fas fa-info-circle me-2"></i>基本信息</div>
                    <div id="detailedFindings"></div>
                </div>
                <div class="results-tab-content" data-tab-content="chart" id="${resultId}_chart">
                    <div class="tab-content-title"><i class="fas fa-chart-bar me-2"></i>图表分析</div>
                    <div id="chartSection"></div>
                </div>
                <div class="results-tab-content" data-tab-content="domain" id="${resultId}_domain">
                    <div class="tab-content-title"><i class="fas fa-globe me-2"></i>域名详情</div>
                    <div id="domainDetails"></div>
                </div>
                <div class="results-tab-content" data-tab-content="report" id="${resultId}_report">
                    <div class="tab-content-title"><i class="fas fa-file-alt me-2"></i>智能分析报告</div>
                    <div id="securityReport"></div>
                </div>
            </div>
        </div>
    </div>`;
}

function initializeResultCharts(report) {
    if (window.resultSecurityChart) {
        window.resultSecurityChart.destroy();
    }
    if (window.resultFeaturesChart) {
        window.resultFeaturesChart.destroy();
    }

    const summary = report.summary || {};
    const scoreDistribution = report.scoreDistribution || [0, 0, 0, 0];
    const total = summary.analyzed_domains || 1;

    const securityCtx = document.getElementById('securityChart');
    if (securityCtx && typeof Chart !== 'undefined') {
        window.resultSecurityChart = new Chart(securityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['优秀 (80-100)', '良好 (60-79)', '一般 (40-59)', '较差 (0-39)'],
                datasets: [{
                    data: scoreDistribution,
                    backgroundColor: ['#28a745', '#20c997', '#ffc107', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }

    const featuresCtx = document.getElementById('featuresChart');
    if (featuresCtx && typeof Chart !== 'undefined') {
        window.resultFeaturesChart = new Chart(featuresCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['HTTPS强制', 'HSTS保护', '安全头', '证书链'],
                datasets: [{
                    label: '通过率 (%)',
                    data: [
                        Math.round((summary.domains_with_https_enforcement || 0) / total * 100),
                        Math.round((summary.domains_with_hsts || 0) / total * 100),
                        Math.round((summary.domains_with_good_security_headers || 0) / total * 100),
                        Math.round((summary.domains_with_valid_certificate_chains || 0) / total * 100)
                    ],
                    backgroundColor: ['rgba(40,167,69,0.8)', 'rgba(32,201,151,0.8)', 'rgba(255,193,7,0.8)', 'rgba(0,123,255,0.8)']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: { y: { beginAtZero: true, max: 100 } },
                plugins: { legend: { display: false } }
            }
        });
    }
}

// ====================== AI 报告生成相关函数 ======================
let currentAiReportTaskId = null;
let aiReportPollInterval = null;

async function generateAiReport(reportData, reportType) {
    console.log(`[AI报告] 开始生成${reportType === 'security' ? '安全分析' : '域名分析'}报告...`);

    const tabReportEl = document.getElementById('securityReport');
    if (tabReportEl) {
        tabReportEl.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border mb-3" role="status" style="color: var(--tech-green) !important;">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p style="color: var(--text-secondary);">正在生成AI深度分析报告...</p>
                <p style="color: var(--text-muted); font-size: 0.85rem;">基于DeepSeek AI分析，请稍候</p>
            </div>
        `;
    }

    try {
        const payload = JSON.parse(JSON.stringify(reportData));
        payload.report_type = reportType === 'domain' ? 'certificate' : 'security';

        const response = await fetch(getApiUrl('/api/security/generate-report'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.status === 'processing' && data.task_id) {
            console.log(`[AI报告] 任务已提交: ${data.task_id}`);
            pollReportStatus(data.task_id, reportType);
        } else {
            throw new Error('未获取到任务ID');
        }
    } catch (error) {
        console.error('[AI报告] 提交失败:', error);
        if (tabReportEl) {
            tabReportEl.innerHTML = `
                <div class="alert" style="background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); color: #F87171;">
                    <h5><i class="fas fa-exclamation-circle me-2"></i>报告生成失败</h5>
                    <p>${escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }
}

async function pollReportStatus(taskId, reportType) {
    const maxRetries = 60;
    const intervalMs = 3000;

    for (let i = 0; i < maxRetries; i++) {
        await new Promise(r => setTimeout(r, intervalMs));

        try {
            const response = await fetch(getApiUrl(`/api/security/report-status/${taskId}`));
            if (!response.ok) continue;

            const data = await response.json();

            if (data.status === 'completed') {
                console.log('[AI报告] 报告生成完成');
                updateReportContent(reportType, data.report_content, true);
                return;
            } else if (data.status === 'failed') {
                console.error('[AI报告] 报告生成失败:', data.error);
                updateReportContent(reportType, null, false);
                return;
            }
        } catch (error) {
            console.warn('[AI报告] 轮询请求失败:', error);
        }
    }

    console.warn('[AI报告] 轮询超时');
    updateReportContent(reportType, null, false);
}

function updateReportContent(reportType, content, success) {
    const tabReportEl = document.getElementById('securityReport');
    if (!tabReportEl) return;

    if (success && content) {
        if (typeof marked !== 'undefined') {
            tabReportEl.innerHTML = marked.parse(content);
        } else {
            tabReportEl.innerHTML = `<pre style="white-space:pre-wrap;word-wrap:break-word;margin:0;font-size:0.85rem;line-height:1.6;color:var(--text-secondary);">${escapeHtml(content)}</pre>`;
        }

        const titleEl = tabReportEl.parentElement?.querySelector('.tab-content-title');
        if (titleEl && !titleEl.querySelector('.ai-report-badge')) {
            titleEl.innerHTML += ` <span class="ai-report-badge" style="display:inline-flex;align-items:center;gap:6px;margin-left:12px;padding:4px 12px;border-radius:20px;background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.2);color:#34D399;font-size:0.75rem;font-weight:600;"><span style="width:6px;height:6px;border-radius:50%;background:#34D399;"></span>AI报告已生成</span>`;
        }
    } else {
        tabReportEl.innerHTML = `
            <div class="alert" style="background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); color: #F87171;">
                <h5><i class="fas fa-exclamation-circle me-2"></i>报告生成失败</h5>
                <p>AI报告生成过程中出现错误，请稍后重试。</p>
            </div>
        `;
    }
}

// ====================== FAQ Stripe风格卡片轮播 ======================
let faqStripeTranslate = 0;

function moveFaqStripe(direction) {
    const track = document.getElementById('faqStripeTrack');
    if (!track) return;
    
    const viewport = track.parentElement;
    const viewportWidth = viewport.clientWidth;
    const trackWidth = track.scrollWidth;
    const cardStep = 380;
    const maxTranslate = Math.max(0, trackWidth - viewportWidth);
    
    faqStripeTranslate += direction * cardStep;
    faqStripeTranslate = Math.max(0, Math.min(faqStripeTranslate, maxTranslate));
    
    track.style.transform = `translateX(-${faqStripeTranslate}px)`;
    updateFaqStripeButtons(faqStripeTranslate, maxTranslate);
}

function updateFaqStripeButtons(current, max) {
    const prevBtn = document.getElementById('faqPrevBtn');
    const nextBtn = document.getElementById('faqNextBtn');
    
    if (prevBtn) {
        prevBtn.classList.toggle('disabled', current <= 0);
    }
    if (nextBtn) {
        nextBtn.classList.toggle('disabled', current >= max - 5);
    }
}

// 拖拽滚动支持
(function initFaqStripeDrag() {
    const viewport = document.querySelector('.faq-stripe-viewport');
    const track = document.getElementById('faqStripeTrack');
    if (!viewport || !track) return;
    
    let isDown = false;
    let startX = 0;
    let startTranslate = 0;
    
    viewport.addEventListener('mousedown', (e) => {
        isDown = true;
        viewport.style.cursor = 'grabbing';
        track.style.transition = 'none';
        startX = e.pageX;
        startTranslate = faqStripeTranslate;
    });
    
    viewport.addEventListener('mouseleave', () => {
        if (!isDown) return;
        isDown = false;
        viewport.style.cursor = 'grab';
        track.style.transition = 'transform 0.7s cubic-bezier(0.23, 1, 0.32, 1)';
        snapFaqStripe();
    });
    
    viewport.addEventListener('mouseup', () => {
        if (!isDown) return;
        isDown = false;
        viewport.style.cursor = 'grab';
        track.style.transition = 'transform 0.7s cubic-bezier(0.23, 1, 0.32, 1)';
        snapFaqStripe();
    });
    
    viewport.addEventListener('mousemove', (e) => {
        if (!isDown) return;
        e.preventDefault();
        const x = e.pageX;
        const walk = startX - x;
        const maxTranslate = Math.max(0, track.scrollWidth - viewport.clientWidth);
        faqStripeTranslate = Math.max(0, Math.min(startTranslate + walk, maxTranslate));
        track.style.transform = `translateX(-${faqStripeTranslate}px)`;
    });
    
    function snapFaqStripe() {
        const cardStep = 380;
        const maxTranslate = Math.max(0, track.scrollWidth - viewport.clientWidth);
        faqStripeTranslate = Math.round(faqStripeTranslate / cardStep) * cardStep;
        faqStripeTranslate = Math.max(0, Math.min(faqStripeTranslate, maxTranslate));
        track.style.transform = `translateX(-${faqStripeTranslate}px)`;
        updateFaqStripeButtons(faqStripeTranslate, maxTranslate);
    }
    
    setTimeout(() => updateFaqStripeButtons(0, track.scrollWidth - viewport.clientWidth), 500);
})();

// ====================== 全局函数导出 ======================
window.escapeHtml = escapeHtml;
window.formatFileSize = formatFileSize;
window.safeToggleDisplay = safeToggleDisplay;
window.resetSecurityAnalysis = resetSecurityAnalysis;
window.processPcapAnalysis = processPcapAnalysis;
window.processCertificateAnalysis = processCertificateAnalysis;
window.displaySecurityReport = displaySecurityReport;
window.toggleQuickStart = toggleQuickStart;
window.moveFaqStripe = moveFaqStripe;
window.switchResultTab = switchResultTab;
window.generateResultsWithTabsHTML = generateResultsWithTabsHTML;

console.log('security.js 完整版加载完成');