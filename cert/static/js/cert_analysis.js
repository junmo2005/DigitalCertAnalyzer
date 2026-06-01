/* =============================================
   证链智审 — 证书分析核心引擎
   Three.js星云 · 3D棱镜 · 3D证书球 · 图表
   ============================================= */

const G = {
    data: null, report: null, charts: {}, solarAnim: null, prismAngle: 0,
    solarScene: null, solarCamera: null, solarRenderer: null, solarMeshes: [],
    solarGroup: null
};

const PAL = {
    chart: ['#0d9488','#06b6d4','#14b8a6','#3b82f6','#10b981','#f59e0b','#ec4899','#8b5cf6'],
    valid: '#10b981', warn: '#f59e0b', danger: '#ef4444',
    label: '#475569', grid: 'rgba(20,184,166,0.15)'
};

document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => { initNebula(); }, 200);
    initPrismDrag();
    initTabs();
    initUploads();
});

// ==================== 星云粒子系统 ====================
function initNebula() {
    const container = document.getElementById('nebula-bg');
    if (!container) { console.error('nebula-bg not found'); return; }
    if (!window.THREE) { console.error('Three.js not loaded'); return; }

    container.innerHTML = '';

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 5000);
    camera.position.z = 1500;

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.display = 'block';
    container.appendChild(renderer.domElement);

    const glowTexture = createGlowTexture();

    const TOTAL = 2500;
    const STARDUST = 400;
    const MAIN = Math.floor((TOTAL - STARDUST) * 0.70);
    const ACCENT = Math.floor((TOTAL - STARDUST) * 0.20);
    const HIGHLIGHT = TOTAL - STARDUST - MAIN - ACCENT;

    const C_MAIN = new THREE.Color('#0d3f8c');
    const C_ACCENT = new THREE.Color('#592680');
    const C_HIGH = new THREE.Color('#0d734d');
    const C_STAR1 = new THREE.Color('#808ca6');
    const C_STAR2 = new THREE.Color('#8c8099');
    const C_CYAN = new THREE.Color('#008ca6');

    const sprites = [];
    const origins = [];
    const types = [];

    function nebulaPos() {
        const r3 = Math.random();
        const r = 100 + Math.sqrt(r3) * 2000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        return new THREE.Vector3(
            r * Math.sin(phi) * Math.cos(theta),
            r * Math.sin(phi) * Math.sin(theta),
            r * Math.cos(phi)
        );
    }

    function createSprite(pos, color, size, type) {
        const material = new THREE.SpriteMaterial({
            map: glowTexture,
            color: color,
            transparent: true,
            opacity: 0.9,
            depthWrite: false,
            blending: THREE.NormalBlending
        });
        const sprite = new THREE.Sprite(material);
        sprite.position.copy(pos);
        sprite.scale.set(size, size, 1);
        scene.add(sprite);
        sprites.push(sprite);
        origins.push(pos.clone());
        types.push(type);
        return sprite;
    }

    for (let i = 0; i < MAIN; i++) {
        createSprite(nebulaPos(), C_MAIN, 2.5 + Math.random() * 1.875, 0);
    }
    for (let i = 0; i < ACCENT; i++) {
        createSprite(nebulaPos(), C_ACCENT, 3.4375 + Math.random() * 2.1875, 1);
    }
    for (let i = 0; i < HIGHLIGHT; i++) {
        createSprite(nebulaPos(), C_HIGH, 4.375 + Math.random() * 2.5, 2);
    }
    for (let i = 0; i < STARDUST; i++) {
        const r = 150 + Math.random() * 2200;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        const c = Math.random() > 0.5 ? C_STAR1 : C_STAR2;
        createSprite(new THREE.Vector3(
            r * Math.sin(phi) * Math.cos(theta),
            r * Math.sin(phi) * Math.sin(theta),
            r * Math.cos(phi)
        ), c, 1.25 + Math.random() * 0.9375, 3);
    }

    let mx = 0, my = 0, mActive = false;
    document.addEventListener('mousemove', e => {
        mx = (e.clientX - window.innerWidth/2) * 0.8;
        my = -(e.clientY - window.innerHeight/2) * 0.8;
        mActive = true;
    });

    let targetCollapse = 0, currentCollapse = 0;
    window.addEventListener('scroll', () => {
        targetCollapse = Math.min(window.scrollY / (window.innerHeight * 1.5), 1);
    });

    let frame = 0;

    function animate() {
        requestAnimationFrame(animate);
        frame++;
        const t = frame * 0.00015;
        const rotY = 0.00008;
        const rotX = 0.00003;
        currentCollapse += (targetCollapse - currentCollapse) * 0.02;

        for (let i = 0; i < sprites.length; i++) {
            const sprite = sprites[i];
            const orig = origins[i];
            const type = types[i];

            const driftX = Math.sin(t + i * 0.13) * 1.5;
            const driftY = Math.cos(t + i * 0.09) * 1.2;
            const driftZ = Math.sin(t * 0.7 + i * 0.17) * 0.8;

            let shrink = 1.0;
            let brightnessBoost = 1.0;
            if (currentCollapse > 0.01) {
                shrink = 1 - currentCollapse * 0.4;
                brightnessBoost = 1 + currentCollapse * 0.3;
                if (type === 2) brightnessBoost += currentCollapse * 0.4;
            }

            let tx = orig.x * shrink + driftX;
            let ty = orig.y * shrink + driftY;
            let tz = orig.z * shrink + driftZ;

            if (mActive && currentCollapse < 0.6) {
                const dx = mx - sprite.position.x;
                const dy = my - sprite.position.y;
                const dist = Math.sqrt(dx*dx + dy*dy);
                const influenceR = 500 + (type === 3 ? 200 : 0);
                if (dist < influenceR) {
                    const pull = (1 - dist/influenceR) * 0.06 * (type === 3 ? 0.3 : 1.0);
                    tx += dx * pull;
                    ty += dy * pull;
                    sprite.material.color.set(C_CYAN);
                    sprite.material.opacity = 0.95;
                } else {
                    if (type === 0) sprite.material.color.set(C_MAIN);
                    else if (type === 1) sprite.material.color.set(C_ACCENT);
                    else if (type === 2) sprite.material.color.set(C_HIGH);
                    else sprite.material.color.set(Math.random() > 0.5 ? C_STAR1 : C_STAR2);
                    sprite.material.opacity = 0.9 * brightnessBoost;
                }
            } else {
                if (type === 0) sprite.material.color.set(C_MAIN);
                else if (type === 1) sprite.material.color.set(C_ACCENT);
                else if (type === 2) sprite.material.color.set(C_HIGH);
                else sprite.material.color.set(Math.random() > 0.5 ? C_STAR1 : C_STAR2);
                sprite.material.opacity = 0.9 * brightnessBoost;
            }

            const cosY = Math.cos(rotY);
            const sinY = Math.sin(rotY);
            const cosX = Math.cos(rotX);
            const sinX = Math.sin(rotX);

            const x = tx * cosY - tz * sinY;
            const z = tx * sinY + tz * cosY;
            const y = ty * cosX - z * sinX;
            const z2 = ty * sinX + z * cosX;

            sprite.position.x += (x - sprite.position.x) * 0.035;
            sprite.position.y += (y - sprite.position.y) * 0.035;
            sprite.position.z += (z2 - sprite.position.z) * 0.035;
        }

        camera.position.x += (mx * 0.15 - camera.position.x) * 0.012;
        camera.position.y += (-my * 0.15 - camera.position.y) * 0.012;
        camera.lookAt(0, 0, 0);
        renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

function createGlowTexture() {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 256;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, 256, 256);
    const grad = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
    grad.addColorStop(0, 'rgba(255,255,255,1)');
    grad.addColorStop(0.15, 'rgba(255,255,255,0.9)');
    grad.addColorStop(0.4, 'rgba(255,255,255,0.5)');
    grad.addColorStop(0.7, 'rgba(255,255,255,0.1)');
    grad.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 256, 256);
    const texture = new THREE.CanvasTexture(canvas);
    texture.needsUpdate = true;
    texture.minFilter = THREE.LinearFilter;
    texture.magFilter = THREE.LinearFilter;
    texture.format = THREE.RGBAFormat;
    texture.type = THREE.UnsignedByteType;
    return texture;
}

// ==================== 3D 棱镜 ====================
function spinPrism(angle) {
    G.prismAngle = angle;
    const prism = document.getElementById('prism');
    if (prism) prism.style.transform = `rotateY(${angle}deg)`;
    document.querySelectorAll('.prism-dots .dot').forEach((d, i) => {
        d.classList.toggle('active', Math.abs(angle - [0, -120, 120][i]) < 10);
    });
}

function initPrismDrag() {
    const box = document.querySelector('.prism-box');
    const prism = document.getElementById('prism');
    if (!box || !prism) return;

    let dragging = false, startX = 0, startAngle = 0;

    box.addEventListener('mousedown', e => {
        dragging = true;
        startX = e.clientX;
        startAngle = G.prismAngle;
        box.style.cursor = 'grabbing';
    });
    document.addEventListener('mousemove', e => {
        if (!dragging) return;
        const dx = e.clientX - startX;
        prism.style.transform = `rotateY(${startAngle + dx * 0.4}deg)`;
    });
    document.addEventListener('mouseup', () => {
        if (!dragging) return;
        dragging = false;
        box.style.cursor = '';
        const match = prism.style.transform.match(/rotateY\(([-\d.]+)deg\)/);
        const currentRot = match ? parseFloat(match[1]) : 0;
        const norm = ((currentRot % 360) + 360) % 360;
        let target = 0;
        if (norm >= 60 && norm < 180) target = 120;
        else if (norm >= 180 && norm < 300) target = -120;
        else target = Math.round(currentRot / 360) * 360;
        spinPrism(target);
    });
    box.addEventListener('touchstart', e => {
        dragging = true;
        startX = e.touches[0].clientX;
        startAngle = G.prismAngle;
    }, { passive: true });
    document.addEventListener('touchmove', e => {
        if (!dragging) return;
        const dx = e.touches[0].clientX - startX;
        prism.style.transform = `rotateY(${startAngle + dx * 0.4}deg)`;
    }, { passive: true });
    document.addEventListener('touchend', () => {
        if (!dragging) return;
        dragging = false;
        const match = prism.style.transform.match(/rotateY\(([-\d.]+)deg\)/);
        const currentRot = match ? parseFloat(match[1]) : 0;
        const norm = ((currentRot % 360) + 360) % 360;
        let target = 0;
        if (norm >= 60 && norm < 180) target = 120;
        else if (norm >= 180 && norm < 300) target = -120;
        else target = Math.round(currentRot / 360) * 360;
        spinPrism(target);
    });
}

function showLoader(type) {
    ['pcap','batch','zip'].forEach(t => {
        const el = document.getElementById(t + 'Loader');
        if (el) el.style.display = 'none';
    });
    const el = document.getElementById(type + 'Loader');
    if (el) el.style.display = 'flex';
}
function hideLoaders() {
    ['pcap','batch','zip'].forEach(t => {
        const el = document.getElementById(t + 'Loader');
        if (el) el.style.display = 'none';
    });
}

function initTabs() {
    document.querySelectorAll('.rtab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.rpanel').forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            const panel = document.getElementById(tab.dataset.tab + 'Panel');
            if (panel) panel.classList.add('active');
            setTimeout(() => Object.values(G.charts).forEach(c => c?.resize?.()), 100);
        });
    });
}

function initUploads() {
    setupDrop('pcapDrop', 'pcapFile', 'pcapName');
    setupDrop('batchDrop', 'batchFiles', 'batchName', true);
    setupDrop('zipDrop', 'zipFile', 'zipName');
}

function setupDrop(dropId, inputId, nameId, isBatch) {
    const drop = document.getElementById(dropId);
    const input = document.getElementById(inputId);
    const nameEl = document.getElementById(nameId);
    if (!drop || !input) return;

    drop.addEventListener('click', () => input.click());
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('dragover'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop.addEventListener('drop', e => {
        e.preventDefault();
        drop.classList.remove('dragover');
        input.files = e.dataTransfer.files;
        input.dispatchEvent(new Event('change'));
    });
    input.addEventListener('change', function() {
        if (isBatch) {
            const list = document.getElementById('batchList');
            list.innerHTML = '';
            for (let f of this.files) {
                const d = document.createElement('div');
                d.className = 'batch-tag';
                d.textContent = f.name;
                list.appendChild(d);
            }
        }
        if (nameEl && this.files.length > 0) {
            const f = this.files[0];
            const mb = (f.size / (1024*1024)).toFixed(2);
            nameEl.innerHTML = `${f.name} <span style="color:var(--t4)">(${mb}MB)</span>`;
        }
    });
}

async function uploadPcap() {
    const input = document.getElementById('pcapFile');
    if (!input?.files[0]) { showErr('请选择PCAP文件'); return; }
    const file = input.files[0];
    if (file.size > 520*1024*1024) { showErr('文件超过520MB'); return; }
    await doUpload('/upload-pcap', 'pcap', { file, extra: [['force_parse','true']] });
}

async function uploadBatch() {
    const input = document.getElementById('batchFiles');
    if (!input?.files.length) { showErr('请选择证书文件'); return; }
    const fd = new FormData();
    for (let f of input.files) {
        if (f.size > 520*1024*1024) { showErr(`${f.name} 超过520MB`); return; }
        fd.append('files[]', f);
    }
    await doUpload('/batch-analyze', 'batch', { formData: fd });
}

async function uploadZip() {
    const input = document.getElementById('zipFile');
    if (!input?.files[0]) { showErr('请选择压缩包'); return; }
    const file = input.files[0];
    if (file.size > 520*1024*1024) { showErr('文件超过520MB'); return; }
    await doUpload('/upload-zip', 'zip', { file });
}

async function doUpload(url, type, { file, formData, extra }) {
    showLoader(type);
    hideErr();
    const sec = document.getElementById('resultSec');
    if (sec) sec.style.display = 'none';
    killSolar();
    killCharts();

    try {
        let fd = formData;
        if (!fd) {
            fd = new FormData();
            fd.append('file', file);
            if (extra) extra.forEach(([k, v]) => fd.append(k, v));
        }
        const res = await fetch(url, { method: 'POST', body: fd });
        const ct = res.headers.get('content-type');
        if (!ct?.includes('json')) { const t = await res.text(); throw new Error('非JSON: ' + t.slice(0,60)); }
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        data.source_type = type;
        G.data = data;

        setTimeout(() => {
            hideLoaders();
            showResults(data);
        }, 1200);
    } catch (e) {
        hideLoaders();
        showErr(e.message);
    }
}

function showResults(data) {
    const sec = document.getElementById('resultSec');
    if (!sec) return;
    sec.style.display = 'block';

    document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.rpanel').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="solar"]')?.classList.add('active');
    document.getElementById('solarPanel')?.classList.add('active');

    initSolar(data);
    renderCharts(data);
    renderDetails(data);

    sec.scrollIntoView({ behavior: 'smooth' });
}

// ==================== 3D 证书球（基于统计数据生成）====================
function initSolar(data) {
    const a = data.analysis || data;
    const container = document.getElementById('solarPanel');
    if (!container) return;

    const canvasContainer = container.querySelector('.solar-wrap');
    if (!canvasContainer) return;
    canvasContainer.innerHTML = '';

    // 创建弹窗元素（先创建，确保在canvas之上）
    const modalEl = document.createElement('div');
    modalEl.className = 'planet-modal';
    modalEl.id = 'planetModal';
    modalEl.innerHTML = `
        <button class="modal-close" onclick="closePlanet()">
            <i class="fas fa-times"></i>
        </button>
        <div class="planet-detail-scroll" id="planetContent"></div>
    `;
    canvasContainer.appendChild(modalEl);

    // ===== Three.js 场景 =====
    const scene = new THREE.Scene();
    const W = canvasContainer.clientWidth || 800;
    const H = canvasContainer.clientHeight || 600;

    const camera = new THREE.PerspectiveCamera(50, W / H, 1, 5000);
    camera.position.set(0, 0, 900);

    const renderer = new THREE.WebGLRenderer({ alpha: false, antialias: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.display = 'block';
    canvasContainer.appendChild(renderer.domElement);
    renderer.setClearColor(0x0a0f1a, 1);

    // ===== 证书数据 =====
    let certs = a.cert_details || [];

    // 如果没有 cert_details，根据统计数据生成虚拟数据（兼容旧逻辑）
    const total = a.total_certificates || 0;
    const validCount = a.valid_certificates || 0;
    const warnCount = a.expiring_soon_certificates || 0;
    const expiredCount = a.expired_certificates || 0;


    // 如果 cert_details 为空，根据统计数据生成虚拟证书列表
    if (certs.length === 0 && total > 0) {
        certs = [];
        for (let i = 0; i < validCount; i++) {
            certs.push({
                status: 'valid',
                is_expired: false,
                is_expiring_soon: false,
                idx: i,
                subject_cn: `证书 ${i + 1}`,
                issuer_cn: '未知颁发者',
                serial_number: 'N/A',
                not_before: '-',
                not_after: '-',
                key_algorithm: '-',
                key_size: '-',
                signature_algorithm: '-',
                days_remaining: 365,
                days_valid: 365,
                san_list: [],
                key_usage: '-'
            });
        }
        for (let i = 0; i < warnCount; i++) {
            certs.push({
                status: 'warn',
                is_expired: false,
                is_expiring_soon: true,
                idx: validCount + i,
                subject_cn: `证书 ${validCount + i + 1}`,
                issuer_cn: '未知颁发者',
                serial_number: 'N/A',
                not_before: '-',
                not_after: '-',
                key_algorithm: '-',
                key_size: '-',
                signature_algorithm: '-',
                days_remaining: 15,
                days_valid: 365,
                san_list: [],
                key_usage: '-'
            });
        }
        for (let i = 0; i < expiredCount; i++) {
            certs.push({
                status: 'expired',
                is_expired: true,
                is_expiring_soon: false,
                idx: validCount + warnCount + i,
                subject_cn: `证书 ${validCount + warnCount + i + 1}`,
                issuer_cn: '未知颁发者',
                serial_number: 'N/A',
                not_before: '-',
                not_after: '-',
                key_algorithm: '-',
                key_size: '-',
                signature_algorithm: '-',
                days_remaining: -30,
                days_valid: 365,
                san_list: [],
                key_usage: '-'
            });
        }
    }

    // 更新右侧统计面板
    updateStatsPanel({
        unique: total,
        valid: validCount,
        warn: warnCount,
        expired: expiredCount
    });

    // ===== 3D 证书球 =====
    const sphereGroup = new THREE.Group();
    scene.add(sphereGroup);

    const SPHERE_RADIUS = 320;
    const meshes = [];
    G.solarMeshes = meshes;

    const C_VALID = 0x10b981;
    const C_WARN = 0xfbbf24;
    const C_EXPIRED = 0xef4444;
    const C_HOVER = 0x22d3ee;

    if (certs.length > 0) {
        const positions = fibonacciSphere(certs.length, SPHERE_RADIUS);

        certs.forEach((cert, idx) => {
            const pos = positions[idx];

            let status, color, size;
            if (cert.is_expired || cert.status === 'expired') {
                status = 'expired';
                color = C_EXPIRED;
                size = 3.5;
            } else if (cert.is_expiring_soon || cert.status === 'warn') {
                status = 'warn';
                color = C_WARN;
                size = 4.0;
            } else {
                status = 'valid';
                color = C_VALID;
                size = 4.5;
            }

            const geometry = new THREE.SphereGeometry(size, 16, 16);
            const material = new THREE.MeshBasicMaterial({
                color: color,
                transparent: true,
                opacity: 0.9
            });
            const mesh = new THREE.Mesh(geometry, material);
            mesh.position.set(pos.x, pos.y, pos.z);

            const glowGeo = new THREE.SphereGeometry(size * 2.2, 16, 16);
            const glowMat = new THREE.MeshBasicMaterial({
                color: color,
                transparent: true,
                opacity: 0.15,
                blending: THREE.AdditiveBlending,
                depthWrite: false
            });
            const glowMesh = new THREE.Mesh(glowGeo, glowMat);
            glowMesh.position.copy(mesh.position);
            sphereGroup.add(glowMesh);

            mesh.userData = {
                cert: cert,
                idx: idx,
                type: status,
                originalColor: color,
                originalScale: mesh.scale.clone(),
                glowMesh: glowMesh,
                originalGlowScale: glowMesh.scale.clone()
            };

            sphereGroup.add(mesh);
            meshes.push(mesh);
        });
    }
    
    console.log('Meshes created:', meshes.length);

    if (certs.length === 0) {
        const sprite = createTextSprite('暂无证书数据', '#94a3b8');
        if (sprite) {
            sprite.position.set(0, 0, 0);
            scene.add(sprite);
        }
    }

    // ===== 中心发光体 =====
    const sunGroup = new THREE.Group();
    scene.add(sunGroup);

    const sunCore = new THREE.Mesh(
        new THREE.SphereGeometry(18, 32, 32),
        new THREE.MeshBasicMaterial({ color: 0xffffff })
    );
    sunGroup.add(sunCore);

    const glows = [
        { r: 45, color: 0x60a5fa, opacity: 0.4 },
        { r: 80, color: 0xa78bfa, opacity: 0.2 },
        { r: 130, color: 0x0d9488, opacity: 0.08 }
    ];
    glows.forEach(g => {
        const mesh = new THREE.Mesh(
            new THREE.SphereGeometry(g.r, 32, 32),
            new THREE.MeshBasicMaterial({
                color: g.color,
                transparent: true,
                opacity: g.opacity,
                blending: THREE.AdditiveBlending,
                depthWrite: false
            })
        );
        sunGroup.add(mesh);
    });

    scene.add(new THREE.PointLight(0xffffff, 1.2, 800));
    scene.add(new THREE.AmbientLight(0x1a2a4a, 0.4));

    // ===== 交互系统（修复版）=====
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-999, -999); // 初始值在屏幕外
    let hoveredMesh = null;
    let isDragging = false;
    let mouseDownTime = 0;
    let mouseDownPos = { x: 0, y: 0 };
    let sphereRotationX = 0;
    let sphereRotationY = 0;
    let targetRotationX = 0;
    let targetRotationY = 0;
    let autoRotate = true;

    // 鼠标按下
    renderer.domElement.addEventListener('mousedown', (e) => {
        isDragging = false;
        mouseDownTime = Date.now();
        mouseDownPos = { x: e.clientX, y: e.clientY };
        renderer.domElement.style.cursor = 'grab';
    });

    // 鼠标移动
    renderer.domElement.addEventListener('mousemove', (e) => {
        const rect = renderer.domElement.getBoundingClientRect();
        mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

        // 检测是否开始拖拽（移动超过5像素）
        if (mouseDownTime > 0) {
            const dx = e.clientX - mouseDownPos.x;
            const dy = e.clientY - mouseDownPos.y;
            if (Math.abs(dx) > 5 || Math.abs(dy) > 5) {
                isDragging = true;
                renderer.domElement.style.cursor = 'grabbing';
                targetRotationY = sphereRotationY + dx * 0.008;
                targetRotationX = sphereRotationX + dy * 0.008;
                autoRotate = false;
            }
        }
    });

    // 鼠标松开
    renderer.domElement.addEventListener('mouseup', (e) => {
        const clickDuration = Date.now() - mouseDownTime;
        const dx = e.clientX - mouseDownPos.x;
        const dy = e.clientY - mouseDownPos.y;
        const distance = Math.sqrt(dx*dx + dy*dy);

        sphereRotationX = targetRotationX;
        sphereRotationY = targetRotationY;
        mouseDownTime = 0;
        renderer.domElement.style.cursor = 'default';

        // 判断为点击（时间短且移动距离小）
        if (!isDragging && clickDuration < 300 && distance < 5) {
            console.log('Click detected, checking intersects...');
            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(meshes);
            console.log('Intersects count:', intersects.length);

            if (intersects.length > 0) {
                const mesh = intersects[0].object;
                console.log('Clicked mesh:', mesh.userData.type, 'idx:', mesh.userData.idx);
                openPlanetDetail(mesh.userData);
            }
        }

        isDragging = false;
        setTimeout(() => { autoRotate = true; }, 3000);
    });

    renderer.domElement.addEventListener('mouseleave', () => {
        isDragging = false;
        mouseDownTime = 0;
        renderer.domElement.style.cursor = 'default';
    });

    // ===== 动画循环 =====
    let frame = 0;
    function animate() {
        G.solarAnim = requestAnimationFrame(animate);
        frame++;
        const t = frame * 0.001;

        if (autoRotate && !isDragging) {
            targetRotationY += 0.0015;
        }

        sphereGroup.rotation.y += (targetRotationY - sphereGroup.rotation.y) * 0.05;
        sphereGroup.rotation.x += (targetRotationX - sphereGroup.rotation.x) * 0.05;

        sunGroup.children.forEach((child, i) => {
            if (i > 0) {
                const pulse = 1 + Math.sin(t * (2 - i * 0.3) + i) * 0.06;
                child.scale.setScalar(pulse);
            }
        });
        sunGroup.rotation.y += 0.001;

        // 悬停检测（仅在非拖拽时）
        if (!isDragging) {
            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(meshes);

            meshes.forEach(mesh => {
                if (mesh !== hoveredMesh) {
                    mesh.material.color.setHex(mesh.userData.originalColor);
                    mesh.material.opacity = 0.9;
                    const targetScale = mesh.userData.originalScale.clone();
                    mesh.scale.lerp(targetScale, 0.1);
                    if (mesh.userData.glowMesh) {
                        mesh.userData.glowMesh.material.opacity = 0.15;
                        mesh.userData.glowMesh.scale.lerp(mesh.userData.originalGlowScale, 0.1);
                    }
                }
            });

            if (intersects.length > 0) {
                const mesh = intersects[0].object;
                hoveredMesh = mesh;
                mesh.material.color.setHex(C_HOVER);
                mesh.material.opacity = 1.0;
                const hoverScale = mesh.userData.originalScale.clone().multiplyScalar(1.6);
                mesh.scale.lerp(hoverScale, 0.15);
                if (mesh.userData.glowMesh) {
                    mesh.userData.glowMesh.material.opacity = 0.4;
                    const glowHoverScale = mesh.userData.originalGlowScale.clone().multiplyScalar(1.4);
                    mesh.userData.glowMesh.scale.lerp(glowHoverScale, 0.15);
                }
                renderer.domElement.style.cursor = 'pointer';
            } else {
                hoveredMesh = null;
                renderer.domElement.style.cursor = 'default';
            }
        }

        camera.position.x += (mouse.x * 15 - camera.position.x) * 0.01;
        camera.position.y += (mouse.y * 15 - camera.position.y) * 0.01;
        camera.lookAt(0, 0, 0);

        renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', () => {
        const w = canvasContainer.clientWidth || 800;
        const h = canvasContainer.clientHeight || 600;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
    });
}

// 斐波那契球面分布
function fibonacciSphere(samples, radius) {
    const points = [];
    const phi = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < samples; i++) {
        const y = 1 - (i / (samples - 1)) * 2;
        const r = Math.sqrt(1 - y * y);
        const theta = phi * i;
        points.push({
            x: Math.cos(theta) * r * radius,
            y: y * radius,
            z: Math.sin(theta) * r * radius
        });
    }
    return points;
}
// 创建文字精灵
function createTextSprite(text, color) {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const fontSize = 24;
        ctx.font = `600 ${fontSize}px "Inter", "Microsoft YaHei", sans-serif`;
        const metrics = ctx.measureText(text);
        const width = metrics.width + 40;
        const height = fontSize + 20;


        canvas.width = width * 2;
        canvas.height = height * 2;
        ctx.scale(2, 2);

        ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
        ctx.beginPath();
        ctx.roundRect(0, 0, width, height, 8);
        ctx.fill();

        ctx.strokeStyle = color + '60';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.roundRect(0, 0, width, height, 8);
        ctx.stroke();

        ctx.fillStyle = color;
        ctx.font = `600 ${fontSize}px "Inter", "Microsoft YaHei", sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, width / 2, height / 2);

        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;
        texture.minFilter = THREE.LinearFilter;
        texture.magFilter = THREE.LinearFilter;

        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true,
            opacity: 0.95,
            depthWrite: false
        });

        const sprite = new THREE.Sprite(material);
        sprite.scale.set(width * 0.3, height * 0.3, 1);
        return sprite;
    } catch (err) {
        console.error('Error creating text sprite:', err);
        return null;
    }
}

// 更新右侧统计面板
function updateStatsPanel(stats) {
    const panel = document.getElementById('solarStatsPanel');
    if (!panel) return;

    animateNumValue('statUnique', stats.unique);
    animateNumValue('statValid', stats.valid);
    animateNumValue('statWarn', stats.warn);
    animateNumValue('statExpired', stats.expired);
}

function animateNumValue(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let cur = parseInt(el.textContent) || 0;
    if (cur === target) return;
    const step = Math.max(1, Math.floor(Math.abs(target - cur) / 20));
    const dir = target > cur ? 1 : -1;
    const iv = setInterval(() => {
        cur += step * dir;
        if ((dir === 1 && cur >= target) || (dir === -1 && cur <= target)) {
            cur = target;
            clearInterval(iv);
        }
        el.textContent = cur;
    }, 30);
}

function killSolar() {
    if (G.solarAnim) cancelAnimationFrame(G.solarAnim);
    G.solarAnim = null;
    G.solarMeshes = [];
}

// ==================== 弹窗详情（展示 cert_details 完整数据）====================
function openPlanetDetail(data) {
    const modal = document.getElementById('planetModal');
    const content = document.getElementById('planetContent');
    if (!modal || !content) return;

    const c = data.cert || {};
    const idx = data.idx;

    // 状态颜色映射
    const headerColors = {
        valid: '#059669',
        warn: '#d97706',
        expired: '#dc2626'
    };
    const hColor = headerColors[data.type] || '#0d9488';

    // 状态标签
    const typeLabels = {
        valid: '有效证书',
        warn: '即将过期',
        expired: '已过期'
    };

    // 状态说明
    const statusDesc = {
        valid: '该证书处于有效期内，加密强度正常，可安全使用。',
        warn: '该证书即将在30天内过期，建议尽快联系管理员续期。',
        expired: '该证书已过期，存在严重安全风险，请立即处理！'
    };

    // 安全地格式化日期
    function fmtDate(d) {
        if (!d || d === '-' || d === 'None' || d === null) return '-';
        try {
            const date = new Date(d);
            if (isNaN(date.getTime())) return String(d);
            return date.toLocaleString('zh-CN', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            });
        } catch {
            return String(d);
        }
    }

    // 安全地截断文本
    function trunc(s, n) {
        if (!s || s === '-' || s === 'None') return '-';
        s = String(s);
        return s.length > n ? s.slice(0, n) + '...' : s;
    }

    // SAN 列表格式化
    const sanList = c.san_list || [];
    const sanDisplay = Array.isArray(sanList) && sanList.length > 0
        ? sanList.join(', ')
        : (c.san_count > 0 ? `${c.san_count} 个域名` : '无');

    // 构建详情 HTML
    const html = `
        <div class="planet-detail-header">
            <span class="planet-status-dot" style="background:${hColor};box-shadow:0 0 10px ${hColor}60"></span>
            <h3 style="color:${hColor}">${typeLabels[data.type]} #${idx + 1}</h3>
            <span class="planet-id">${typeLabels[data.type]}</span>
        </div>

        <!-- 状态概览 -->
        <div class="planet-detail-grid">
            <div class="pd-field planet-detail-full">
                <label>证书状态</label>
                <div class="pd-value" style="color:${hColor};font-weight:600;font-size:1.05rem">
                    ${typeLabels[data.type]}
                </div>
            </div>
            <div class="pd-field planet-detail-full">
                <label>状态说明</label>
                <div class="pd-value">${statusDesc[data.type]}</div>
            </div>
        </div>

        <!-- 主体信息 -->
        <div class="planet-detail-grid" style="margin-top:0.75rem">
            <div class="pd-field planet-detail-full">
                <label>主题名称 (Subject CN)</label>
                <div class="pd-value">${esc(trunc(c.subject_cn || '-', 60))}</div>
            </div>
            <div class="pd-field planet-detail-full">
                <label>颁发者 (Issuer CN)</label>
                <div class="pd-value">${esc(trunc(c.issuer_cn || '-', 60))}</div>
            </div>
        </div>

        <!-- 序列号与算法 -->
        <div class="planet-detail-grid" style="margin-top:0.5rem">
            <div class="pd-field">
                <label>序列号</label>
                <div class="pd-value">${esc(trunc(c.serial_number || '-', 30))}</div>
            </div>
            <div class="pd-field">
                <label>签名算法</label>
                <div class="pd-value">${esc(c.signature_algorithm || '-')}</div>
            </div>
            <div class="pd-field">
                <label>密钥算法</label>
                <div class="pd-value">${esc(c.key_algorithm || '-')}</div>
            </div>
            <div class="pd-field">
                <label>密钥长度</label>
                <div class="pd-value">${esc(c.key_size ? c.key_size + ' bit' : '-')}</div>
            </div>
        </div>

        <!-- 有效期 -->
        <div class="planet-detail-grid" style="margin-top:0.5rem">
            <div class="pd-field">
                <label>生效时间 (Not Before)</label>
                <div class="pd-value">${fmtDate(c.not_before)}</div>
            </div>
            <div class="pd-field">
                <label>过期时间 (Not After)</label>
                <div class="pd-value">${fmtDate(c.not_after)}</div>
            </div>
            <div class="pd-field">
                <label>总有效期</label>
                <div class="pd-value">${c.days_valid ? c.days_valid + ' 天' : '-'}</div>
            </div>
            <div class="pd-field">
                <label>剩余天数</label>
                <div class="pd-value" style="color:${hColor};font-weight:600">
                    ${c.days_remaining !== undefined ? c.days_remaining + ' 天' : '-'}
                </div>
            </div>
        </div>

        <!-- SAN 与密钥用途 -->
        <div class="planet-detail-grid" style="margin-top:0.5rem">
            <div class="pd-field planet-detail-full">
                <label>主题备用名 (SAN)</label>
                <div class="pd-value">${esc(sanDisplay)}</div>
            </div>
            <div class="pd-field planet-detail-full">
                <label>密钥用途 (Key Usage)</label>
                <div class="pd-value">${esc(trunc(c.key_usage || '-', 100))}</div>
            </div>
            ${c.extended_key_usage ? `
            <div class="pd-field planet-detail-full">
                <label>扩展密钥用途 (EKU)</label>
                <div class="pd-value">${esc(trunc(c.extended_key_usage, 100))}</div>
            </div>
            ` : ''}
        </div>

        <!-- 自签名与 CA 标志 -->
        <div class="planet-detail-grid" style="margin-top:0.5rem">
            <div class="pd-field">
                <label>自签名</label>
                <div class="pd-value">${c.is_self_signed ? '是' : '否'}</div>
            </div>
            <div class="pd-field">
                <label>CA 证书</label>
                <div class="pd-value">${c.is_ca ? '是' : '否'}</div>
            </div>
            <div class="pd-field">
                <label>链索引</label>
                <div class="pd-value">${c.chain_index !== undefined ? c.chain_index : '-'}</div>
            </div>
            <div class="pd-field">
                <label>链长度</label>
                <div class="pd-value">${c.chain_length !== undefined ? c.chain_length : '-'}</div>
            </div>
        </div>

        <!-- 来源信息 -->
        ${c.source_file ? `
        <div class="planet-detail-grid" style="margin-top:0.5rem">
            <div class="pd-field planet-detail-full">
                <label>来源文件</label>
                <div class="pd-value">${esc(c.source_file)}</div>
            </div>
        </div>
        ` : ''}
    `;

    content.innerHTML = html;
    modal.classList.add('active');
}

function closePlanet() {
    const m = document.getElementById('planetModal');
    if (m) m.classList.remove('active');
}

function renderCharts(data) {
    const a = data.analysis || data;
    const scales = {
        x: { ticks: { color: PAL.label, font: { size: 13, weight: '500', family: "'Inter', 'Microsoft YaHei', sans-serif" } }, grid: { color: PAL.grid }, border: { color: PAL.grid } },
        y: { ticks: { color: PAL.label, font: { size: 13, weight: '500', family: "'Inter', 'Microsoft YaHei', sans-serif" } }, grid: { color: PAL.grid }, border: { color: PAL.grid } }
    };
    const legend = { labels: { color: PAL.label, font: { size: 14, weight: '500', family: "'Inter', 'Microsoft YaHei', sans-serif" }, padding: 16 }, position: 'bottom' };

    mkChart('validityChart', {
        type: 'doughnut',
        data: {
            labels: ['有效', '即将过期', '已过期'],
            datasets: [{
                data: [a.valid_certificates||0, a.expiring_soon_certificates||0, a.expired_certificates||0],
                backgroundColor: [PAL.valid, PAL.warn, PAL.danger],
                borderWidth: 0, hoverOffset: 8
            }]
        },
        options: { responsive: true, cutout: '62%', plugins: { legend, title: { display: true, text: `总计 ${a.total_certificates||0}`, color: PAL.label, font: { size: 16, weight: '700', family: "'Inter', 'Microsoft YaHei', sans-serif" } } } }
    });

    const cTypes = Object.keys(a.crypto_stats || {});
    const cVals = Object.values(a.crypto_stats || {});
    if (cTypes.length) {
        mkChart('cryptoChart', {
            type: 'bar',
            data: { labels: cTypes.map(t=>t.replace(/:/g,' ')), datasets: [{ data: cVals, backgroundColor: PAL.chart, borderWidth: 0, borderRadius: 6 }] },
            options: { responsive: true, plugins: { legend: { display: false }, title: { display: true, text: '密码学算法分布统计', color: PAL.label, font: { size: 16, weight: '700', family: "'Inter', 'Microsoft YaHei', sans-serif" } } }, scales }
        });
    }

    const issuers = Object.keys(a.ca_stats || {});
    const iCounts = Object.values(a.ca_stats || {});
    if (issuers.length) {
        const sorted = issuers.map((n,i) => ({ name: (n.split('CN=')[1]?.split(',')[0]||n).slice(0,18), count: iCounts[i] }))
            .sort((a,b) => b.count - a.count).slice(0, 10);
        mkChart('issuerChart', {
            type: 'bar',
            data: { labels: sorted.map(s=>s.name), datasets: [{ data: sorted.map(s=>s.count), backgroundColor: PAL.chart.slice(0, sorted.length), borderWidth: 0, borderRadius: 6, barThickness: 22, maxBarThickness: 26 }] },
            options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: '证书颁发机构统计 TOP10', color: PAL.label, font: { size: 16, weight: '700', family: "'Inter', 'Microsoft YaHei', sans-serif" } } }, scales: { x: { ticks: { color: PAL.label, font: { size: 13, weight: '500', family: "'Inter', 'Microsoft YaHei', sans-serif" } }, grid: { color: PAL.grid }, border: { color: PAL.grid } }, y: { ticks: { color: PAL.label, font: { size: 13, weight: '500', family: "'Inter', 'Microsoft YaHei', sans-serif" } }, grid: { display: false }, border: { color: PAL.grid } } } }
        });
    }

    const dCounts = a.san_stats?.domain_counts || {};
    const sanL = Object.keys(dCounts).map(n=>`${n}域名`);
    const sanD = Object.values(dCounts);
    if (sanL.length) {
        mkChart('sanChart', {
            type: 'bar',
            data: { labels: sanL, datasets: [{ data: sanD, backgroundColor: PAL.chart[1], borderWidth: 0, borderRadius: 6 }] },
            options: { responsive: true, plugins: { legend: { display: false }, title: { display: true, text: `SAN域名统计: ${a.san_stats?.with_san||0}`, color: PAL.label, font: { size: 16, weight: '700', family: "'Inter', 'Microsoft YaHei', sans-serif" } } }, scales }
        });
    }

    const kuL = Object.keys(a.key_usage_stats || {});
    const kuD = Object.values(a.key_usage_stats || {});
    if (kuL.length) {
        mkChart('keyUsageChart', {
            type: 'pie',
            data: { labels: kuL, datasets: [{ data: kuD, backgroundColor: PAL.chart.slice(0, kuL.length), borderWidth: 0, hoverOffset: 6 }] },
            options: { responsive: true, plugins: { legend, title: { display: true, text: '密钥用途分布', color: PAL.label, font: { size: 16, weight: '700', family: "'Inter', 'Microsoft YaHei', sans-serif" } } } }
        });
    }
}

function mkChart(id, cfg) {
    if (G.charts[id]) G.charts[id].destroy();
    const el = document.getElementById(id);
    if (!el) return;
    G.charts[id] = new Chart(el, cfg);
}
function killCharts() {
    Object.values(G.charts).forEach(c => c?.destroy?.());
    G.charts = {};
}

function renderDetails(data) {
    const a = data.analysis || data;
    const box = document.getElementById('detailBox');
    if (!box) return;
    const T = a.total_certificates || 1;
    let h = '';

    h += `<div class="detail-sec"><h4><i class="fas fa-shield-alt"></i> 证书有效性</h4>
        <table class="dtable"><thead><tr><th>指标</th><th>数量</th><th>占比</th></tr></thead><tbody>
        <tr><td><span class="d-badge ok">有效</span></td><td>${a.valid_certificates||0}</td><td>${((a.valid_certificates||0)/T*100).toFixed(1)}%</td></tr>
        <tr><td><span class="d-badge wa">即将过期</span></td><td>${a.expiring_soon_certificates||0}</td><td>${((a.expiring_soon_certificates||0)/T*100).toFixed(1)}%</td></tr>
        <tr><td><span class="d-badge no">已过期</span></td><td>${a.expired_certificates||0}</td><td>${((a.expired_certificates||0)/T*100).toFixed(1)}%</td></tr>
        </tbody></table></div>`;

    if (a.ca_stats && Object.keys(a.ca_stats).length) {
        h += `<div class="detail-sec"><h4><i class="fas fa-building"></i> 颁发机构</h4>
            <div style="overflow-x:auto"><table class="dtable"><thead><tr><th>机构</th><th>数量</th><th>占比</th></tr></thead><tbody>
            ${Object.entries(a.ca_stats).map(([n,c])=>`<tr><td>${esc(n.length>50?n.slice(0,50)+'...':n)}</td><td>${c}</td><td>${((c/T)*100).toFixed(1)}%</td></tr>`).join('')}
            </tbody></table></div></div>`;
    }
    if (a.crypto_stats && Object.keys(a.crypto_stats).length) {
        h += `<div class="detail-sec"><h4><i class="fas fa-key"></i> 密码学算法</h4>
            <div style="overflow-x:auto"><table class="dtable"><thead><tr><th>算法</th><th>数量</th><th>占比</th></tr></thead><tbody>
            ${Object.entries(a.crypto_stats).map(([n,c])=>`<tr><td><code>${esc(n)}</code></td><td>${c}</td><td>${((c/T)*100).toFixed(1)}%</td></tr>`).join('')}
            </tbody></table></div></div>`;
    }
    if (a.key_usage_stats && Object.keys(a.key_usage_stats).length) {
        h += `<div class="detail-sec"><h4><i class="fas fa-tasks"></i> 密钥用途</h4>
            <div style="overflow-x:auto"><table class="dtable"><thead><tr><th>用途</th><th>数量</th><th>占比</th></tr></thead><tbody>
            ${Object.entries(a.key_usage_stats).map(([n,c])=>`<tr><td>${esc(n)}</td><td>${c}</td><td>${((c/T)*100).toFixed(1)}%</td></tr>`).join('')}
            </tbody></table></div></div>`;
    }
    box.innerHTML = h;
}

async function genReport() {
    if (!G.data) { alert('请先完成分析'); return; }
    const btn = document.querySelector('#reportTrigger .action-btn');
    const orig = btn?.innerHTML;
    if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 合成中...';
    try {
        const res = await fetch(`/generate-report?t=${Date.now()}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analysis: G.data.analysis || G.data, source_type: G.data.source_type })
        });
        const d = await res.json();
        if (d.error) throw new Error(d.error);
        G.report = d;
        document.getElementById('reportMd').innerHTML = window.marked ? marked.parse(d.report_content) : d.report_content;
        document.getElementById('reportTrigger').style.display = 'none';
        document.getElementById('reportOutput').style.display = 'block';
    } catch (e) { showErr('报告失败: ' + e.message); }
    finally { if (btn) btn.innerHTML = orig; }
}
function dlReport() {
    if (G.report?.report_filename) window.open(`/download-report/${G.report.report_filename}`, '_blank');
}
async function cpReport() {
    if (!G.report?.report_content) return;
    try { await navigator.clipboard.writeText(G.report.report_content); alert('已复制'); }
    catch { alert('复制失败'); }
}

function showErr(msg) {
    const el = document.getElementById('errorBox');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
}
function hideErr() {
    const el = document.getElementById('errorBox');
    if (el) el.style.display = 'none';
}
function esc(s) { return String(s).replace(/[&<>]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])); }

window.addEventListener('resize', () => {
    Object.values(G.charts).forEach(c => c?.resize?.());
});