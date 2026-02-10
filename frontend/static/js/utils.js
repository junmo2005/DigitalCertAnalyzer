// 通用工具函数

/**
 * 显示加载状态
 */
function showLoading(elementId, message = '处理中...') {
    let element;
    if (typeof elementId === 'string') {
        element = document.getElementById(elementId);
    } else {
        element = elementId;
    }
    
    if (element) {
        element.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                ${message}
            </div>
        `;
        element.style.display = 'block';
    }
}

/**
 * 显示成功消息
 */
function showSuccess(elementId, message) {
    let element;
    if (typeof elementId === 'string') {
        element = document.getElementById(elementId);
    } else {
        element = elementId;
    }
    
    if (element) {
        element.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>${message}
            </div>
        `;
        element.style.display = 'block';
    }
}

/**
 * 显示错误消息 - 与原文件保持一致
 */
function showError(elementId, message) {
    let element;
    if (typeof elementId === 'string') {
        element = document.getElementById(elementId);
    } else {
        element = elementId;
    }
    
    if (element) {
        let errorHTML = `<div class="error">${message}</div>`;
        if (message.includes("未检测到TLS证书")) {
            errorHTML += `<br><br>可能原因：
                <ul>
                    <li>PCAP文件不包含TLS握手过程</li>
                    <li>流量已加密或使用非常规协议</li>
                    <li>捕获时间点错过了证书交换</li>
                </ul>
               建议：使用Wireshark打开文件，过滤 <code>tls.handshake.type == 11</code> 验证`;
        }
        element.innerHTML = errorHTML;
        element.style.display = 'block';
    }
}

/**
 * 格式化文件大小
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * 安全的JSON解析
 */
function safeJsonParse(str, defaultValue = {}) {
    try {
        return JSON.parse(str);
    } catch (e) {
        return defaultValue;
    }
}

/**
 * 防抖函数
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * ========== 新增函数（用于安全分析页面）==========
 */

/**
 * 显示分析区域
 */
function showAnalysisSection(sectionId) {
    const sections = document.querySelectorAll('.analysis-section');
    sections.forEach(section => {
        if (section.id !== 'analysisEntrance') {
            section.style.display = 'none';
        }
    });
    
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.style.display = 'block';
        targetSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/**
 * 隐藏分析区域
 */
function hideAnalysisSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = 'none';
    }
    
    const entrance = document.getElementById('analysisEntrance');
    if (entrance) {
        entrance.style.display = 'block';
    }
}

/**
 * 显示骨架屏加载状态
 */
function showSkeletonLoading() {
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const actualResults = document.getElementById('actualResults');
    const resultsSection = document.getElementById('analysisResults');
    
    if (loadingSkeleton) {
        loadingSkeleton.style.display = 'block';
    }
    
    if (actualResults) {
        actualResults.style.display = 'none';
    }
    
    if (resultsSection) {
        resultsSection.style.display = 'block';
    }
    
    // 禁用分析区域交互
    const analysisSections = document.querySelectorAll('#pcapAnalysis, #certAnalysis');
    analysisSections.forEach(section => {
        if (section.style.display !== 'none') {
            section.style.opacity = '0.6';
            section.style.pointerEvents = 'none';
        }
    });
}

/**
 * 隐藏骨架屏加载状态
 */
function hideSkeletonLoading() {
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const actualResults = document.getElementById('actualResults');
    
    if (loadingSkeleton) {
        loadingSkeleton.style.display = 'none';
    }
    
    if (actualResults) {
        actualResults.style.display = 'block';
    }
    
    // 恢复分析区域交互
    const analysisSections = document.querySelectorAll('#pcapAnalysis, #certAnalysis');
    analysisSections.forEach(section => {
        if (section) {
            section.style.opacity = '1';
            section.style.pointerEvents = 'auto';
        }
    });
}

/**
 * 安全评分等级
 */
function getSecurityGrade(score) {
    if (score >= 90) return '优秀';
    if (score >= 70) return '良好';
    if (score >= 50) return '一般';
    return '需要改进';
}

/**
 * 评分颜色
 */
function getScoreColor(score) {
    if (score >= 80) return 'bg-success';
    if (score >= 60) return 'bg-info';
    if (score >= 40) return 'bg-warning';
    return 'bg-danger';
}

/**
 * 状态图标
 */
function getStatusIcon(status) {
    return status ? 
        '<i class="fas fa-check text-success" title="已配置"></i>' : 
        '<i class="fas fa-times text-danger" title="未配置"></i>';
}

/**
 * 复制文本到剪贴板
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error('复制失败:', err);
        // 降级方案：使用旧的execCommand方法
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            return true;
        } catch (err2) {
            console.error('降级复制也失败:', err2);
            return false;
        } finally {
            document.body.removeChild(textArea);
        }
    }
}

/**
 * 下载文件
 */
function downloadFile(content, fileName, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/**
 * 获取安全的文件名
 */
function getSafeFileName(name) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const cleanName = name.replace(/[^\w\u4e00-\u9fa5-]/g, '_');
    return `${cleanName}_${timestamp}`;
}

/**
 * 验证域名格式
 */
function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    
    // 基础验证
    const domainPattern = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
    
    // 特殊处理：允许带端口
    const parts = domain.split(':');
    if (parts.length > 1) {
        const port = parseInt(parts[1]);
        if (isNaN(port) || port < 1 || port > 65535) return false;
    }
    
    return domainPattern.test(parts[0]);
}

/**
 * 解析域名列表
 */
function parseDomainList(text) {
    if (!text || typeof text !== 'string') return [];
    
    return text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .filter(domain => isValidDomain(domain.split(':')[0]));
}