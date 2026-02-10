// 安全分析功能JavaScript
// 注意：本文件依赖 utils.js 中的通用函数
// showSkeletonLoading() -> utils.js 中的函数
// hideSkeletonLoading() -> utils.js 中的函数
// getSecurityGrade() -> utils.js 中的函数
// getScoreColor() -> utils.js 中的函数
// getStatusIcon() -> utils.js 中的函数
// showAnalysisSection() -> utils.js 中的函数
// hideAnalysisSection() -> utils.js 中的函数
// copyToClipboard() -> utils.js 中的函数
// downloadFile() -> utils.js 中的函数

// 存储图表实例的变量
let securityChartInstance = null;
let featuresChartInstance = null;
let reportTimeout = null;

// 报告生成相关全局变量（新增）
let currentTaskId = null;
let pollInterval = null;
let reportData = null;
let statusTimer = 0;
let timerInterval = null;
let currentSecurityReport = null; // 保留原有变量

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeSecurityFeatures();
});

/**
 * 初始化安全分析功能
 */
function initializeSecurityFeatures() {
    // 初始化图表
    initializeChartsConfig();
    
    // 新的文件分析事件监听器
    initializeFileAnalysisEvents();

    // 初始化快速开始指南状态
    initializeQuickStartGuide();
}

/**
 * 初始化快速开始指南状态
 */
function initializeQuickStartGuide() {
    // 这里可以添加快速开始指南的初始化逻辑
    const isCollapsed = localStorage.getItem('quickStartCollapsed') === 'true';
    if (isCollapsed) {
        collapseQuickStart();
    } else {
        expandQuickStart();
    }
}

/**
 * 折叠快速开始指南
 */
function collapseQuickStart() {
    const quickStartCard = document.getElementById('quickStartCard');
    const quickStartBody = document.getElementById('quickStartBody');
    
    if (quickStartCard && quickStartBody) {
        quickStartCard.classList.add('quick-start-collapsed');
        quickStartBody.style.display = 'none';
        localStorage.setItem('quickStartCollapsed', 'true');
    }
}

/**
 * 展开快速开始指南
 */
function expandQuickStart() {
    const quickStartCard = document.getElementById('quickStartCard');
    const quickStartBody = document.getElementById('quickStartBody');
    
    if (quickStartCard && quickStartBody) {
        quickStartCard.classList.remove('quick-start-collapsed');
        quickStartBody.style.display = 'block';
        localStorage.setItem('quickStartCollapsed', 'false');
    }
}

/**
 * 切换快速开始指南显示状态
 */
function toggleQuickStart() {
    const quickStartCard = document.getElementById('quickStartCard');
    if (quickStartCard && quickStartCard.classList.contains('quick-start-collapsed')) {
        expandQuickStart();
    } else {
        collapseQuickStart();
    }
}

/**
 * 初始化文件分析事件监听器
 */
function initializeFileAnalysisEvents() {
    // PCAP文件上传事件
    const pcapFileInput = document.getElementById('pcapFile');
    if (pcapFileInput) {
        pcapFileInput.addEventListener('change', function(e) {
            console.log('PCAP文件已选择:', e.target.files[0]?.name);
        });
    }
    
    // 证书文件上传事件
    const certZipFileInput = document.getElementById('certZipFile');
    const certDerFileInput = document.getElementById('certDerFile');
    
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
    
    // 标签切换事件
    const certTabs = document.querySelectorAll('#certTab .nav-link');
    certTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            if (this.id === 'zip-tab') {
                certDerFileInput.value = '';
            } else if (this.id === 'single-tab') {
                certZipFileInput.value = '';
            }
        });
    });
}

/**
 * 初始化图表配置
 */
function initializeChartsConfig() {
    // 设置全局的Chart.js配置
    if (typeof Chart !== 'undefined') {
        Chart.defaults.font.family = 'Inter, sans-serif';
        Chart.defaults.color = '#4E5165';
        Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(56, 58, 122, 0.8)';
    }
}

/**
 * 分析单个域名安全状态
 */
function analyzeDomainSecurity(domain, fetchCert) {
    console.log('分析单个域名:', domain);
    // 可以保留这个函数作为备用接口
}

/**
 * 批量安全分析
 */
function batchSecurityAnalyze(domains) {
    console.log('批量分析域名:', domains);
    // 可以保留作为直接域名列表分析的接口
}

/**
 * 初始化图表 - 根据报告数据创建图表
 */
function initializeCharts(report) {
    // 更严格的图表实例销毁
    destroyAllChartInstances();
    
    // 安全分数分布图
    const securityCtx = document.getElementById('securityChart');
    if (securityCtx) {
        securityChartInstance = new Chart(securityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['优秀 (80-100)', '良好 (60-79)', '一般 (40-59)', '较差 (0-39)'],
                datasets: [{
                    data: report.scoreDistribution || [0, 0, 0, 0],
                    backgroundColor: ['#28a745', '#20c997', '#ffc107', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: '域名安全分数分布'
                    }
                }
            }
        });
    }
    
    // 安全特性覆盖率图 - 修复版
    const featuresCtx = document.getElementById('featuresChart');
    if (featuresCtx) {
        const summary = report.summary || {};
        const total = summary.analyzed_domains || summary.total_domains || 1;
        
        // 直接从summary获取百分比数据，避免重复计算
        const httpsPercentage = Math.round((summary.domains_with_https_enforcement || 0) / total * 100);
        const hstsPercentage = Math.round((summary.domains_with_hsts || 0) / total * 100);
        const headersPercentage = Math.round((summary.domains_with_good_security_headers || 0) / total * 100);
        const chainsPercentage = Math.round((summary.domains_with_valid_certificate_chains || 0) / total * 100);
        
        featuresChartInstance = new Chart(featuresCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['HTTPS强制', 'HSTS保护', '安全头', '证书链'],
                datasets: [{
                    label: '通过率 (%)',
                    data: [
                        httpsPercentage,
                        hstsPercentage, 
                        headersPercentage,
                        chainsPercentage
                    ],
                    backgroundColor: [
                        'rgba(40, 167, 69, 0.8)',
                        'rgba(32, 201, 151, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(0, 123, 255, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: '通过率 (%)'
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `通过率: ${context.raw}%`;
                            }
                        }
                    },
                    title: {
                        display: true,
                        text: '安全特性覆盖率'
                    }
                }
            }
        });
    }
}

/**
 * 销毁所有图表实例 - 新增函数
 */
function destroyAllChartInstances() {
    // 销毁全局变量存储的实例
    if (securityChartInstance) {
        try {
            securityChartInstance.destroy();
            securityChartInstance = null;
        } catch (e) {
            console.warn('销毁securityChartInstance失败:', e);
        }
    }
    
    if (featuresChartInstance) {
        try {
            featuresChartInstance.destroy();
            featuresChartInstance = null;
        } catch (e) {
            console.warn('销毁featuresChartInstance失败:', e);
        }
    }
    
    // 销毁Chart.js注册的所有实例
    try {
        Chart.helpers.each(Chart.instances, function(instance) {
            try {
                instance.destroy();
            } catch (e) {
                console.warn('销毁Chart实例失败:', e);
            }
        });
    } catch (e) {
        console.warn('遍历Chart实例失败:', e);
    }
}

/**
 * 显示安全分析结果 - 完全修复版
 */
function displaySecurityReport(report) {
    console.log('显示安全报告:', report);
    
    // 首先设置当前分析结果 - 这是关键修复！
    setCurrentSecurityReport(report);

    // 在创建新图表前先销毁所有现有实例
    destroyAllChartInstances();
    
    // 确保结果区域可见 - 修复ID选择器
    const resultsSection = document.getElementById('analysisResults');
    if (resultsSection) {
        resultsSection.style.display = 'block';
        console.log('结果区域已显示');
    } else {
        console.error('未找到结果区域元素: analysisResults');
        // 尝试其他可能的选择器
        const fallbackResults = document.querySelector('.analysis-section') || 
                               document.getElementById('results');
        if (fallbackResults) {
            fallbackResults.style.display = 'block';
            console.log('使用备用结果区域');
        }
    }
    
    // 隐藏加载状态，显示实际结果（使用 utils.js 中的函数）
    hideSkeletonLoading();
    
    // 计算安全等级（使用 utils.js 中的函数）
    const securityScore = report.summary?.security_score || 0;
    const grade = getSecurityGrade(securityScore);
    
    // 先初始化图表
    initializeCharts(report);
    
    // 显示评分卡 - 修复参数传递
    displayScoreCard(securityScore, grade, report.summary?.analyzed_domains || 0);
    
    // 显示详细发现 - 修复参数传递
    displayDetailedFindings(report);
    
    // 显示域名详情（批量分析时）
    if (report.detailed_results && report.detailed_results.length > 0) {
        displayDomainDetails(report.detailed_results);
    }

    // 首先检查report是否有效
    if (!report) {
        console.error('报告数据为空，无法显示');
        // 显示错误信息
        showError('analysisResults', '分析结果为空，请重新尝试分析');
        hideSkeletonLoading();
        return;
    }

    if (report.ai_report_content) {
        // 如果有AI报告内容，使用formatReportToHTML显示
        const formattedReport = formatReportToHTML(report.ai_report_content);
        const reportText = document.getElementById('reportText');
        if (reportText) {
            reportText.innerHTML = formattedReport;
        }
    }
    
    // 安全的滚动到结果区域 - 修复版（现在在 utils.js 中）
    const possibleSelectors = ['#analysisResults', '#actualResults', '.analysis-section'];
    for (const selector of possibleSelectors) {
        const element = document.querySelector(selector);
        if (element && element.offsetParent !== null) {
            try {
                element.scrollIntoView({ 
                    behavior: 'smooth',
                    block: 'start'
                });
                console.log('成功滚动到结果区域');
                break;
            } catch (scrollError) {
                console.warn('滚动失败:', scrollError);
            }
        }
    }

    console.log('安全报告显示完成，数据已设置');
}

/**
 * 显示评分卡 - 修复版
 */
function displayScoreCard(securityScore, grade, analyzedCount) {
    const scoreCard = document.getElementById('scoreCard');
    if (scoreCard) {
        scoreCard.innerHTML = `
            <div class="score-card">
                <div class="score-number">${securityScore}</div>
                <div class="score-grade">${grade}</div>
                <p class="mb-0">基于 ${analyzedCount} 个域名的安全分析</p>
            </div>
        `;
    }
}

/**
 * 显示详细发现 - 增强版（显示域名统计）
 */
function displayDetailedFindings(report) {
    const detailedFindings = document.getElementById('detailedFindings');
    if (!detailedFindings) return;

    const summary = report.summary || {};
    const featureStats = report.featureStats || {};
    const domainStats = report.domain_stats || {};
    
    // 使用实际分析的数量
    const analyzedCount = summary.analyzed_domains || report.detailed_results?.length || 0;
    const totalCount = summary.total_domains || analyzedCount;

    let findingsHtml = `
        <div class="card-header bg-light">
            <h6 class="mb-0"><i class="fas fa-search me-2"></i>详细发现</h6>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6>域名提取统计</h6>
                    <ul class="list-unstyled">
                        <li><i class="fas fa-file-export me-1"></i> 提取域名总数: <strong>${domainStats.total_extracted || 0}</strong></li>
                        <li><i class="fas fa-filter me-1"></i> 过滤后域名: <strong>${domainStats.after_filtering || 0}</strong></li>
                        <li><i class="fas fa-chart-line me-1"></i> 实际分析: <strong>${domainStats.to_analyze || analyzedCount}</strong></li>
                        <li><i class="fas fa-check-circle me-1"></i> 成功分析: <strong>${analyzedCount}</strong></li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6>安全特性统计</h6>
                    <ul class="list-unstyled">
                        <li><i class="fas fa-check text-success me-1"></i> HTTPS强制重定向: <strong>${summary.domains_with_https_enforcement || featureStats.https || 0}</strong> 个域名</li>
                        <li><i class="fas fa-check text-success me-1"></i> HSTS保护: <strong>${summary.domains_with_hsts || featureStats.hsts || 0}</strong> 个域名</li>
                        <li><i class="fas fa-check text-success me-1"></i> 安全头配置良好: <strong>${summary.domains_with_good_security_headers || featureStats.good_headers || 0}</strong> 个域名</li>
                        <li><i class="fas fa-check text-success me-1"></i> 证书链完整: <strong>${summary.domains_with_valid_certificate_chains || featureStats.valid_chains || 0}</strong> 个域名</li>
                    </ul>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <h6>分析概况</h6>
                    <ul class="list-unstyled">
                        <li><i class="fas fa-star me-1"></i> 平均安全分数: <strong>${summary.security_score || 0}</strong></li>
                        <li><i class="fas fa-clock me-1"></i> 分析时间: <strong>${new Date().toLocaleString()}</strong></li>
                    </ul>
                </div>
            </div>
        </div>
    `;
    
    detailedFindings.innerHTML = findingsHtml;
}

/**
 * 显示生成的报告 - 使用marked.js版本（修复版）
 */
function displayGeneratedReport(reportContent, generatedAt) {
    const reportText = document.getElementById('reportText');
    const reportContentDiv = document.getElementById('reportContent');
    const reportTime = document.getElementById('reportTime');
    
    try {
        console.log('=== 显示报告（marked.js版本） ===');
        console.log('报告内容长度:', reportContent?.length);
        console.log('报告内容前100字符:', reportContent?.substring(0, 100));
        
        if (!reportContent) {
            throw new Error('报告内容为空');
        }

        // 设置显示时间
        const displayTime = generatedAt ? 
            new Date(generatedAt).toLocaleString() : 
            new Date().toLocaleString();
        
        reportTime.textContent = displayTime;

        // 使用formatReportWithMarked转换报告
        console.log('开始转换Markdown报告...');
        const formattedReport = formatReportWithMarked(reportContent);
        console.log('转换完成，HTML长度:', formattedReport?.length);
        
        // 检查转换结果是否有效
        if (!formattedReport || formattedReport.includes('alert alert-warning') && 
            formattedReport.includes('报告内容为空')) {
            console.warn('转换结果可能有问题，使用降级显示');
            // 降级显示
            reportText.innerHTML = `<pre class="bg-light p-3 rounded">${escapeHtml(reportContent)}</pre>`;
        } else {
            // 正常显示转换后的内容
            reportText.innerHTML = formattedReport;
        }
        
        // 确保报告区域显示
        reportContentDiv.style.display = 'block';
        
        // 隐藏错误状态
        document.getElementById('reportError').style.display = 'none';
        
        // 初始化代码复制功能
        initCodeCopyButtons();
        
        // 高亮代码块（如果有）
        if (typeof hljs !== 'undefined') {
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        }
        
        console.log('=== 报告显示完成 ===');
        
    } catch (error) {
        console.error('报告显示失败:', error);
        
        // 即使出错，也要显示报告内容
        const errorHtml = `
            <div class="alert alert-danger mb-3">
                <i class="fas fa-exclamation-triangle me-2"></i>
                报告显示错误: ${escapeHtml(error.message)}
            </div>
            <div class="card">
                <div class="card-header bg-light">
                    <h6 class="mb-0">原始报告内容</h6>
                </div>
                <div class="card-body">
                    <pre class="mb-0 bg-light p-3">${escapeHtml(reportContent || '无报告内容')}</pre>
                </div>
            </div>
        `;
        
        reportText.innerHTML = errorHtml;
        reportContentDiv.style.display = 'block';
        reportTime.textContent = new Date().toLocaleString();
    }
}

/**
 * 简单的降级报告显示
 */
function displayReportFallback(reportContent) {
    if (!reportContent) return '<div class="alert alert-warning">报告内容为空</div>';
    
    // 简单的Markdown转换（基础版）
    let html = reportContent
        // 标题
        .replace(/^# (.*$)/gm, '<h1 class="report-main-title">$1</h1>')
        .replace(/^## (.*$)/gm, '<h2 class="report-section-title">$1</h2>')
        .replace(/^### (.*$)/gm, '<h3 class="report-subsection-title">$1</h3>')
        // 分隔线
        .replace(/^\s*[-=]{3,}\s*$/gm, '<hr>')
        // 粗体
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        // 斜体
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        // 代码块
        .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
        // 行内代码
        .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
        // 链接
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>')
        // 无序列表
        .replace(/^\s*[-*+]\s+(.*$)/gm, '<li>$1</li>')
        // 换行
        .replace(/\n/g, '<br>');
    
    return `<div class="security-report">${html}</div>`;
}

/**
 * 初始化代码复制按钮
 */
function initCodeCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-code-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const code = this.getAttribute('data-code');
            try {
                await navigator.clipboard.writeText(code);
                const originalHtml = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check me-1"></i>已复制';
                this.classList.remove('btn-outline-light');
                this.classList.add('btn-success');
                
                setTimeout(() => {
                    this.innerHTML = originalHtml;
                    this.classList.remove('btn-success');
                    this.classList.add('btn-outline-light');
                }, 2000);
            } catch (err) {
                console.error('复制失败:', err);
                alert('复制失败，请手动选择代码复制');
            }
        });
    });
}


/**
 * HTML转义
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * 清理Markdown标题符号 (#, ##, ### 等)
 */
function cleanMarkdownHeaders(text) {
    if (!text) return '';
    
    // 移除开头的 # 符号和空格
    let cleaned = text.replace(/^#+\s*/, '');
    
    // 如果清理后为空，返回原文本（避免误删）
    if (cleaned.trim() === '') {
        return text;
    }
    
    return cleaned;
}


/**
 * 创建风险项
 */
function createRiskItem(line) {
    let style = 'padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; font-size: 14px;';
    
    if (line.includes('🔴') || line.includes('❌') || line.includes('🚨')) {
        style += 'background-color: #f8d7da; border: 1px solid #f1aeb5; color: #721c24;';
    } else if (line.includes('🟠') || line.includes('⚠️')) {
        style += 'background-color: #fff3cd; border: 1px solid #ffd966; color: #664d03;';
    } else if (line.includes('🟡')) {
        style += 'background-color: #fff3cd; border: 1px solid #ffd966; color: #664d03;';
    } else if (line.includes('🟢') || line.includes('✅')) {
        style += 'background-color: #d1e7dd; border: 1px solid #a3cfbb; color: #0f5132;';
    } else {
        style += 'background-color: #e7f1ff; border: 1px solid #b8d4fe; color: #084298;';
    }
    
    return `<div style="${style}">${processInlineFormatting(line)}</div>`;
}

/**
 * 获取标题信息
 */
function getHeadingInfo(line, nextLine) {
    const trimmedLine = line.trim();
    
    // 主标题
    if (trimmedLine.includes('域名安全配置深度分析报告') || (nextLine && nextLine.match(/^=+$/))) {
        return {
            class: 'report-main-title',
            style: 'font-size: 1.4rem; font-weight: 700; color: #1a365d; margin: 1.5rem 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 3px solid #2c5aa0;'
        };
    }
    
    // 主要章节（带emoji）
    if (trimmedLine.match(/^[📋📊🔍⚠️💡🛡️]/) || (nextLine && nextLine.match(/^-+$/))) {
        return {
            class: 'report-section-title',
            style: 'font-size: 1.2rem; font-weight: 600; color: #2d3748; margin: 1.25rem 0 0.75rem 0; padding-left: 0.5rem; border-left: 4px solid #4299e1;'
        };
    }
    
    // 数字编号子标题
    if (trimmedLine.match(/^\d+\.\d+\s/)) {
        return {
            class: 'report-subsection-title',
            style: 'font-size: 1.1rem; font-weight: 600; color: #4a5568; margin: 1rem 0 0.5rem 0;'
        };
    }
    
    // 三级标题
    if (trimmedLine.match(/^\d+\.\d+\.\d+\s/) || trimmedLine.match(/^###\s/)) {
        return {
            class: 'report-subsubsection-title',
            style: 'font-size: 1rem; font-weight: 600; color: #718096; margin: 0.75rem 0 0.5rem 0.5rem;'
        };
    }
    
    // 默认标题
    return {
        class: 'report-default-title',
        style: 'font-size: 1rem; font-weight: 600; color: #4a5568; margin: 0.75rem 0 0.5rem 0;'
    };
}

/**
 * 判断是否为章节标题
 */
function isSectionTitle(line, nextLine) {
    if (!line || line.length < 2) return false;
    
    const trimmedLine = line.trim();
    
    // 明显的标题特征
    const isMainTitle = trimmedLine.includes('域名安全配置深度分析报告');
    const hasEmoji = /^[🔒📋📊🔍⚠️💡🛡️📝🎯✨🔧📈🔑🏆]/.test(trimmedLine);
    const hasNumbering = /^\d+(\.\d+)*\s+.+/.test(trimmedLine);
    const hasDividerBelow = nextLine && (nextLine.match(/^=+$/) || nextLine.match(/^-+$/));
    const isMarkdownHeader = trimmedLine.match(/^#+\s/);
    
    // 标题关键词
    const titleKeywords = [
        '报告信息', '执行摘要', '深度技术分析', '安全风险评估', 
        '具体修复方案', '行业最佳实践', 'HTTPS配置分析', 'HSTS策略评估',
        '安全响应头审计', '证书信任链验证情况', '高风险问题', '中风险问题', 
        '低风险问题', '总体安全态势评估', '关键安全指标亮点', '主要风险概况',
        '技术影响分析', '安全影响', '当前配置状态表', '分析结果', '影响',
        '攻击可能性', '业务影响', '修复方案', '验证方法', '配置示例',
        '行业最佳实践', 'OWASP安全标准遵循', 'NIST安全框架建议'
    ];
    
    const hasTitleKeyword = titleKeywords.some(keyword => trimmedLine.includes(keyword));
    
    return isMainTitle || hasEmoji || hasNumbering || hasDividerBelow || hasTitleKeyword || isMarkdownHeader;
}

/**
 * 显示报告错误
 */
function showReportError(message) {
    const reportError = document.getElementById('reportError');
    const errorMessage = document.getElementById('errorMessage');
    
    errorMessage.textContent = message;
    reportError.style.display = 'block';
    
    // 隐藏加载状态和报告内容
    document.getElementById('reportLoading').style.display = 'none';
    document.getElementById('reportContent').style.display = 'none';
}

/**
 * 重置报告区域状态
 */
function resetReportArea() {
    document.getElementById('reportContent').style.display = 'none';
    document.getElementById('reportLoading').style.display = 'none';
    document.getElementById('reportError').style.display = 'none';
    document.getElementById('copyReportBtn').style.display = 'none';
    document.getElementById('downloadReportBtn').style.display = 'none';
    document.getElementById('generateReportBtn').disabled = false;
    document.getElementById('generateReportBtn').innerHTML = '<i class="fas fa-magic me-2"></i>生成AI报告';
}

/**
 * 显示域名详情 - 修复版
 */
function displayDomainDetails(detailedResults) {
    const domainDetails = document.getElementById('domainDetails');
    if (!domainDetails || !detailedResults) return;

    let detailsHtml = `
        <div class="card-header bg-light">
            <h6 class="mb-0"><i class="fas fa-list me-2"></i>域名详情</h6>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm table-striped">
                    <thead>
                        <tr>
                            <th>域名</th>
                            <th class="text-center">HTTPS强制</th>
                            <th class="text-center">HSTS</th>
                            <th class="text-center">安全头</th>
                            <th class="text-center">证书链</th>
                            <th class="text-center">安全分数</th>
                        </tr>
                    </thead>
                    <tbody>
    `;
    
    detailedResults.forEach(result => {
        if (result.error) {
            // 处理错误结果
            detailsHtml += `
                <tr>
                    <td><code>${result.domain}</code></td>
                    <td colspan="5" class="text-center text-danger">分析失败: ${result.error}</td>
                </tr>
            `;
        } else {
            const score = result.security_score || 0;
            // 使用 utils.js 中的 getStatusIcon 函数
            const statusIcon = getStatusIcon;
            detailsHtml += `
                <tr>
                    <td><code>${result.domain}</code></td>
                    <td class="text-center">${result.https_enforcement?.enabled ? '<i class="fas fa-check text-success" title="已配置"></i>' : '<i class="fas fa-times text-danger" title="未配置"></i>'}</td>
                    <td class="text-center">${result.hsts?.enabled ? '<i class="fas fa-check text-success" title="已配置"></i>' : '<i class="fas fa-times text-danger" title="未配置"></i>'}</td>
                    <td class="text-center">${getSecurityHeadersIcon(result.security_headers)}</td>
                    <td class="text-center">${result.certificate_chain_valid ? '<i class="fas fa-check text-success" title="已配置"></i>' : '<i class="fas fa-times text-danger" title="未配置"></i>'}</td>
                    <td class="text-center"><span class="badge ${getScoreColor(score)}">${score}</span></td>
                </tr>
            `;
        }
    });
    
    detailsHtml += `
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    domainDetails.innerHTML = detailsHtml;
}

// 安全头图标辅助函数
function getSecurityHeadersIcon(securityHeaders) {
    if (!securityHeaders || !securityHeaders.assessment) {
        return '<i class="fas fa-times text-danger" title="未配置安全头"></i>';
    }
    
    const assessment = securityHeaders.assessment;
    const goodHeaders = [
        assessment.has_csp,
        assessment.has_x_content_type_options, 
        assessment.has_x_frame_options,
        assessment.has_referrer_policy
    ].filter(Boolean).length;
    
    if (goodHeaders >= 3) {
        return '<i class="fas fa-check text-success" title="安全头配置良好"></i>';
    } else if (goodHeaders >= 1) {
        return '<i class="fas fa-exclamation-triangle text-warning" title="部分安全头已配置"></i>';
    } else {
        return '<i class="fas fa-times text-danger" title="未配置安全头"></i>';
    }
}

/**
 * 处理PCAP文件分析 - 修复版
 */
async function processPcapAnalysis(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        // 使用 utils.js 中的 showSkeletonLoading
        showSkeletonLoading();
        
        const response = await fetch('/api/security/analyze-pcap', {
            method: 'POST',
            body: formData
        });
        
        // 首先检查HTTP状态
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('收到PCAP分析响应:', data);
        
        // 验证响应数据
        if (!data || typeof data !== 'object') {
            throw new Error('服务器返回的数据格式不正确');
        }
        
        if (data.status === 'success') {
            // 验证安全报告数据
            if (!data.security_report) {
                console.warn('API返回成功状态，但security_report为空');
                // 创建空报告结构
                data.security_report = createEmptySecurityReport();
            }
            
            displaySecurityReport(data.security_report);
        } else if (data.status === 'processing') {
            // 处理异步任务
            console.log('分析任务正在处理中:', data.task_id);
            // 可以在这里添加轮询逻辑
        } else {
            throw new Error(data.error || data.message || '分析失败');
        }
    } catch (error) {
        console.error('PCAP分析错误:', error);
        // 使用 utils.js 中的 showError
        showError('analysisResults', '分析失败: ' + error.message);
        hideSkeletonLoading();
    }
}

/**
 * 处理证书文件分析
 */
async function processCertificateAnalysis(file, type) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('analysis_type', type);
    
    try {
        // 使用 utils.js 中的 showSkeletonLoading
        showSkeletonLoading();
        
        const response = await fetch('/api/security/analyze-certificates', {
            method: 'POST',
            body: formData
        });
        
        // 首先检查HTTP状态
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('收到响应:', data);  // 添加调试日志
        
        // 根据不同的状态进行处理
        if (data.status === 'success') {
            displaySecurityReport(data.security_report);
        } else if (data.status === 'info') {
            // 处理信息状态（如自签名证书、CA证书等）
            showCertificateInfo(data);
        } else if (data.status === 'warning') {
            // 处理警告状态
            showCertificateWarning(data.message, data.certificate_analysis);
        } else if (data.status === 'error') {
            // 处理错误状态
            throw new Error(data.error || '分析失败');
        } else {
            // 未知状态
            throw new Error('未知的响应状态: ' + data.status);
        }
        
    } catch (error) {
        console.error('证书分析错误:', error);
        destroyAllChartInstances();
        // 使用 utils.js 中的 hideSkeletonLoading
        hideSkeletonLoading();
        
        // 只在真正错误时显示弹窗，对于info状态不显示错误
        if (!error.message.includes('info') && !error.message.includes('warning')) {
            // 使用 utils.js 中的 showError
            showError('analysisResults', '证书分析失败: ' + error.message);
        }
    }
}

// 新增函数：显示证书信息（用于自签名证书、CA证书等）
function showCertificateInfo(data) {
    destroyAllChartInstances();
    // 使用 utils.js 中的 hideSkeletonLoading
    hideSkeletonLoading();
    
    const resultsSection = document.getElementById('analysisResults');
    if (resultsSection) {
        resultsSection.style.display = 'block';
        
        let analysisHtml = `
            <div class="alert alert-info">
                <div class="d-flex align-items-center">
                    <i class="fas fa-info-circle fa-2x me-3"></i>
                    <div>
                        <h5 class="alert-heading mb-2">证书分析结果</h5>
                        <p class="mb-0" style="white-space: pre-line;">${data.message}</p>
                    </div>
                </div>
            </div>
        `;
        
        // 显示详细的证书信息
        if (data.certificate_analysis && data.certificate_analysis.length > 0) {
            const certInfo = data.certificate_analysis[0];
            
            analysisHtml += `
                <div class="card mt-4">
                    <div class="card-header bg-light">
                        <h6 class="mb-0"><i class="fas fa-search me-2"></i> 证书详细信息</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
            `;
            
            // 证书基本信息
            if (certInfo.type) {
                analysisHtml += `
                    <div class="col-md-6 mb-3">
                        <strong><i class="fas fa-certificate me-2"></i>证书类型:</strong>
                        <span class="ms-2 badge ${certInfo.is_ca ? 'bg-warning' : 'bg-info'}">${certInfo.type}</span>
                    </div>
                `;
            }
            
            if (certInfo.subject) {
                analysisHtml += `
                    <div class="col-12 mb-3">
                        <strong><i class="fas fa-user me-2"></i>证书主题:</strong>
                        <code class="ms-2 bg-light p-2 rounded d-block mt-1">${certInfo.subject}</code>
                    </div>
                `;
            }
            
            if (certInfo.issuer) {
                analysisHtml += `
                    <div class="col-12 mb-3">
                        <strong><i class="fas fa-building me-2"></i>颁发机构:</strong>
                        <code class="ms-2 bg-light p-2 rounded d-block mt-1">${certInfo.issuer}</code>
                    </div>
                `;
            }
            
            if (certInfo.not_valid_before && certInfo.not_valid_after) {
                analysisHtml += `
                    <div class="col-md-6 mb-3">
                        <strong><i class="fas fa-calendar me-2"></i>有效期:</strong>
                        <div class="ms-2">
                            <div>从: ${certInfo.not_valid_before.substring(0, 10)}</div>
                            <div>到: ${certInfo.not_valid_after.substring(0, 10)}</div>
                        </div>
                    </div>
                `;
            }
            
            if (certInfo.serial_number) {
                analysisHtml += `
                    <div class="col-md-6 mb-3">
                        <strong><i class="fas fa-hashtag me-2"></i>序列号:</strong>
                        <code class="ms-2 bg-light p-1 rounded">${certInfo.serial_number}</code>
                    </div>
                `;
            }
            
            analysisHtml += `
                        </div>
                    </div>
                </div>
            `;
        }
        
        // 添加操作指南
        analysisHtml += `
            <div class="card mt-4">
                <div class="card-header bg-light">
                    <h6 class="mb-0"><i class="fas fa-lightbulb me-2"></i> 下一步操作</h6>
                </div>
                <div class="card-body">
                    <div class="text-center">
                        <button class="btn btn-primary me-3" onclick="showAnalysisSection('certAnalysis')">
                            <i class="fas fa-upload me-2"></i>重新上传证书
                        </button>
                        <button class="btn btn-outline-secondary" onclick="showAnalysisSection('pcapAnalysis')">
                            <i class="fas fa-network-wired me-2"></i>尝试PCAP分析
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        resultsSection.innerHTML = analysisHtml;
        // 滚动到结果区域
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * 创建空的安全报告
 */
function createEmptySecurityReport() {
    return {
        'summary': {
            'security_score': 0,
            'domains_with_https_enforcement': 0,
            'domains_with_hsts': 0,
            'domains_with_valid_certificate_chains': 0,
            'total_domains': 0,
            'analyzed_domains': 0
        },
        'detailed_results': [],
        'scoreDistribution': [0, 0, 0, 0],
        'featureStats': {
            'https': 0,
            'hsts': 0,
            'good_headers': 0,
            'valid_chains': 0
        },
        'domain_stats': {
            'total_extracted': 0,
            'after_filtering': 0,
            'to_analyze': 0,
            'successfully_analyzed': 0
        },
        'recommendations': [
            "分析过程中出现错误",
            "请检查网络连接或重新尝试分析",
            "如果问题持续，请联系系统管理员"
        ]
    };
}

/**
 * 显示证书分析警告信息 - 详细指导版
 */
function showCertificateWarning(message, certificateAnalysis) {
    destroyAllChartInstances();
    // 使用 utils.js 中的 hideSkeletonLoading
    hideSkeletonLoading();
    
    const resultsSection = document.getElementById('analysisResults');
    if (resultsSection) {
        resultsSection.style.display = 'block';
        
        let analysisHtml = `
            <div class="alert alert-info">
                <div class="d-flex align-items-center">
                    <i class="fas fa-info-circle fa-2x me-3"></i>
                    <div>
                        <h5 class="alert-heading mb-2">证书分析结果</h5>
                        <p class="mb-0" style="white-space: pre-line;">${message}</p>
                    </div>
                </div>
            </div>
        `;
        
        // 显示详细的证书分析信息
        if (certificateAnalysis && certificateAnalysis.length > 0) {
            analysisHtml += `
                <div class="card mt-4">
                    <div class="card-header bg-light">
                        <h6 class="mb-0"><i class="fas fa-search me-2"></i> 证书详细信息分析</h6>
                    </div>
                    <div class="card-body">
            `;
            
            certificateAnalysis.forEach((cert, index) => {
                const certNumber = certificateAnalysis.length > 1 ? `证书 ${index + 1}` : '上传的证书';
                
                analysisHtml += `
                    <div class="certificate-detail mb-4 p-4 border rounded bg-white">
                        <h6 class="text-primary mb-3">
                            <i class="fas fa-file-certificate me-2"></i>${certNumber}
                        </h6>
                        <div class="row">
                `;
                
                // 证书基本信息
                if (cert.filename) {
                    analysisHtml += `
                        <div class="col-md-6 mb-2">
                            <strong><i class="fas fa-file me-2"></i>文件名:</strong>
                            <span class="ms-2">${cert.filename}</span>
                        </div>
                    `;
                }
                
                if (cert.type) {
                    const typeIcon = cert.type.includes('根证书') || cert.type.includes('CA证书') ? 
                                   'fa-shield-alt text-warning' : 'fa-globe text-success';
                    analysisHtml += `
                        <div class="col-md-6 mb-2">
                            <strong><i class="fas ${typeIcon} me-2"></i>证书类型:</strong>
                            <span class="ms-2 badge ${cert.type.includes('根证书') ? 'bg-warning' : 'bg-info'}">${cert.type}</span>
                        </div>
                    `;
                }
                
                if (cert.subject) {
                    analysisHtml += `
                        <div class="col-12 mb-2">
                            <strong><i class="fas fa-user me-2"></i>证书主题:</strong>
                            <code class="ms-2 bg-light p-1 rounded">${cert.subject}</code>
                        </div>
                    `;
                }
                
                if (cert.issuer) {
                    analysisHtml += `
                        <div class="col-12 mb-2">
                            <strong><i class="fas fa-building me-2"></i>颁发机构:</strong>
                            <code class="ms-2 bg-light p-1 rounded">${cert.issuer}</code>
                        </div>
                    `;
                }
                
                if (cert.error) {
                    analysisHtml += `
                        <div class="col-12 mb-2">
                            <strong><i class="fas fa-exclamation-triangle me-2 text-danger"></i>解析错误:</strong>
                            <span class="ms-2 text-danger">${cert.error}</span>
                        </div>
                    `;
                }
                
                analysisHtml += `
                        </div>
                    </div>
                `;
            });
            
            // 添加操作指南
            analysisHtml += `
                    </div>
                </div>
                
                <!-- 操作指南 -->
                <div class="card mt-4">
                    <div class="card-header bg-light">
                        <h6 class="mb-0"><i class="fas fa-lightbulb me-2"></i> 操作指南</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="d-flex align-items-start mb-3">
                                    <i class="fas fa-check-circle text-success me-3 mt-1"></i>
                                    <div>
                                        <h6 class="mb-1">应该上传的证书</h6>
                                        <p class="text-muted mb-0 small">• 网站服务器证书（叶子证书）<br>• 包含具体域名的证书<br>• 用于HTTPS服务的证书</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="d-flex align-items-start mb-3">
                                    <i class="fas fa-times-circle text-warning me-3 mt-1"></i>
                                    <div>
                                        <h6 class="mb-1">无法分析的证书</h6>
                                        <p class="text-muted mb-0 small">• 根证书（Root CA）<br>• 中间证书（Intermediate CA）<br>• 代码签名证书</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="alert alert-warning mt-3">
                            <h6><i class="fas fa-question-circle me-2"></i>如何获取正确的证书？</h6>
                            <ul class="mb-0 small">
                                <li>从网站直接导出服务器证书</li>
                                <li>使用浏览器查看网站证书信息</li>
                                <li>确保证书包含具体的域名（如 www.example.com）</li>
                                <li>避免使用CA机构的根证书或中间证书</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- 快速操作按钮 -->
                <div class="text-center mt-4">
                    <button class="btn btn-primary me-3" onclick="showAnalysisSection('certAnalysis')">
                        <i class="fas fa-upload me-2"></i>重新上传证书
                    </button>
                    <button class="btn btn-outline-secondary" onclick="showAnalysisSection('pcapAnalysis')">
                        <i class="fas fa-network-wired me-2"></i>尝试PCAP分析
                    </button>
                </div>
            `;
        }
        
        resultsSection.innerHTML = analysisHtml;
        // 滚动到结果区域
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    } else {
        // 如果找不到结果区域，使用alert显示主要信息
        alert("证书分析提示:\n\n" + message);
    }
}

/**
 * 生成安全分析AI报告 - 修复版
 */
async function generateSecurityAIReport() {
    console.log('开始生成安全报告...');
    
    // 使用修复版的getCurrentSecurityReport
    const currentReport = getCurrentSecurityReport();
    if (!currentReport) {
        console.error('未找到分析结果数据');
        alert('请先完成安全分析，获取分析结果后再生成报告');
        return;
    }

    console.log('当前分析数据:', currentReport);
    
    const generateBtn = document.getElementById('generateReportBtn');
    const loadingDiv = document.getElementById('reportLoading');
    const reportContent = document.getElementById('reportContent');
    const reportError = document.getElementById('reportError');
    
    // 重置状态
    reportError.style.display = 'none';
    reportContent.style.display = 'none';
    
    // 显示加载状态
    generateBtn.disabled = true;
    generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>生成中...';
    loadingDiv.style.display = 'block';

    try {
        console.log('发送请求到后端...');
        
        // 构建完整的安全分析数据结构
        const requestData = {
            source_type: 'security',
            report_type: 'security',
            original_file: '安全分析报告_' + new Date().toLocaleDateString(),
            timestamp: new Date().toISOString(),
            analysis_data: currentReport  // 关键：使用完整的分析数据
        };
        
        console.log('发送的数据:', JSON.stringify(requestData, null, 2));

        // 设置超时（90秒）
        const timeoutPromise = new Promise((_, reject) => {
            reportTimeout = setTimeout(() => {
                reject(new Error('报告生成超时，请重试'));
            }, 90000); // 90秒超时
        });

        // 使用Promise.race实现超时控制
        const response = await Promise.race([
            fetch('/api/security/generate-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            }),
            timeoutPromise
        ]);
        
        // 清理超时
        clearTimeout(reportTimeout);

        // 检查响应状态
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('后端响应:', data);
        
        if (data.status === 'success') {
            // 保存完整的报告内容，包括生成时间戳
            currentSecurityReport = {
                content: data.report_content,
                generated_at: data.generated_at || new Date().toISOString(),
                analysis_data: currentReport
            };
            
            // 使用修复的displayGeneratedReport函数
            displayGeneratedReport(data.report_content, data.generated_at);
            
            // 显示操作按钮
            document.getElementById('copyReportBtn').style.display = 'inline-block';
            document.getElementById('downloadReportBtn').style.display = 'inline-block';
            
            // 滚动到报告区域
            setTimeout(() => {
                const reportContentDiv = document.getElementById('reportContent');
                if (reportContentDiv) {
                    reportContentDiv.scrollIntoView({ 
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }, 300);
            
        } else {
            throw new Error(data.error || '报告生成失败');
        }
    } catch (error) {
        console.error('报告生成失败:', error);

        // 确保清理超时
        if (reportTimeout) clearTimeout(reportTimeout);
        
        // 根据错误类型显示不同的消息
        let errorMessage = '报告生成失败: ';
        if (error.message.includes('超时')) {
            errorMessage += '生成时间过长，可能是数据量较大或网络延迟，请稍后重试';
        } else if (error.message.includes('网络')) {
            errorMessage += '网络连接问题，请检查网络后重试';
        } else {
            errorMessage += error.message;
        }
        showReportError(errorMessage);
    } finally {
        // 恢复按钮状态
        generateBtn.disabled = false;
        generateBtn.innerHTML = '<i class="fas fa-magic me-2"></i>生成AI报告';
        loadingDiv.style.display = 'none';
        if (reportTimeout) clearTimeout(reportTimeout);
    }
}

/**
 * 显示生成的报告区域 - 修复版
 */
function displayReportGenerationArea(reportContent) {
    if (!reportContent) {
        console.warn('报告内容为空，不显示报告区域');
        return;
    }
    
    const reportText = document.getElementById('reportText');
    const reportContentDiv = document.getElementById('reportContent');
    
    if (!reportText || !reportContentDiv) {
        console.error('找不到报告显示元素');
        return;
    }
    
    // 确保是字符串类型
    const content = typeof reportContent === 'string' 
        ? reportContent 
        : JSON.stringify(reportContent, null, 2);
    
    reportText.textContent = content;
    reportContentDiv.style.display = 'block';
    console.log('报告区域已显示，内容长度:', content.length);
}

/**
 * 复制报告内容 - 保持HTML格式
 */
async function copySecurityReport() {
    if (!currentSecurityReport) {
        alert('没有可复制的报告内容');
        return;
    }

    try {
        // 将报告内容转换为HTML格式
        const htmlContent = formatReportToHTML(currentSecurityReport.content);
        
        // 创建包含样式的完整HTML文档
        const fullHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        .security-report {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            font-size: 14px;
            color: #333;
        }
        .report-main-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: #1a365d;
            margin: 1.5rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 3px solid #2c5aa0;
        }
        .report-section-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2d3748;
            margin: 1.25rem 0 0.75rem 0;
            padding-left: 0.5rem;
            border-left: 4px solid #4299e1;
        }
        .report-subsection-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #4a5568;
            margin: 1rem 0 0.5rem 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        th, td {
            padding: 0.5rem;
            border: 1px solid #dee2e6;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        code {
            background: #f1f3f4;
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
        }
        pre {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.9em;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    ${htmlContent}
</body>
</html>`;
        
        // 复制HTML格式内容
        await navigator.clipboard.write([
            new ClipboardItem({
                'text/html': new Blob([fullHtml], { type: 'text/html' }),
                'text/plain': new Blob([currentSecurityReport.content], { type: 'text/plain' })
            })
        ]);
        
        // 显示复制成功反馈
        const copyBtn = document.getElementById('copyReportBtn');
        const originalHtml = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="fas fa-check me-2"></i>已复制';
        copyBtn.classList.remove('btn-outline-secondary');
        copyBtn.classList.add('btn-success');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalHtml;
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('btn-outline-secondary');
        }, 2000);
        
    } catch (error) {
        console.error('复制失败:', error);
        // 降级方案：复制纯文本
        try {
            await navigator.clipboard.writeText(currentSecurityReport.content);
            alert('已复制纯文本格式报告');
        } catch (fallbackError) {
            alert('复制失败，请手动选择文本复制');
        }
    }
}

/**
 * 下载报告文件 - 保持HTML格式
 */
function downloadSecurityReport() {
    if (!currentSecurityReport) {
        alert('没有可下载的报告内容');
        return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // 创建HTML格式的报告
    const htmlContent = formatReportToHTML(currentSecurityReport.content);
    const fullHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>域名安全配置深度分析报告</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            max-width: 900px; 
            margin: 0 auto; 
            padding: 2rem;
        }
        .security-report {
            line-height: 1.5;
            font-size: 14px;
        }
        .report-main-title {
            font-size: 1.6rem;
            font-weight: 700;
            color: #1a365d;
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 3px solid #2c5aa0;
            text-align: center;
        }
        .report-section-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2d3748;
            margin: 1.5rem 0 1rem 0;
            padding-left: 0.5rem;
            border-left: 4px solid #4299e1;
        }
        .report-subsection-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #4a5568;
            margin: 1.25rem 0 0.75rem 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 13px;
        }
        th, td {
            padding: 0.75rem;
            border: 1px solid #dee2e6;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        code {
            background: #f1f3f4;
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
        }
        pre {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            border: 1px solid #e9ecef;
        }
        .risk-high { background-color: #f8d7da; border: 1px solid #f1aeb5; color: #721c24; padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; }
        .risk-medium { background-color: #fff3cd; border: 1px solid #ffd966; color: #664d03; padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; }
        .risk-low { background-color: #d1e7dd; border: 1px solid #a3cfbb; color: #0f5132; padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; }
        ul { margin: 0.5rem 0 0.5rem 1.5rem; }
        li { margin-bottom: 0.25rem; }
        hr { margin: 2rem 0; border: none; border-top: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="security-report">
        ${htmlContent}
    </div>
</body>
</html>`;

    // 创建下载
    const blob = new Blob([fullHtml], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.href = url;
    link.download = `安全分析报告_${timestamp}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/**
 * 获取当前安全分析结果 - 增强修复版
 */
function getCurrentSecurityReport() {
    console.log('=== 获取当前安全分析结果 ===');
    
    // 方法1: 检查全局变量（主要来源）
    if (typeof window.lastSecurityReport !== 'undefined' && window.lastSecurityReport !== null) {
        console.log('从全局变量获取分析结果:', window.lastSecurityReport.summary);
        return window.lastSecurityReport;
    }
    
    // 方法2: 检查sessionStorage备份
    try {
        const storedReport = sessionStorage.getItem('lastSecurityReport');
        if (storedReport) {
            const parsedReport = JSON.parse(storedReport);
            console.log('从sessionStorage恢复分析结果:', parsedReport.summary);
            window.lastSecurityReport = parsedReport; // 恢复到全局变量
            return parsedReport;
        }
    } catch (e) {
        console.warn('sessionStorage解析失败:', e);
    }
    
    // 方法3: 从DOM中提取（最后手段）
    console.log('尝试从DOM提取分析结果...');
    const fallbackReport = createFallbackReportFromDOM();
    if (fallbackReport && fallbackReport.summary) {
        console.log('从DOM创建回退报告成功');
        return fallbackReport;
    }
    
    console.error('未找到有效的安全分析结果');
    return null;
}

/**
 * 从DOM创建回退报告（当数据丢失时）
 */
function createFallbackReportFromDOM() {
    console.log('尝试从DOM创建回退报告');
    
    // 从页面显示的内容提取基本信息
    const scoreCard = document.getElementById('scoreCard');
    let securityScore = 0;
    
    if (scoreCard) {
        const scoreMatch = scoreCard.textContent.match(/(\d+)\/100/);
        if (scoreMatch) {
            securityScore = parseInt(scoreMatch[1]);
        }
    }
    
    return {
        summary: {
            security_score: securityScore,
            analyzed_domains: 1,
            domains_with_https_enforcement: 0,
            domains_with_hsts: 0,
            domains_with_good_security_headers: 0,
            domains_with_valid_certificate_chains: 0
        },
        detailed_results: [],
        scoreDistribution: [0, 0, 0, 0],
        featureStats: {
            https: 0,
            hsts: 0,
            good_headers: 0,
            valid_chains: 0
        }
    };
}

/**
 * 设置当前安全分析结果 - 增强版
 */
function setCurrentSecurityReport(reportData) {
    console.log('设置当前安全分析结果:', reportData?.summary);
    
    if (!reportData) {
        console.warn('尝试设置空的报告数据');
        return;
    }
    
    // 确保数据结构完整
    const completeReport = {
        ...reportData,
        summary: reportData.summary || {},
        detailed_results: reportData.detailed_results || [],
        timestamp: new Date().toISOString()
    };
    
    // 设置到全局变量
    window.lastSecurityReport = completeReport;
    
    // 同时保存到sessionStorage
    try {
        sessionStorage.setItem('lastSecurityReport', JSON.stringify(completeReport));
        console.log('分析结果已保存到sessionStorage');
    } catch (e) {
        console.warn('无法保存到sessionStorage:', e);
    }
    
    // 同时保存到localStorage作为备份
    try {
        localStorage.setItem('lastSecurityReportBackup', JSON.stringify(completeReport));
    } catch (e) {
        console.warn('无法保存到localStorage:', e);
    }
}

/**
 * 初始化页面事件监听器
 */
function initializeEventListeners() {
    // 快速开始指南按钮
    const startUsingBtn = document.getElementById('startUsingBtn');
    if (startUsingBtn) {
        startUsingBtn.addEventListener('click', function() {
            document.getElementById('analysisEntrance').style.display = 'block';
            document.getElementById('analysisEntrance').scrollIntoView({ behavior: 'smooth' });
        });
    }
    
    // 折叠/展开指南按钮
    const toggleGuideBtn = document.getElementById('toggleGuideBtn');
    if (toggleGuideBtn) {
        toggleGuideBtn.addEventListener('click', function() {
            const quickStartBody = document.getElementById('quickStartBody');
            if (quickStartBody.style.display === 'none') {
                quickStartBody.style.display = 'block';
                this.innerHTML = '<i class="fas fa-times"></i> 折叠';
            } else {
                quickStartBody.style.display = 'none';
                this.innerHTML = '<i class="fas fa-chevron-down"></i> 展开';
            }
        });
    }
    
    // 功能入口卡片点击事件
    const featureEntrances = document.querySelectorAll('.feature-entrance');
    featureEntrances.forEach(card => {
        card.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            if (targetId) {
                // 使用 utils.js 中的 showAnalysisSection
                if (typeof showAnalysisSection === 'function') {
                    showAnalysisSection(targetId);
                }
            }
        });
    });
    
    // 关闭分析区域按钮
    const closeButtons = document.querySelectorAll('[data-hide]');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-hide');
            if (targetId) {
                // 使用 utils.js 中的 hideAnalysisSection
                if (typeof hideAnalysisSection === 'function') {
                    hideAnalysisSection(targetId);
                }
            }
        });
    });
    
    // PCAP分析按钮
    const analyzePcapBtn = document.getElementById('analyzePcapBtn');
    if (analyzePcapBtn) {
        analyzePcapBtn.addEventListener('click', function() {
            const fileInput = document.getElementById('pcapFile');
            if (!fileInput.files.length) {
                alert('请选择PCAP文件');
                return;
            }
            processPcapAnalysis(fileInput.files[0]);
        });
    }
    
    // 证书分析按钮
    const analyzeCertBtn = document.getElementById('analyzeCertBtn');
    if (analyzeCertBtn) {
        analyzeCertBtn.addEventListener('click', function() {
            const zipFileInput = document.getElementById('certZipFile');
            const derFileInput = document.getElementById('certDerFile');
            
            let fileToAnalyze = null;
            let analysisType = '';
            
            if (zipFileInput.files.length) {
                fileToAnalyze = zipFileInput.files[0];
                analysisType = 'zip';
            } else if (derFileInput.files.length) {
                fileToAnalyze = derFileInput.files[0];
                analysisType = 'der';
            } else {
                alert('请选择证书文件');
                return;
            }
            
            processCertificateAnalysis(fileToAnalyze, analysisType);
        });
    }
    
    // AI报告生成按钮 - 修改为使用新的异步函数
    const generateReportBtn = document.getElementById('generateReportBtn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', generateSecurityReport);
    }
    
    // 复制报告按钮
    const copyReportBtn = document.getElementById('copyReportBtn');
    if (copyReportBtn) {
        copyReportBtn.addEventListener('click', copyReport);
    }
    
    // 下载报告按钮
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', downloadReport);
    }
    
    // 安全增强分析表单
    const domainSecurityForm = document.getElementById('domainSecurityForm');
    if (domainSecurityForm) {
        domainSecurityForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const domain = document.getElementById('domainInput').value.trim();
            if (domain) {
                analyzeSingleDomain(domain);
            }
        });
    }
    
    const batchSecurityForm = document.getElementById('batchSecurityForm');
    if (batchSecurityForm) {
        batchSecurityForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const domainsText = document.getElementById('domainsTextarea').value.trim();
            if (domainsText) {
                const domains = domainsText.split('\n').filter(d => d.trim());
                if (domains.length > 0) {
                    analyzeBatchDomains(domains);
                }
            }
        });
    }
    
    // 监听页面卸载事件，清理轮询
    window.addEventListener('beforeunload', function() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    });
}

// ============== 新增的异步报告生成功能 ==============

/**
 * 生成安全分析报告 - 修复超时问题
 */
async function generateSecurityReport() {
    // 重置状态
    resetReportUI();
    
    // 隐藏原有按钮，显示状态
    document.getElementById('generateReportBtn').style.display = 'none';
    document.getElementById('reportStatus').style.display = 'block';
    updateStatusMessage('正在提交报告生成任务...');
    updateProgress(10);
    
    // 开始计时器
    startStatusTimer();
    
    try {
        // 获取当前的安全分析数据
        const securityReport = getCurrentSecurityReport();
        
        if (!securityReport) {
            throw new Error('没有可用的安全分析数据。请先完成安全分析');
        }
        
        // 准备请求数据 - 确保数据结构正确
        const requestData = {
            source_type: 'security',
            report_type: 'security',
            analysis_data: {
                summary: securityReport.summary || {},
                detailed_results: securityReport.detailed_results || [],
                scoreDistribution: securityReport.scoreDistribution || [0, 0, 0, 0],
                featureStats: securityReport.featureStats || {},
                timestamp: new Date().toISOString()
            },
            original_file: '安全分析报告_' + new Date().toLocaleDateString()
        };
        
        console.log('提交报告生成请求，数据大小:', JSON.stringify(requestData).length, '字节');
        
        // 1. 提交异步任务 - 添加超时控制
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000); // 15秒超时
        
        const response = await fetch('/api/security/generate-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestData),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('API响应错误:', response.status, errorText);
            
            // 尝试解析错误信息
            try {
                const errorData = JSON.parse(errorText);
                throw new Error(errorData.error || `HTTP错误: ${response.status}`);
            } catch (e) {
                throw new Error(`服务器响应错误: ${response.status} ${response.statusText}`);
            }
        }
        
        const result = await response.json();
        console.log('任务提交响应:', result);
        
        // 处理不同的响应格式
        if (result.status === 'processing' && result.task_id) {
            // 任务提交成功，开始轮询
            currentTaskId = result.task_id;
            document.getElementById('taskIdDisplay').textContent = currentTaskId;
            updateStatusMessage('AI正在生成报告...');
            updateProgress(30);
            
            // 开始轮询任务状态
            pollReportStatus(currentTaskId);
            
        } else if (result.status === 'success' && result.report_content) {
            // 直接返回报告（同步处理）
            console.log('收到同步生成的报告，长度:', result.report_content.length);
            updateProgress(100);
            updateStatusMessage('报告生成完成！');
            
            // 保存到全局变量
            window.currentSecurityReport = {
                content: result.report_content,
                generated_at: result.generated_at || new Date().toISOString(),
                analysis_data: securityReport
            };
            
            // 显示报告
            setTimeout(() => {
                if (typeof displayGeneratedReport === 'function') {
                    displayGeneratedReport(result.report_content, result.generated_at);
                } else {
                    displayReportContent(result.report_content);
                }
                
                // 显示按钮
                document.getElementById('copyReportBtn').style.display = 'inline-block';
                document.getElementById('downloadReportBtn').style.display = 'inline-block';
                
                // 隐藏状态
                document.getElementById('reportStatus').style.display = 'none';
            }, 300);
            
        } else if (result.status === 'error') {
            // 直接返回错误
            showReportError(result.error || '报告生成失败');
        } else {
            // 未知响应格式
            console.warn('未知的响应格式:', result);
            showReportError('服务器返回了未知的响应格式');
        }
        
    } catch (error) {
        console.error('提交报告任务失败:', error);
        
        // 根据错误类型显示不同的消息
        let errorMessage = '报告生成失败: ';
        if (error.name === 'AbortError') {
            errorMessage += '请求超时，请检查网络连接';
        } else if (error.message.includes('网络') || error.message.includes('Network')) {
            errorMessage += '网络连接问题，请检查网络后重试';
        } else if (error.message.includes('JSON')) {
            errorMessage += '服务器响应格式错误';
        } else {
            errorMessage += error.message;
        }
        
        showReportError(errorMessage);
        
        // 重新显示生成按钮
        document.getElementById('generateReportBtn').style.display = 'inline-block';
    }
}

/**
 * 轮询报告生成状态 - 修复版
 * @param {string} taskId - 任务ID
 */
function pollReportStatus(taskId) {
    // 清除之前的轮询
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    
    let pollCount = 0;
    const maxPollCount = 60; // 增加到60次（3分钟）
    const pollIntervalMs = 3000; // 每3秒轮询一次
    
    pollInterval = setInterval(async () => {
        pollCount++;
        
        // 更新进度（随时间增加）
        const progress = Math.min(30 + Math.floor(pollCount / maxPollCount * 50), 95);
        updateProgress(progress);
        updateStatusMessage(`AI生成报告中... (已等待${pollCount * 3}秒)`);
        
        try {
            console.log(`轮询 ${taskId} 第 ${pollCount} 次`);
            const response = await fetch(`/api/security/report-status/${taskId}`);
            
            if (!response.ok) {
                console.error(`HTTP错误 ${response.status}:`, response.statusText);
                // 不要立即失败，尝试继续轮询
                if (pollCount >= 10 && response.status >= 500) {
                    throw new Error(`服务器错误: ${response.status}`);
                }
                return; // 继续下一次轮询
            }
            
            const result = await response.json();
            console.log(`轮询 ${taskId} 状态:`, result);
            
            // 处理各种状态 - 修复状态判断逻辑
            if (result.status === 'completed' || result.status === 'success' || result.status === 'finished') {
                if (!result.report_content || result.report_content.trim() === '') {
                    console.warn('报告任务完成但内容为空，状态:', result);
                    // 检查是否有其他字段包含报告内容
                    const possibleContent = result.report || result.content || result.data || result.result;
                    if (possibleContent && possibleContent.trim() !== '') {
                        console.log('从其他字段找到报告内容');
                        result.report_content = possibleContent;
                    } else {
                        throw new Error('报告内容为空，请重试');
                    }
                }
                
                // 任务完成，显示报告
                clearInterval(pollInterval);
                pollInterval = null;
                clearInterval(timerInterval);
                timerInterval = null;
                
                updateProgress(100);
                updateStatusMessage('报告生成完成！');
                
                // 使用后端返回的生成时间
                const generatedAt = result.generated_at || new Date().toISOString();
    
                // 保存到全局变量
                window.currentSecurityReport = {
                    content: result.report_content,
                    generated_at: generatedAt,
                    analysis_data: getCurrentSecurityReport()
                };
        
                // 立即显示报告
                setTimeout(() => {
                    // 使用 displayGeneratedReport 函数
                    if (typeof displayGeneratedReport === 'function') {
                        console.log('使用 displayGeneratedReport 显示报告');
                        displayGeneratedReport(result.report_content, generatedAt);
                    } else {
                        console.log('使用 displayReportContent 显示报告');
                        displayReportContent(result.report_content);
                    }
                    
                    // 显示按钮
                    document.getElementById('copyReportBtn').style.display = 'inline-block';
                    document.getElementById('downloadReportBtn').style.display = 'inline-block';
        
                    // 隐藏状态
                    document.getElementById('reportStatus').style.display = 'none';
                    
                    // 滚动到报告位置
                    document.getElementById('reportContent').scrollIntoView({ 
                        behavior: 'smooth',
                        block: 'start' 
                    });
                    
                }, 300);
                
            } else if (result.status === 'error' || result.status === 'failed') {
                // 任务失败
                clearInterval(pollInterval);
                pollInterval = null;
                clearInterval(timerInterval);
                timerInterval = null;
                showReportError(result.error || result.message || '报告生成失败');
                
            } else if (result.status === 'processing' || result.status === 'pending' || result.status === 'running') {
                // 仍在处理中，继续轮询
                updateStatusMessage(`AI生成报告中... (已等待${pollCount * 3}秒)`);
                
                // 如果轮询次数超过上限，显示超时
                if (pollCount >= maxPollCount) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    clearInterval(timerInterval);
                    timerInterval = null;
                    
                    // 尝试最后一次获取报告（可能后端已经完成但状态未更新）
                    try {
                        console.log('轮询超时，尝试最后获取一次报告');
                        const finalResponse = await fetch(`/api/security/get-report/${taskId}`);
                        if (finalResponse.ok) {
                            const finalResult = await finalResponse.json();
                            if (finalResult.report_content) {
                                // 成功获取到报告
                                displayReportContent(finalResult.report_content);
                                return;
                            }
                        }
                    } catch (e) {
                        console.error('最后获取失败:', e);
                    }
                    
                    showReportError('报告生成超时，但可能已经生成。请刷新页面检查报告列表');
                }
                
            } else if (result.status === 'not_found' || result.status === '404') {
                // 任务不存在
                clearInterval(pollInterval);
                pollInterval = null;
                clearInterval(timerInterval);
                timerInterval = null;
                showReportError('报告任务不存在或已过期');
            } else {
                // 未知状态，继续轮询
                console.warn('未知状态:', result.status);
            }
            
        } catch (error) {
            console.error(`轮询${taskId}失败:`, error);
            
            // 如果多次轮询失败，停止轮询
            if (pollCount >= 10) {
                clearInterval(pollInterval);
                pollInterval = null;
                clearInterval(timerInterval);
                timerInterval = null;
                showReportError(`获取报告状态失败: ${error.message}`);
            }
        }
    }, pollIntervalMs);
    
    // 设置更长的超时时间
    const timeoutDuration = pollIntervalMs * maxPollCount + 15000; // 3分钟+15秒缓冲
    setTimeout(() => {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
            clearInterval(timerInterval);
            timerInterval = null;
            if (document.getElementById('reportStatus').style.display !== 'none') {
                showReportError('报告生成超时，请检查网络连接后重试或联系管理员');
            }
        }
    }, timeoutDuration);
}

/**
 * 显示报告内容
 * @param {string} reportContent - 报告内容
 */
function displayReportContent(reportContent) {
    // 保存报告数据
    reportData = {
        content: reportContent,
        generatedAt: new Date().toLocaleString()
    };
    
    // 隐藏状态显示
    document.getElementById('reportStatus').style.display = 'none';
    
    // 显示报告内容
    const reportText = document.getElementById('reportText');
    reportText.textContent = reportContent;
    
    // 显示报告生成时间
    document.getElementById('reportTime').textContent = reportData.generatedAt;
    
    // 显示报告区域
    document.getElementById('reportContent').style.display = 'block';
    
    // 显示复制和下载按钮
    document.getElementById('copyReportBtn').style.display = 'inline-block';
    document.getElementById('downloadReportBtn').style.display = 'inline-block';
    
    // 添加报告样式
    highlightReportContent(reportContent);
    
    // 滚动到报告位置
    document.getElementById('reportContent').scrollIntoView({ behavior: 'smooth' });
}

/**
 * 使用marked.js转换Markdown报告 - 修复版
 */
function formatReportWithMarked(reportContent) {
    if (!reportContent || typeof reportContent !== 'string') {
        console.warn('报告内容为空或不是字符串');
        return '<div class="alert alert-warning">报告内容为空</div>';
    }
    
    console.log('使用marked.js转换报告，长度:', reportContent.length);
    
    // 检查marked.js是否已加载
    if (typeof marked === 'undefined') {
        console.error('marked.js未加载，显示原始内容');
        // 返回包含原始内容的格式，而不是错误信息
        return `
            <div class="security-report">
                <div class="alert alert-info mb-3">
                    <i class="fas fa-info-circle me-2"></i>
                    显示原始报告内容（格式美化不可用）
                </div>
                <pre class="bg-light p-3 rounded border">${escapeHtml(reportContent)}</pre>
            </div>
        `;
    }
    
    try {
        // 配置marked选项
        const options = {
            gfm: true,
            breaks: true,
            headerIds: true,
            headerPrefix: 'report-',
            mangle: false,
            smartLists: true,
            smartypants: true,
            xhtml: false
        };
        
        // 调试：检查marked版本
        console.log('marked版本检查:', {
            isFunction: typeof marked,
            hasParse: typeof marked.parse,
            hasMarked: typeof marked.marked,
            version: marked.version
        });
        
        let html;
        
        // 尝试不同的marked版本调用方式
        if (typeof marked.parse === 'function') {
            // marked v4+
            console.log('使用marked.parse (v4+)');
            html = marked.parse(reportContent, options);
        } else if (typeof marked === 'function') {
            // marked v3及以下
            console.log('使用marked() (v3)');
            html = marked(reportContent, options);
        } else if (marked.marked && typeof marked.marked.parse === 'function') {
            // marked v5+
            console.log('使用marked.marked.parse (v5+)');
            html = marked.marked.parse(reportContent, options);
        } else {
            console.error('未知的marked版本格式');
            throw new Error('无法识别的marked库版本');
        }
        
        console.log('marked转换成功，HTML长度:', html.length);
        
        // 返回转换后的内容（不包含错误信息）
        return `
            <div class="security-report">
                ${html}
            </div>
        `;
        
    } catch (error) {
        console.error('marked.js转换失败，错误详情:', error);
        console.error('错误堆栈:', error.stack);
        
        // 即使出错，也显示报告内容（只是没有格式美化）
        // 而不是显示错误信息隐藏了报告内容
        return `
            <div class="security-report">
                <div class="alert alert-warning mb-3">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    格式美化功能暂不可用，显示原始报告内容
                </div>
                <pre class="bg-light p-3 rounded border">${escapeHtml(reportContent)}</pre>
            </div>
        `;
    }
}

/**
 * 下载报告
 */
function downloadReport() {
    if (!reportData || !reportData.content) {
        showAlert('没有可下载的报告内容', 'warning');
        return;
    }
    
    // 获取报告文件名
    const timestamp = new Date().toISOString().slice(0, 19).replace(/[:]/g, '-');
    const filename = `安全分析报告_${timestamp}.txt`;
    
    // 创建Blob并下载
    const blob = new Blob([reportData.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    // 显示成功消息
    showAlert('报告下载成功', 'success');
}

/**
 * 复制报告内容到剪贴板
 */
async function copyReport() {
    if (!reportData || !reportData.content) {
        showAlert('没有可复制的报告内容', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(reportData.content);
        showAlert('报告内容已复制到剪贴板', 'success');
    } catch (err) {
        console.error('复制失败:', err);
        
        // 降级方案：使用textarea
        const textArea = document.createElement('textarea');
        textArea.value = reportData.content;
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                showAlert('报告内容已复制到剪贴板', 'success');
            } else {
                showAlert('复制失败，请手动选择并复制', 'error');
            }
        } catch (err) {
            showAlert('复制失败，请手动选择并复制', 'error');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * 显示报告错误
 * @param {string} errorMessage - 错误信息
 */
function showReportError(errorMessage) {
    // 隐藏状态显示
    document.getElementById('reportStatus').style.display = 'none';
    
    // 显示错误信息
    document.getElementById('errorMessage').textContent = errorMessage;
    document.getElementById('reportError').style.display = 'block';
    
    // 重新显示生成按钮
    document.getElementById('generateReportBtn').style.display = 'inline-block';
    
    // 清除轮询和计时器
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
    
    // 滚动到错误位置
    document.getElementById('reportError').scrollIntoView({ behavior: 'smooth' });
}

/**
 * 重试报告生成
 */
function retryReport() {
    // 隐藏错误
    document.getElementById('reportError').style.display = 'none';
    
    // 重新生成报告
    generateSecurityReport();
}

/**
 * 更新状态消息
 * @param {string} message - 状态消息
 */
function updateStatusMessage(message) {
    const statusElement = document.getElementById('statusMessage');
    if (statusElement) {
        statusElement.textContent = message;
    }
}

/**
 * 更新进度条
 * @param {number} percentage - 进度百分比 (0-100)
 */
function updateProgress(percentage) {
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = `${percentage}%`;
        progressBar.setAttribute('aria-valuenow', percentage);
    }
}

/**
 * 开始状态计时器
 */
function startStatusTimer() {
    statusTimer = 0;
    clearInterval(timerInterval);
    
    timerInterval = setInterval(() => {
        statusTimer++;
        document.getElementById('statusTimer').textContent = `${statusTimer}s`;
    }, 1000);
}

/**
 * 重置报告UI
 */
function resetReportUI() {
    // 隐藏所有显示区域
    document.getElementById('reportContent').style.display = 'none';
    document.getElementById('reportError').style.display = 'none';
    document.getElementById('copyReportBtn').style.display = 'none';
    document.getElementById('downloadReportBtn').style.display = 'none';
    
    // 重置进度条
    updateProgress(0);
    
    // 重置计时器
    statusTimer = 0;
    document.getElementById('statusTimer').textContent = '0s';
    
    // 清除报告数据
    reportData = null;
    
    // 清除轮询和计时器
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
}

/**
 * 显示提示消息
 * @param {string} message - 消息内容
 * @param {string} type - 消息类型 (success, error, info, warning)
 */
function showAlert(message, type = 'info') {
    // 创建提示元素
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // 添加到页面顶部
    const alertContainer = document.querySelector('.container') || document.body;
    const firstChild = alertContainer.firstChild;
    if (firstChild) {
        alertContainer.insertBefore(createElementFromHTML(alertHtml), firstChild);
    } else {
        alertContainer.appendChild(createElementFromHTML(alertHtml));
    }
    
    // 5秒后自动消失
    setTimeout(() => {
        const alertElement = document.getElementById(alertId);
        if (alertElement) {
            alertElement.remove();
        }
    }, 5000);
}

/**
 * 从HTML字符串创建元素
 */
function createElementFromHTML(htmlString) {
    const div = document.createElement('div');
    div.innerHTML = htmlString.trim();
    return div.firstChild;
}

/**
 * 获取当前分析数据（需要根据你的实际代码调整）
 */
function getCurrentAnalysisData() {
    // 这里需要根据你的实际数据结构返回数据
    // 示例：返回全局变量或从DOM获取
    return getCurrentSecurityReport() || null;
}

// 在DOM加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeSecurityFeatures();
    initializeEventListeners();
    
    // 初始化页面状态
    document.getElementById('quickStartGuide').style.display = 'block';
    document.getElementById('analysisEntrance').style.display = 'none';
    document.getElementById('analysisResults').style.display = 'none';
    if (document.getElementById('securityEnhancement')) {
        document.getElementById('securityEnhancement').style.display = 'none';
    }
    document.getElementById('quickStartBody').style.display = 'block';
});

// 在原有的 security.js 文件末尾添加以下代码

/**
 * 页面初始化函数 - 更新版
 */
function initializeSecurityPage() {
    console.log('初始化安全分析页面...');
    
    // 隐藏AI报告生成区域（按照需求文档要求）
    const aiReportSection = document.getElementById('reportGeneration');
    if (aiReportSection) {
        aiReportSection.style.display = 'none';
    }
    
    // 确保动态内容区域初始隐藏
    const dynamicContentArea = document.getElementById('dynamicContentArea');
    if (dynamicContentArea) {
        dynamicContentArea.style.display = 'none';
    }
    
    // 初始化原有的事件监听器
    if (typeof initializeEventListeners === 'function') {
        initializeEventListeners();
    }
}

// 在DOM加载完成后调用新的初始化函数
document.addEventListener('DOMContentLoaded', function() {
    // 原有的初始化函数
    initializeSecurityFeatures();
    
    // 新的页面初始化
    initializeSecurityPage();
    
    // 设置页面初始状态
    console.log('页面初始化完成');
    
    // 确保分析结果区域初始隐藏
    const analysisResults = document.getElementById('analysisResults');
    if (analysisResults) {
        analysisResults.style.display = 'none';
    }
});

/**
 * 分析PCAP文件 - 适配新页面结构
 */
async function processPcapAnalysis(file) {
    console.log('开始分析PCAP文件:', file.name);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        // 显示加载状态
        showLoadingState();
        
        const response = await fetch('/api/security/analyze-pcap', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('PCAP分析响应:', data);
        
        if (data.status === 'success') {
            // 显示分析结果
            displaySecurityReport(data.security_report);
            
            // 确保分析结果区域在动态内容区域内显示
            const resultsSection = document.getElementById('analysisResults');
            if (resultsSection) {
                resultsSection.style.display = 'block';
                resultsSection.scrollIntoView({ behavior: 'smooth' });
            }
            
        } else {
            throw new Error(data.error || '分析失败');
        }
    } catch (error) {
        console.error('PCAP分析错误:', error);
        alert('分析失败: ' + error.message);
    } finally {
        hideLoadingState();
    }
}

/**
 * 分析证书文件 - 适配新页面结构
 */
async function processCertificateAnalysis(file, type) {
    console.log('开始分析证书文件:', file.name, '类型:', type);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('analysis_type', type);
        
        // 显示加载状态
        showLoadingState();
        
        const response = await fetch('/api/security/analyze-certificates', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('证书分析响应:', data);
        
        if (data.status === 'success') {
            // 显示分析结果
            displaySecurityReport(data.security_report);
            
            // 确保分析结果区域在动态内容区域内显示
            const resultsSection = document.getElementById('analysisResults');
            if (resultsSection) {
                resultsSection.style.display = 'block';
                resultsSection.scrollIntoView({ behavior: 'smooth' });
            }
            
        } else if (data.status === 'info') {
            // 处理信息状态
            showCertificateInfo(data);
        } else if (data.status === 'warning') {
            // 处理警告状态
            showCertificateWarning(data.message, data.certificate_analysis);
        } else {
            throw new Error(data.error || '分析失败');
        }
    } catch (error) {
        console.error('证书分析错误:', error);
        alert('分析失败: ' + error.message);
    } finally {
        hideLoadingState();
    }
}

/**
 * 显示加载状态
 */
function showLoadingState() {
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const actualResults = document.getElementById('actualResults');
    
    if (loadingSkeleton) {
        loadingSkeleton.style.display = 'block';
    }
    if (actualResults) {
        actualResults.style.display = 'none';
    }
}

/**
 * 隐藏加载状态
 */
function hideLoadingState() {
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const actualResults = document.getElementById('actualResults');
    
    if (loadingSkeleton) {
        loadingSkeleton.style.display = 'none';
    }
    if (actualResults) {
        actualResults.style.display = 'block';
    }
}

// 在原有的 security.js 文件末尾添加以下代码

/**
 * 页面初始化函数 - 确保与页面脚本兼容
 */
function initializeSecurityPage() {
    console.log('安全分析页面初始化...');
    
    // 确保动态内容区域初始隐藏
    const dynamicContentArea = document.getElementById('dynamicContentArea');
    if (dynamicContentArea) {
        dynamicContentArea.style.display = 'none';
    }
    
    // 初始化原有的事件监听器
    if (typeof initializeEventListeners === 'function') {
        initializeEventListeners();
    }
    
    console.log('安全分析页面初始化完成');
}

// 在DOM加载完成后调用
document.addEventListener('DOMContentLoaded', function() {
    // 原有的初始化函数
    if (typeof initializeSecurityFeatures === 'function') {
        initializeSecurityFeatures();
    }
    
    // 新的页面初始化
    initializeSecurityPage();
    
    console.log('页面完全加载完成');
});

/**
 * 分析PCAP文件 - 更新版，确保能正确显示结果
 */
async function processPcapAnalysis(file) {
    console.log('开始分析PCAP文件:', file.name);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        // 显示加载状态（使用页面中的函数）
        if (typeof showSecurityAnalysisLoading === 'function') {
            showSecurityAnalysisLoading();
        }
        
        const response = await fetch('/api/security/analyze-pcap', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('PCAP分析响应:', data);
        
        if (data.status === 'success') {
            // 调用页面中的结果显示函数
            if (typeof showSecurityAnalysisResult === 'function') {
                showSecurityAnalysisResult(data.security_report);
            } else if (typeof onSecurityAnalysisComplete === 'function') {
                onSecurityAnalysisComplete(data.security_report);
            } else {
                // 降级方案：直接显示结果
                alert('分析完成！安全分数：' + (data.security_report?.summary?.security_score || 0));
            }
            
        } else {
            throw new Error(data.error || '分析失败');
        }
    } catch (error) {
        console.error('PCAP分析错误:', error);
        
        // 隐藏加载状态
        const loadingSkeleton = document.getElementById('loadingSkeleton');
        if (loadingSkeleton) {
            loadingSkeleton.style.display = 'none';
        }
        
        alert('分析失败: ' + error.message);
        
        // 返回到选择界面
        if (typeof resetSecurityAnalysis === 'function') {
            resetSecurityAnalysis();
        }
    }
}

/**
 * 分析证书文件 - 更新版
 */
async function processCertificateAnalysis(file, type) {
    console.log('开始分析证书文件:', file.name, '类型:', type);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('analysis_type', type);
        
        // 显示加载状态（使用页面中的函数）
        if (typeof showSecurityAnalysisLoading === 'function') {
            showSecurityAnalysisLoading();
        }
        
        const response = await fetch('/api/security/analyze-certificates', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP错误: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('证书分析响应:', data);
        
        if (data.status === 'success') {
            // 调用页面中的结果显示函数
            if (typeof showSecurityAnalysisResult === 'function') {
                showSecurityAnalysisResult(data.security_report);
            } else if (typeof onSecurityAnalysisComplete === 'function') {
                onSecurityAnalysisComplete(data.security_report);
            } else {
                // 降级方案：直接显示结果
                alert('分析完成！安全分数：' + (data.security_report?.summary?.security_score || 0));
            }
            
        } else if (data.status === 'info') {
            // 处理信息状态
            if (typeof showCertificateInfo === 'function') {
                showCertificateInfo(data);
            }
        } else if (data.status === 'warning') {
            // 处理警告状态
            if (typeof showCertificateWarning === 'function') {
                showCertificateWarning(data.message, data.certificate_analysis);
            }
        } else {
            throw new Error(data.error || '分析失败');
        }
    } catch (error) {
        console.error('证书分析错误:', error);
        
        // 隐藏加载状态
        const loadingSkeleton = document.getElementById('loadingSkeleton');
        if (loadingSkeleton) {
            loadingSkeleton.style.display = 'none';
        }
        
        alert('分析失败: ' + error.message);
        
        // 返回到选择界面
        if (typeof resetSecurityAnalysis === 'function') {
            resetSecurityAnalysis();
        }
    }
}

// 如果页面中缺少必要的函数，在这里定义它们
if (typeof getSecurityGrade === 'undefined') {
    function getSecurityGrade(score) {
        if (score >= 90) return '优秀';
        if (score >= 70) return '良好';
        if (score >= 50) return '一般';
        return '需改进';
    }
}

if (typeof getScoreColor === 'undefined') {
    function getScoreColor(score) {
        if (score >= 90) return 'bg-success';
        if (score >= 70) return 'bg-primary';
        if (score >= 50) return 'bg-warning';
        return 'bg-danger';
    }
}

/**
 * 兼容性函数 - 确保原有的图表函数在页面中可用
 */

// 如果页面中已经定义了这些函数，就不重新定义
if (typeof window.initializeCharts === 'undefined') {
    /**
     * 初始化图表 - 根据报告数据创建图表
     */
    window.initializeCharts = function(report) {
        console.log('使用全局initializeCharts函数');
        
        // 如果页面中有新的图表初始化函数，就调用它
        if (typeof initializeChartsAfterAnalysis === 'function') {
            initializeChartsAfterAnalysis(report);
            return;
        }
        
        // 否则使用原有的逻辑
        if (typeof initializeCharts === 'function') {
            initializeCharts(report);
        }
    };
}

if (typeof window.destroyAllChartInstances === 'undefined') {
    window.destroyAllChartInstances = function() {
        console.log('使用全局destroyAllChartInstances函数');
        
        // 如果页面中有新的销毁函数，就调用它
        if (typeof destroyAllChartInstances === 'function') {
            destroyAllChartInstances();
            return;
        }
        
        // 否则使用原有的逻辑
        if (typeof destroyAllChartInstances === 'function') {
            destroyAllChartInstances();
        }
    };
}

/**
 * 适配原有的displaySecurityReport函数，使其在新页面中工作
 */
if (typeof window.displaySecurityReport === 'function') {
    // 保存原有函数
    const originalDisplaySecurityReport = window.displaySecurityReport;
    
    // 重写函数以适配新页面
    window.displaySecurityReport = function(report) {
        console.log('适配displaySecurityReport函数');
        
        // 调用页面中的结果显示函数
        if (typeof showSecurityAnalysisResult === 'function') {
            showSecurityAnalysisResult(report);
        } else if (typeof onSecurityAnalysisComplete === 'function') {
            onSecurityAnalysisComplete(report);
        } else {
            // 降级到原有函数
            originalDisplaySecurityReport(report);
        }
    };
}

/**
 * 页面卸载时清理图表
 */
window.addEventListener('beforeunload', function() {
    if (typeof destroyAllChartInstances === 'function') {
        destroyAllChartInstances();
    }
});