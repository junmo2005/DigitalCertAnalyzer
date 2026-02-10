// 证书分析页面专用JavaScript功能

// ====================== 全局变量和初始化 ======================
let chartInstances = {};
let currentReport = null;
let currentAnalysisData = null;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeCertAnalysis();
});

/**
 * 初始化证书分析功能
 */
function initializeCertAnalysis() {
    // 初始化选项卡
    initializeTabs();
    
    // 初始化文件事件
    initializeFileEvents();
    
    // 初始化图表
    initializeCharts();
}

/**
 * 初始化选项卡功能
 */
function initializeTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');
        });
    });
}

/**
 * 初始化文件事件
 */
function initializeFileEvents() {
    // PCAP文件信息显示
    document.getElementById('pcap-file').addEventListener('change', function(e) {
        const fileInfo = document.getElementById('pcap-file-info');
        if (this.files.length > 0) {
            const sizeMB = (this.files[0].size / (1024 * 1024)).toFixed(2);
            fileInfo.innerHTML = `已选择文件: ${this.files[0].name} (${sizeMB} MB)`;
        } else {
            fileInfo.textContent = '';
        }
    });

    // 压缩包文件信息显示
    document.getElementById('zip-file').addEventListener('change', function(e) {
        const fileInfo = document.getElementById('zip-file-info');
        if (this.files.length > 0) {
            const sizeMB = (this.files[0].size / (1024 * 1024)).toFixed(2);
            fileInfo.innerHTML = `已选择文件: ${this.files[0].name} (${sizeMB} MB)`;
        } else {
            fileInfo.textContent = '';
        }
    });

    // 批量文件预览
    document.getElementById('batch-files').addEventListener('change', handleBatchFiles);
}

/**
 * 初始化图表
 */
function initializeCharts() {
    console.log('证书分析图表系统初始化完成');
}

// ====================== 图表管理函数 ======================

function destroyAllCharts() {
    Object.values(chartInstances).forEach(chart => {
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    });
    chartInstances = {};
}

function createChart(chartId, config) {
    if (chartInstances[chartId]) {
        chartInstances[chartId].destroy();
    }
    
    const ctx = document.getElementById(chartId).getContext('2d');
    chartInstances[chartId] = new Chart(ctx, config);
    return chartInstances[chartId];
}

// ====================== 文件处理函数 ======================

function handleBatchFiles() {
    if (!checkFileSize(document.getElementById('batch-files'))) {
        return;
    }
    const fileInput = document.getElementById('batch-files');
    const previewContainer = document.getElementById('batch-preview');
    previewContainer.innerHTML = '';
    
    if (fileInput.files.length === 0) {
        previewContainer.innerHTML = '<p class="text-muted">未选择文件</p>';
        return;
    }
    
    for (let i = 0; i < fileInput.files.length; i++) {
        const file = fileInput.files[i];
        const preview = document.createElement('div');
        preview.className = 'file-preview';
        preview.textContent = file.name;
        previewContainer.appendChild(preview);
    }
}

function checkFileSize(input) {
    const maxSize = 520 * 1024 * 1024;
    let invalidFiles = [];

    for (let i = 0; i < input.files.length; i++) {
        if (input.files[i].size > maxSize) {
            invalidFiles.push(input.files[i].name);
        }
    }

    if (invalidFiles.length > 0) {
        alert(`以下文件超过520MB限制:\n${invalidFiles.join('\n')}`);
        input.value = "";
        return false;
    }
    return true;
}

// ====================== 上传和分析函数 ======================
async function uploadPcap() {
    const fileInput = document.getElementById('pcap-file');
    const file = fileInput.files[0];
            
    if (!file) {
        showError('errorContainer', '请选择PCAP文件');
        return;
    }
            
    if (!checkFileSize(fileInput)) return;
            
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    const progress = document.getElementById('pcap-progress');
    progress.innerHTML = `
        <p>正在解析PCAP文件 (${sizeMB} MB)，请稍候...</p>
        <div class="progress">
            <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
        </div>
        <p class="mt-2">大文件处理可能需要较长时间</p>
    `;
    progress.style.display = 'block';
            
    document.getElementById('loading').style.display = 'block';
    document.getElementById('errorContainer').style.display = 'none';
    document.getElementById('results').style.display = 'none';
            
    destroyAllCharts();
            
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('force_parse', 'true');
                
        const response = await fetch('/upload-pcap', {
            method: 'POST',
            body: formData
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`服务器返回非JSON数据: ${text.substring(0, 100)}...`);
        }
                
        const result = await response.json();
        if (result.error) throw new Error(result.error);
                
        result.source_type = 'pcap';
        displayResults(result);
        displayCharts(result);
        document.getElementById('results').style.display = 'block';
                
    } catch (error) {
        showError('errorContainer', `PCAP分析失败: ${error.message}`);
    } finally {
        progress.style.display = 'none';
        document.getElementById('loading').style.display = 'none';
    }
}

async function uploadBatch() {
    const fileInput = document.getElementById('batch-files');
    const files = fileInput.files;
            
    if (files.length === 0) {
        showError('errorContainer', '请选择至少一个证书文件');
        return;
    }
            
    if (!checkFileSize(fileInput)) return;
            
    document.getElementById('loading').style.display = 'block';
    document.getElementById('errorContainer').style.display = 'none';
    document.getElementById('results').style.display = 'none';
            
    destroyAllCharts();
            
    try {
        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
            formData.append('files[]', files[i]);
        }
                
        const response = await fetch('/batch-analyze', {
            method: 'POST',
            body: formData
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`服务器返回非JSON数据: ${text.substring(0, 100)}...`);
        }
                
        const result = await response.json();
        if (result.error) throw new Error(result.error);
                
        result.source_type = 'batch';
        displayResults(result);
        displayCharts(result);
        document.getElementById('results').style.display = 'block';
                
    } catch (error) {
        showError('errorContainer', `批量分析失败: ${error.message}`);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

async function uploadZip() {
    const fileInput = document.getElementById('zip-file');
    const file = fileInput.files[0];
            
    if (!file) {
        showError('errorContainer', '请选择压缩包文件');
        return;
    }
            
    if (!checkFileSize(fileInput)) return;
            
    const progress = document.getElementById('zip-progress');
    progress.style.display = 'block';
    document.getElementById('loading').style.display = 'block';
    document.getElementById('errorContainer').style.display = 'none';
    document.getElementById('results').style.display = 'none';
            
    destroyAllCharts();
            
    try {
        const formData = new FormData();
        formData.append('file', file);
                
        const response = await fetch('/upload-zip', {
            method: 'POST',
            body: formData
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`服务器返回非JSON数据: ${text.substring(0, 100)}...`);
        }
                
        const result = await response.json();
        if (result.error) throw new Error(result.error);
                
        result.source_type = 'zip';
        displayResults(result);
        displayCharts(result);
        document.getElementById('results').style.display = 'block';
                
    } catch (error) {
        showError('errorContainer', `压缩包分析失败: ${error.message}`);
    } finally {
        progress.style.display = 'none';
        document.getElementById('loading').style.display = 'none';
    }
}
// ====================== 结果显示函数 ======================

function displayResults(data) {
    // 保存分析数据到全局变量（用于报告生成）
    window.currentAnalysisData = data.analysis || data;
    const analysis = window.currentAnalysisData;

    // 清除之前的内容
    document.getElementById('basicInfo').innerHTML = '';
    document.getElementById('cryptoStats').innerHTML = '';
    document.getElementById('sanStats').innerHTML = '';
    document.getElementById('validityStats').innerHTML = '';
    document.getElementById('detailedResults').innerHTML = '';

    // 显示PCAP特定信息
    if (data.source_type === 'pcap') {
        document.getElementById('pcap-specific-info').style.display = 'block';
        document.getElementById('pcap-stats').innerHTML = `
            <table class="table table-sm">
                <tr><th>原始文件</th><td>${data.original_file || '未知'}</td></tr>
                <tr><th>提取证书数</th><td>${data.pcap_stats?.certificates_extracted || 0}</td></tr>
            </table>
        `;
    } else {
        document.getElementById('pcap-specific-info').style.display = 'none';
    }

    // 显示摘要信息 - 使用CSS类而不是内联样式
    let summaryHTML = `
        <div class="pcap-stats">
        <h3>${data.source_type === 'pcap' ? 'PCAP分析摘要' : data.source_type === 'zip' ? '压缩包分析摘要' : '批量分析摘要'}</h3>
        <table class="table table-sm">
    `;

    if (data.source_type === 'pcap') {
        summaryHTML += `  
            <tr>
                <th>原始文件</th>
                <td>${data.original_file || '未知'}</td>
            </tr>
            <tr>
                <th>提取证书数</th>
                <td>${data.pcap_stats?.certificates_extracted || 0}</td>
            </tr>
        `;
    }

    if (data.file_count) {
        summaryHTML += `
            <tr>
                <th>分析文件数</th>
                <td>${data.file_count}</td>
             </tr>
        `;
    }

    summaryHTML += `
                <tr>
                    <th>唯一证书数</th>
                    <td>${analysis.total_certificates || 0}</td>
                </tr>
                <tr>
                    <th>去重前证书数</th>
                    <td>${analysis.total_before_deduplication || analysis.total_certificates || 0}</td>
                </tr>
                <tr>
                    <th>解析错误数</th>
                    <td>${analysis.parse_errors || 0}</td>
                </tr>
            </table>
        </div>
    `;

    document.getElementById('basicInfo').innerHTML = summaryHTML;

    // 证书有效性分析
    const totalCerts = analysis.total_certificates || (data.file_count || 1);
    const validCerts = analysis.valid_certificates || 0;
    const expiringSoon = analysis.expiring_soon_certificates || 0;
    const expiredCerts = analysis.expired_certificates || 0;

    document.getElementById('basicInfo').innerHTML += `
       <div class="cert-summary">
           <h3>证书有效性分析</h3>
           <table class="table table-sm">
               <tr>
                   <th>证书总数</th>
                   <td>${totalCerts}</td>
               </tr>
               <tr>
                   <th>有效证书</th>
                   <td>${validCerts} (${((validCerts / totalCerts) * 100).toFixed(1)}%)</td>
               </tr>
               <tr>
                   <th>即将过期证书</th>
                   <td>${expiringSoon} (${((expiringSoon / totalCerts) * 100).toFixed(1)}%)</td>
               </tr>
               <tr>
                   <th>已过期证书</th>
                   <td>${expiredCerts} (${((expiredCerts / totalCerts) * 100).toFixed(1)}%)</td>
               </tr>
           </table>
        </div>
    `;

    // 显示统计卡片数据 - 同样删除内联样式
    if (analysis.crypto_stats && Object.keys(analysis.crypto_stats).length > 0) {
        let cryptoHtml = '<table class="table table-sm">';
        for (const [crypto, count] of Object.entries(analysis.crypto_stats)) {
            cryptoHtml += `<tr><td>${crypto}</td><td class="stat-value">${count}</td></tr>`;
        }
        cryptoHtml += '</table>';
        document.getElementById('cryptoStats').innerHTML = cryptoHtml;
    }

    if (analysis.san_stats) {
        let sanHtml = `<table class="table table-sm">
            <tr><td>含SAN证书</td><td class="stat-value">${analysis.san_stats.with_san || 0}</td></tr>
            <tr><td>通配符证书</td><td class="stat-value">${analysis.san_stats.wildcard || 0}</td></tr>
        </table>`;
        document.getElementById('sanStats').innerHTML = sanHtml;
    }

    // 显示证书状态统计
    let validityHtml = `<table class="table table-sm">
        <tr><td>有效证书</td><td class="stat-value">${validCerts}</td></tr>
        <tr><td>即将过期</td><td class="stat-value">${expiringSoon}</td></tr>
        <tr><td>已过期</td><td class="stat-value">${expiredCerts}</td></tr>
    </table>`;
    document.getElementById('validityStats').innerHTML = validityHtml;
    
    // 详细数据
    let detailedHtml = '';

    if (analysis.ca_stats && Object.keys(analysis.ca_stats).length > 0) {
        detailedHtml += `
            <h4>证书颁发机构分布</h4>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>颁发机构</th>
                        <th>证书数量</th>
                        <th>百分比</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(analysis.ca_stats).map(([issuer, count]) => `
                        <tr>
                            <td>${issuer.length > 50 ? issuer.substring(0, 50) + '...' : issuer}</td>
                            <td>${count}</td>
                            <td>${((count / totalCerts) * 100).toFixed(1)}%</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    // 密钥用途统计
    if (analysis.key_usage_stats && Object.keys(analysis.key_usage_stats).length > 0) {
        detailedHtml += `
            <h4>密钥用途统计</h4>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>用途类型</th>
                        <th>证书数量</th>
                        <th>百分比</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(analysis.key_usage_stats).map(([usage, count]) => `
                        <tr>
                            <td>${usage}</td>
                            <td>${count}</td>
                            <td>${((count / totalCerts) * 100).toFixed(1)}%</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }
    
    document.getElementById('detailedResults').innerHTML = detailedHtml || '<p class="text-muted">无详细数据</p>';
}

function displayCharts(data) {
    const analysis = data.analysis || data;

    // 1. 证书有效期分布
    createChart('validityChart', {
        type: 'pie',
        data: {
            labels: ['有效证书', '即将过期', '已过期'],
            datasets: [{
                data: [
                    analysis.valid_certificates || 0,
                    analysis.expiring_soon_certificates || 0,
                    analysis.expired_certificates || 0
                ],
                backgroundColor: ['#4CAF50', '#FFC107', '#F44336'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: `证书有效期分布 (总计: ${analysis.total_certificates || 0})`,
                    font: { size: 16 }
                },
                legend: { position: 'right' }
            }
        }
    });

    // 2. 颁发机构分布
    const issuers = Object.keys(analysis.ca_stats || {});
    const counts = Object.values(analysis.ca_stats || {});
    
    if (issuers.length > 0) {
        createChart('issuerChart', {
            type: 'bar',
            data: {
                labels: issuers.map(issuer => 
                    issuer.split('CN=')[1]?.split(',')[0] || issuer.slice(0, 20) + '...'),
                datasets: [{
                    label: '证书数量',
                    data: counts,
                    backgroundColor: '#2196F3',
                    borderColor: '#0d47a1',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: '颁发机构分布',
                        font: { size: 16 }
                    }
                },
                scales: {
                    x: { beginAtZero: true }
                }
            }
        });
    }

    // 3. 密码学强度分布
    const cryptoTypes = Object.keys(analysis.crypto_stats || {});
    const cryptoCounts = Object.values(analysis.crypto_stats || {});
    
    if (cryptoTypes.length > 0) {
        createChart('cryptoChart', {
            type: 'bar',
            data: {
                labels: cryptoTypes.map(t => t.replace(/:/g, ' ')),
                datasets: [{
                    label: '证书数量',
                    data: cryptoCounts,
                    backgroundColor: '#9C27B0',
                    borderColor: '#6A1B9A',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: '密码学强度分布',
                        font: { size: 16 }
                    }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }

    // 4. SAN域名数量分布
    const domainCounts = analysis.san_stats?.domain_counts || {};
    const sanLabels = Object.keys(domainCounts).map(n => `${n}个域名`);
    const sanData = Object.values(domainCounts);
    
    if (sanLabels.length > 0) {
        createChart('sanChart', {
            type: 'bar',
            data: {
                labels: sanLabels,
                datasets: [{
                    label: '证书数量',
                    data: sanData,
                    backgroundColor: '#FF9800',
                    borderColor: '#E65100',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: `SAN域名数量分布 (含SAN证书: ${analysis.san_stats?.with_san || 0})`,
                        font: { size: 16 }
                    }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }

    // 5. 密钥用途分布
    const keyUsageData = analysis.key_usage_stats || {};
    const keyUsageLabels = Object.keys(keyUsageData);
    const keyUsageCounts = Object.values(keyUsageData);
    
    if (keyUsageLabels.length > 0) {
        createChart('keyUsageChart', {
            type: 'pie',
            data: {
                labels: keyUsageLabels,
                datasets: [{
                    data: keyUsageCounts,
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: '密钥用途分布',
                        font: { size: 16 }
                    },
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
}

// ====================== 报告生成函数 ======================

async function generateReport() {
    if (!window.currentAnalysisData) {
        alert('请先完成文件分析');
        return;
    }
    
    const btn = document.getElementById('generateReportBtn');
    const originalBtnText = btn.textContent;
    
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>正在生成报告...';
    btn.disabled = true;

    try {
        const analysisData = {
            analysis: window.currentAnalysisData,
            source_type: window.currentAnalysisData.source_type,
            original_file: window.currentAnalysisData.original_file
        };

        const timestamp = new Date().getTime();
        const response = await fetch(`/generate-report?t=${timestamp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache'
            },
            body: JSON.stringify(analysisData)
        });

        const result = await response.json();
        if (result.error) throw new Error(result.error);

        currentReport = result;
        // 使用Marked.js解析Markdown内容
        const reportHtml = marked.parse(result.report_content);
        document.getElementById('reportContent').innerHTML = reportHtml;
        document.getElementById('reportSection').style.display = 'block';
       
        // 显示生成时间
        if (result.generated_at) {
            const generatedTime = new Date(result.generated_at).toLocaleString();
            const timeElement = document.createElement('div');
            timeElement.className = 'text-muted small mt-2';
            timeElement.textContent = `生成时间: ${generatedTime}`;
            document.getElementById('reportContent').appendChild(timeElement);
        }
        
    } catch (error) {
        showError('errorContainer', `报告生成失败: ${error.message}`);
    } finally {
        btn.textContent = originalBtnText;
        btn.disabled = false;
    }
}

function downloadReport() {
    if (!currentReport) return;
    window.open(`/download-report/${currentReport.report_filename}`, '_blank');
}

async function copyReport() {
    if (!currentReport) return;
    try {
        await navigator.clipboard.writeText(currentReport.report_content);
        alert('报告已复制到剪贴板');
    } catch (error) {
        showError('errorContainer', '复制失败: ' + error.message);
    }
}

// ====================== 工具函数 ======================

/**
 * 显示错误信息
 */
function showError(elementId, message) {
    const errorContainer = document.getElementById(elementId);
    if (message.includes("未检测到TLS证书")) {
        message += `<br><br>可能原因：
            <ul>
                <li>PCAP文件不包含TLS握手过程</li>
                <li>流量已加密或使用非常规协议</li>
                <li>捕获时间点错过了证书交换</li>
            </ul>
            建议：使用Wireshark打开文件，过滤 <code>tls.handshake.type == 11</code> 验证`;
    }
    errorContainer.innerHTML = message;
    errorContainer.style.display = 'block';
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
 * 显示加载状态
 */
function showLoading(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                ${message}
            </div>
        `;
    }
}

/**
 * 显示成功消息
 */
function showSuccess(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>${message}
            </div>
        `;
    }
}

// ====================== 页面辅助功能 ======================

/**
 * 重置页面状态
 */
function resetPage() {
    destroyAllCharts();
    document.getElementById('results').style.display = 'none';
    document.getElementById('errorContainer').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';
    
    // 清空文件输入
    document.getElementById('pcap-file').value = '';
    document.getElementById('batch-files').value = '';
    document.getElementById('zip-file').value = '';
    
    // 清空文件信息显示
    document.getElementById('pcap-file-info').textContent = '';
    document.getElementById('zip-file-info').textContent = '';
    document.getElementById('batch-preview').innerHTML = '';
}

/**
 * 导出分析数据
 */
function exportAnalysisData() {
    if (!window.currentAnalysisData) {
        alert('没有可导出的分析数据');
        return;
    }
    
    const dataStr = JSON.stringify(window.currentAnalysisData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `certificate_analysis_${new Date().getTime()}.json`;
    link.click();
}

/**
 * 打印分析报告
 */
function printReport() {
    const reportContent = document.getElementById('reportContent');
    if (!reportContent || reportContent.style.display === 'none') {
        alert('请先生成分析报告');
        return;
    }
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>证书分析报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 2em; line-height: 1.6; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #34495e; border-bottom: 1px solid #eee; padding-bottom: 8px; }
                table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                th { background-color: #f8f9fa; font-weight: bold; }
                .no-print { display: none; }
                @media print {
                    body { margin: 1em; }
                    .no-print { display: none; }
                }
            </style>
        </head>
        <body>
            ${reportContent.innerHTML}
            <div class="no-print" style="margin-top: 2em; text-align: center;">
                <button onclick="window.print()">打印报告</button>
                <button onclick="window.close()">关闭</button>
            </div>
        </body>
        </html>
    `);
    printWindow.document.close();
}

// ====================== 事件监听器 ======================

// 页面卸载前清理资源
window.addEventListener('beforeunload', function() {
    destroyAllCharts();
});

// 键盘快捷键支持
document.addEventListener('keydown', function(e) {
    // Ctrl + R 重置页面
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        resetPage();
    }
    
    // Ctrl + E 导出数据
    if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        exportAnalysisData();
    }
    
    // Ctrl + P 打印报告
    if (e.ctrlKey && e.key === 'p') {
        e.preventDefault();
        printReport();
    }
});

// 响应式图表调整
window.addEventListener('resize', function() {
    Object.values(chartInstances).forEach(chart => {
        if (chart && typeof chart.resize === 'function') {
            chart.resize();
        }
    });
});

// ====================== 初始化完成 ======================

console.log('证书分析页面初始化完成');