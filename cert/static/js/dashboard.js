new Vue({
  el: '#app',
  data: {
    stats: {
      certificate: {
        total_active: 0,
        expired_ratio: 0,
        expire_30d: 0,
        expire_7d: 0,
        avg_valid_days: 0,
        self_signed_ratio: 0,
        weak_crypto_ratio: 0,
        unauthorized: 0,
        missing_key_usage_ratio: 0,
        with_san_ratio: 0,
        avg_san_domains: 0,
        max_san_domains: 0,
        free_ca_share: 0,
        multi_issuer_domains: 0,
        key_usage_stats: {},
        ca_market: []
      },
      domain: {
        total: 0,
        https_enforced: 0,
        hsts_enabled: 0,
        csp: 0,
        xfo: 0,
        xcto: 0,
        referrer_policy: 0,
        all_four_headers: 0,
        chain_ok: 0,
        avg_score: 0
      },
      grade_distribution: {}
    },
    domainHttpsPct: 0,
    domainHstsPct: 0,
    domainAll4Pct: 0,
    domainChainPct: 0,
    reportLoading: false,
    reportContent: null
  },
  mounted() {
    this.fetchStats();   // 先拉取基础统计，完成后自动渲染密钥用途和安全头图表
    this.fetchTrends();  // 再拉取趋势，绘制趋势图、颁发机构等
  },
  methods: {
    async fetchStats() {
      try {
        const res = await axios.get('/api/dashboard/stats');
        if (res.data.status === 'success') {
          // 合并数据
          this.stats.certificate = { ...this.stats.certificate, ...res.data.certificate };
          this.stats.domain = { ...this.stats.domain, ...res.data.domain };
          this.stats.grade_distribution = res.data.grade_distribution || {};
          this.calculateDomainPercentages();
          // 数据就绪后立即渲染依赖 stats 的图表
          this.renderKeyUsageChart(this.stats.certificate.key_usage_stats);
          this.renderHeadersChart();
        } else {
          console.error('统计接口返回错误:', res.data.error);
        }
      } catch (e) {
        console.error('fetchStats error:', e);
      }
    },
    calculateDomainPercentages() {
      const d = this.stats.domain;
      const total = d.total || 1;
      this.domainHttpsPct = Math.round((d.https_enforced || 0) / total * 100);
      this.domainHstsPct = Math.round((d.hsts_enabled || 0) / total * 100);
      this.domainAll4Pct = Math.round((d.all_four_headers || 0) / total * 100);
      this.domainChainPct = Math.round((d.chain_ok || 0) / total * 100);
    },
    async fetchTrends() {
      try {
        const res = await axios.get('/api/dashboard/trends');
        if (res.data.status === 'success') {
          const d = res.data;
          this.renderValidityTrend(d.validity_trend);
          this.renderCryptoChart(d.crypto_distribution);
          this.renderIssuerChart(d.top_issuers);
          this.renderGradeChart(d.grade_distribution);
          this.renderScoreTrendChart(d.score_trend);
        }
      } catch (e) {
        console.error('fetchTrends error:', e);
      }
    },
    renderValidityTrend(data) {
      if (!data || !data.length) return;
      const chart = echarts.init(document.getElementById('validityTrendChart'));
      chart.setOption({
        tooltip: { trigger: 'axis' },
        legend: { data: ['过期率', '自签名率', '弱加密率'] },
        xAxis: { data: data.map(d => d.date) },
        yAxis: { max: 100 },
        series: [
          { name: '过期率', type: 'line', data: data.map(d => d.expired_ratio), color: '#e94560' },
          { name: '自签名率', type: 'line', data: data.map(d => d.self_signed_ratio), color: '#f39c12' },
          { name: '弱加密率', type: 'line', data: data.map(d => d.weak_crypto_ratio), color: '#3498db' }
        ]
      });
    },
    renderCryptoChart(data) {
      if (!data) return;
      const chart = echarts.init(document.getElementById('cryptoChart'));
      chart.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie', radius: ['40%', '70%'],
          data: Object.entries(data).map(([name, value]) => ({ name, value })),
          emphasis: { itemStyle: { shadowBlur: 10 } }
        }]
      });
    },
    renderIssuerChart(data) {
      if (!data) return;
      const chart = echarts.init(document.getElementById('issuerChart'));
      chart.setOption({
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
        yAxis: { type: 'category', data: data.map(d => d.name).reverse() },
        xAxis: { type: 'value' },
        series: [{ type: 'bar', data: data.map(d => d.count).reverse(), color: '#0f3460' }]
      });
    },
    renderGradeChart(data) {
      if (!data) return;
      const chart = echarts.init(document.getElementById('gradeChart'));
      // 修改为 A/B/C/D 四个等级
      const grades = ['A','B','C','D'];
      const values = grades.map(g => data[g] || 0);
      chart.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie', radius: '65%',
          data: grades.map((g,i) => ({ name: g, value: values[i] })),
          label: { formatter: '{b}: {c} ({d}%)' }
        }]
      });
    },
    renderKeyUsageChart(data) {
      if (!data || Object.keys(data).length === 0) return;
      const chart = echarts.init(document.getElementById('keyUsageChart'));
      chart.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie', radius: ['40%', '70%'],
          data: Object.entries(data).map(([name, value]) => ({ name, value }))
        }]
      });
    },
    renderHeadersChart() {
      const d = this.stats.domain;
      if (!d) return;
      const chart = echarts.init(document.getElementById('headersChart'));
      chart.setOption({
        tooltip: { trigger: 'axis' },
        xAxis: { type: 'category', data: ['CSP', 'X-Frame', 'X-Content-Type', 'Referrer-Policy'] },
        yAxis: { type: 'value', max: d.total || 1 },
        series: [{
          type: 'bar',
          data: [d.csp, d.xfo, d.xcto, d.referrer_policy],
          color: '#2ecc71'
        }]
      });
    },
    renderScoreTrendChart(data) {
      if (!data || !data.length) return;
      const chart = echarts.init(document.getElementById('scoreTrendChart'));
      chart.setOption({
        tooltip: { trigger: 'axis' },
        xAxis: { data: data.map(d => d.month) },
        yAxis: { min: 0, max: 100 },
        series: [{
          name: '平均安全评分', type: 'line',
          data: data.map(d => d.avg_score),
          smooth: true, color: '#9b59b6',
          markLine: { data: [{ type: 'average', name: '平均值' }] }
        }]
      });
    },

    async generateReport() {
        this.reportLoading = true;
        this.reportContent = null;   // 清空旧内容
        try {
            const res = await axios.post('/api/dashboard/generate-report');
            if (res.data.status === 'success') {
                const markdownText = res.data.report_html;   // 后端返回的 Markdown 字符串
                // 检查 marked 库是否可用
                if (typeof marked !== 'undefined' && marked.parse) {
                    // marked.parse 在 v4+ 中返回 Promise，在低版本中同步返回字符串
                    let html;
                    try {
                        // 尝试异步调用（兼容新版）
                        const result = marked.parse(markdownText);
                        if (result && typeof result.then === 'function') {
                            html = await result;
                        } else {
                            html = result;
                        }
                    } catch (parseErr) {
                        console.error('marked.parse 错误:', parseErr);
                        // 降级：直接显示原始文本（转义）
                        html = `<pre>${this.escapeHtml(markdownText)}</pre>`;
                    }
                    this.reportContent = html;
                } else {
                    // marked 未加载，降级显示原始文本
                    console.warn('marked 库未加载，将以纯文本显示报告');
                    this.reportContent = `<pre>${this.escapeHtml(markdownText)}</pre>`;
                }
            } else {
                alert('报告生成失败：' + (res.data.error || '未知错误'));
            }
        } catch (e) {
            console.error('生成报告出错:', e);
            alert('请求失败，请稍后再试');
        } finally {
            this.reportLoading = false;
        }
    },

    copyReport() {
      // 获取报告容器的纯文本内容
      const container = document.querySelector('.report-container');
      if (!container) return;
      // 提取纯文本（不包含 HTML 标签）
      const text = container.innerText || container.textContent;
      navigator.clipboard.writeText(text).then(() => {
          alert('报告内容已复制到剪贴板');
        }).catch(err => {
          console.error('复制失败:', err);
          alert('复制失败，请手动复制');
        });
    },

    // 下载报告为 .html 文件
    downloadReport() {
        if (!this.reportContent) return;
        // 获取报告 HTML 内容（已经包含内部样式）
        let htmlContent = this.reportContent;
        // 包装为一个完整的 HTML 文档，方便独立打开
        const fullHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>安全态势报告_${new Date().toISOString().slice(0,19)}</title>
    <style>
        /* 复制报告内的样式，确保下载后也能正常显示 */
        body {
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #f4f7fc;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 28px;
            padding: 40px 45px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.12);
        }
        /* 这里可以追加更多样式，或者依赖报告内嵌的 style */
    </style>
    ${this.extractStylesFromReport(htmlContent)}
</head>
<body>
<div class="container">
    ${htmlContent}
</div>
</body>
</html>`;
        const blob = new Blob([fullHtml], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${new Date().toISOString().slice(0,19)}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    // 辅助方法：从报告 HTML 中提取所有样式（如果有 style 标签）
    extractStylesFromReport(html) {
        const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi;
        let styles = '';
        let match;
        while ((match = styleRegex.exec(html)) !== null) {
            styles += match[0];
        }
        return styles;
    
},

    // 辅助方法：转义 HTML 特殊字符（防止 XSS）
    escapeHtml(str) {
        if (!str) return '';
        return str.replace(/[&<>]/g, function(m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        });
    }
  }
})