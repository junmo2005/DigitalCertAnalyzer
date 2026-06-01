import time
import requests
import json
import logging
import os
from datetime import datetime
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()
# 创建独立的日志记录器
logger = logging.getLogger(__name__)

# ==================== 配置管理 ====================
class DeepSeekConfig:
    """DeepSeek API 配置管理类"""
    
    # 从环境变量读取配置，如果不存在则使用空字符串
    API_KEY = os.getenv('DEEPSEEK_API_KEY', '')
    API_URL = os.getenv('DEEPSEEK_API_URL', 'https://api.deepseek.com/chat/completions')
    
    @classmethod
    def is_configured(cls):
        """检查配置是否完整"""
        return bool(cls.API_KEY.strip())
    
    @classmethod
    def get_api_key(cls):
        """获取API密钥"""
        return cls.API_KEY
    
    @classmethod
    def get_api_url(cls):
        """获取API URL"""
        return cls.API_URL
    
    @classmethod
    def configure(cls, api_key=None, api_url=None):
        """动态配置（可选）"""
        if api_key is not None:
            cls.API_KEY = api_key
        if api_url is not None:
            cls.API_URL = api_url

# ==================== 报告生成模块 ====================

def generate_ai_report(analysis_data, source_type, original_filename=None, report_type="certificate",):
    """使用DeepSeek API生成智能分析报告 - 扩展版，支持多种报告类型
    
    Args:
        analysis_data: 分析数据
        source_type: 数据来源类型 (pcap, batch, zip, security)
        original_filename: 原始文件名
        report_type: 报告类型 ("certificate" | "security")
        api_key: DeepSeek API密钥
        api_url: DeepSeek API URL
    """
    # 使用 DeepSeekConfig 类获取配置
    if not DeepSeekConfig.is_configured():
        logger.warning("DeepSeek API密钥未配置，使用默认报告")
        return generate_default_report(analysis_data, source_type, original_filename, report_type)
    
    if not check_network_connection():
        logger.warning("网络连接不可用，使用默认报告")
        return generate_default_report(analysis_data, source_type, original_filename, report_type)
    
    try:
         # ✅ 优先使用调用方构造好的完整提示词
        if 'prompt' in analysis_data:
            prompt = analysis_data['prompt']
        elif report_type == "security":
            prompt = build_security_report_prompt(analysis_data, source_type, original_filename)
        else:
            prompt = build_certificate_report_prompt(analysis_data, source_type, original_filename)
        
        result = call_deepseek_api_with_retry(prompt)
        
        if result['success']:
            return result['report']
        else:
            logger.warning(f"DeepSeek API调用失败: {result.get('error', '未知错误')}")
            return generate_default_report(analysis_data, source_type, original_filename, report_type)
            
    except Exception as e:
        logger.error(f"AI报告生成过程中出现异常: {str(e)}")
        return generate_default_report(analysis_data, source_type, original_filename, report_type)

def generate_default_report(analysis_data, source_type, original_filename=None, report_type="certificate"):
    """支持多种报告类型的默认报告生成
    
    Args:
        report_type: "certificate" | "security"
    """
    if report_type == "security":
        return generate_security_default_report(analysis_data, source_type, original_filename)
    elif report_type == "dashboard":
        # 返回一段简单的提示，告知报告生成失败
        return "<h3>报告生成失败</h3><p>AI 服务暂时不可用，请稍后重试。</p>"
    else:  # certificate
        return generate_certificate_default_report(analysis_data, source_type, original_filename)

def check_network_connection():
    """检查网络连接是否可用"""
    try:
        response = requests.get('https://api.deepseek.com', timeout=5)
        return response.status_code < 500
    except requests.exceptions.Timeout:
        logger.warning("网络连接超时")
        return False
    except requests.exceptions.ConnectionError:
        logger.warning("网络连接错误")
        return False
    except Exception as e:
        logger.warning(f"网络检查异常: {str(e)}")
        return False

def call_deepseek_api_with_retry(prompt, max_retries=3):
    """带重试机制的DeepSeek API调用"""
    for attempt in range(max_retries):
        try:
            result = call_deepseek_api(prompt, attempt + 1)
            if result['success']:
                return result
            
            if attempt < max_retries - 1:
                wait_time = 2 * (attempt + 1)
                logger.warning(f"API调用失败，{wait_time}秒后第{attempt + 2}次重试...")
                time.sleep(wait_time)
                
        except Exception as e:
            logger.warning(f"API调用异常: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2)
    
    return {'success': False, 'error': '所有重试尝试均失败'}

def call_deepseek_api(prompt, attempt_number=1):
    """调用DeepSeek API核心函数"""
    try:
        headers = {
            'Authorization': f'Bearer {DeepSeekConfig.get_api_key()}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system", 
                    "content": "你是一个专业的网络安全分析师，擅长数字证书安全分析和报告撰写。请提供专业、详细的安全分析报告，报告标题是‘数字证书分析报告‘。"
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 8000,
            "top_p": 0.9
        }
        
        timeout = 30 * attempt_number
        
        logger.info(f"第{attempt_number}次尝试调用DeepSeek API,超时: {timeout}秒")
        
        response = requests.post(
            DeepSeekConfig.get_api_url(),
            headers=headers,
            json=payload,
            timeout=timeout
        )
        
        if response.status_code == 200:
            result = response.json()
            logger.info("DeepSeek API调用成功")
            return {
                'success': True,
                'report': result['choices'][0]['message']['content']
            }
        else:
            error_msg = f"HTTP {response.status_code} - {response.text}"
            logger.error(f"DeepSeek API调用失败: {error_msg}")
            return {'success': False, 'error': error_msg}
            
    except requests.exceptions.Timeout:
        logger.warning(f"DeepSeek API请求超时（尝试{attempt_number}）")
        return {'success': False, 'error': '请求超时'}
        
    except requests.exceptions.ConnectionError:
        logger.warning(f"网络连接错误（尝试{attempt_number}）")
        return {'success': False, 'error': '网络连接错误'}
        
    except Exception as e:
        logger.error(f"DeepSeek API调用异常（尝试{attempt_number}）: {str(e)}")
        return {'success': False, 'error': str(e)}

#===========================证书分析报告==========================

def build_certificate_report_prompt(analysis_data, source_type, original_filename):
    """构建证书分析AI报告生成的提示词"""
    analysis = analysis_data.get('analysis', {})
    
    prompt = f"""请基于以下数字证书分析结果生成一份专业的安全分析报告：

原始文件: {original_filename or '未知'}
分析时间: {datetime.now().strftime('%Y年%m月%d日')}

分析结果摘要:
- 证书总数: {analysis.get('total_certificates', 0)}
- 有效证书: {analysis.get('valid_certificates', 0)} ({analysis.get('valid_percentage', 0)}%)
- 即将过期: {analysis.get('expiring_soon_certificates', 0)} ({analysis.get('expiring_percentage', 0)}%)
- 已过期证书: {analysis.get('expired_certificates', 0)} ({analysis.get('expired_percentage', 0)}%)
- 解析错误: {analysis.get('parse_errors', 0)}

加密强度分布: {json.dumps(analysis.get('crypto_stats', {}), ensure_ascii=False)}
颁发机构分布: {json.dumps(dict(list(analysis.get('ca_stats', {}).items())[:5]), ensure_ascii=False)}
SAN特性: {json.dumps(analysis.get('san_stats', {}), ensure_ascii=False)}
密钥用途: {json.dumps(analysis.get('key_usage_stats', {}), ensure_ascii=False)}

请生成一份包含以下内容的实用报告：
1. 执行摘要 - 总体评估和关键指标
2. 详细发现 - 按类别分析具体发现
3. 风险评估 - 识别具体安全风险等级
4. 紧急程度 - 按优先级排序的问题
5. 具体建议 - 可操作的技术和管理建议
6. 最佳实践 - 证书管理的实用建议

报告要求：
- 使用专业但易懂的技术语言
- 包含具体数据和量化指标
- 提供可直接执行的建议
- 使用emoji图标增强可读性
- 重点关注实际安全运维
- 不要包含分析人员和版本号
- 使用当前真实时间: {datetime.now().strftime('%Y年%m月%d日')}

报告格式示例：
📊 执行摘要
[内容]

🔍 详细发现  
[内容]

🎯 风险评估
[内容]

💡 建议措施
[内容]
"""

    return prompt  

def generate_certificate_default_report(analysis_data, source_type, original_filename):
    """证书分析专用默认报告 - 原有函数重命名"""
    analysis = analysis_data.get('analysis', {})
    current_time = datetime.now() 

    report = f"""数字证书安全分析报告
{'='*60}

📊 执行摘要
{'='*60}
本次分析共处理 {analysis.get('total_certificates', 0)} 个数字证书。

🔍 证书状态统计:
✅  有效证书: {analysis.get('valid_certificates', 0)} 个 ({analysis.get('valid_percentage', 0)}%)
⚠️  即将过期: {analysis.get('expiring_soon_certificates', 0)} 个 ({analysis.get('expiring_percentage', 0)}%)
❌  已过期证书: {analysis.get('expired_certificates', 0)} 个 ({analysis.get('expired_percentage', 0)}%)
❓  解析错误: {analysis.get('parse_errors', 0)} 个

📈 详细分析
{'='*60}

1. 加密强度分析:
{format_crypto_stats(analysis.get('crypto_stats', {}))}

2. 颁发机构分布 (前5名):
{format_ca_stats(analysis.get('ca_stats', {}))}

3. SAN扩展分析:
{format_san_stats(analysis.get('san_stats', {}))}

4. 密钥用途统计:
{format_key_usage_stats(analysis.get('key_usage_stats', {}))}

🎯 关键发现与风险评估
{{'='*60}}
{generate_certificate_risk_assessment(analysis)}

💡  可执行建议措施
{'='*60}
{generate_actionable_recommendations(analysis)}

📋 证书管理最佳实践
{'='*60}
1. 建立证书清单和到期预警机制
2. 定期进行证书生命周期审查
3. 实施自动化证书监控和更新
4. 制定证书安全策略和标准
5. 建立应急响应流程

🔧 技术建议
{'='*60}
- 优先使用2048位以上RSA或ECC加密
- 确保证书包含适当的SAN扩展
- 定期检查证书链完整性
- 监控证书撤销状态

📞 后续步骤
{'='*60}
- 立即处理已过期证书
- 30天内更新即将过期证书
- 建立定期审查计划
- 考虑使用证书管理平台

报告生成系统: 数字证书安全分析系统 
"""

    return report

def generate_certificate_risk_assessment(analysis):
    """生成风险评估"""
    risks = []
    
    expired_count = analysis.get('expired_certificates', 0)
    if expired_count > 0:
        risks.append(f"• 存在 {expired_count} 个已过期证书，可能导致服务中断和安全漏洞")
    
    expiring_count = analysis.get('expiring_soon_certificates', 0)
    if expiring_count > 0:
        risks.append(f"• 有 {expiring_count} 个证书即将过期，需要及时更新")
    
    crypto_stats = analysis.get('crypto_stats', {})
    weak_crypto = sum(count for key, count in crypto_stats.items() if '弱' in key or '1024' in key)
    if weak_crypto > 0:
        risks.append(f"• 发现 {weak_crypto} 个弱加密证书，存在安全风险")
    
    if not risks:
        risks.append("• 未发现重大安全风险，证书状态总体良好")
    
    return "\n".join(risks)

def generate_actionable_recommendations(analysis):
    """生成可操作的建议"""
    recommendations = []
    
    if analysis.get('expired_certificates', 0) > 0:
        recommendations.append("• 🚨 立即更换所有已过期证书")
    
    if analysis.get('expiring_soon_certificates', 0) > 0:
        recommendations.append("• ⏰ 制定30天内证书更新计划")
    
    crypto_stats = analysis.get('crypto_stats', {})
    for key, count in crypto_stats.items():
        if '弱' in key or '1024' in key:
            recommendations.append(f"• 🔒 升级 {count} 个弱加密证书到2048位以上RSA或ECC")
    
    recommendations.extend([
        "• 📊 建立证书清单和监控仪表板",
        "• 🔔 设置证书到期自动提醒",
        "• 📝 制定证书管理策略和流程",
        "• 🛡️ 实施定期安全审计"
    ])
    
    return "\n".join(recommendations)

# 辅助函数

def format_crypto_stats(stats):
    """格式化加密强度统计"""
    if not stats:
        return "   无数据"
    return "\n".join([f"   - {k}: {v}个" for k, v in stats.items()])

def format_ca_stats(stats):
    """格式化颁发机构统计"""
    if not stats:
        return "   无数据"
    return "\n".join([f"   - {k[:50]}: {v}个" for k, v in list(stats.items())[:5]])

def format_san_stats(stats):
    """格式化SAN统计"""
    if not stats:
        return "   无数据"
    
    lines = []
    if stats.get('with_san', 0) > 0:
        lines.append(f"   - 含SAN证书: {stats['with_san']}个")
    if stats.get('wildcard', 0) > 0:
        lines.append(f"   - 通配符证书: {stats['wildcard']}个")
    
    return "\n".join(lines)

def format_key_usage_stats(stats):
    """格式化密钥用途统计"""
    if not stats:
        return "   无数据"
    
    sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
    return "\n".join([f"   - {k}: {v}次" for k, v in sorted_stats[:5]])


#======================安全分析报告生成=============================

def build_security_report_prompt(analysis_data, source_type, original_filename):
    """构建详细的安全分析AI提示词 - 利用现有分析函数"""
    summary = analysis_data.get('summary', {})
    feature_stats = analysis_data.get('featureStats', {})
    domain_stats = analysis_data.get('domain_stats', {})
    detailed_results = analysis_data.get('detailed_results', [])
    score_distribution = analysis_data.get('scoreDistribution', [0, 0, 0, 0])
    
    total_domains = summary.get('analyzed_domains', 0) or 1
    
    # 使用现有的详细分析函数生成结构化数据
    https_analysis = analyze_https_configuration(detailed_results, total_domains)
    hsts_analysis = analyze_hsts_configuration(detailed_results, total_domains)
    headers_analysis = analyze_security_headers(detailed_results, total_domains)
    risk_assessment = generate_risk_assessment(summary, detailed_results)
    current_date = datetime.now().strftime('%Y年%m月%d日')
    prompt = f"""请基于以下数据生成一份域名安全配置深度分析报告


基本信息:
- 报告生成时间: {current_date}  # 确保使用当前时间
- 分析域名总数: {summary.get('total_domains', 0)}
- 成功分析域名: {summary.get('analyzed_domains', 0)}
- 总体安全评分: {summary.get('security_score', 0)}/100
- 安全等级: {get_security_grade(summary.get('security_score', 0))}

安全分数分布:
- 优秀 (80-100分): {score_distribution[0]} 个域名 ({score_distribution[0]/total_domains*100:.1f}%)
- 良好 (60-79分): {score_distribution[1]} 个域名 ({score_distribution[1]/total_domains*100:.1f}%)
- 一般 (40-59分): {score_distribution[2]} 个域名 ({score_distribution[2]/total_domains*100:.1f}%)
- 较差 (0-39分): {score_distribution[3]} 个域名 ({score_distribution[3]/total_domains*100:.1f}%)

详细配置分析数据:

 1. HTTPS强制重定向分析
{https_analysis}

 2. HSTS保护策略分析  
{hsts_analysis}
 3. 安全响应头配置分析
{headers_analysis}
4. 风险评估结果
{risk_assessment}
请基于以上详细数据，生成一份包含以下内容的专业的域名安全配置分析报告：
1. 执行摘要
   - 总体安全态势评估
   - 关键安全指标亮点
   - 主要风险概况
2. 深度技术分析（按安全特性详细展开）
   - HTTPS配置完整性分析
   - HSTS策略有效性评估  
   - 安全响应头配置深度检查
   - 证书信任链验证情况
3. 安全风险评估
   - 高风险问题识别（可能导致严重安全事件的配置）
   - 中风险问题分析（影响安全性的配置缺陷）
   - 低风险问题说明（优化建议类问题）
4. 紧急程度排序
   - P0（紧急）：必须立即修复的问题
   - P1（高优先级）：一周内需要修复的问题  
   - P2（中优先级）：一个月内需要优化的问题
   - P3（低优先级）：长期优化建议
5. 具体修复方案
   - 针对每个发现的问题提供可执行的技术方案
   - 包含具体的配置代码示例
   - 提供验证修复效果的方法
6. 行业最佳实践
   - 基于OWASP、NIST等标准的配置建议
   - 针对不同业务场景的定制化建议
   - 持续安全监控和改进方案
内容专业性要求：
1.技术准确性-确保所有技术建议符合当前安全标准
2.可操作性-提供具体的配置步骤和代码示例
3.风险评估-基于实际数据量化风险等级
4.业务影响-分析安全问题对业务的实际影响
5.成本效益-考虑实施复杂度和安全收益的平衡
报告风格要求：
- 使用专业但易懂的技术语言
- 重要的安全风险使用emoji和强调格式
- 技术配置提供具体的代码示例
- 使用表格和列表增强可读性
- 避免过于学术化的表述，注重实用性

重点关注的安全领域：
A. 传输层安全
- TLS/SSL配置完整性
- HTTPS强制跳转的有效性
- HSTS策略的完整性和正确性
- 协议降级攻击防护

B. 应用层安全
- 内容安全策略(CSP)的配置
- 点击劫持防护(X-Frame-Options)
- MIME类型嗅探防护
- XSS攻击防护机制
- Referrer信息泄露防护

C. 证书信任安全
- 证书链完整性和有效性
- 证书透明度合规性
- 加密算法强度评估
- 证书生命周期管理

特殊考虑因素：

1.请特别关注以下基于实际数据的发现：
- 安全配置的普遍性问题和个别异常
- 不同域名间的安全配置一致性
- 配置缺失的模式和规律
- 可能存在的系统性安全缺陷

2.业务上下文考虑
- 如果涉及多个子域名，分析整体安全策略的一致性
- 考虑不同业务功能的安全要求差异
- 评估安全配置对用户体验的影响
- 提供渐进式改进的路线图

报告输出格式
请使用以下格式组织报告内容：

🔒域名安全配置深度分析报告
==================================================

📋报告信息
...

📊执行摘要
...

🔍深度技术分析

 HTTPS配置分析
[详细技术分析]

 HSTS策略评估
[详细技术分析]

 安全响应头审计
[详细技术分析]

 证书信任链验证情况
[详细技术分析]

⚠️安全风险评估
  高风险问题 (P0)
[问题描述和影响]
  中风险问题 (P1)
[问题描述和影响]
  低风险问题 (P2)
[问题描述和影响]

💡具体修复方案
[针对每个问题的可执行方案]

🛡️行业最佳实践
[基于标准的配置建议]


请基于提供的详细分析数据，生成一份全面、专业、可操作的域名安全配置分析报告
"""

    return prompt

def generate_security_default_report(analysis_data, source_type, original_filename):
    """安全分析专用默认报告"""
    
    summary = analysis_data.get('summary', {})
    feature_stats = analysis_data.get('featureStats', {})
    domain_stats = analysis_data.get('domain_stats', {})
    detailed_results = analysis_data.get('detailed_results', [])
    score_distribution = analysis_data.get('scoreDistribution', [0, 0, 0, 0])
    
    total_domains = summary.get('analyzed_domains', 0) or 1
    security_score = summary.get('security_score', 0)
    
    # 计算各项通过率
    https_rate = (summary.get('domains_with_https_enforcement', 0) / total_domains) * 100
    hsts_rate = (summary.get('domains_with_hsts', 0) / total_domains) * 100
    headers_rate = (summary.get('domains_with_good_security_headers', 0) / total_domains) * 100
    chains_rate = (summary.get('domains_with_valid_certificate_chains', 0) / total_domains) * 100
    
    # 安全等级和安全态势
    security_grade = get_security_grade(security_score)
    security_posture = get_security_posture(security_score)
    
    # 构建报告内容 - 使用字符串连接避免f-string多行问题
    report_lines = [
        "🔒 网站安全配置分析报告",
        "=" * 70,
        "",
        "📋 报告信息",
        "=" * 70,
        f"• 报告类型: 网站安全配置分析",
        f"• 分析时间: {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}",
        f"• 数据来源: {original_filename or '安全分析数据'}",
        f"• 分析域名: {total_domains} 个",
        "",
        "📊 执行摘要",
        "=" * 70,
        f"总体安全评分: {security_score}/100 - {security_grade}",
        f"安全态势: {security_posture}",
        "",
        "📈 关键指标概览",
        "=" * 70,
        "┌──────────────────────┬──────────┬──────────┐",
        "│       安全特性       │ 通过数量 │ 通过率   │",
        "├──────────────────────┼──────────┼──────────┤",
        f"│ HTTPS强制重定向      │ {summary.get('domains_with_https_enforcement', 0):>4}     │ {https_rate:>6.1f}%  │",
        f"│ HSTS保护策略         │ {summary.get('domains_with_hsts', 0):>4}     │ {hsts_rate:>6.1f}%  │",
        f"│ 安全响应头配置       │ {summary.get('domains_with_good_security_headers', 0):>4}     │ {headers_rate:>6.1f}%  │",
        f"│ 证书链完整性         │ {summary.get('domains_with_valid_certificate_chains', 0):>4}     │ {chains_rate:>6.1f}%  │",
        "└──────────────────────┴──────────┴──────────┘",
        "",
        "🎯 安全分数分布",
        "=" * 70,
        f"• 优秀 (80-100分): {score_distribution[0]} 个域名 ({score_distribution[0]/total_domains*100:.1f}%)",
        f"• 良好 (60-79分):  {score_distribution[1]} 个域名 ({score_distribution[1]/total_domains*100:.1f}%)",
        f"• 一般 (40-59分):  {score_distribution[2]} 个域名 ({score_distribution[2]/total_domains*100:.1f}%)",
        f"• 较差 (0-39分):   {score_distribution[3]} 个域名 ({score_distribution[3]/total_domains*100:.1f}%)",
        "",
        "🔍 详细配置分析",
        "=" * 70,
        "",
        "1. HTTPS强制重定向配置",
        "-" * 40,
        analyze_https_configuration(detailed_results, total_domains),
        "",
        "2. HSTS保护策略分析",
        "-" * 40,
        analyze_hsts_configuration(detailed_results, total_domains),
        "",
        "3. 安全响应头配置分析",
        "-" * 40,
        analyze_security_headers(detailed_results, total_domains),
        "",
        "4. 证书信任链分析",
        "-" * 40,
        analyze_certificate_chains(detailed_results, total_domains),
        "",
        "⚠️ 风险评估",
        "=" * 70,
        generate_risk_assessment(summary, detailed_results),
        "",
        "🚨 紧急程度排序",
        "=" * 70,
        generate_priority_actions(summary, detailed_results),
        "",
        "💡 具体改进措施",
        "=" * 70,
        "",
        "🔧 技术配置建议",
        "-" * 40,
        generate_technical_recommendations(detailed_results),
        "",
        "📋 管理流程建议",
        "-" * 40,
        generate_management_recommendations(summary),
        "",
        "🛡️ 安全配置最佳实践",
        "=" * 70,
        "",
        "1. HTTPS配置标准",
        "   • 实现301永久重定向从HTTP到HTTPS",
        "   • 确保所有资源（图片、CSS、JS）均通过HTTPS加载",
        "   • 消除混合内容警告",
        "",
        "2. HSTS最佳实践",
        "   • 设置max-age至少为31536000秒（1年）",
        "   • 包含includeSubDomains指令",
        "   • 在生产环境部署前使用max-age=300进行测试",
        "",
        "3. 安全响应头配置",
        "   • Content-Security-Policy: 定义资源加载策略",
        "   • X-Content-Type-Options: nosniff 防止MIME类型嗅探",
        "   • X-Frame-Options: DENY 防止点击劫持",
        "   • Referrer-Policy: strict-origin-when-cross-origin 控制Referrer信息",
        "   • X-XSS-Protection: 1; mode=block 启用XSS保护",
        "",
        "4. 证书管理要求",
        "   • 使用2048位以上RSA或ECC加密",
        "   • 确保证书链完整可验证",
        "   • 监控证书到期时间，设置自动更新",
        "",
        "📞 后续行动计划",
        "=" * 70,
        "",
        "立即行动（1-3天）:",
        generate_immediate_actions(summary),
        "",
        "短期改进（1-2周）:",
        generate_short_term_actions(summary),
        "",
        "长期优化（1-3月）:",
        generate_long_term_actions(summary),
        "",
        "持续监控:",
        generate_monitoring_recommendations(),
        "",
        "=" * 70,
        "报告生成: 证书安全分析系统 - 安全分析模块",
        "注意: 此为系统自动生成的默认报告，建议结合专业安全审计使用"
    ]
    
    return "\n".join(report_lines)

# 添加缺失的辅助函数
def get_security_grade(score):
    """获取安全等级"""
    if score >= 90:
        return "优秀"
    elif score >= 70:
        return "良好"
    elif score >= 50:
        return "一般"
    else:
        return "需要改进"

def get_security_posture(score):
    """获取安全态势描述"""
    if score >= 90:
        return "优秀 - 安全配置完善"
    elif score >= 70:
        return "良好 - 基础安全配置到位"
    elif score >= 50:
        return "一般 - 需要改进关键安全配置"
    else:
        return "薄弱 - 存在重大安全风险"

def analyze_certificate_chains(detailed_results, total_domains):
    """分析证书链情况"""
    valid_chains = sum(1 for r in detailed_results if r.get('certificate_chain_valid'))
    invalid_chains = total_domains - valid_chains
    
    analysis = f"""
• 证书链完整: {valid_chains} 个域名 ({valid_chains/total_domains*100:.1f}%)
• 证书链问题: {invalid_chains} 个域名 ({invalid_chains/total_domains*100:.1f}%)

影响分析:
"""
    
    if invalid_chains > 0:
        analysis += "  - 部分域名证书链不完整，可能影响用户信任\n"
        analysis += "  - 浏览器可能显示证书警告信息\n"
        analysis += "  - 需要检查中间证书安装情况\n"
    else:
        analysis += "  - ✓ 所有域名证书链完整有效\n"
    
    return analysis

def generate_priority_actions(summary, detailed_results):
    """生成优先级行动"""
    total = summary.get('analyzed_domains', 1)
    
    actions = []
    
    # P0: 紧急行动
    if summary.get('domains_with_https_enforcement', 0) == 0:
        actions.append("🔴 P0 - 立即在所有域名启用HTTPS强制重定向")
    
    # P1: 高优先级
    if summary.get('domains_with_hsts', 0) / total < 0.5:
        actions.append("🟠 P1 - 配置HSTS头部，防止SSL剥离攻击")
    
    # P2: 中优先级
    if summary.get('domains_with_good_security_headers', 0) / total < 0.7:
        actions.append("🟡 P2 - 完善安全响应头配置")
    
    # P3: 低优先级
    actions.append("🔵 P3 - 建立持续安全监控机制")
    
    return "\n".join(actions) if actions else "✅ 所有关键安全配置已到位"

def generate_immediate_actions(summary):
    """生成立即行动"""
    actions = []
    if summary.get('domains_with_https_enforcement', 0) == 0:
        actions.append("• 配置Web服务器实现HTTP到HTTPS重定向")
    if summary.get('domains_with_hsts', 0) == 0:
        actions.append("• 添加HSTS响应头配置")
    
    return "\n".join(actions) if actions else "• 检查现有配置的完整性"

def generate_short_term_actions(summary):
    """生成短期行动"""
    return "\n".join([
        "• 部署完整的安全响应头套件",
        "• 验证证书链完整性",
        "• 建立安全配置检查清单"
    ])

def generate_long_term_actions(summary):
    """生成长期行动"""
    return "\n".join([
        "• 实施自动化安全监控",
        "• 建立安全配置标准",
        "• 定期进行安全审计"
    ])

def generate_monitoring_recommendations():
    """生成监控建议"""
    return "\n".join([
        "• 监控HTTPS重定向状态",
        "• 检查HSTS头部的有效性",
        "• 定期扫描安全头配置",
        "• 监控证书到期时间"
    ])

def generate_management_recommendations(summary):
    """生成管理建议"""
    return "\n".join([
        "• 制定安全配置标准和流程",
        "• 建立变更管理和审计机制",
        "• 培训开发团队安全配置知识",
        "• 定期进行安全配置审查"
    ])

def analyze_https_configuration(detailed_results, total_domains):
    """分析HTTPS配置情况"""
    https_enabled = sum(1 for r in detailed_results if r.get('https_enforcement', {}).get('enforced'))
    https_disabled = total_domains - https_enabled
    
    analysis = f"""
• 启用HTTPS强制: {https_enabled} 个域名 ({https_enabled/total_domains*100:.1f}%)
• 未启用HTTPS强制: {https_disabled} 个域名 ({https_disabled/total_domains*100:.1f}%)

常见问题:
"""
    
    if https_disabled > 0:
        analysis += "  - 存在HTTP访问入口，可能遭受中间人攻击\n"
        analysis += "  - 用户可能通过HTTP访问，导致信息泄露\n"
        analysis += "  - 不符合现代Web安全标准要求\n"
    else:
        analysis += "  - ✓ HTTPS配置完整，所有流量强制加密\n"
    
    return analysis

def analyze_hsts_configuration(detailed_results, total_domains):
    """分析HSTS配置情况"""
    hsts_enabled = sum(1 for r in detailed_results if r.get('hsts', {}).get('enabled'))
    hsts_disabled = total_domains - hsts_enabled
    
    analysis = f"""
• 启用HSTS保护: {hsts_enabled} 个域名 ({hsts_enabled/total_domains*100:.1f}%)
• 未启用HSTS保护: {hsts_disabled} 个域名 ({hsts_disabled/total_domains*100:.1f}%)

安全影响:
"""
    
    if hsts_disabled > 0:
        analysis += "  - 可能遭受SSL剥离攻击(SSL Stripping)\n"
        analysis += "  - 首次访问仍可能通过HTTP进行\n"
        analysis += "  - 不符合OWASP安全标准要求\n"
    else:
        analysis += "  - ✓ HSTS配置有效，防止协议降级攻击\n"
    
    return analysis

def analyze_security_headers(detailed_results, total_domains):
    """分析安全响应头配置"""
    headers_stats = {
        'csp': 0, 'xcto': 0, 'xfo': 0, 'rp': 0, 'xxp': 0
    }
    
    for result in detailed_results:
        assessment = result.get('security_headers', {}).get('assessment', {})
        if assessment.get('has_csp'): headers_stats['csp'] += 1
        if assessment.get('has_x_content_type_options'): headers_stats['xcto'] += 1
        if assessment.get('has_x_frame_options'): headers_stats['xfo'] += 1
        if assessment.get('has_referrer_policy'): headers_stats['rp'] += 1
        # 假设有X-XSS-Protection检查
        if assessment.get('has_x_xss_protection'): headers_stats['xxp'] += 1
    
    analysis = f"""
安全头配置统计:
• Content-Security-Policy: {headers_stats['csp']} 域名 ({headers_stats['csp']/total_domains*100:.1f}%)
• X-Content-Type-Options: {headers_stats['xcto']} 域名 ({headers_stats['xcto']/total_domains*100:.1f}%)
• X-Frame-Options: {headers_stats['xfo']} 域名 ({headers_stats['xfo']/total_domains*100:.1f}%)
• Referrer-Policy: {headers_stats['rp']} 域名 ({headers_stats['rp']/total_domains*100:.1f}%)
• X-XSS-Protection: {headers_stats['xxp']} 域名 ({headers_stats['xxp']/total_domains*100:.1f}%)

关键风险:
"""
    
    risks = []
    if headers_stats['csp'] == 0:
        risks.append("  - 缺少CSP策略，无法有效防御XSS攻击")
    if headers_stats['xfo'] == 0:
        risks.append("  - 缺少X-Frame-Options，存在点击劫持风险")
    if headers_stats['xcto'] == 0:
        risks.append("  - 缺少X-Content-Type-Options，可能遭受MIME混淆攻击")
    
    if risks:
        analysis += "\n".join(risks)
    else:
        analysis += "  - ✓ 安全响应头配置相对完善"
    
    return analysis

def generate_risk_assessment(summary, detailed_results):
    """生成风险评估"""
    total = summary.get('analyzed_domains', 1)
    
    risks = []
    
    # 高风险：完全没有HTTPS强制
    if summary.get('domains_with_https_enforcement', 0) == 0:
        risks.append("🔴 高风险: 所有域名均未启用HTTPS强制重定向，存在中间人攻击风险")
    
    # 中高风险：HSTS缺失
    if summary.get('domains_with_hsts', 0) / total < 0.3:
        risks.append("🟠 中高风险: 超过70%域名缺少HSTS保护，易受SSL剥离攻击")
    
    # 中风险：安全头配置不足
    if summary.get('domains_with_good_security_headers', 0) / total < 0.5:
        risks.append("🟡 中风险: 安全响应头配置不完整，存在XSS、点击劫持等风险")
    
    # 低风险：证书链问题
    if summary.get('domains_with_valid_certificate_chains', 0) / total < 0.8:
        risks.append("🔵 低风险: 部分域名证书链不完整，可能影响用户信任")
    
    if not risks:
        risks.append("✅ 风险可控: 未发现重大安全配置风险")
    
    return "\n".join(risks)

def generate_technical_recommendations(detailed_results):
    """生成技术配置建议"""
    recommendations = [
        "1. 配置Web服务器实现HTTP到HTTPS的301重定向",
        "2. 添加Strict-Transport-Security响应头，建议配置:",
        "   Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "3. 部署完整的安全响应头套件:",
        "   • Content-Security-Policy: 根据业务需求定制",
        "   • X-Content-Type-Options: nosniff", 
        "   • X-Frame-Options: DENY 或 SAMEORIGIN",
        "   • Referrer-Policy: strict-origin-when-cross-origin",
        "   • X-XSS-Protection: 1; mode=block",
        "4. 确保证书链完整，包括中间证书",
        "5. 考虑实施证书透明度(CT)日志监控"
    ]
    
    return "\n".join(recommendations)
