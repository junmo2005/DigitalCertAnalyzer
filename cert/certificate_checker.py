# certificate_checker.py - 优化版（调用核心模块）
"""
证书链查询与可视化工具 - 优化版
- 证书获取：调用 certificate_fetcher
- 证书解析：调用 cryptography
- 证书链验证：调用 certificate_chain_validator
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 图表库延迟加载
MATPLOTLIB_AVAILABLE = None
plt = None
patches = None
FancyBboxPatch = None
np = None

def ensure_plotting_libs():
    """仅在真正要生成图表时再加载 matplotlib/numpy"""
    global MATPLOTLIB_AVAILABLE, plt, patches, FancyBboxPatch, np
    if MATPLOTLIB_AVAILABLE is True:
        return True
    if MATPLOTLIB_AVAILABLE is False:
        return False
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as _plt
        import matplotlib.patches as _patches
        from matplotlib.patches import FancyBboxPatch as _FancyBboxPatch
        import numpy as _np
        plt = _plt
        patches = _patches
        FancyBboxPatch = _FancyBboxPatch
        np = _np
        MATPLOTLIB_AVAILABLE = True
        return True
    except Exception as e:
        MATPLOTLIB_AVAILABLE = False
        print(f"⚠️ 图表依赖加载失败: {e}")
        return False

# 标准库导入
import ssl
import socket
import sys
import subprocess
import re
import os
import tempfile
import base64
import hashlib
from datetime import datetime
from collections import Counter, defaultdict

# 加密库导入
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# 导入核心模块
try:
    from certificate_fetcher import CertificateFetcher
    from certificate_chain_validator import CertificateChainValidator
    CORE_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ 核心模块导入失败: {e}")
    CORE_MODULES_AVAILABLE = False

# ==================== 常量定义 ====================

# 机构名称规范化字典
CA_ORGANIZATION_NORMALIZATION = {
    'DigiCert Inc': 'DigiCert, Inc.',
    'DigiCert, Inc.': 'DigiCert, Inc.',
    'DigiCert Inc.': 'DigiCert, Inc.',
    'DigiCert Global Root G2': 'DigiCert, Inc.',
    'DigiCert Global Root G3': 'DigiCert, Inc.',
    'DigiCert Global Root CA': 'DigiCert, Inc.',
    'GlobalSign nv-sa': 'GlobalSign nv-sa',
    'GlobalSign': 'GlobalSign nv-sa',
    'Microsoft Corporation': 'Microsoft Corporation',
    'Microsoft Corp': 'Microsoft Corporation',
    'Amazon': 'Amazon',
    'Amazon.com': 'Amazon',
    'Let\'s Encrypt': 'Let\'s Encrypt',
    'Sectigo Limited': 'Sectigo Limited',
    'COMODO CA Limited': 'Sectigo Limited',
    'Entrust, Inc.': 'Entrust, Inc.',
    'GoDaddy.com, Inc.': 'GoDaddy',
    'RapidSSL': 'DigiCert, Inc.',
    'GeoTrust': 'DigiCert, Inc.',
    'Thawte': 'DigiCert, Inc.',
    'VeriSign': 'DigiCert, Inc.',
    'Symantec': 'DigiCert, Inc.',
}

# 国家代码映射
COUNTRY_CODE_MAP = {
    'CN': '中国', 'US': '美国', 'GB': '英国', 'FR': '法国', 'DE': '德国',
    'JP': '日本', 'KR': '韩国', 'SG': '新加坡', 'IN': '印度', 'RU': '俄罗斯',
    'CA': '加拿大', 'AU': '澳大利亚', 'BE': '比利时', 'NL': '荷兰', 'CH': '瑞士',
    'SE': '瑞典', 'FI': '芬兰', 'NO': '挪威', 'DK': '丹麦', 'IT': '意大利',
    'ES': '西班牙', 'PT': '葡萄牙', 'IE': '爱尔兰', 'AT': '奥地利',
    'BR': '巴西', 'MX': '墨西哥', 'ZA': '南非', 'NZ': '新西兰',
    'HK': '香港', 'TW': '台湾', 'MO': '澳门', 'PL': '波兰',
}

# 全局变量
certificate_chain_data = []
analysis_results = []
certificate_cache = {}


# ==================== 工具函数 ====================

def normalize_organization_name(org_name):
    """规范化机构名称"""
    if not org_name or org_name == '未知':
        return '未知'
    if org_name in CA_ORGANIZATION_NORMALIZATION:
        return CA_ORGANIZATION_NORMALIZATION[org_name]
    for key, value in CA_ORGANIZATION_NORMALIZATION.items():
        if key in org_name or org_name in key:
            return value
    return org_name

def get_country_name(country_code):
    """将国家代码转换为中文名称"""
    return COUNTRY_CODE_MAP.get(country_code, country_code)

def is_valid_domain(domain):
    """验证域名格式"""
    if not domain or len(domain) > 253:
        return False
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(domain_pattern, domain) is not None

def format_pem_content(content, line_length=64):
    """格式化PEM内容"""
    return '\n'.join([content[i:i + line_length] for i in range(0, len(content), line_length)])


# ==================== 证书解析函数 ====================

def parse_certificate_fast(cert_der):
    """快速解析DER格式的证书"""
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        return _extract_cert_info_from_object(cert)
    except Exception as e:
        print(f"快速解析证书失败: {e}")
        return None

def parse_certificate_fast_pem(pem_content):
    """快速解析PEM证书"""
    try:
        cert = x509.load_pem_x509_certificate(pem_content.encode('utf-8'), default_backend())
        return _extract_cert_info_from_object(cert)
    except Exception as e:
        return parse_certificate_from_pem_improved(pem_content)

def parse_certificate_from_pem_improved(pem_content):
    """改进的PEM证书解析方法"""
    try:
        cert = x509.load_pem_x509_certificate(pem_content.encode('utf-8'), default_backend())
        return _extract_cert_info_from_object(cert)
    except Exception as e:
        print(f"cryptography解析失败: {e}")
        return _parse_certificate_with_openssl(pem_content)

def _extract_cert_info_from_object(cert):
    """从证书对象中提取信息"""
    subject_dict = {}
    for attr in cert.subject:
        subject_dict[attr.oid._name] = attr.value
    
    issuer_dict = {}
    for attr in cert.issuer:
        issuer_dict[attr.oid._name] = attr.value
    
    subject_str = f"CN={subject_dict.get('commonName', '')}"
    issuer_str = f"CN={issuer_dict.get('commonName', '')}"
    
    if issuer_dict.get('organizationName'):
        issuer_str += f", O={issuer_dict['organizationName']}"
    if issuer_dict.get('countryName'):
        issuer_str += f", C={issuer_dict['countryName']}"
    
    organization = issuer_dict.get('organizationName') or issuer_dict.get('organizationalUnitName')
    
    return {
        'subject': subject_str,
        'issuer': issuer_str,
        'not_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
        'not_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
        'serial': hex(cert.serial_number),
        'subject_country': subject_dict.get('countryName'),
        'issuer_country': issuer_dict.get('countryName'),
        'organization': organization,
        'common_name': subject_dict.get('commonName'),
        'issuer_common_name': issuer_dict.get('commonName')
    }

def _parse_certificate_with_openssl(pem_content):
    """使用OpenSSL命令行解析证书"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem', encoding='utf-8') as temp_file:
            temp_file.write(pem_content)
            temp_filename = temp_file.name
        
        try:
            openssl_cmd = f'openssl x509 -in "{temp_filename}" -noout -subject -issuer -dates -serial -nameopt RFC2253'
            info_result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True, timeout=5)
            
            if info_result.returncode == 0:
                return _parse_openssl_output(info_result.stdout)
            return None
        finally:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
    except Exception as e:
        print(f"OpenSSL解析失败: {e}")
        return None

def _parse_openssl_output(output):
    """解析OpenSSL命令输出"""
    subject_match = re.search(r'subject=\s*(.*)', output)
    issuer_match = re.search(r'issuer=\s*(.*)', output)
    not_before_match = re.search(r'notBefore=(.*)', output)
    not_after_match = re.search(r'notAfter=(.*)', output)
    serial_match = re.search(r'serial=(.*)', output)
    
    subject = subject_match.group(1).strip() if subject_match else "未知"
    issuer = issuer_match.group(1).strip() if issuer_match else "未知"
    
    subject_country_match = re.search(r', C=([A-Z]{2})', subject)
    issuer_country_match = re.search(r', C=([A-Z]{2})', issuer)
    common_name_match = re.search(r', CN=([^,]+)', subject)
    issuer_common_name_match = re.search(r', CN=([^,]+)', issuer)
    organization_match = re.search(r', O=([^,]+)', issuer)
    
    return {
        'subject': subject,
        'issuer': issuer,
        'not_before': not_before_match.group(1).strip() if not_before_match else "未知",
        'not_after': not_after_match.group(1).strip() if not_after_match else "未知",
        'serial': serial_match.group(1).strip() if serial_match else "未知",
        'subject_country': subject_country_match.group(1) if subject_country_match else None,
        'issuer_country': issuer_country_match.group(1) if issuer_country_match else None,
        'organization': organization_match.group(1) if organization_match else None,
        'common_name': common_name_match.group(1) if common_name_match else None,
        'issuer_common_name': issuer_common_name_match.group(1) if issuer_common_name_match else None
    }

def extract_cert_info(cert):
    """从证书对象中提取信息（兼容旧接口）"""
    return _extract_cert_info_from_object(cert)

def extract_certificates_fast(output):
    """快速从OpenSSL输出中提取证书"""
    certificates = []
    cert_blocks = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', output, re.DOTALL)
    for block in cert_blocks:
        cert_content = re.sub(r'\s+', '', block.strip())
        pem_cert = f"-----BEGIN CERTIFICATE-----\n{format_pem_content(cert_content)}\n-----END CERTIFICATE-----"
        certificates.append(pem_cert)
    return certificates

def extract_certificates_from_openssl_output(output):
    """从OpenSSL输出中提取证书"""
    return extract_certificates_fast(output)


# ==================== 证书链获取函数 ====================

def get_certificate_chain_fast(hostname, port=443):
    """
    快速获取证书链信息 - 优化版
    优先使用 certificate_fetcher，降级到原有实现
    """
    global certificate_chain_data
    certificate_chain_data = []
    
    clean_hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]
    
    print(f"🔍 正在快速查询 {clean_hostname} 的证书链...")
    print("=" * 60)
    
    # 优先使用核心模块
    if CORE_MODULES_AVAILABLE:
        try:
            fetcher = CertificateFetcher(timeout=10)
            cert_chain, cert_info = fetcher.fetch_certificate_chain(clean_hostname, port)
            
            if cert_chain:
                print(f"📜 使用 CertificateFetcher 获取到 {len(cert_chain)} 个证书")
                
                for i, cert_data in enumerate(cert_chain):
                    cert_type = '叶子证书' if i == 0 else '中间证书' if i < len(cert_chain) - 1 else '根证书'
                    cert_info_parsed = parse_certificate_fast(cert_data)
                    
                    if cert_info_parsed:
                        cert_data_obj = {
                            'index': i + 1,
                            'type': cert_type,
                            'subject': cert_info_parsed['subject'],
                            'issuer': cert_info_parsed['issuer'],
                            'not_before': cert_info_parsed['not_before'],
                            'not_after': cert_info_parsed['not_after'],
                            'serial': cert_info_parsed['serial'],
                            'subject_country': cert_info_parsed['subject_country'],
                            'issuer_country': cert_info_parsed['issuer_country'],
                            'organization': cert_info_parsed['organization'],
                            'common_name': cert_info_parsed['common_name'],
                            'issuer_common_name': cert_info_parsed['issuer_common_name']
                        }
                        certificate_chain_data.append(cert_data_obj)
                
                if certificate_chain_data:
                    print(f"✅ 成功获取 {len(certificate_chain_data)} 个证书")
                    return certificate_chain_data
                    
        except Exception as e:
            print(f"⚠️ CertificateFetcher 获取失败: {e}，使用降级方案")
    
    # 降级方案：使用原有实现
    return _get_certificate_chain_fallback(clean_hostname, port)

#修复 OpenSSL 调用

def _get_certificate_chain_fallback(hostname, port=443):
    """降级方案：使用Python ssl和OpenSSL获取证书链 - 修复版"""
    global certificate_chain_data
    
    # 缩短超时时间
    SOCKET_TIMEOUT = 5      # socket 连接超时（原来8秒）
    OPENSSL_TIMEOUT = 8     # OpenSSL 命令超时（原来12秒）
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                server_cert_der = ssock.getpeercert(binary_form=True)
                if server_cert_der:
                    cache_key = base64.b64encode(server_cert_der).decode('utf-8')
                    if cache_key in certificate_cache:
                        cert_info = certificate_cache[cache_key]
                    else:
                        cert_info = parse_certificate_fast(server_cert_der)
                        certificate_cache[cache_key] = cert_info
                    
                    if cert_info:
                        cert_data = {
                            'index': 1,
                            'type': '叶子证书',
                            'subject': cert_info['subject'],
                            'issuer': cert_info['issuer'],
                            'not_before': cert_info['not_before'],
                            'not_after': cert_info['not_after'],
                            'serial': cert_info['serial'],
                            'subject_country': cert_info['subject_country'],
                            'issuer_country': cert_info['issuer_country'],
                            'organization': cert_info['organization'],
                            'common_name': cert_info['common_name'],
                            'issuer_common_name': cert_info['issuer_common_name']
                        }
                        certificate_chain_data.append(cert_data)
    except Exception as e:
        print(f"❌ SSL连接失败: {e}")
    
    # 使用OpenSSL获取完整链 - 修复编码问题
    try:
        # 设置正确的编码环境
        import subprocess
        import locale
        
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['LANG'] = 'en_US.UTF-8'
        env['LC_ALL'] = 'en_US.UTF-8'
        
        # Windows 特殊处理
        if sys.platform == 'win32':
            # 使用 chcp 65001 设置控制台为 UTF-8
            cmd = f'chcp 65001 > nul && echo | openssl s_client -connect {hostname}:{port} -showcerts -servername {hostname} 2>nul'
        else:
            cmd = f'echo | openssl s_client -connect {hostname}:{port} -showcerts -servername {hostname} 2>/dev/null'
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            timeout=OPENSSL_TIMEOUT,
            encoding='utf-8',
            errors='ignore'  # 忽略编码错误
        )
        
        if result.returncode == 0 and result.stdout:
            # 安全地提取证书
            try:
                certificates = extract_certificates_fast(result.stdout)
            except Exception as e:
                print(f"⚠️ 证书提取失败: {e}")
                return certificate_chain_data
            
            for i, cert_pem in enumerate(certificates):
                if i == 0 and len(certificate_chain_data) > 0:
                    continue
                
                cert_type = '叶子证书' if i == 0 else '中间证书' if i < len(certificates) - 1 else '根证书'
                cert_info = parse_certificate_fast_pem(cert_pem)
                
                if cert_info:
                    cert_data = {
                        'index': len(certificate_chain_data) + 1,
                        'type': cert_type,
                        'subject': cert_info['subject'],
                        'issuer': cert_info['issuer'],
                        'not_before': cert_info['not_before'],
                        'not_after': cert_info['not_after'],
                        'serial': cert_info['serial'],
                        'subject_country': cert_info['subject_country'],
                        'issuer_country': cert_info['issuer_country'],
                        'organization': cert_info['organization'],
                        'common_name': cert_info['common_name'],
                        'issuer_common_name': cert_info['issuer_common_name']
                    }
                    certificate_chain_data.append(cert_data)
            
            print(f"📜 OpenSSL获取到 {len(certificate_chain_data)} 个证书")
    except subprocess.TimeoutExpired:
        print(f"⚠️ OpenSSL获取超时（{OPENSSL_TIMEOUT}秒）")
    except Exception as e:
        print(f"❌ OpenSSL获取失败: {e}")
    
    return certificate_chain_data

# ==================== 结果显示函数 ====================

def display_certificate_hierarchy(hostname):
    """显示证书层级结构"""
    try:
        print(f"\n📋 证书层级结构 ({len(certificate_chain_data) if certificate_chain_data else 0} 个证书):")
        if certificate_chain_data:
            print("┌─ " + "根证书".ljust(50, '─'))
            for i in range(len(certificate_chain_data) - 1, -1, -1):
                level = "  " * (len(certificate_chain_data) - i - 1)
                cert = certificate_chain_data[i]
                if cert['type'] == '根证书':
                    print(f"{level}├─ 根证书")
                elif cert['type'] == '叶子证书':
                    print(f"{level}└─ 叶子证书 (服务器证书)")
                else:
                    print(f"{level}├─ 中间证书 #{len(certificate_chain_data) - i}")
        else:
            print("❌ 无证书数据")
    except Exception as e:
        print(f"无法显示证书层级结构: {e}")


# ==================== 结果保存函数 ====================

def save_analysis_result(hostname, result_data):
    """保存单个域名的分析结果"""
    analysis_results.append({
        'hostname': hostname,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'chain_data': result_data.copy() if result_data else [],
        'chain_length': len(result_data) if result_data else 0,
        'status': '成功' if result_data else '失败'
    })

def get_analysis_results():
    """获取所有分析结果"""
    return analysis_results

def clear_analysis_results():
    """清空分析结果"""
    global analysis_results
    analysis_results = []


# ==================== 报告生成函数 ====================

def ensure_report_directory():
    """确保报告目录存在"""
    report_dir = "域名分析报告"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        print(f"📁 创建报告文件夹: {report_dir}")
    return report_dir

def generate_analysis_report():
    """生成分析报告"""
    if not analysis_results:
        print("❌ 没有分析数据，请先查询证书链")
        return None
    
    try:
        report_dir = ensure_report_directory()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f'certificate_analysis_report_{timestamp}.txt'
        report_path = os.path.join(report_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as report_file:
            report_file.write("=" * 80 + "\n")
            report_file.write("                 证书链分析报告\n")
            report_file.write("=" * 80 + "\n\n")
            
            report_file.write(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report_file.write(f"分析域名数量: {len(analysis_results)}\n")
            
            successful = sum(1 for r in analysis_results if r['status'] == '成功')
            failed = len(analysis_results) - successful
            avg_length = sum(r['chain_length'] for r in analysis_results if r['status'] == '成功') / successful if successful > 0 else 0
            
            report_file.write(f"成功分析: {successful} 个域名\n")
            report_file.write(f"分析失败: {failed} 个域名\n")
            report_file.write(f"平均证书链长度: {avg_length:.2f}\n\n")
            
            # CA统计
            ca_organizations = {}
            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        org = cert.get('organization', '未知')
                        normalized_org = normalize_organization_name(org)
                        ca_organizations[normalized_org] = ca_organizations.get(normalized_org, 0) + 1
            
            if ca_organizations:
                report_file.write("证书颁发机构统计:\n")
                for org, count in sorted(ca_organizations.items(), key=lambda x: x[1], reverse=True):
                    report_file.write(f"   - {org}: {count} 次\n")
                report_file.write("\n")
            
            # 国家统计
            country_distribution = {}
            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        country = cert.get('issuer_country')
                        if country:
                            country_name = get_country_name(country)
                            country_distribution[country_name] = country_distribution.get(country_name, 0) + 1
            
            if country_distribution:
                report_file.write("证书颁发国家分布:\n")
                for country, count in sorted(country_distribution.items(), key=lambda x: x[1], reverse=True):
                    report_file.write(f"   - {country}: {count} 次\n")
                report_file.write("\n")
            
            report_file.write("=" * 80 + "\n")
            report_file.write("                 详细分析结果\n")
            report_file.write("=" * 80 + "\n\n")
            
            for i, result in enumerate(analysis_results, 1):
                report_file.write(f"{i}. 域名: {result['hostname']}\n")
                report_file.write(f"   分析时间: {result['timestamp']}\n")
                report_file.write(f"   分析状态: {result['status']}\n")
                
                if result['status'] == '成功':
                    report_file.write(f"   证书链长度: {result['chain_length']}\n")
                    for cert in result['chain_data']:
                        report_file.write(f"     - {cert['type']} (#{cert['index']})\n")
                        report_file.write(f"       主题: {cert.get('common_name', 'N/A')}\n")
                        report_file.write(f"       颁发者: {cert.get('issuer_common_name', 'N/A')}\n")
                        if cert.get('issuer_country'):
                            report_file.write(f"       国家: {get_country_name(cert['issuer_country'])}\n")
                        report_file.write(f"       有效期: {cert['not_before']} 至 {cert['not_after']}\n")
                report_file.write("\n" + "-" * 60 + "\n\n")
        
        print(f"✅ 分析报告已保存为 '{report_path}'")
        return report_path
        
    except Exception as e:
        print(f"❌ 生成分析报告时出错: {e}")
        return None


# ==================== 拓扑图生成函数 ====================

def generate_issuer_topology_graph():
    """生成颁发机构汇总拓扑图"""
    if not analysis_results:
        print("❌ 没有分析数据，请先查询证书链")
        return None
    
    if not ensure_plotting_libs():
        return None
    
    try:
        report_dir = ensure_report_directory()
        
        all_issuers = {}
        for result in analysis_results:
            if result['status'] == '成功' and result['chain_data']:
                for cert in result['chain_data']:
                    issuer_name = normalize_organization_name(cert.get('organization', '未知'))
                    if issuer_name != '未知':
                        if issuer_name not in all_issuers:
                            all_issuers[issuer_name] = {'count': 1, 'countries': set()}
                        else:
                            all_issuers[issuer_name]['count'] += 1
                        if cert.get('issuer_country'):
                            all_issuers[issuer_name]['countries'].add(get_country_name(cert['issuer_country']))
        
        if not all_issuers:
            print("❌ 未找到有效的颁发机构数据")
            return None
        
        print(f"📊 找到 {len(all_issuers)} 个不同的颁发机构")
        
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False
        
        fig, ax = plt.subplots(figsize=(14, 10))
        ax.set_xlim(0, 12)
        ax.set_ylim(0, 10)
        ax.axis('off')
        
        sorted_issuers = sorted(all_issuers.items(), key=lambda x: x[1]['count'], reverse=True)
        colors = plt.cm.tab20c(np.linspace(0, 1, len(sorted_issuers)))
        
        center_x, center_y = 6, 5
        
        ax.add_patch(plt.Circle((center_x, center_y), 0.5, color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=2))
        ax.text(center_x, center_y, f'颁发机构汇总\n({len(sorted_issuers)}个)',
                ha='center', va='center', fontsize=10, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.9))
        
        for i, (issuer_name, issuer_data) in enumerate(sorted_issuers):
            angle = 2 * np.pi * i / len(sorted_issuers)
            radius = 4
            x = center_x + radius * np.cos(angle)
            y = center_y + radius * np.sin(angle)
            
            max_count = max([data['count'] for _, data in sorted_issuers])
            node_size = 0.3 + (issuer_data['count'] / max_count) * 0.7
            
            ax.add_patch(plt.Circle((x, y), node_size, color=colors[i], alpha=0.8, edgecolor='black', linewidth=2))
            
            if len(issuer_name) > 15:
                parts = re.split(r'[,\.\s\-]+', issuer_name)
                short_name = parts[0] if len(parts) >= 2 else issuer_name[:12] + "..."
            else:
                short_name = issuer_name
            
            display_text = f"{short_name}\n{issuer_data['count']}个"
            
            ha = 'left' if x > center_x else 'right'
            x_text = x + node_size + 0.1 if x > center_x else x - node_size - 0.1
            va = 'bottom' if y > center_y else 'top'
            y_text = y + node_size + 0.1 if y > center_y else y - node_size - 0.1
            
            ax.text(x_text, y_text, display_text, ha=ha, va=va, fontsize=8, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8))
            
            ax.plot([center_x, x], [center_y, y], color=colors[i], alpha=0.5, linewidth=1.5)
        
        ax.set_title('🔗 证书颁发机构拓扑关系图', fontsize=16, fontweight='bold', pad=20)
        
        stats_text = f"📊 统计信息:\n• 颁发机构总数: {len(all_issuers)}\n"
        stats_text += f"• 证书总数: {sum(data['count'] for _, data in sorted_issuers)}\n"
        stats_text += f"• 平均颁发数: {sum(data['count'] for _, data in sorted_issuers) / len(all_issuers):.1f}\n"
        
        all_countries = set()
        for issuer_data in all_issuers.values():
            all_countries.update(issuer_data['countries'])
        stats_text += f"• 涉及国家数: {len(all_countries)}"
        
        ax.text(1, 9, stats_text, fontsize=9, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.9))
        
        plt.tight_layout()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'issuer_topology_{timestamp}.png'
        file_path = os.path.join(report_dir, filename)
        plt.savefig(file_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✅ 颁发机构拓扑图已保存为 '{file_path}'")
        return file_path
        
    except Exception as e:
        print(f"❌ 生成颁发机构拓扑图时出错: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==================== 主入口函数 ====================

def query_and_generate_fast(hostname):
    """优化的查询功能"""
    clean_hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]
    
    print(f"⚡ 正在快速处理 {clean_hostname} ...")
    print("=" * 60)
    
    get_certificate_chain_fast(clean_hostname)
    display_certificate_hierarchy(clean_hostname)
    
    print("\n" + "=" * 60)
    print("✅ 快速查询完成！")
    
    if certificate_chain_data:
        save_analysis_result(clean_hostname, certificate_chain_data)
    else:
        save_analysis_result(clean_hostname, None)


def main():
    """主程序"""
    print("🔐 证书链查询与可视化工具")
    print("=" * 50)
    
    while True:
        print("\n请选择功能:")
        print("1. 单域名分析")
        print("2. 退出程序")
        
        choice = input("请输入选择 (1-2): ").strip()
        
        if choice in ['2', 'quit', 'exit', 'q']:
            print("👋 再见！")
            break
        
        if choice == '1':
            hostname = input("🌐 请输入要查询的域名: ").strip()
            if not hostname:
                print("❌ 请输入有效的域名")
                continue
            
            query_and_generate_fast(hostname)
            
            if analysis_results:
                print("\n📊 正在生成分析报告...")
                report_file = generate_analysis_report()
                if report_file:
                    print(f"📄 分析报告已保存: {report_file}")
                
                print("\n🕸️ 正在生成颁发机构拓扑图...")
                topology_file = generate_issuer_topology_graph()
                if topology_file:
                    print(f"📊 颁发机构拓扑图已保存: {topology_file}")
        else:
            print("❌ 无效选择，请重新输入")


if __name__ == "__main__":
    try:
        import cryptography
    except ImportError:
        print("❌ 缺少必要的库，请安装: pip install cryptography")
        sys.exit(1)
    
    main()