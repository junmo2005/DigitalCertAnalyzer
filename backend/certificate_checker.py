import ssl
import socket
import sys
import subprocess
import re
import matplotlib
import numpy as np
from datetime import datetime

# 在文件开头添加机构名称规范化字典
CA_ORGANIZATION_NORMALIZATION = {
    'DigiCert Inc': 'DigiCert, Inc.',
    'DigiCert, Inc.': 'DigiCert, Inc.',
    'DigiCert Inc.': 'DigiCert, Inc.',
    'DigiCert Global Root G2': 'DigiCert, Inc.',
    'DigiCert Global Root G3': 'DigiCert, Inc.',
    'DigiCert Global Root CA': 'DigiCert, Inc.',

    # GlobalSign
    'GlobalSign nv-sa': 'GlobalSign nv-sa',
    'GlobalSign': 'GlobalSign nv-sa',
    'GlobalSign Root CA': 'GlobalSign nv-sa',

    # Microsoft
    'Microsoft Corporation': 'Microsoft Corporation',
    'Microsoft Corp': 'Microsoft Corporation',
    'Microsoft RSA Root Certificate Authority 2017': 'Microsoft Corporation',

    # Amazon
    'Amazon': 'Amazon',
    'Amazon.com': 'Amazon',
    'Amazon Root CA 1': 'Amazon',
    'Amazon Root CA 2': 'Amazon',
    'Amazon Root CA 3': 'Amazon',
    'Amazon Root CA 4': 'Amazon',

    # Let's Encrypt
    'Let\'s Encrypt': 'Let\'s Encrypt',
    'Let\'s Encrypt Authority X3': 'Let\'s Encrypt',
    'Let\'s Encrypt Authority X4': 'Let\'s Encrypt',

    # Sectigo (原Comodo)
    'Sectigo Limited': 'Sectigo Limited',
    'COMODO CA Limited': 'Sectigo Limited',
    'COMODO RSA Certification Authority': 'Sectigo Limited',

    # Entrust
    'Entrust, Inc.': 'Entrust, Inc.',
    'Entrust.net Certification Authority': 'Entrust, Inc.',

    # GoDaddy
    'GoDaddy.com, Inc.': 'GoDaddy',
    'GoDaddy Secure Certificate Authority': 'GoDaddy',

    # WoTrus
    'WoTrus CA Limited': 'WoTrus CA Limited',

    # 子品牌归属
    'RapidSSL': 'DigiCert, Inc.',  # RapidSSL 是 DigiCert 的子品牌
    'GeoTrust': 'DigiCert, Inc.',  # GeoTrust 是 DigiCert 的子品牌
    'Thawte': 'DigiCert, Inc.',  # Thawte 是 DigiCert 的子品牌
    'VeriSign': 'DigiCert, Inc.',  # VeriSign 被 DigiCert 收购
    'Symantec': 'DigiCert, Inc.',  # Symantec 证书业务被 DigiCert 收购

    # 其他常见机构
    'Sectigo RSA Organization Validation Secure Server CA': 'Sectigo Limited',
    'Baltimore CyberTrust Root': 'Baltimore CyberTrust',
    'SwissSign Gold CA - G2': 'SwissSign',
    'USERTrust RSA Certification Authority': 'Sectigo Limited',
    'Starfield Technologies, Inc.': 'Starfield Technologies',
    'Starfield Secure Certificate Authority': 'Starfield Technologies',
    'Network Solutions Certificate Authority': 'Network Solutions',
}

# 使用非交互式后端，避免显示问题
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import warnings
import os
import tempfile
import base64


def normalize_organization_name(org_name):
    """
    规范化机构名称，解决重名问题
    """
    if not org_name or org_name == '未知':
        return '未知'

    # 首先尝试精确匹配
    if org_name in CA_ORGANIZATION_NORMALIZATION:
        return CA_ORGANIZATION_NORMALIZATION[org_name]

    # 然后尝试模糊匹配（包含关系）
    for key, value in CA_ORGANIZATION_NORMALIZATION.items():
        if key in org_name or org_name in key:
            return value

    # 如果没有匹配，返回原名称
    return org_name


# 忽略cryptography的弃用警告
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 国家代码到中文名称的映射
COUNTRY_CODE_MAP = {
    'CN': '中国',
    'US': '美国',
    'GB': '英国',
    'FR': '法国',
    'DE': '德国',
    'JP': '日本',
    'KR': '韩国',
    'SG': '新加坡',
    'IN': '印度',
    'RU': '俄罗斯',
    'CA': '加拿大',
    'AU': '澳大利亚',
    'BE': '比利时',
    'NL': '荷兰',
    'CH': '瑞士',
    'SE': '瑞典',
    'FI': '芬兰',
    'NO': '挪威',
    'DK': '丹麦',
    'IT': '意大利',
    'ES': '西班牙',
    'PT': '葡萄牙',
    'IE': '爱尔兰',
    'AT': '奥地利',
    'BR': '巴西',
    'MX': '墨西哥',
    'ZA': '南非',
    'NZ': '新西兰',
    'HK': '香港',
    'TW': '台湾',
    'MO': '澳门',
    'PL': '波兰',
}

# 全局变量存储证书链信息
certificate_chain_data = []
analysis_results = []  # 存储所有分析结果

# 缓存已解析的证书，避免重复解析
certificate_cache = {}


def get_country_name(country_code):
    """将国家代码转换为中文名称"""
    return COUNTRY_CODE_MAP.get(country_code, country_code)


def get_certificate_chain_fast(hostname, port=443):
    """
    快速获取证书链信息 - 优化版本
    """
    global certificate_chain_data
    certificate_chain_data = []  # 重置数据

    try:
        print(f"🔍 正在快速查询 {hostname} 的证书链...")
        print("=" * 60)
        # 方法1: 使用Python ssl模块快速获取证书链
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as sock:
                    # 获取服务器证书
                    server_cert_der = sock.getpeercert(binary_form=True)
                    if server_cert_der:
                        # 使用缓存或快速解析
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
                            print(f"✅ 成功获取服务器证书")
        except Exception as e:
            print(f"❌ 方法1失败: {e}")

        # 方法2: 使用优化的OpenSSL命令获取完整证书链
        try:
            # 构建优化的OpenSSL命令
            if sys.platform == "win32":
                null_device = "nul"
            else:
                null_device = "/dev/null"

            # 优化的命令：减少超时时间，使用更快的密码套件
            cmd = f'echo | openssl s_client -connect {hostname}:{port} -server name {hostname} -brief -no_ticket 2>{null_device}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # 快速提取证书信息
                certificates = extract_certificates_fast(result.stdout)

                if certificates:
                    print(f"📜 找到 {len(certificates)} 个证书在链中")

                    # 快速解析每个证书
                    for i, cert_pem in enumerate(certificates):
                        if i == 0 and certificate_chain_data:  # 如果已经通过方法1获取了服务器证书，跳过第一个
                            continue

                        cert_type = '叶子证书' if i == 0 else '中间证书' if i < len(certificates) - 1 else '根证书'

                        # 使用快速解析方法
                        cert_info = parse_certificate_fast_pem(cert_pem)

                        if cert_info:
                            cert_data = {
                                'index': i + 1,
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
            else:
                print("❌ OpenSSL快速命令执行失败")
        except Exception as e:
            print(f"❌ 快速方法2失败: {e}")

        # 如果快速方法没有获取到完整链，使用完整方法
        if len(certificate_chain_data) <= 1:
            print("🔄 快速方法获取证书链不完整，使用完整方法...")
            get_certificate_chain_complete(hostname, port)

    except Exception as e:
        print(f"❌ 快速查询发生错误: {e}")


def get_certificate_chain_complete(hostname, port=443):
    """
    完整获取证书链信息 - 作为快速方法的补充
    """
    try:
        # 构建OpenSSL命令获取完整证书链
        if sys.platform == "win32":
            null_device = "nul"
        else:
            null_device = "/dev/null"

        cmd = f'echo | openssl s_client -connect {hostname}:{port} -showcases -server name {hostname} 2>{null_device}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)

        if result.returncode == 0:
            certificates = extract_certificates_from_openssl_output(result.stdout)

            if certificates:
                print(f"📜 完整方法找到 {len(certificates)} 个证书")

                # 解析每个证书
                for i, cert_pem in enumerate(certificates):
                    # 检查是否已存在相同证书
                    cert_hash = hash(cert_pem)
                    if any(hash(cert.get('pem', '')) == cert_hash for cert in certificate_chain_data):
                        continue

                    cert_type = '叶子证书' if i == 0 else '中间证书' if i < len(certificates) - 1 else '根证书'

                    cert_info = parse_certificate_from_pem_improved(cert_pem)

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
                            'issuer_common_name': cert_info['issuer_common_name'],
                            'pem': cert_pem  # 存储PEM用于去重
                        }
                        certificate_chain_data.append(cert_data)
    except Exception as e:
        print(f"❌ 完整方法失败: {e}")


def parse_certificate_fast(cert_der):
    """快速解析DER格式的证书"""
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # 主题信息 - 只提取关键字段
        subject_dict = {}
        for attr in cert.subject:
            subject_dict[attr.oid._name] = attr.value

        # 颁发者信息 - 只提取关键字段
        issuer_dict = {}
        for attr in cert.issuer:
            issuer_dict[attr.oid._name] = attr.value

        # 构建简化的显示字符串
        subject_str = f"CN={subject_dict.get('commonName', '')}"
        issuer_str = f"CN={issuer_dict.get('commonName', '')}"

        if issuer_dict.get('organizationName'):
            issuer_str += f", O={issuer_dict['organizationName']}"
        if issuer_dict.get('countryName'):
            issuer_str += f", C={issuer_dict['countryName']}"

        # 尝试获取更多机构信息
        organization = None
        if issuer_dict.get('organizationName'):
            organization = issuer_dict['organizationName']
        elif issuer_dict.get('organizationalUnitName'):
            organization = issuer_dict['organizationalUnitName']

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
    except Exception as e:
        print(f"快速解析证书失败: {e}")
        return None


def parse_certificate_fast_pem(pem_content):
    """快速解析PEM证书"""
    try:
        # 直接使用cryptography库解析
        cert = x509.load_pem_x509_certificate(pem_content.encode('utf-8'), default_backend())
        return parse_certificate_fast(cert.public_bytes(serialization.Encoding.DER))
    except Exception as e:
        # 如果快速解析失败，使用完整解析
        return parse_certificate_from_pem_improved(pem_content)


def extract_certificates_fast(output):
    """
    快速从OpenSSL输出中提取证书
    """
    certificates = []

    # 匹配完整的PEM证书块
    cert_blocks = re.findall(
        r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
        output,
        re.DOTALL
    )

    for block in cert_blocks:
        # 清理证书内容
        cert_content = re.sub(r'\s+', '', block.strip())
        # 重新构建完整的PEM证书
        pem_cert = f"-----BEGIN CERTIFICATE-----\n{format_pem_content(cert_content)}\n-----END CERTIFICATE-----"
        certificates.append(pem_cert)

    return certificates


def format_pem_content(content, line_length=64):
    """
    格式化PEM内容，每行指定长度
    """
    return '\n'.join([content[i:i + line_length] for i in range(0, len(content), line_length)])


def parse_certificate_from_pem_improved(pem_content):
    """改进的PEM证书解析方法"""
    try:
        # 方法1: 使用cryptography库直接解析
        cert = x509.load_pem_x509_certificate(pem_content.encode('utf-8'), default_backend())
        return extract_cert_info(cert)
    except Exception as e:
        print(f"cryptography解析失败: {e}")
        # 方法2: 使用OpenSSL命令行解析
        return parse_certificate_with_openssl_improved(pem_content)


def parse_certificate_with_openssl_improved(pem_content):
    """改进的OpenSSL命令行解析方法"""
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem', encoding='utf-8') as temp_file:
            temp_file.write(pem_content)
            temp_filename = temp_file.name

        try:
            # 使用OpenSSL命令获取证书信息
            openssl_cmd = f'openssl x509 -in "{temp_filename}" -no out -subject -issuer -dates -serial -name opt RFC2253'
            info_result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True, timeout=5)  # 减少超时时间

            if info_result.returncode == 0:
                output = info_result.stdout
                return parse_openssl_output(output)
            else:
                print(f"OpenSSL解析失败: {info_result.stderr}")
                return None

        finally:
            # 删除临时文件
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

    except Exception as e:
        print(f"OpenSSL解析过程出错: {e}")
        return None


def parse_openssl_output(output):
    """解析OpenSSL命令输出"""
    # 提取信息
    subject_match = re.search(r'subject=\s*(.*)', output)
    issuer_match = re.search(r'issuer=\s*(.*)', output)
    not_before_match = re.search(r'notBefore=(.*)', output)
    not_after_match = re.search(r'notAfter=(.*)', output)
    serial_match = re.search(r'serial=(.*)', output)

    subject = subject_match.group(1).strip() if subject_match else "未知"
    issuer = issuer_match.group(1).strip() if issuer_match else "未知"
    not_before = not_before_match.group(1).strip() if not_before_match else "未知"
    not_after = not_after_match.group(1).strip() if not_after_match else "未知"
    serial = serial_match.group(1).strip() if serial_match else "未知"

    # 从主题和颁发者中提取国家信息
    subject_country_match = re.search(r', C=([A-Z]{2})', subject)
    issuer_country_match = re.search(r', C=([A-Z]{2})', issuer)

    subject_country = subject_country_match.group(1) if subject_country_match else None
    issuer_country = issuer_country_match.group(1) if issuer_country_match else None

    # 从主题中提取通用名称
    common_name_match = re.search(r', CN=([^,]+)', subject)
    common_name = common_name_match.group(1) if common_name_match else None

    # 从颁发者中提取通用名称
    issuer_common_name_match = re.search(r', CN=([^,]+)', issuer)
    issuer_common_name = issuer_common_name_match.group(1) if issuer_common_name_match else None

    # 从颁发者中提取组织
    organization_match = re.search(r', O=([^,]+)', issuer)
    organization = organization_match.group(1) if organization_match else None

    return {
        'subject': subject,
        'issuer': issuer,
        'not_before': not_before,
        'not_after': not_after,
        'serial': serial,
        'subject_country': subject_country,
        'issuer_country': issuer_country,
        'organization': organization,
        'common_name': common_name,
        'issuer_common_name': issuer_common_name
    }


def extract_cert_info(cert):
    """从证书对象中提取信息"""
    # 主题信息
    subject = {}
    for attr in cert.subject:
        subject[attr.oid._name] = attr.value

    # 颁发者信息
    issuer = {}
    for attr in cert.issuer:
        issuer[attr.oid._name] = attr.value

    # 构建显示字符串
    subject_str = ", ".join([f"{k}={v}" for k, v in subject.items()])
    issuer_str = ", ".join([f"{k}={v}" for k, v in issuer.items()])

    return {
        'subject': subject_str,
        'issuer': issuer_str,
        'not_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
        'not_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
        'serial': hex(cert.serial_number),
        'subject_country': subject.get('countryName'),
        'issuer_country': issuer.get('countryName'),
        'organization': issuer.get('organizationName'),
        'common_name': subject.get('commonName'),
        'issuer_common_name': issuer.get('commonName')
    }


def extract_certificates_from_openssl_output(output):
    """
    从OpenSSL输出中提取证书 - 改进版本
    """
    certificates = []

    # 匹配完整的PEM证书块
    cert_blocks = re.findall(
        r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
        output,
        re.DOTALL
    )

    for block in cert_blocks:
        # 清理证书内容 - 移除多余的空格和换行符
        cert_content = re.sub(r'\s+', '', block.strip())
        # 重新构建完整的PEM证书
        pem_cert = f"-----BEGIN CERTIFICATE-----\n{format_pem_content(cert_content)}\n-----END CERTIFICATE-----"
        certificates.append(pem_cert)

    return certificates


def display_certificate_hierarchy(hostname):
    """
    显示证书层级结构
    """
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


def create_certificate_chain_diagram(hostname):
    """
    创建证书链可视化图表
    """
    if not certificate_chain_data:
        print("❌ 没有证书链数据，请先查询证书链")
        return

    try:
        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False

        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 12)
        ax.axis('off')

        # 颜色设置
        colors = {
            '根证书': '#FF6B6B',
            '中间证书': '#4ECDC4',
            '叶子证书': '#45B7D1'
        }

        # 根据证书数量动态计算位置
        num_certs = len(certificate_chain_data)
        if num_certs == 1:
            certs_y = [6]
        elif num_certs == 2:
            certs_y = [8, 4]
        else:
            certs_y = [9, 6, 3]

        # 绘制证书框和连接线
        for i, cert in enumerate(certificate_chain_data):
            y_pos = certs_y[i] if i < len(certs_y) else certs_y[-1] - (i - len(certs_y) + 1) * 3

            # 证书框
            box = FancyBboxPatch((1, y_pos), 8, 2.5,
                                 boxstyle="round,pad=0.02",
                                 facecolor=colors.get(cert['type'], '#CCCCCC'),
                                 alpha=0.8,
                                 edgecolor='black',
                                 linewidth=2)
            ax.add_patch(box)

            # 证书标题
            ax.text(5, y_pos + 2.2, f"{cert['type']} (#{cert['index']})",
                    ha='center', va='center', fontsize=14, fontweight='bold')

            # 证书名称
            cert_name = cert.get('common_name', '')
            if not cert_name:
                # 从subject中提取CN
                cn_match = re.search(r'CN=([^,]+)', cert['subject'])
                cert_name = cn_match.group(1) if cn_match else cert['subject'][:30] + "..."

            ax.text(5, y_pos + 1.8, cert_name,
                    ha='center', va='center', fontsize=12, fontweight='bold')

            # 颁发者
            issuer_cn = cert.get('issuer_common_name', '')
            if not issuer_cn:
                issuer_cn_match = re.search(r'CN=([^,]+)', cert['issuer'])
                issuer_cn = issuer_cn_match.group(1) if issuer_cn_match else cert['issuer'][:30] + "..."

            ax.text(1.2, y_pos + 1.4, '颁发者:', fontsize=10, fontweight='bold')
            ax.text(1.2, y_pos + 1.1, issuer_cn, fontsize=9)

            # 国家 - 显示颁发者国家
            country_to_show = None
            if cert.get('issuer_country'):
                country_to_show = get_country_name(cert['issuer_country'])
            else:
                # 从issuer中提取国家
                country_match = re.search(r'C=([A-Z]{2})', cert['issuer'])
                if country_match:
                    country_code = country_match.group(1)
                    country_to_show = get_country_name(country_code)
            if country_to_show:
                ax.text(1.2, y_pos + 0.7, f'国家: {country_to_show}', fontsize=10)

            # 有效期
            ax.text(1.2, y_pos + 0.4, '有效期:', fontsize=10, fontweight='bold')
            validity_text = f"{cert['not_before'][:16]} 至\n{cert['not_after'][:16]}"
            ax.text(1.2, y_pos + 0.1, validity_text, fontsize=8)

            # 序列号
            ax.text(5.5, y_pos + 0.7, '序列号:', fontsize=10, fontweight='bold')
            serial_text = cert['serial'][:20] + "..." if len(cert['serial']) > 20 else cert['serial']
            ax.text(5.5, y_pos + 0.4, serial_text, fontsize=8)

            # 连接线（除了最后一个证书）
            if i < len(certificate_chain_data) - 1:
                next_y = certs_y[i + 1] if i + 1 < len(certs_y) else certs_y[-1] - (i + 1 - len(certs_y) + 1) * 3
                ax.plot([5, 5], [y_pos - 0.2, next_y + 2.7],
                        'k-', linewidth=2)
                # 箭头
                ax.annotate('', xy=(5, next_y + 2.7),
                            xytext=(5, y_pos - 0.2),
                            arrowprops=dict(arrowstyle='->', lw=2))

        # 标题
        ax.text(5, 11.5, f'🔐 证书链结构 - {hostname}',
                ha='center', va='center', fontsize=16, fontweight='bold')

        # 图例
        legend_elements = [
            plt.Rectangle((0, 0), 1, 1, facecolor='#FF6B6B', alpha=0.8, label='根证书'),
            plt.Rectangle((0, 0), 1, 1, facecolor='#4ECDC4', alpha=0.8, label='中间证书'),
            plt.Rectangle((0, 0), 1, 1, facecolor='#45B7D1', alpha=0.8, label='叶子证书')
        ]
        ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.98, 0.98))

        plt.tight_layout()
        filename = f'certificate_chain_{hostname.replace(".", "_")}.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✅ 详细证书链图已保存为 '{filename}'")

    except Exception as e:
        print(f"❌ 生成证书链图时出错: {e}")


def save_analysis_result(hostname, result_data):
    """
    保存单个域名的分析结果
    """
    analysis_results.append({
        'hostname': hostname,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'chain_data': result_data.copy() if result_data else [],
        'chain_length': len(result_data) if result_data else 0,
        'status': '成功' if result_data else '失败'
    })


def generate_analysis_report():
    """
    生成分析报告 - 增强分析功能
    """
    if not analysis_results:
        print("❌ 没有分析数据，请先查询证书链")
        return

    try:
        # 创建report文件夹（如果不存在）
        report_dir = "report"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            print(f"📁 创建报告文件夹: {report_dir}")

        # 生成报告文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f'certificate_analysis_report_{timestamp}.txt'
        report_path = os.path.join(report_dir, report_filename)  # 修改路径到report文件夹

        with open(report_path, 'w', encoding='utf-8') as report_file:
            # 报告头部
            report_file.write("=" * 80 + "\n")
            report_file.write("                 证书链分析报告\n")
            report_file.write("=" * 80 + "\n\n")

            # 基本信息
            report_file.write(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report_file.write(f"分析域名数量: {len(analysis_results)}\n")

            # 统计信息
            successful_analysis = sum(1 for result in analysis_results if result['status'] == '成功')
            failed_analysis = len(analysis_results) - successful_analysis
            avg_chain_length = sum(result['chain_length'] for result in analysis_results if
                                   result['status'] == '成功') / successful_analysis if successful_analysis > 0 else 0

            report_file.write(f"成功分析: {successful_analysis} 个域名\n")
            report_file.write(f"分析失败: {failed_analysis} 个域名\n")
            report_file.write(f"平均证书链长度: {avg_chain_length:.2f}\n\n")

            # ==================== 新增分析功能 ====================

            # 证书链长度分布分析
            chain_length_distribution = {}
            for result in analysis_results:
                if result['status'] == '成功':
                    length = result['chain_length']
                    if length in chain_length_distribution:
                        chain_length_distribution[length] += 1
                    else:
                        chain_length_distribution[length] = 1

            if chain_length_distribution:
                report_file.write("证书链长度分布:\n")
                for length, count in sorted(chain_length_distribution.items()):
                    percentage = (count / successful_analysis) * 100
                    report_file.write(f"   - {length}个证书: {count}个域名 ({percentage:.1f}%)\n")
                report_file.write("\n")

            # 证书有效期分析
            current_time = datetime.now()
            validity_analysis = {
                'expired': 0,
                'expiring_soon': 0,  # 30天内过期
                'expiring_3months': 0,  # 3个月内过期
                'expiring_year': 0,  # 1年内过期
                'valid': 0
            }

            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        try:
                            # 解析证书有效期
                            not_after_str = cert['not_after']
                            # 处理不同格式的日期
                            if 'GMT' in not_after_str:
                                not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y GMT')
                            else:
                                not_after = datetime.strptime(not_after_str, '%Y-%m-%d %H:%M:%S')

                            days_remaining = (not_after - current_time).days

                            if days_remaining < 0:
                                validity_analysis['expired'] += 1
                            elif days_remaining <= 30:
                                validity_analysis['expiring_soon'] += 1
                            elif days_remaining <= 90:
                                validity_analysis['expiring_3months'] += 1
                            elif days_remaining <= 365:
                                validity_analysis['expiring_year'] += 1
                            else:
                                validity_analysis['valid'] += 1

                        except Exception as e:
                            # 如果日期解析失败，跳过
                            continue

            total_certs = sum(validity_analysis.values())
            if total_certs > 0:
                report_file.write("证书有效期分析:\n")
                report_file.write(f"   - 已过期证书: {validity_analysis['expired']} 个\n")
                report_file.write(f"   - 30天内过期: {validity_analysis['expiring_soon']} 个\n")
                report_file.write(f"   - 3个月内过期: {validity_analysis['expiring_3months']} 个\n")
                report_file.write(f"   - 1年内过期: {validity_analysis['expiring_year']} 个\n")
                report_file.write(f"   - 有效期充足: {validity_analysis['valid']} 个\n")
                report_file.write("\n")

            # 证书类型分析
            cert_type_distribution = {}
            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        cert_type = cert['type']
                        if cert_type in cert_type_distribution:
                            cert_type_distribution[cert_type] += 1
                        else:
                            cert_type_distribution[cert_type] = 1

            if cert_type_distribution:
                report_file.write("证书类型分布:\n")
                for cert_type, count in sorted(cert_type_distribution.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total_certs) * 100 if total_certs > 0 else 0
                    report_file.write(f"   - {cert_type}: {count} 个 ({percentage:.1f}%)\n")
                report_file.write("\n")

            # 证书颁发机构统计（使用规范化名称）
            ca_organizations = {}
            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        org = cert.get('organization', '未知')
                        # 使用规范化后的机构名称
                        normalized_org = normalize_organization_name(org)
                        if normalized_org in ca_organizations:
                            ca_organizations[normalized_org] += 1
                        else:
                            ca_organizations[normalized_org] = 1

            if ca_organizations:
                report_file.write("证书颁发机构统计:\n")
                for org, count in sorted(ca_organizations.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total_certs) * 100 if total_certs > 0 else 0
                    report_file.write(f"   - {org}: {count} 次 ({percentage:.1f}%)\n")
                report_file.write("\n")

            # 国家分布统计
            country_distribution = {}
            for result in analysis_results:
                if result['status'] == '成功' and result['chain_data']:
                    for cert in result['chain_data']:
                        country = cert.get('issuer_country')
                        if country:
                            country_name = get_country_name(country)
                            if country_name in country_distribution:
                                country_distribution[country_name] += 1
                            else:
                                country_distribution[country_name] = 1

            if country_distribution:
                report_file.write("证书颁发国家分布:\n")
                for country, count in sorted(country_distribution.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total_certs) * 100 if total_certs > 0 else 0
                    report_file.write(f"   - {country}: {count} 次 ({percentage:.1f}%)\n")
                report_file.write("\n")

            # 失败域名分析
            if failed_analysis > 0:
                report_file.write("分析失败的域名:\n")
                for result in analysis_results:
                    if result['status'] == '失败':
                        report_file.write(f"   - {result['hostname']} (分析时间: {result['timestamp']})\n")
                report_file.write("\n")

            # 生成统计饼图
            if ca_organizations or country_distribution:
                print("📊 正在生成统计饼图...")
                chart_files = generate_statistics_charts(ca_organizations, country_distribution, timestamp)

                report_file.write("=" * 80 + "\n")
                report_file.write("                 统计图表\n")
                report_file.write("=" * 80 + "\n\n")

                if chart_files:
                    report_file.write("生成的统计图表文件:\n")
                    for chart_file in chart_files:
                        report_file.write(f"   - {chart_file}\n")
                    report_file.write("\n")

            report_file.write("=" * 80 + "\n")
            report_file.write("                 详细分析结果\n")
            report_file.write("=" * 80 + "\n\n")

            # 逐个域名详细报告
            for i, result in enumerate(analysis_results, 1):
                report_file.write(f"{i}. 域名: {result['hostname']}\n")
                report_file.write(f"   分析时间: {result['timestamp']}\n")
                report_file.write(f"   分析状态: {result['status']}\n")

                if result['status'] == '成功':
                    report_file.write(f"   证书链长度: {result['chain_length']}\n")

                    # 添加证书有效期状态
                    if result['chain_data']:
                        for cert in result['chain_data']:
                            try:
                                not_after_str = cert['not_after']
                                if 'GMT' in not_after_str:
                                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y GMT')
                                else:
                                    not_after = datetime.strptime(not_after_str, '%Y-%m-%d %H:%M:%S')

                                days_remaining = (not_after - current_time).days
                                status = "✅ 有效" if days_remaining > 30 else "⚠️ 即将过期" if days_remaining > 0 else "❌ 已过期"
                                report_file.write(f"   有效期状态: {status} (剩余{days_remaining}天)\n")
                                break  # 只检查第一个证书（叶子证书）
                            except:
                                report_file.write(f"   有效期状态: 未知\n")
                                break

                    report_file.write("   证书链详情:\n")

                    for cert in result['chain_data']:
                        report_file.write(f"     - {cert['type']} (#{cert['index']})\n")
                        report_file.write(f"       主题: {cert.get('common_name', 'N/A')}\n")
                        report_file.write(f"       颁发者: {cert.get('issuer_common_name', 'N/A')}\n")

                        # 国家信息
                        if cert.get('issuer_country'):
                            country_name = get_country_name(cert['issuer_country'])
                            report_file.write(f"       国家: {country_name}\n")

                        report_file.write(f"       有效期: {cert['not_before']} 至 {cert['not_after']}\n")
                        report_file.write(f"       序列号: {cert['serial']}\n")
                else:
                    report_file.write("   错误: 无法获取证书链信息\n")

                report_file.write("\n" + "-" * 60 + "\n\n")

            # ==================== 增强总结和建议 ====================
            report_file.write("=" * 80 + "\n")
            report_file.write("                 总结与建议\n")
            report_file.write("=" * 80 + "\n\n")

            # 安全建议
            report_file.write("安全建议:\n")

            # 连接成功率建议
            if failed_analysis > 0:
                failure_rate = (failed_analysis / len(analysis_results)) * 100
                report_file.write(f"   ❌ 连接成功率: {100 - failure_rate:.1f}% ({failed_analysis}个域名失败)\n")
                report_file.write("     建议检查网络连接或服务器配置\n")
            else:
                report_file.write("   ✅ 所有域名连接成功\n")

            # 证书链完整性建议
            if avg_chain_length < 2:
                report_file.write("   ⚠️  证书链完整性: 较差 (平均长度 {:.1f})\n".format(avg_chain_length))
                report_file.write("     可能存在中间证书缺失问题\n")
            elif avg_chain_length < 3:
                report_file.write("   ✅ 证书链完整性: 一般 (平均长度 {:.1f})\n".format(avg_chain_length))
                report_file.write("     建议检查是否缺少根证书\n")
            else:
                report_file.write("   ✅ 证书链完整性: 优秀 (平均长度 {:.1f})\n".format(avg_chain_length))

            # 证书有效期建议
            if validity_analysis['expired'] > 0:
                report_file.write(f"   ❌ 发现 {validity_analysis['expired']} 个已过期证书\n")
                report_file.write("     立即更新过期证书以避免服务中断\n")

            if validity_analysis['expiring_soon'] > 0:
                report_file.write(f"   ⚠️  发现 {validity_analysis['expiring_soon']} 个30天内过期证书\n")
                report_file.write("     建议尽快更新即将过期的证书\n")

            if validity_analysis['expiring_3months'] > 0:
                report_file.write(f"   📝 发现 {validity_analysis['expiring_3months']} 个3个月内过期证书\n")
                report_file.write("     建议制定证书更新计划\n")

            # CA机构多样性建议
            if len(ca_organizations) <= 3:
                report_file.write("   🔒 CA机构多样性: 较低\n")
                report_file.write("     建议考虑使用多个不同的证书颁发机构\n")
            else:
                report_file.write("   🌐 CA机构多样性: 良好\n")

            # 通用建议
            report_file.write("\n通用建议:\n")
            report_file.write("   🔒 建议定期检查证书有效期，避免证书过期导致服务中断\n")
            report_file.write("   🌐 建议使用权威CA颁发的证书，确保浏览器兼容性\n")
            report_file.write("   📊 建议建立证书管理台账，跟踪证书状态\n")
            report_file.write("   ⚡ 建议设置证书过期提醒机制\n")
            report_file.write("   🔄 建议实施证书自动续期策略\n\n")

            # 文件列表
            report_file.write("=" * 80 + "\n")
            report_file.write("                 生成文件列表\n")
            report_file.write("=" * 80 + "\n\n")

            report_file.write("可视化图表文件:\n")
            for result in analysis_results:
                if result['status'] == '成功':
                    safe_hostname = result['hostname'].replace('.', '_')
                    report_file.write(f"   - certificate_chain_{safe_hostname}.png (详细图)\n")

            # 添加统计图表文件
            if ca_organizations or country_distribution:
                report_file.write(f"\n统计图表文件:\n")
                for chart_file in chart_files:
                    report_file.write(f"   - {chart_file}\n")

            report_file.write(f"\n分析报告文件:\n")
            report_file.write(f"   - {report_path} (本文件)\n")

        print(f"✅ 增强分析报告已保存为 '{report_path}'")
        return report_path

    except Exception as e:
        print(f"❌ 生成分析报告时出错: {e}")
        return None


def generate_statistics_charts(ca_organizations, country_distribution, timestamp):
    """
    生成统计饼图
    """
    chart_files = []

    try:
        # 创建report文件夹（如果不存在）
        report_dir = "report"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False

        # 生成证书颁发机构饼图
        if ca_organizations:
            fig1, ax1 = plt.subplots(figsize=(12, 8))

            # 处理数据：将小的份额合并为"其他"
            sorted_orgs = sorted(ca_organizations.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_orgs) > 8:  # 如果超过8个，将小的合并
                main_orgs = sorted_orgs[:7]
                other_count = sum(count for _, count in sorted_orgs[7:])
                data = dict(main_orgs)
                data['其他'] = other_count
            else:
                data = dict(sorted_orgs)

            labels = list(data.keys())
            sizes = list(data.values())

            # 颜色设置
            colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))

            # 绘制饼图
            wedges, texts, autotexts = ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
                                               startangle=90, colors=colors,
                                               textprops={'fontsize': 10})

            # 美化百分比文本
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')

            ax1.set_title('证书颁发机构分布', fontsize=16, fontweight='bold', pad=20)

            # 添加图例
            ax1.legend(wedges, [f'{l}: {s}次' for l, s in zip(labels, sizes)],
                       title="颁发机构",
                       loc="center left",
                       bbox_to_anchor=(1, 0, 0.5, 1))

            plt.tight_layout()
            org_chart_file = f'certificate_issuers_chart_{timestamp}.png'
            org_chart_path = os.path.join(report_dir, org_chart_file)  # 修改路径到report文件夹
            plt.savefig(org_chart_path, dpi=300, bbox_inches='tight')
            chart_files.append(org_chart_path)
            plt.close(fig1)
            print(f"✅ 颁发机构分布图已保存为 '{org_chart_path}'")

        # 生成国家分布饼图
        if country_distribution:
            fig2, ax2 = plt.subplots(figsize=(10, 8))

            # 处理数据：将小的份额合并为"其他"
            sorted_countries = sorted(country_distribution.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_countries) > 6:  # 如果超过6个，将小的合并
                main_countries = sorted_countries[:5]
                other_count = sum(count for _, count in sorted_countries[5:])
                data = dict(main_countries)
                data['其他'] = other_count
            else:
                data = dict(sorted_countries)

            labels = list(data.keys())
            sizes = list(data.values())

            # 颜色设置 - 使用更鲜明的颜色
            colors = plt.cm.Pastel1(np.linspace(0, 1, len(labels)))

            # 绘制饼图
            wedges, texts, autotexts = ax2.pie(sizes, labels=labels, autopct='%1.1f%%',
                                               startangle=90, colors=colors,
                                               textprops={'fontsize': 10})

            # 美化百分比文本
            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontweight('bold')

            ax2.set_title('证书颁发国家分布', fontsize=16, fontweight='bold', pad=20)

            # 添加图例
            ax2.legend(wedges, [f'{l}: {s}次' for l, s in zip(labels, sizes)],
                       title="国家",
                       loc="center left",
                       bbox_to_anchor=(1, 0, 0.5, 1))

            plt.tight_layout()
            country_chart_file = f'certificate_countries_chart_{timestamp}.png'
            country_chart_path = os.path.join(report_dir, country_chart_file)  # 修改路径到report文件夹
            plt.savefig(country_chart_path, dpi=300, bbox_inches='tight')
            chart_files.append(country_chart_path)
            plt.close(fig2)
            print(f"✅ 国家分布图已保存为 '{country_chart_path}'")

        # 生成组合统计图
        if ca_organizations and country_distribution:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

            # 左侧：颁发机构饼图
            sorted_orgs = sorted(ca_organizations.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_orgs) > 6:
                main_orgs = sorted_orgs[:5]
                other_count = sum(count for _, count in sorted_orgs[5:])
                org_data = dict(main_orgs)
                org_data['其他'] = other_count
            else:
                org_data = dict(sorted_orgs)

            org_labels = list(org_data.keys())
            org_sizes = list(org_data.values())
            org_colors = plt.cm.Set3(np.linspace(0, 1, len(org_labels)))

            ax1.pie(org_sizes, labels=org_labels, autopct='%1.1f%%',
                    startangle=90, colors=org_colors, textprops={'fontsize': 9})
            ax1.set_title('颁发机构分布', fontsize=14, fontweight='bold')

            # 右侧：国家分布饼图
            sorted_countries = sorted(country_distribution.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_countries) > 5:
                main_countries = sorted_countries[:4]
                other_count = sum(count for _, count in sorted_countries[4:])
                country_data = dict(main_countries)
                country_data['其他'] = other_count
            else:
                country_data = dict(sorted_countries)

            country_labels = list(country_data.keys())
            country_sizes = list(country_data.values())
            country_colors = plt.cm.Pastel2(np.linspace(0, 1, len(country_labels)))

            ax2.pie(country_sizes, labels=country_labels, autopct='%1.1f%%',
                    startangle=90, colors=country_colors, textprops={'fontsize': 9})
            ax2.set_title('国家分布', fontsize=14, fontweight='bold')

            plt.suptitle('证书链统计分析', fontsize=16, fontweight='bold', y=0.95)
            plt.tight_layout()

            combined_chart_file = f'certificate_combined_chart_{timestamp}.png'
            combined_chart_path = os.path.join(report_dir, combined_chart_file)  # 修改路径到report文件夹
            plt.savefig(combined_chart_path, dpi=300, bbox_inches='tight')
            chart_files.append(combined_chart_path)
            plt.close(fig)
            print(f"✅ 组合统计图已保存为 '{combined_chart_path}'")

        return chart_files

    except Exception as e:
        print(f"❌ 生成统计图表时出错: {e}")
        return []


def generate_issuer_topology_graph():
    """
    生成颁发机构汇总拓扑图 - 优化版
    """
    if not analysis_results:
        print("❌ 没有分析数据，请先查询证书链")
        return

    try:
        # 创建report文件夹（如果不存在）
        report_dir = "report"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        # 收集所有颁发机构数据
        all_issuers = {}
        all_certs = []

        # 遍历所有分析结果，收集证书和颁发者信息
        for result in analysis_results:
            if result['status'] == '成功' and result['chain_data']:
                for cert in result['chain_data']:
                    # 使用规范化后的机构名称
                    issuer_name = normalize_organization_name(cert.get('organization', '未知'))
                    subject_name = cert.get('common_name', cert.get('subject', '未知'))

                    # 提取域名（对于叶子证书）
                    if cert['type'] == '叶子证书':
                        # 尝试从common_name或subject中提取域名
                        cn = cert.get('common_name', '')
                        if cn:
                            domain = cn
                        else:
                            # 从subject中提取CN
                            match = re.search(r'CN=([^,]+)', cert.get('subject', ''))
                            domain = match.group(1) if match else '未知域名'

                        # 只添加域名部分，去除通配符
                        domain = domain.replace('*.', '')
                        all_certs.append({
                            'domain': domain,
                            'issuer': issuer_name,
                            'type': cert['type'],
                            'country': cert.get('issuer_country')
                        })

                    # 统计颁发机构
                    if issuer_name != '未知':
                        if issuer_name in all_issuers:
                            all_issuers[issuer_name]['count'] += 1
                        else:
                            all_issuers[issuer_name] = {
                                'count': 1,
                                'countries': set(),
                                'domains': set()  # 新增：存储该机构颁发的域名
                            }

                        # 添加国家信息
                        if cert.get('issuer_country'):
                            country_name = get_country_name(cert['issuer_country'])
                            all_issuers[issuer_name]['countries'].add(country_name)

                        # 添加域名信息（只添加叶子证书的域名）
                        if cert['type'] == '叶子证书':
                            if cn:
                                domain_name = cn.replace('*.', '')
                                all_issuers[issuer_name]['domains'].add(domain_name)

        if not all_issuers:
            print("❌ 未找到有效的颁发机构数据")
            return

        print(f"📊 找到 {len(all_issuers)} 个不同的颁发机构")
        print(f"📋 分析 {len(all_certs)} 个证书")

        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False

        # 创建图形 - 使用更合理的布局
        fig = plt.figure(figsize=(18, 12))

        # 使用GridSpec创建复杂的子图布局
        gs = plt.GridSpec(2, 3, figure=fig, hspace=0.4, wspace=0.4)

        # 主拓扑图 - 占据左上角2x2区域
        ax1 = fig.add_subplot(gs[0:2, 0:2])
        # 条形图 - 右上角
        ax2 = fig.add_subplot(gs[0, 2])
        # 国家分布饼图 - 右下角
        ax3 = fig.add_subplot(gs[1, 2])

        # 设置主拓扑图
        ax1.set_xlim(0, 12)
        ax1.set_ylim(0, 10)
        ax1.axis('off')

        # 1. 生成颁发机构拓扑图
        print("🕸️  正在生成颁发机构拓扑图...")

        # 颜色设置
        colors = plt.cm.tab20c(np.linspace(0, 1, len(all_issuers)))
        issuer_colors = {}

        # 根据颁发证书数量排序
        sorted_issuers = sorted(all_issuers.items(), key=lambda x: x[1]['count'], reverse=True)

        # 布局参数
        center_x, center_y = 6, 5

        # 绘制中心节点（所有证书）
        center_circle = plt.Circle((center_x, center_y), 0.5,
                                   color='#FF6B6B', alpha=0.9,
                                   edgecolor='black', linewidth=3)
        ax1.add_patch(center_circle)
        ax1.text(center_x, center_y, f'所有证书\n({len(all_certs)}个)',
                 ha='center', va='center', fontsize=12, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.9))

        # 绘制颁发机构节点
        print("📝 绘制颁发机构节点...")

        # 动态调整节点位置，避免重叠
        num_issuers = len(sorted_issuers)
        radius = 3.5

        # 先绘制节点
        for i, (issuer_name, issuer_data) in enumerate(sorted_issuers):
            # 计算角度（从顶部开始）
            angle = 2 * np.pi * i / num_issuers

            # 稍微随机化半径，避免完美圆形导致重叠
            actual_radius = radius + np.random.uniform(-0.2, 0.2)

            # 计算位置
            x = center_x + actual_radius * np.cos(angle - np.pi / 2)  # -π/2使顶部开始
            y = center_y + actual_radius * np.sin(angle - np.pi / 2)

            # 分配颜色
            color = colors[i]
            issuer_colors[issuer_name] = color

            # 计算节点大小（基于颁发证书数量，对数缩放避免大小差异过大）
            max_count = max([issuer['count'] for issuer in all_issuers.values()])
            node_size = 0.3 + 0.6 * (np.log(issuer_data['count'] + 1) / np.log(max_count + 1))

            # 绘制节点
            circle = plt.Circle((x, y), node_size,
                                color=color, alpha=0.85,
                                edgecolor='black', linewidth=2)
            ax1.add_patch(circle)

            # 绘制连接线（从中心到节点）
            ax1.plot([center_x, x], [center_y, y],
                     color=color, alpha=0.4, linewidth=1.2, zorder=1)

        # 后绘制文本，避免被节点遮挡
        for i, (issuer_name, issuer_data) in enumerate(sorted_issuers):
            # 重新计算位置（与绘制节点时相同）
            angle = 2 * np.pi * i / num_issuers
            actual_radius = radius + np.random.uniform(-0.2, 0.2)
            x = center_x + actual_radius * np.cos(angle - np.pi / 2)
            y = center_y + actual_radius * np.sin(angle - np.pi / 2)

            # 计算节点大小
            max_count = max([issuer['count'] for issuer in all_issuers.values()])
            node_size = 0.3 + 0.6 * (np.log(issuer_data['count'] + 1) / np.log(max_count + 1))

            # 准备文本内容
            # 截断机构名称
            if len(issuer_name) > 20:
                display_name = issuer_name[:17] + "..."
            else:
                display_name = issuer_name

            # 国家信息
            country_text = ""
            if issuer_data['countries']:
                countries_list = list(issuer_data['countries'])
                if countries_list:
                    country_text = f"\n{countries_list[0]}"

            # 完整显示文本
            display_text = f"{display_name}\n{issuer_data['count']}个{country_text}"

            # 根据位置决定文本对齐方式
            # 计算文本应该放置的方向
            dx = x - center_x
            dy = y - center_y

            # 标准化方向向量
            norm = np.sqrt(dx ** 2 + dy ** 2)
            if norm > 0:
                dx /= norm
                dy /= norm

            # 文本位置在节点外侧
            text_x = x + (node_size + 0.15) * dx
            text_y = y + (node_size + 0.15) * dy

            # 决定水平对齐
            if dx > 0.3:  # 右侧
                ha = 'left'
            elif dx < -0.3:  # 左侧
                ha = 'right'
            else:  # 中间
                ha = 'center'

            # 决定垂直对齐
            if dy > 0.3:  # 上部
                va = 'bottom'
            elif dy < -0.3:  # 下部
                va = 'top'
            else:  # 中间
                va = 'center'

            # 绘制文本
            ax1.text(text_x, text_y, display_text,
                     ha=ha, va=va, fontsize=8, fontweight='bold',
                     bbox=dict(boxstyle="round,pad=0.2",
                               facecolor="white",
                               edgecolor=issuer_colors[issuer_name],
                               alpha=0.9, linewidth=1),
                     zorder=10)  # 确保文本在最上层

        # 添加标题
        ax1.set_title('🔐 证书颁发机构拓扑关系图', fontsize=18, fontweight='bold', pad=20)

        # 2. 生成颁发机构分布条形图（优化版）
        print("📈 正在生成颁发机构分布图...")

        # 准备数据（最多显示12个）
        top_issuers = sorted_issuers[:12]
        issuer_names = [name[:15] + "..." if len(name) > 15 else name for name, _ in top_issuers]
        issuer_counts = [data['count'] for _, data in top_issuers]

        # 条形图颜色（与拓扑图一致）
        bar_colors = colors[:len(top_issuers)]

        # 绘制水平条形图
        bars = ax2.barh(range(len(issuer_names)), issuer_counts, color=bar_colors, edgecolor='black', height=0.6)
        ax2.set_yticks(range(len(issuer_names)))
        ax2.set_yticklabels(issuer_names, fontsize=9)
        ax2.set_xlabel('颁发证书数量', fontsize=11)
        ax2.set_title('TOP 颁发机构统计', fontsize=14, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3, linestyle='--')

        # 在条形上添加数值
        for i, (bar, count) in enumerate(zip(bars, issuer_counts)):
            width = bar.get_width()
            # 如果条形太窄，把文本放在外面
            if width < max(issuer_counts) * 0.1:
                ax2.text(width + max(issuer_counts) * 0.02, bar.get_y() + bar.get_height() / 2,
                         f'{count}', ha='left', va='center', fontsize=9)
            else:
                ax2.text(width / 2, bar.get_y() + bar.get_height() / 2,
                         f'{count}', ha='center', va='center', fontsize=9, color='white', fontweight='bold')

        # 3. 生成国家分布饼图（优化版）
        print("🌍 正在生成国家分布图...")

        # 统计国家分布
        country_stats = {}
        for issuer_name, issuer_data in all_issuers.items():
            for country in issuer_data['countries']:
                if country in country_stats:
                    country_stats[country] += issuer_data['count']
                else:
                    country_stats[country] = issuer_data['count']

        # 处理数据：将小的份额合并为"其他"
        if country_stats:
            sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)

            # 如果国家数量多，只显示前8个
            if len(sorted_countries) > 8:
                main_countries = sorted_countries[:7]
                other_count = sum(count for _, count in sorted_countries[7:])
                pie_data = dict(main_countries)
                pie_data['其他'] = other_count
            else:
                pie_data = dict(sorted_countries)

            labels = list(pie_data.keys())
            sizes = list(pie_data.values())

            # 饼图颜色
            pie_colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))

            # 绘制饼图
            wedges, texts, autotexts = ax3.pie(sizes, labels=labels, autopct='%1.1f%%',
                                               startangle=90, colors=pie_colors,
                                               textprops={'fontsize': 9})

            # 美化百分比文本
            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontweight('bold')

            ax3.set_title('颁发国家分布', fontsize=14, fontweight='bold')

            # 添加图例
            ax3.legend(wedges, [f'{l}: {s}次' for l, s in zip(labels, sizes)],
                       title="国家", loc="center left",
                       bbox_to_anchor=(1, 0, 0.5, 1), fontsize=9)
        else:
            ax3.text(0.5, 0.5, '无国家数据', ha='center', va='center', fontsize=12)
            ax3.set_title('颁发国家分布', fontsize=14, fontweight='bold')

        # 4. 添加统计信息框
        stats_text = f"📊 整体统计信息\n"
        stats_text += f"• 分析域名数量: {len(analysis_results)}\n"
        stats_text += f"• 成功分析域名: {sum(1 for r in analysis_results if r['status'] == '成功')}\n"
        stats_text += f"• 证书总数: {len(all_certs)}\n"
        stats_text += f"• 颁发机构数: {len(all_issuers)}\n"

        # 国家统计
        all_countries = set()
        for issuer_data in all_issuers.values():
            all_countries.update(issuer_data['countries'])
        stats_text += f"• 涉及国家数: {len(all_countries)}\n"

        # 机构集中度
        if len(sorted_issuers) > 0:
            top3_percent = sum(data['count'] for _, data in sorted_issuers[:3]) / len(all_certs) * 100
            stats_text += f"• 前三机构占比: {top3_percent:.1f}%\n"

        # 在图像底部添加统计信息
        fig.text(0.02, 0.02, stats_text, fontsize=10, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.9))

        # 调整整体布局
        plt.suptitle(f'📊 证书颁发机构综合分析报告', fontsize=20, fontweight='bold', y=0.98)
        plt.tight_layout(rect=[0, 0.05, 1, 0.95])  # 为底部统计信息留出空间

        # 保存图片
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'issuer_topology_{timestamp}.png'
        file_path = os.path.join(report_dir, filename)  # 修改路径到report文件夹
        plt.savefig(file_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✅ 优化版颁发机构拓扑图已保存为 '{file_path}'")

        # 生成简化的机构关系图（网络图风格）
        generate_network_style_graph(all_issuers, all_certs, timestamp, report_dir)

        return file_path

    except Exception as e:
        print(f"❌ 生成颁发机构拓扑图时出错: {e}")
        import traceback
        traceback.print_exc()
        return None


def generate_network_style_graph(all_issuers, all_certs, timestamp, report_dir="."):
    """
    生成网络风格的机构关系图
    """
    try:
        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False

        # 创建图形
        fig, ax = plt.subplots(figsize=(16, 12))
        ax.set_xlim(0, 12)
        ax.set_ylim(0, 10)
        ax.axis('off')

        # 根据颁发数量排序
        sorted_issuers = sorted(all_issuers.items(), key=lambda x: x[1]['count'], reverse=True)

        # 只取前10个颁发机构
        top_issuers = sorted_issuers[:10]

        # 颜色设置
        colors = plt.cm.tab20c(np.linspace(0, 1, len(top_issuers)))

        # 计算节点位置（力导向布局的简化版）
        num_nodes = len(top_issuers)
        positions = {}

        # 使用圆形布局，但根据节点大小调整位置
        center_x, center_y = 6, 5
        base_radius = 3.0

        for i, (issuer_name, issuer_data) in enumerate(top_issuers):
            angle = 2 * np.pi * i / num_nodes

            # 根据证书数量调整半径（数量多的更靠外）
            max_count = max([data['count'] for _, data in top_issuers])
            radius_factor = 0.5 + (issuer_data['count'] / max_count) * 0.5
            radius = base_radius * radius_factor

            x = center_x + radius * np.cos(angle - np.pi / 2)
            y = center_y + radius * np.sin(angle - np.pi / 2)

            positions[issuer_name] = (x, y)

        # 绘制连接线（机构之间的关联）
        # 这里我们可以根据共享国家或共同颁发域名来创建连接
        # 简化：随机连接部分节点，展示网络效果
        import random
        connections = []
        for i in range(min(15, len(top_issuers) * 2)):
            if len(top_issuers) >= 2:
                idx1, idx2 = random.sample(range(len(top_issuers)), 2)
                name1, data1 = top_issuers[idx1]
                name2, data2 = top_issuers[idx2]

                # 计算连接强度（基于证书数量）
                strength = min(data1['count'], data2['count']) / max_count
                if strength > 0.1:  # 只有强度足够才绘制
                    x1, y1 = positions[name1]
                    x2, y2 = positions[name2]

                    # 绘制连接线
                    line = plt.Line2D([x1, x2], [y1, y2],
                                      color='gray', alpha=0.3 * strength,
                                      linewidth=1 + strength * 2, zorder=1)
                    ax.add_line(line)
                    connections.append((name1, name2, strength))

        # 绘制节点
        for i, (issuer_name, issuer_data) in enumerate(top_issuers):
            x, y = positions[issuer_name]

            # 计算节点大小（基于颁发证书数量）
            max_count = max([data['count'] for _, data in top_issuers])
            node_size = 500 + (issuer_data['count'] / max_count) * 2500

            # 绘制节点
            circle = plt.Circle((x, y), node_size / 1000,
                                color=colors[i], alpha=0.85,
                                edgecolor='black', linewidth=2, zorder=2)
            ax.add_patch(circle)

            # 准备显示文本
            # 截断机构名称
            if len(issuer_name) > 15:
                display_name = issuer_name[:12] + "..."
            else:
                display_name = issuer_name

            # 国家信息
            country_text = ""
            if issuer_data['countries']:
                countries_list = list(issuer_data['countries'])
                if countries_list:
                    country_text = f"\n{countries_list[0]}"

            # 节点内部文本
            inner_text = f"{display_name}\n{issuer_data['count']}个"
            ax.text(x, y, inner_text,
                    ha='center', va='center', fontsize=9, fontweight='bold',
                    color='white', zorder=3)

            # 节点外部标签（国家）
            if country_text:
                # 计算标签位置（节点外侧）
                angle = np.arctan2(y - center_y, x - center_x)
                label_x = x + (node_size / 1000 + 0.2) * np.cos(angle)
                label_y = y + (node_size / 1000 + 0.2) * np.sin(angle)

                ax.text(label_x, label_y, country_text,
                        ha='center', va='center', fontsize=8,
                        bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8),
                        zorder=4)

        # 添加标题
        ax.set_title('🌐 证书颁发机构网络关系图', fontsize=18, fontweight='bold', pad=20)

        # 添加图例
        legend_elements = []
        for i, (issuer_name, issuer_data) in enumerate(top_issuers[:5]):  # 只显示前5个
            legend_elements.append(plt.Line2D([0], [0], marker='o', color='w',
                                              markerfacecolor=colors[i], markersize=10,
                                              label=f"{issuer_name} ({issuer_data['count']}证书)"))

        ax.legend(handles=legend_elements, loc='upper right',
                  bbox_to_anchor=(1.05, 1), fontsize=9)

        # 添加统计信息
        stats_text = f"网络统计:\n"
        stats_text += f"• 节点数: {len(top_issuers)}\n"
        stats_text += f"• 连接数: {len(connections)}\n"
        stats_text += f"• 平均连接强度: {sum(c[2] for c in connections) / len(connections):.2f if connections else 0}\n"

        ax.text(0.02, 0.02, stats_text, transform=ax.transAxes,
                fontsize=10, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.9))

        plt.tight_layout()
        filename = f'issuer_network_{timestamp}.png'
        file_path = os.path.join(report_dir, filename)  # 修改路径到report文件夹
        plt.savefig(file_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✅ 网络风格机构关系图已保存为 '{file_path}'")

    except Exception as e:
        print(f"❌ 生成网络风格图时出错: {e}")


def generate_simple_issuer_graph(all_issuers, all_certs, timestamp, report_dir="."):
    """
    生成简化的颁发机构关系图 - 改进版
    """
    try:
        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False

        fig, ax = plt.subplots(figsize=(14, 10))
        ax.set_xlim(0, 12)
        ax.set_ylim(0, 10)
        ax.axis('off')

        # 根据颁发数量排序
        sorted_issuers = sorted(all_issuers.items(), key=lambda x: x[1]['count'], reverse=True)

        # 只取前8个颁发机构（避免过于拥挤）
        top_issuers = sorted_issuers[:8]

        # 颜色设置
        colors = plt.cm.tab20c(np.linspace(0, 1, len(top_issuers)))

        # 布局：中心节点和外围节点
        center_x, center_y = 6, 5

        # 绘制中心节点（所有证书）
        ax.add_patch(plt.Circle((center_x, center_y), 0.5,
                                color='#FF6B6B', alpha=0.8,
                                edgecolor='black', linewidth=2))
        ax.text(center_x, center_y, f'所有证书\n({len(all_certs)}个)',
                ha='center', va='center', fontsize=10, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.9))

        # 绘制颁发机构节点并连接
        for i, (issuer_name, issuer_data) in enumerate(top_issuers):
            # 计算角度和位置
            angle = 2 * np.pi * i / len(top_issuers)
            radius = 4
            x = center_x + radius * np.cos(angle)
            y = center_y + radius * np.sin(angle)

            # 计算节点大小（基于颁发证书数量）
            max_count = max([data['count'] for _, data in top_issuers])
            node_size = 0.3 + (issuer_data['count'] / max_count) * 0.7

            # 绘制节点
            ax.add_patch(plt.Circle((x, y), node_size,
                                    color=colors[i], alpha=0.8,
                                    edgecolor='black', linewidth=2))

            # 智能截断机构名称
            if len(issuer_name) > 15:
                # 尝试找到常见的分隔符来截断
                parts = re.split(r'[,\.\s\-]+', issuer_name)
                if len(parts) >= 2:
                    # 使用缩写形式，如 DigiCert, Inc. -> DigiCert
                    short_name = parts[0]
                else:
                    # 直接截断
                    short_name = issuer_name[:12] + "..."
            else:
                short_name = issuer_name

            # 添加机构名称和国家信息
            country_text = ""
            if issuer_data['countries']:
                countries_list = list(issuer_data['countries'])
                if countries_list:
                    # 只显示第一个国家（如果有多个）
                    country = countries_list[0]
                    # 如果国家名太长，也进行截断
                    if len(country) > 8:
                        country = country[:6] + "..."
                    country_text = f"\n{country}"

            # 使用更小的字体和换行显示
            display_text = f"{short_name}\n{issuer_data['count']}个{country_text}"

            # 根据位置调整文本对齐方式
            if x > center_x:  # 右侧
                ha = 'left'
                x_text = x + node_size + 0.1
            else:  # 左侧
                ha = 'right'
                x_text = x - node_size - 0.1

            if y > center_y:  # 上部
                va = 'bottom'
                y_text = y + node_size + 0.1
            else:  # 下部
                va = 'top'
                y_text = y - node_size - 0.1

            ax.text(x_text, y_text, display_text,
                    ha=ha, va=va, fontsize=8, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8))

            # 绘制连接线
            ax.plot([center_x, x], [center_y, y],
                    color=colors[i], alpha=0.5, linewidth=1.5)

            # 添加箭头
            ax.annotate('', xy=(x, y), xytext=(center_x, center_y),
                        arrowprops=dict(arrowstyle='->', color=colors[i],
                                        lw=1.5, alpha=0.6))

        # 添加标题
        ax.set_title('🔗 证书颁发机构关系图（含国家信息）', fontsize=16, fontweight='bold', pad=20)

        # 添加详细统计信息
        stats_text = f"📊 详细统计信息:\n"
        stats_text += f"• 分析证书总数: {len(all_certs)}\n"
        stats_text += f"• 不同颁发机构数: {len(all_issuers)}\n"
        stats_text += f"• 前{len(top_issuers)}大颁发机构:\n"

        for i, (issuer_name, issuer_data) in enumerate(sorted_issuers[:8]):
            countries_str = "未知"
            if issuer_data['countries']:
                countries_str = ', '.join(list(issuer_data['countries'])[:3])
                if len(issuer_data['countries']) > 3:
                    countries_str += "..."

            stats_text += f"  {i + 1}. {issuer_name[:25]}{'...' if len(issuer_name) > 25 else ''}:\n"
            stats_text += f"     证书数: {issuer_data['count']}个\n"
            stats_text += f"     国家: {countries_str}\n"

        ax.text(1, 9, stats_text, fontsize=8, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.9))

        # 添加图例说明
        legend_text = "图例说明:\n"
        legend_text += "• 🔴 红色中心节点: 所有被分析的证书\n"
        legend_text += "• 🟣 彩色外围节点: 各颁发机构\n"
        legend_text += "• 📏 节点大小: 颁发证书数量\n"
        legend_text += "• 🔗 连接线: 颁发关系\n"
        legend_text += "• 🌍 节点信息: 机构名称/证书数/国家"

        ax.text(10, 9, legend_text, fontsize=8,
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.9))

        # 添加机构总数和国家总数信息
        total_countries = set()
        for issuer_data in all_issuers.values():
            total_countries.update(issuer_data['countries'])

        summary_text = f"🌐 机构汇总:\n"
        summary_text += f"• 总共 {len(all_issuers)} 个颁发机构\n"
        summary_text += f"• 来自 {len(total_countries)} 个国家\n"
        summary_text += f"• 平均每个机构颁发 {len(all_certs) / len(all_issuers):.1f} 个证书"

        ax.text(1, 1, summary_text, fontsize=8, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgreen", alpha=0.9))

        plt.tight_layout()
        filename = f'issuer_relation_{timestamp}.png'
        file_path = os.path.join(report_dir, filename)  # 修改路径到report文件夹
        plt.savefig(file_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"✅ 改进版机构关系图已保存为 '{file_path}'")

        # 同时生成一个纯文本的机构国家列表
        generate_issuer_country_list(all_issuers, timestamp, report_dir)

    except Exception as e:
        print(f"❌ 生成简化机构关系图时出错: {e}")
        import traceback
        traceback.print_exc()


def generate_issuer_country_list(all_issuers, timestamp, report_dir="."):
    """
    生成机构-国家列表文件
    """
    try:
        filename = f'issuer_country_list_{timestamp}.txt'
        file_path = os.path.join(report_dir, filename)  # 修改路径到report文件夹

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("              证书颁发机构及所属国家列表\n")
            f.write("=" * 80 + "\n\n")

            # 按证书数量排序
            sorted_issuers = sorted(all_issuers.items(), key=lambda x: x[1]['count'], reverse=True)

            f.write(f"总计: {len(sorted_issuers)} 个颁发机构\n\n")

            f.write("排名 | 机构名称 | 证书数量 | 国家\n")
            f.write("-" * 80 + "\n")

            for i, (issuer_name, issuer_data) in enumerate(sorted_issuers, 1):
                countries = list(issuer_data['countries'])
                if countries:
                    countries_str = ', '.join(countries)
                else:
                    countries_str = '未知'

                f.write(f"{i:3d}. {issuer_name[:50]:<50} {issuer_data['count']:>4d}    {countries_str}\n")

            # 统计国家分布
            country_stats = {}
            for issuer_data in all_issuers.values():
                for country in issuer_data['countries']:
                    if country in country_stats:
                        country_stats[country] += 1
                    else:
                        country_stats[country] = 1

            if country_stats:
                f.write("\n" + "=" * 80 + "\n")
                f.write("              国家分布统计\n")
                f.write("=" * 80 + "\n\n")

                sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)

                for country, count in sorted_countries:
                    f.write(f"• {country}: {count} 个机构\n")

        print(f"✅ 机构国家列表已保存为 '{file_path}'")

    except Exception as e:
        print(f"❌ 生成机构国家列表时出错: {e}")

def query_and_generate_fast(hostname):
    """
    优化的查询和生成图片功能
    """
    # 移除可能的协议前缀和路径
    clean_hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]

    print(f"⚡ 正在快速处理 {clean_hostname} ...")
    print("=" * 60)

    # 执行快速查询功能
    get_certificate_chain_fast(clean_hostname)
    display_certificate_hierarchy(clean_hostname)

    print("\n" + "=" * 60)
    print("✅ 快速查询完成！")

    # 如果查询成功且有数据，自动生成图片
    if certificate_chain_data:
        print("\n🖼️  正在生成证书链图片...")
        create_certificate_chain_diagram(clean_hostname)
        print("✅ 图片生成完成！")

        # 保存分析结果
        save_analysis_result(clean_hostname, certificate_chain_data)
    else:
        print("❌ 无法生成图片：没有获取到证书链数据")
        # 保存失败的分析结果
        save_analysis_result(clean_hostname, None)


def is_valid_domain(domain):
    """
    验证域名格式是否有效
    """
    if not domain or len(domain) > 253:
        return False

    # 简单的域名格式验证
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(domain_pattern, domain) is not None


def extract_domains_from_file_content(content):
    """
    从文件内容中提取域名
    支持多种格式：
    1. 每行一个域名
    2. 带编号的域名 (如: "1. example.com")
    3. 包含注释的文件
    """
    domains = []
    lines = content.split('\n')

    for line in lines:
        line = line.strip()

        # 跳过空行和注释行
        if not line or line.startswith('#') or line.startswith('//'):
            continue

        # 处理带编号的域名 (如: "1. example.com")
        if re.match(r'^\d+\.', line):
            # 提取编号后面的内容
            domain_part = re.sub(r'^\d+\.\s*', '', line)
        else:
            domain_part = line

        # 清理域名：移除协议前缀和路径
        clean_domain = domain_part.replace('https://', '').replace('http://', '').split('/')[0].strip()

        # 验证域名格式
        if is_valid_domain(clean_domain):
            domains.append(clean_domain)
        else:
            print(f"⚠️  跳过无效域名: {clean_domain}")

    return domains


def process_cert_zip_file_fast(filename):
    """
    快速处理类似cert_zip格式的文件
    """
    try:
        print(f"📁 正在快速读取cert_zip格式文件: {filename}")

        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()

        # 解析文件内容，提取域名
        domains = extract_domains_from_file_content(content)

        if not domains:
            print("❌ 文件中未找到有效的域名")
            return

        print(f"📋 从文件中找到 {len(domains)} 个域名")

        # 询问用户要处理多少个域名
        print(f"\n📊 文件中共有 {len(domains)} 个域名")
        print("💡 提示：处理大量域名可能需要较长时间")

        while True:
            try:
                choice = input(
                    "请选择处理方式:\n1. 处理前N个域名\n2. 处理所有域名\n3. 取消\n请输入选择 (1-3): ").strip()

                if choice == '1':
                    try:
                        n = int(input(f"请输入要处理的域名数量 (1-{len(domains)}): "))
                        if 1 <= n <= len(domains):
                            selected_domains = domains[:n]
                            break
                        else:
                            print(f"❌ 请输入 1-{len(domains)} 之间的数字")
                    except ValueError:
                        print("❌ 请输入有效的数字")
                elif choice == '2':
                    selected_domains = domains
                    break
                elif choice == '3':
                    print("取消文件处理")
                    return
                else:
                    print("❌ 无效选择，请重新输入")

            except KeyboardInterrupt:
                print("\n取消文件处理")
                return

        print(f"\n🔄 开始快速处理 {len(selected_domains)} 个域名...")

        # 处理选中的域名
        for i, domain in enumerate(selected_domains, 1):
            print(f"\n{'=' * 80}")
            print(f"🌐 正在处理第 {i}/{len(selected_domains)} 个域名: {domain}")
            print(f"{'=' * 80}")

            # 快速查询并生成图片
            query_and_generate_fast(domain)

            # 添加短暂延迟，避免请求过于频繁
            if i < len(selected_domains):
                print("⏳ 等待1秒后继续下一个域名...")  # 减少等待时间
                import time
                time.sleep(1)

        print(f"\n🎉 所有 {len(selected_domains)} 个域名处理完成！")

        # 生成分析报告
        print("\n📊 正在生成分析报告...")
        report_file = generate_analysis_report()
        if report_file:
            print(f"📄 分析报告已保存: {report_file}")

    except FileNotFoundError:
        print(f"❌ 文件未找到: {filename}")
    except Exception as e:
        print(f"❌ 处理文件时出错: {e}")


def main():
    """
    主程序 - 提供多种功能选择
    """
    print("🔐 证书链查询与可视化工具")
    print("=" * 50)

    while True:
        print("\n请选择功能:")
        print("1. 单域名分析")
        print("2. 文件内域名分析")
        print("3. 生成颁发机构汇总拓扑图（需要先查询）")
        print("4. 退出程序")

        choice = input("请输入选择 (1-4): ").strip()

        if choice == '4' or choice.lower() in ['quit', 'exit', 'q']:
            print("👋 再见！")
            break

        if choice == '1':
            # 快速查询单个证书链信息并生成图片
            hostname = input("🌐 请输入要查询的域名: ").strip()
            if not hostname:
                print("❌ 请输入有效的域名")
                continue

            query_and_generate_fast(hostname)

            # 为单个域名也生成分析报告
            if analysis_results:
                print("\n📊 正在生成分析报告...")
                report_file = generate_analysis_report()
                if report_file:
                    print(f"📄 分析报告已保存: {report_file}")

        elif choice == '2':
            # 快速处理cert_zip格式文件
            filename = input("📁 请输入文件路径: ").strip()
            if not filename:
                print("❌ 请输入有效的文件路径")
                continue

            if not os.path.exists(filename):
                print("❌ 文件不存在，请检查路径")
                continue

            process_cert_zip_file_fast(filename)

        elif choice == '3':
            # 生成颁发机构汇总拓扑图
            if not analysis_results:
                print("❌ 没有分析数据，请先查询证书链")
                continue

            print("\n🕸️  正在生成颁发机构汇总拓扑图...")
            topology_file = generate_issuer_topology_graph()
            if topology_file:
                print(f"📊 颁发机构拓扑图已保存: {topology_file}")

        else:
            print("❌ 无效选择，请重新输入")


if __name__ == "__main__":
    # 检查是否安装了必要的库
    try:
        import cryptography
    except ImportError:
        print("❌ 缺少必要的库，请安装: pip install cryptography")
        sys.exit(1)

    try:
        import matplotlib
    except ImportError:
        print("❌ 缺少必要的库，请安装: pip install matplotlib")
        sys.exit(1)

    main()