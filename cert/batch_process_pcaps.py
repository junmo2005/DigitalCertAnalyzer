#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量处理数字证书文件并统计分析 - 集成数据库版本
"""

import os
import sys
import json
import shutil
import hashlib
from datetime import datetime, timezone
from cryptography import x509
from typing import Optional, List, Union
from certificate_validity_analyzer import CertificateValidityAnalyzer
from certificate_filter import TLSCertificateFilter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import tempfile

# 导入新数据库模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db_session import get_db, get_current_task_id

def generate_issuer_key(issuer_name: str, serial_number: str) -> str:
    """生成颁发者唯一键（为兼容旧逻辑保留）"""
    combined = f"{issuer_name}_{serial_number}"
    return hashlib.md5(combined.encode('utf-8')).hexdigest()[:32]

# ==================== 资产化存储辅助函数 ====================
def _build_asset_info(cert, san_list_json, key_usage_str, ext_key_usage_str):
    """从 x509 证书对象提取资产信息"""
    subject_cn = None
    issuer_cn = None
    issuer_o = None
    issuer_c = None

    for attr in cert.subject:
        if attr.oid._name == 'commonName':
            subject_cn = attr.value
            break
    for attr in cert.issuer:
        if attr.oid._name == 'commonName':
            issuer_cn = attr.value
        elif attr.oid._name == 'organizationName':
            issuer_o = attr.value
        elif attr.oid._name == 'countryName':
            issuer_c = attr.value

    key_algorithm = type(cert.public_key()).__name__.replace("PublicKey", "")
    key_size = getattr(cert.public_key(), 'key_size', None)
    sig_algo = cert.signature_algorithm_oid._name

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_o": issuer_o,
        "issuer_c": issuer_c,
        "not_before": cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else None,
        "not_after": cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else None,
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "san_list": san_list_json,
        "san_count": len(json.loads(san_list_json)) if san_list_json else 0,
        "key_usage": key_usage_str,
        "extended_key_usage": ext_key_usage_str,
        "is_self_signed": (cert.issuer == cert.subject),
        "is_ca": False  # 可后续从 BasicConstraints 覆盖
    }

def _extract_san_and_key_usage(cert):
    """提取 SAN 和 Key Usage 信息"""
    import json
    from cryptography import x509
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = [name.value for name in san_ext.value]
    except (x509.ExtensionNotFound, Exception):
        pass
    san_json = json.dumps(san_list, ensure_ascii=False) if san_list else "[]"

    key_usage = ""
    try:
        ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        key_usage = str(ku_ext.value)
    except (x509.ExtensionNotFound, Exception):
        pass

    ext_key_usage = ""
    try:
        eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
        ext_key_usage = str(eku_ext.value)
    except (x509.ExtensionNotFound, Exception):
        pass

    # 检查 basic constraints 是否为 CA
    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bc_ext.value.ca
    except (x509.ExtensionNotFound, Exception):
        pass

    return san_json, key_usage, ext_key_usage, is_ca


def _save_cert_to_asset_and_analysis(cert, db, task_id, domain=None):
    from cryptography.hazmat.primitives import serialization

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = db.compute_fingerprint_sha256(cert_der)

    san_json, ku_str, eku_str, is_ca = _extract_san_and_key_usage(cert)

    asset_info = _build_asset_info(cert, san_json, ku_str, eku_str)
    asset_info["is_ca"] = is_ca
    asset_id = db.get_or_create_certificate_asset(fingerprint, asset_info)

    # 修复点：使用 aware datetime
    now_utc = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    days_valid = (not_after - not_before).days if not_before and not_after else None
    days_remaining = (not_after - now_utc).days if not_after else None
    validity_status = "valid" if days_remaining and days_remaining > 0 else "expired"

    analysis_data = {
        "domain": domain,
        "serial_number": str(cert.serial_number),
        "issuer_key": asset_info["issuer_cn"] or "",
        "subject_cn": asset_info["subject_cn"],
        "issuer_cn": asset_info["issuer_cn"],
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_valid": days_valid,
        "days_remaining": days_remaining,
        "validity_status": validity_status,
        "key_algorithm": asset_info["key_algorithm"],
        "key_size": asset_info["key_size"],
        "signature_algorithm": asset_info["signature_algorithm"],
        "san_list": san_json,
        "san_count": asset_info["san_count"],
        "key_usage": ku_str,
        "extended_key_usage": eku_str,
        "chain_index": 0,
        "chain_length": 1,
        "is_self_signed": asset_info["is_self_signed"],
        "is_valid": validity_status == "valid",
        "source_file": None,
        "source_index": 0
    }

    db.save_certificate_analysis(task_id, asset_id, fingerprint, analysis_data)

def extract_certificates_from_pcap(pcap_path: str, output_dir: str = "temp_pcap_certs"):
    """使用 certificate_filter.py 提取证书"""
    
    print(f"\n=== 开始处理PCAP文件 ===")
    print(f"文件路径: {pcap_path}")
    print(f"文件大小: {os.path.getsize(pcap_path)/1024/1024:.2f} MB")
   
    try:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        print("使用 TLSCertificateFilter 分析PCAP文件...")
        filter_analyzer = TLSCertificateFilter()
        filter_analyzer.set_debug(False)

        certificates = filter_analyzer.parse_pcap_and_extract_certificates(pcap_path)
        
        stats = filter_analyzer.get_statistics()
        
        print(f"PCAP分析统计:")
        print(f"  总数据包数: {stats.get('total_packets', 0)}")
        print(f"  TLS握手包数: {stats.get('tls_packets', 0)}")
        print(f"  证书消息数: {stats.get('certificate_messages', 0)}")
        print(f"  证书实例总数: {stats.get('total_certificates', 0)}")
        print(f"  唯一证书总数: {stats.get('unique_certificates', 0)}")
        print(f"  处理的会话数: {stats.get('sessions_processed', 0)}")

        cert_counts = filter_analyzer.get_certificate_counts()
        if cert_counts:
            duplicate_certs = sum(1 for count in cert_counts.values() if count > 1)
            duplicate_rate = duplicate_certs / len(cert_counts) * 100 if cert_counts else 0
            print(f"  重复出现的证书数: {duplicate_certs}")
            print(f"  证书重复率: {duplicate_rate:.1f}%")

        if certificates:
            filter_analyzer.save_certificates_to_files(output_dir)
            print(f"证书已保存到: {output_dir}")
            
            # ========== 新增：保存证书到数据库 ==========
            _save_pcap_certs_to_db(certificates)
        else:
            raise ValueError("未从PCAP文件中提取到任何证书")

        return output_dir

    except Exception as e:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)
        raise ValueError(f"PCAP处理失败: {str(e)}")

def _save_pcap_certs_to_db(certificates):
    """将 PCAP 提取的证书数据写入资产库"""
    db = get_db()
    task_id = get_current_task_id()
    if not task_id:
        print("⚠️ 无当前任务ID，跳过保存")
        return

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    saved = 0
    for cert_msg in certificates:
        for cert_info in cert_msg.get('certificates', []):
            try:
                cert_der = cert_info['data']
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                _save_cert_to_asset_and_analysis(cert, db, task_id)
                saved += 1
            except Exception as e:
                print(f"⚠️ 入库单证失败: {e}")
    print(f"✅ PCAP 证书已入库 {saved} 个")

def analyze_pcap_with_detailed_stats(pcap_path: str):
    """PCAP分析并返回详细统计（用于原始API兼容），且入库"""
    print("开始详细PCAP分析...")
    # 1. 使用 filter 解析
    filter_analyzer = TLSCertificateFilter()
    certificates = filter_analyzer.parse_pcap_and_extract_certificates(pcap_path)
    stats = filter_analyzer.get_statistics()
    cert_counts = filter_analyzer.get_certificate_counts()
    duplicate_certs = sum(1 for count in cert_counts.values() if count > 1) if cert_counts else 0
    duplicate_rate = duplicate_certs / len(cert_counts) * 100 if cert_counts else 0

    # 2. 提取唯一证书并保存到临时目录用于有效期分析
    unique_certs_data = {}
    if certificates:
        for cert_msg in certificates:
            for cert in cert_msg.get('certificates', []):
                h = cert.get('hash')
                if h and h not in unique_certs_data:
                    unique_certs_data[h] = cert['data']

    validity_analysis = {}
    if unique_certs_data:
        temp_dir = tempfile.mkdtemp()
        try:
            for i, cert_der in enumerate(unique_certs_data.values()):
                cert_path = os.path.join(temp_dir, f"cert_{i}.der")
                with open(cert_path, 'wb') as f:
                    f.write(cert_der)
            analyzer = CertificateValidityAnalyzer(expiry_warning_days=30)
            validity_analysis = analyzer.analyze_certificates_directory(temp_dir)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 3. 入库
    _save_pcap_certs_to_db(certificates)

    combined = {
        "pcap_statistics": {
            "total_packets": stats.get('total_packets', 0),
            "tls_handshake_packets": stats.get('tls_packets', 0),
            "certificate_messages": stats.get('certificate_messages', 0),
            "total_certificates": stats.get('total_certificates', 0),
            "unique_certificates": stats.get('unique_certificates', 0),
            "sessions_processed": stats.get('sessions_processed', 0),
            "duplicate_certificates": duplicate_certs,
            "duplicate_rate": round(duplicate_rate, 1)
        },
        "certificate_validity": validity_analysis,
        "summary": {
            "total_certificates": stats.get('total_certificates', 0),
            "unique_certificates": stats.get('unique_certificates', 0),
            "duplicate_rate": round(duplicate_rate, 1),
            "valid_certificates": validity_analysis.get('valid_certificates', 0),
            "expired_certificates": validity_analysis.get('expired_certificates', 0),
            "expiring_soon_certificates": validity_analysis.get('expiring_soon_certificates', 0)
        }
    }
    return combined

# ==================== 批量证书目录处理 ====================
def batch_process_certificates(cert_dir: str, expiry_days: int, output_dir: str = "cert_analysis"):
    """批量处理证书目录：有效分析 + 资产入库"""
    cert_dir = os.path.abspath(cert_dir)
    output_dir = os.path.abspath(output_dir)
    print(f"开始处理证书目录: {cert_dir}")

    if not os.path.exists(cert_dir):
        raise FileNotFoundError(f"证书目录不存在: {cert_dir}")

    os.makedirs(output_dir, exist_ok=True)
    cert_extensions = ('.cer', '.crt', '.pem', '.der')
    cert_files = [f for f in os.listdir(cert_dir) if f.lower().endswith(cert_extensions)]
    if not cert_files:
        raise ValueError("目录中没有找到证书文件")

    print(f"找到 {len(cert_files)} 个证书文件")

    # 有效分析准备
    temp_dir = os.path.join(output_dir, "temp_certs")
    os.makedirs(temp_dir, exist_ok=True)
    try:
        for cert_file in cert_files:
            shutil.copy2(os.path.join(cert_dir, cert_file), os.path.join(temp_dir, cert_file))

        analyzer = CertificateValidityAnalyzer(expiry_warning_days=expiry_days)
        results = analyzer.analyze_certificates_directory(temp_dir)

        # 入库每个证书（使用资产化写入）
        _save_cert_directory_to_db(temp_dir)

        # 保存报告
        report_file = os.path.join(output_dir, f"certificate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"批量分析完成：{results.get('total_certificates', 0)} 个唯一证书")
        return results
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def _save_cert_directory_to_db(cert_dir: str):
    """遍历目录下的证书文件，写入资产库"""
    db = get_db()
    task_id = get_current_task_id()
    if not task_id:
        print("⚠️ 无任务ID，跳过目录入库")
        return

    cert_extensions = ('.cer', '.crt', '.pem', '.der')
    saved = 0
    for filename in os.listdir(cert_dir):
        if not filename.lower().endswith(cert_extensions):
            continue
        filepath = os.path.join(cert_dir, filename)
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            # 尝试 DER 或 PEM
            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
            except:
                try:
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                except:
                    continue
            _save_cert_to_asset_and_analysis(cert, db, task_id)
            saved += 1
        except Exception as e:
            print(f"⚠️ 无法解析 {filename}: {e}")
    print(f"✅ 目录证书入库 {saved} 个")

# ==================== 简化调用：处理压缩包 ====================
def process_certificate_archive(archive_path: str, upload_folder: str):
    """解压并分析压缩包中的证书（用于路由调用）"""
    from utils.file_utils import extract_archive, find_certificate_files
    extract_dir = os.path.join(upload_folder, f"archive_extract_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    os.makedirs(extract_dir, exist_ok=True)
    try:
        extract_archive(archive_path, extract_dir)
        cert_files = find_certificate_files(extract_dir)
        if not cert_files:
            raise ValueError("压缩包中未找到支持的证书文件")
        # 复制到统一目录
        temp_cert_dir = os.path.join(upload_folder, f"certs_temp_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        os.makedirs(temp_cert_dir, exist_ok=True)
        for cf in cert_files:
            shutil.copy2(cf, os.path.join(temp_cert_dir, os.path.basename(cf)))
        # 直接调用批量处理（有效期分析+入库）
        result = batch_process_certificates(temp_cert_dir, expiry_days=30)
        return result, cert_files
    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        if 'temp_cert_dir' in locals() and os.path.exists(temp_cert_dir):
            shutil.rmtree(temp_cert_dir, ignore_errors=True)

# ==================== 命令行入口（保持不变） ====================
def main():
    if len(sys.argv) < 2:
        print("用法: python batch_process_pcaps.py <证书目录> [过期天数]  或  --pcap <pcap文件>")
        sys.exit(1)

    if sys.argv[1] == "--pcap":
        if len(sys.argv) < 3:
            print("错误: 请指定PCAP文件路径")
            sys.exit(1)
        pcap_path = sys.argv[2]
        # 命令行使用无 task_id，不入库，仅测试
        print("命令行PCAP分析模式（不入库）")
        results = analyze_pcap_with_detailed_stats(pcap_path)
        if results:
            print(json.dumps(results["summary"], indent=2))
        else:
            print("分析失败")
    else:
        cert_dir = sys.argv[1]
        expiry_days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        # 命令行模式不入库，仅测试
        print("命令行证书目录分析模式（不入库）")
        results = batch_process_certificates(cert_dir, expiry_days)
        if results:
            print(json.dumps({k: v for k, v in results.items() if k != 'cert_details'}, indent=2))

if __name__ == "__main__":
    main()