import os
import json
from datetime import datetime
from werkzeug.utils import secure_filename

def save_report_to_file(report_content, source_type, original_filename, reports_folder):
    """保存报告到文件"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = secure_filename(original_filename or 'unknown') if original_filename else 'unknown'
    report_filename = f"cert_report_{source_type}_{safe_filename}_{timestamp}.txt"
    report_path = os.path.join(reports_folder, report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return report_path, report_filename

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