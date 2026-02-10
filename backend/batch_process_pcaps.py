#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量处理数字证书文件并统计分析 - 修复版本
使用 certificate_filter.py 进行PCAP分析
"""

import os
import sys
import json
import shutil
from datetime import datetime
from certificate_validity_analyzer import CertificateValidityAnalyzer
from certificate_filter import TLSCertificateFilter  # 使用正确的导入
import tempfile

def extract_certificates_from_pcap(pcap_path: str, output_dir: str = "temp_pcap_certs"):
    """使用 certificate_filter.py 提取证书 - 修复版本"""
    
    print(f"\n=== 开始处理PCAP文件 ===")
    print(f"文件路径: {pcap_path}")
    print(f"文件大小: {os.path.getsize(pcap_path)/1024/1024:.2f} MB")
   
    try:
        # 确保输出目录存在且为空
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        # 使用 TLSCertificateFilter 分析PCAP文件
        print("使用 TLSCertificateFilter 分析PCAP文件...")
        filter_analyzer = TLSCertificateFilter()
        filter_analyzer.set_debug(False)  # 关闭调试信息

        # 解析PCAP文件并提取证书
        certificates = filter_analyzer.parse_pcap_and_extract_certificates(pcap_path)
        
        # 获取详细统计信息
        stats = filter_analyzer.get_statistics()
        
        print(f"PCAP分析统计:")
        print(f"  总数据包数: {stats.get('total_packets', 0)}")
        print(f"  TLS握手包数: {stats.get('tls_packets', 0)}")
        print(f"  证书消息数: {stats.get('certificate_messages', 0)}")
        print(f"  证书实例总数: {stats.get('total_certificates', 0)}")
        print(f"  唯一证书总数: {stats.get('unique_certificates', 0)}")
        print(f"  处理的会话数: {stats.get('sessions_processed', 0)}")

        # 获取证书出现次数统计
        cert_counts = filter_analyzer.get_certificate_counts()
        if cert_counts:
            duplicate_certs = sum(1 for count in cert_counts.values() if count > 1)
            duplicate_rate = duplicate_certs / len(cert_counts) * 100 if cert_counts else 0
            print(f"  重复出现的证书数: {duplicate_certs}")
            print(f"  证书重复率: {duplicate_rate:.1f}%")

        # 保存证书到文件
        if certificates:
            filter_analyzer.save_certificates_to_files(output_dir)
            print(f"证书已保存到: {output_dir}")
        else:
            raise ValueError("未从PCAP文件中提取到任何证书")

        return output_dir

    except Exception as e:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)
        raise ValueError(f"PCAP处理失败: {str(e)}")

def analyze_pcap_with_detailed_stats(pcap_path: str):
    """
    专门用于PCAP分析的函数，返回详细统计信息
    """
    try:
        # 使用 TLSCertificateFilter 进行详细分析
        filter_analyzer = TLSCertificateFilter()
        certificates = filter_analyzer.parse_pcap_and_extract_certificates(pcap_path)
        stats = filter_analyzer.get_statistics()
        
        # 获取证书出现次数统计
        cert_counts = filter_analyzer.get_certificate_counts()
        duplicate_certs = sum(1 for count in cert_counts.values() if count > 1) if cert_counts else 0
        duplicate_rate = duplicate_certs / len(cert_counts) * 100 if cert_counts else 0
        
        # 提取证书用于后续有效性分析
        unique_certs = []
        if certificates:
            # 收集所有唯一证书数据
            cert_data_map = {}
            for cert_msg in certificates:
                for cert in cert_msg.get('certificates', []):
                    cert_hash = cert.get('hash')
                    if cert_hash and cert_hash not in cert_data_map:
                        cert_data_map[cert_hash] = cert.get('data')
            
            unique_certs = list(cert_data_map.values())
        
        # 如果有证书，进行有效性分析
        validity_analysis = {}
        if unique_certs:
            # 创建临时目录保存证书
            temp_dir = tempfile.mkdtemp()
            try:
                # 保存证书
                for i, cert_data in enumerate(unique_certs):
                    if cert_data:
                        cert_path = os.path.join(temp_dir, f"cert_{i}.der")
                        with open(cert_path, 'wb') as f:
                            f.write(cert_data)
                
                # 分析证书有效性
                analyzer = CertificateValidityAnalyzer(expiry_warning_days=30)
                validity_analysis = analyzer.analyze_certificates_directory(temp_dir)
                
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        # 合并统计信息
        combined_results = {
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
        
        return combined_results
        
    except Exception as e:
        print(f"PCAP详细分析失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def batch_process_certificates(cert_dir: str, expiry_days: int, output_dir: str = "cert_analysis"):
    """
    批量处理证书目录中的所有证书文件
    """
    cert_dir = os.path.abspath(cert_dir)
    output_dir = os.path.abspath(output_dir)
    print(f"开始处理证书目录: {cert_dir}")
    print(f"分析结果输出目录: {output_dir}")

    # 检查证书目录
    if not os.path.exists(cert_dir):
        print(f"错误: 证书目录不存在: {cert_dir}")
        return None

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    # 查找所有证书文件
    cert_extensions = ('.cer', '.crt', '.pem', '.der')
    cert_files = [f for f in os.listdir(cert_dir) 
                 if f.lower().endswith(cert_extensions)]
    
    if not cert_files:
        print(f"警告: 目录 {cert_dir} 中没有找到证书文件")
        return None

    print(f"找到 {len(cert_files)} 个证书文件")

    # 复制证书到临时目录
    temp_dir = os.path.join(output_dir, "temp_certs")
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # 复制证书到临时目录
        for cert_file in cert_files:
            src_path = os.path.join(cert_dir, cert_file)
            dst_path = os.path.join(temp_dir, cert_file)
            shutil.copy2(src_path, dst_path)
            print(f"准备分析: {cert_file}")

        # 分析证书
        analyzer = CertificateValidityAnalyzer(expiry_warning_days=expiry_days)
        results = analyzer.analyze_certificates_directory(temp_dir)
        
        # 保存完整结果
        report_file = os.path.join(output_dir, 
                                 f"certificate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n=== 批量分析完成 ===")
        print(f"处理证书总数: {len(cert_files)}")
        print(f"唯一证书数: {results.get('total_certificates', 0)}")
        print(f"分析报告已保存至: {report_file}")
        
        return results
        
    except Exception as e:
        print(f"分析过程中出错: {str(e)}")
        return None
        
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)

def safe_division(numerator, denominator, default=0):
    """安全的除法运算"""
    if denominator == 0:
        return default
    return numerator / denominator

# 修改现有的主函数以支持PCAP分析
def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python batch_process_pcaps.py <证书目录> [过期天数]")
        print("  python batch_process_pcaps.py --pcap <pcap文件> [输出目录]")
        print("示例:")
        print("  python batch_process_pcaps.py ../certs 30")
        print("  python batch_process_pcaps.py --pcap chunk_1.pcap ./analysis_results")
        sys.exit(1)

    if sys.argv[1] == "--pcap":
        # PCAP文件分析模式
        if len(sys.argv) < 3:
            print("错误: 请指定PCAP文件路径")
            sys.exit(1)
            
        pcap_path = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "pcap_analysis"
        
        print(f"开始分析PCAP文件: {pcap_path}")
        results = analyze_pcap_with_detailed_stats(pcap_path)
        
        if results:
            # 保存结果
            report_file = os.path.join(output_dir, 
                                     f"pcap_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            os.makedirs(output_dir, exist_ok=True)
            
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            print(f"\n=== PCAP分析完成 ===")
            print(f"分析报告已保存至: {report_file}")
            print(f"总数据包数: {results['pcap_statistics'].get('total_packets', 0)}")
            print(f"证书实例总数: {results['pcap_statistics'].get('total_certificates', 0)}")
            print(f"唯一证书数: {results['pcap_statistics'].get('unique_certificates', 0)}")
            print(f"证书重复率: {results['pcap_statistics'].get('duplicate_rate', 0)}%")
        else:
            print("PCAP分析失败")
            
    else:
        # 证书目录分析模式
        cert_dir = sys.argv[1]
        expiry_days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        batch_process_certificates(cert_dir, expiry_days)

if __name__ == "__main__":
    main()