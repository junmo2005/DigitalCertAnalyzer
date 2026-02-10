#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证书分析测试脚本
演示证书过滤器和有效期分析器的完整流程
"""

import sys
import os
from certificate_filter import TLSCertificateFilter
from certificate_validity_analyzer import CertificateValidityAnalyzer

def test_certificate_analysis_pipeline(pcap_file: str, cert_dir: str = "certificates", expiry_days: int = 30):
    """
    测试证书分析完整流程
    
    Args:
        pcap_file: pcap文件路径
        cert_dir: 证书输出目录
        expiry_days: 即将过期天数阈值
    """
    print("=" * 60)
    print("证书分析完整流程测试")
    print("=" * 60)
    
    # 第一步：从pcap文件提取证书
    print("\n第一步：从pcap文件提取证书")
    print("-" * 40)
    
    try:
        # 创建证书过滤器
        filter_instance = TLSCertificateFilter()
        
        # 解析pcap文件
        certificates = filter_instance.parse_pcap_and_extract_certificates(pcap_file)
        
        if not certificates:
            print("未从pcap文件中提取到任何证书，测试结束")
            return
        
        # 保存证书到文件
        filter_instance.save_certificates_to_files(cert_dir)
        
        # 显示提取统计
        stats = filter_instance.get_statistics()
        print(f"\n证书提取统计:")
        print(f"- 总数据包数: {stats['total_packets']}")
        print(f"- TLS握手包数: {stats['tls_packets']}")
        print(f"- 证书消息数: {stats['certificate_messages']}")
        print(f"- 证书实例总数: {stats['total_certificates']}")
        print(f"- 唯一证书总数: {stats['unique_certificates']}")
        
    except Exception as e:
        print(f"证书提取过程中发生错误: {e}")
        return
    
    # 第二步：分析证书有效期
    print(f"\n第二步：分析证书有效期")
    print("-" * 40)
    
    try:
        # 创建有效期分析器
        analyzer = CertificateValidityAnalyzer(expiry_warning_days=expiry_days)
        
        # 分析证书目录
        results = analyzer.analyze_certificates_directory(cert_dir)
        
        # 保存分析报告
        from datetime import datetime
        report_file = f"certificate_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        analyzer.save_analysis_report(report_file)
        
        print(f"\n有效期分析完成，报告已保存至: {report_file}")
        
    except Exception as e:
        print(f"有效期分析过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("证书分析完整流程测试完成")
    print("=" * 60)

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("使用方法: python test_certificate_analysis.py <pcap_file> [cert_dir] [expiry_days]")
        print("示例:")
        print("  python test_certificate_analysis.py sample.pcap")
        print("  python test_certificate_analysis.py sample.pcap certificates 30")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    cert_dir = sys.argv[2] if len(sys.argv) > 2 else "certificates"
    expiry_days = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    
    # 检查pcap文件是否存在
    if not os.path.exists(pcap_file):
        print(f"错误: pcap文件不存在: {pcap_file}")
        sys.exit(1)
    
    # 运行测试
    test_certificate_analysis_pipeline(pcap_file, cert_dir, expiry_days)

if __name__ == "__main__":
    main() 