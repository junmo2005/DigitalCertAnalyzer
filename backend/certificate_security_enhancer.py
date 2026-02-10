#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证书安全增强模块
集成真实的安全分析功能：
    证书钉扎、
    证书链完整性检查、
    HTTPS强制与HSTS防护
"""

import hashlib
import json
import os
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import requests
import logging
from certificate_fetcher import CertificateFetcher
from http_security_checker import HttpSecurityChecker
from certificate_chain_validator import CertificateChainValidator

logger = logging.getLogger(__name__)

class CertificateSecurityEnhancer:
    """证书安全增强类"""
    
    def __init__(self, pinning_db_path: str = "certificate_pinning_db.json"):
        """
        初始化安全增强器
        
        Args:
            pinning_db_path: 证书钉扎数据库路径
        """
        self.pinning_db_path = pinning_db_path
        self.pinning_db = self._load_pinning_database()
        self.hsts_domains: Set[str] = set()

         # 初始化新模块
        self.cert_fetcher = CertificateFetcher(timeout=10)
        self.http_checker = HttpSecurityChecker(timeout=10)
        self.chain_validator = CertificateChainValidator()

    def analyze_domain_security(self, domain: str, cert_data: bytes = None) -> Dict:
        """
        综合分析域名安全状态 - 增强版
        
        Args:
            domain: 域名
            cert_data: 证书数据（可选，如未提供则自动获取）
            
        Returns:
            安全分析结果
        """
        security_report = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'certificate_pinning': {
                'configured': False,
                'verified': False,
                'error': None
            },
            'https_enforcement': {
                'enforced': False,
                'error': None
            },
            'hsts': {
                'enabled': False,
                'details': None,
                'error': None
            },
            'certificate_info': None,  # 新增：证书详细信息
            'security_headers': None,  # 新增：安全头信息
            'certificate_chain_valid': None,  # 新增：证书链验证
            'recommendations': []
        }
        
        try:
            # 1. 获取真实证书数据（如果未提供）
            if not cert_data:
                cert_data, cert_info = self.cert_fetcher.fetch_certificate_from_domain(domain)
                if cert_data:
                    security_report['certificate_info'] = self.cert_fetcher.parse_certificate_info(cert_data)
            
            # 2. 证书钉扎检查
            if cert_data and domain in self.pinning_db:
                security_report['certificate_pinning']['configured'] = True
                pinned, error = self.verify_certificate_pinning(domain, cert_data)
                security_report['certificate_pinning']['verified'] = pinned
                security_report['certificate_pinning']['error'] = error
                
                if not pinned:
                    security_report['recommendations'].append("修复证书钉扎配置")
            
            # 3. HTTPS强制检查（真实检查）
            https_enforced, redirect_target, https_details = self.http_checker.check_https_redirect(domain)
            security_report['https_enforcement']['enforced'] = https_enforced
            security_report['https_enforcement']['details'] = https_details
            
            if not https_enforced:
                security_report['recommendations'].append("配置HTTP到HTTPS的重定向")
            
            # 4. HSTS检查（真实检查）
            hsts_enabled, hsts_details, headers_info,hsts_error = self.http_checker.check_hsts_header(domain)
            security_report['hsts']['enabled'] = hsts_enabled
            security_report['hsts']['details'] = hsts_details
            security_report['hsts']['error'] = hsts_error  # 添加错误类型信息

            # 根据错误类型提供更准确的建议
            if hsts_error:
                if hsts_error == "NO_HSTS_HEADER":
                    security_report['recommendations'].append("启用HSTS头")
                elif hsts_error in ["TIMEOUT", "CONNECTION_ERROR"]:
                    security_report['recommendations'].append(f"网络连接问题，无法检测HSTS: {hsts_error}")
                elif hsts_error == "SSL_ERROR":
                    security_report['recommendations'].append("SSL证书问题，无法检测HSTS")
            
            # 5. 安全头检查（新增）
            security_headers = self.http_checker.check_security_headers(domain)
            security_report['security_headers'] = security_headers
            
            # 6. 证书链验证（新增）
            cert_chain, chain_info = self.cert_fetcher.fetch_certificate_chain(domain)
            if cert_chain:
                chain_valid, chain_issues, chain_report = self.chain_validator.validate_certificate_chain(cert_chain)
                security_report['certificate_chain_valid'] = chain_valid
                security_report['certificate_chain_issues'] = chain_issues
            
            # 7. 生成综合建议
            self._generate_comprehensive_recommendations(security_report)
            
            return security_report
            
        except Exception as e:
            logger.error(f"域名安全分析失败 {domain}: {str(e)}")
            security_report['error'] = str(e)
            return security_report
    
    def _generate_comprehensive_recommendations(self, security_report: Dict):
        """生成综合建议"""
        recommendations = security_report['recommendations']
        
        # 基于安全头评估添加建议
        if security_report.get('security_headers'):
            headers_assessment = security_report['security_headers'].get('assessment', {})
            
            if not headers_assessment.get('has_csp'):
                recommendations.append("添加Content-Security-Policy头")
            if not headers_assessment.get('has_x_content_type_options'):
                recommendations.append("添加X-Content-Type-Options: nosniff头")
            if not headers_assessment.get('has_x_frame_options'):
                recommendations.append("添加X-Frame-Options头防止点击劫持")
            if not headers_assessment.get('has_referrer_policy'):
                recommendations.append("添加Referrer-Policy头控制引用信息")
        
        # 基于证书链验证添加建议
        if security_report.get('certificate_chain_issues'):
            recommendations.append("修复证书链完整性问题")
        
        security_report['recommendations'] = list(set(recommendations))  # 去重
        
    def _load_pinning_database(self) -> Dict:
        """加载证书钉扎数据库"""
        try:
            if os.path.exists(self.pinning_db_path):
                with open(self.pinning_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"加载钉扎数据库失败: {str(e)}")
            return {}
    
    def _save_pinning_database(self) -> None:
        """保存证书钉扎数据库"""
        try:
            with open(self.pinning_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.pinning_db, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存钉扎数据库失败: {str(e)}")
    
    def calculate_certificate_hash(self, cert_data: bytes, hash_algorithm: str = "sha256") -> str:
        """
        计算证书哈希值
        
        Args:
            cert_data: 证书数据
            hash_algorithm: 哈希算法
            
        Returns:
            证书哈希值
        """
        if hash_algorithm == "sha256":
            return hashlib.sha256(cert_data).hexdigest()
        elif hash_algorithm == "sha1":
            return hashlib.sha1(cert_data).hexdigest()
        else:
            raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
    
    def pin_certificate(self, domain: str, cert_data: bytes, 
                       pin_type: str = "leaf", 
                       hash_algorithm: str = "sha256") -> bool:
        """
        钉扎证书
        
        Args:
            domain: 域名
            cert_data: 证书数据
            pin_type: 钉扎类型 (leaf/chain)
            hash_algorithm: 哈希算法
            
        Returns:
            是否成功
        """
        try:
            cert_hash = self.calculate_certificate_hash(cert_data, hash_algorithm)
            
            if domain not in self.pinning_db:
                self.pinning_db[domain] = {}
            
            self.pinning_db[domain][pin_type] = {
                "hash": cert_hash,
                "algorithm": hash_algorithm,
                "pinned_at": datetime.now().isoformat(),
                "pin_type": pin_type
            }
            
            self._save_pinning_database()
            logger.info(f"成功钉扎证书: {domain} ({pin_type})")
            return True
            
        except Exception as e:
            logger.error(f"钉扎证书失败 {domain}: {str(e)}")
            return False
    
    def verify_certificate_pinning(self, domain: str, cert_data: bytes, 
                                 pin_type: str = "leaf") -> Tuple[bool, Optional[str]]:
        """
        验证证书钉扎
        
        Args:
            domain: 域名
            cert_data: 证书数据
            pin_type: 钉扎类型
            
        Returns:
            (验证结果, 错误信息)
        """
        try:
            if domain not in self.pinning_db:
                return False, f"域名 {domain} 未配置证书钉扎"
            
            domain_pins = self.pinning_db[domain]
            if pin_type not in domain_pins:
                return False, f"域名 {domain} 未配置 {pin_type} 类型钉扎"
            
            pin_info = domain_pins[pin_type]
            current_hash = self.calculate_certificate_hash(cert_data, pin_info["algorithm"])
            expected_hash = pin_info["hash"]
            
            if current_hash == expected_hash:
                return True, None
            else:
                error_msg = f"证书钉扎验证失败: {domain}\n期望: {expected_hash}\n实际: {current_hash}"
                logger.warning(error_msg)
                return False, error_msg
                
        except Exception as e:
            return False, f"证书钉扎验证异常: {str(e)}"
    
    def check_certificate_chain_integrity(self, cert_chain: List[bytes]) -> Tuple[bool, List[str]]:
        """
        检查证书链完整性
        
        """
        return self.chain_validator.validate_certificate_chain(cert_chain)

       
    def generate_security_report(self, domains: List[str]) -> Dict:
        """
        生成安全报告 - 增强版
    
        Args:
            domains: 域名列表
        
        Returns:
            包含评分、详细结果和图表数据的完整报告
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_domains': len(domains),
                'domains_with_https_enforcement': 0,
                'domains_with_hsts': 0,
                'domains_with_good_security_headers': 0,
                'domains_with_valid_certificate_chains': 0,
                'security_score': 0
            },
            'detailed_results': [],
            'scoreDistribution': [0, 0, 0, 0],  # 优秀, 良好, 一般, 较差
            'featureStats': {
                'https': 0,
                'hsts': 0,
                'good_headers': 0,
                'valid_chains': 0,
                'total_domains': len(domains)
            }
        }
    
        security_scores = []
    
        # 分析每个域名
        for domain in domains:
            try:
                domain_report = self.analyze_domain_security(domain)
                report['detailed_results'].append(domain_report)
            
                # 计算综合安全分数
                score = self._calculate_comprehensive_security_score(domain_report)
                security_scores.append(score)
            
                # 更新统计信息
                if domain_report['https_enforcement']['enforced']:
                    report['summary']['domains_with_https_enforcement'] += 1
                    report['featureStats']['https'] += 1
            
                if domain_report['hsts']['enabled']:
                    report['summary']['domains_with_hsts'] += 1
                    report['featureStats']['hsts'] += 1
             
                security_headers = domain_report.get('security_headers', {})
                assessment = security_headers.get('assessment', {})

                if assessment.get('has_csp') and assessment.get('has_x_content_type_options'):
                    report['summary']['domains_with_good_security_headers'] += 1
                    report['featureStats']['good_headers'] += 1
            
                if domain_report.get('certificate_chain_valid', False):
                    report['summary']['domains_with_valid_certificate_chains'] += 1
                    report['featureStats']['valid_chains'] += 1
            
                # 更新分数分布
                if score >= 80:
                    report['scoreDistribution'][0] += 1
                elif score >= 60:
                    report['scoreDistribution'][1] += 1
                elif score >= 40:
                    report['scoreDistribution'][2] += 1
                else:
                    report['scoreDistribution'][3] += 1
                
            except Exception as e:
                app.logger.error(f"域名 {domain} 分析失败: {str(e)}")
                # 添加一个错误报告
                error_report = {
                    'domain': domain,
                    'error': str(e),
                    'security_score': 0
                }
                report['detailed_results'].append(error_report)
                security_scores.append(0)
                report['scoreDistribution'][3] += 1  # 计入较差类别
    
        # 计算平均安全分数
        if security_scores:
            report['summary']['security_score'] = round(sum(security_scores) / len(security_scores), 1)
    
        # 生成总体建议
        report['recommendations'] = self._generate_overall_recommendations(report)
    
        return report

    def _generate_overall_recommendations(self, report: Dict) -> List[str]:
        """生成总体改进建议"""
        recommendations = []
        summary = report['summary']
        total = summary['total_domains']
    
        # HTTPS强制建议
        https_percentage = (summary['domains_with_https_enforcement'] / total) * 100
        if https_percentage < 100:
            recommendations.append(f"配置HTTPS强制重定向：当前{https_percentage:.1f}%的域名已配置，建议达到100%")
    
        # HSTS建议
        hsts_percentage = (summary['domains_with_hsts'] / total) * 100
        if hsts_percentage < 80:
            recommendations.append(f"启用HSTS保护：当前{hsts_percentage:.1f}%的域名已配置，建议达到80%以上")
    
        # 安全头建议
        headers_percentage = (summary['domains_with_good_security_headers'] / total) * 100
        if headers_percentage < 70:
            recommendations.append(f"完善安全头配置：当前{headers_percentage:.1f}%的域名配置良好，建议达到70%以上")
    
        # 证书链建议
        chain_percentage = (summary['domains_with_valid_certificate_chains'] / total) * 100
        if chain_percentage < 90:
            recommendations.append(f"修复证书链问题：当前{chain_percentage:.1f}%的域名证书链完整，建议达到90%以上")
    
        # 总体评分建议
        overall_score = summary['security_score']
        if overall_score < 60:
            recommendations.append("整体安全状况需要立即改进，建议优先处理HTTPS强制和HSTS配置")
        elif overall_score < 80:
            recommendations.append("整体安全状况良好，建议继续优化安全头配置和证书链完整性")
        else:
            recommendations.append("整体安全状况优秀，建议保持并定期审查安全配置")
    
        return recommendations

    def _calculate_comprehensive_security_score(self, domain_report: Dict) -> float:
        """计算综合安全分数"""
        score = 0
    
        # HTTPS强制 (30分)
        if domain_report['https_enforcement']['enforced']:
            score += 30
    
        # HSTS (30分)
        if domain_report['hsts']['enabled']:
            hsts_details = domain_report['hsts']['details'] or {}
            max_age = hsts_details.get('max-age', 0)
            if max_age >= 31536000:  # 1年
                score += 30
            else:
                score += 20  # 部分分数给短期HSTS
    
        # 安全头 (25分)
        if domain_report.get('security_headers', {}).get('assessment', {}):
            assessment = domain_report['security_headers']['assessment']
            header_score = sum([
                10 if assessment.get('has_csp') else 0,
                5 if assessment.get('has_x_content_type_options') else 0,
                5 if assessment.get('has_x_frame_options') else 0,
                5 if assessment.get('has_referrer_policy') else 0
            ])
            score += min(header_score, 25)
    
        # 证书链 (15分)
        if domain_report.get('certificate_chain_valid', False):
            score += 15
    
        return score

if __name__ == "__main__":
    enhancer = CertificateSecurityEnhancer()
    
    print("=== 证书安全分析器演示 ===")
    
    # 演示单个域名的完整安全分析
    demo_domains = ["github.com", "example.com", "httpbin.org"]
    
    for demo_domain in demo_domains:
        print(f"\n正在分析域名: {demo_domain}")
        print("=" * 50)
        
        try:
            # 执行完整的安全分析
            security_report = enhancer.analyze_domain_security(demo_domain)
            
            # 显示关键安全指标
            print("\n🔒 安全状态概览:")
            print(f"  • HTTPS强制重定向: {'✅ 已启用' if security_report['https_enforcement']['enforced'] else '❌ 未启用'}")
            print(f"  • HSTS保护: {'✅ 已启用' if security_report['hsts']['enabled'] else '❌ 未启用'}")
            
            # 安全头配置状态
            security_headers = security_report.get('security_headers', {})
            assessment = security_headers.get('assessment', {})
            print(f"  • 安全头配置: {'✅ 良好' if assessment.get('has_csp') and assessment.get('has_x_content_type_options') else '⚠️  需改进'}")
            
            if security_report.get('certificate_chain_valid') is not None:
                print(f"  • 证书链完整性: {'✅ 有效' if security_report['certificate_chain_valid'] else '❌ 无效'}")
            
            # 显示HSTS详情
            if security_report['hsts']['enabled'] and security_report['hsts']['details']:
                hsts = security_report['hsts']['details']
                print(f"\n📋 HSTS配置详情:")
                print(f"  • Max-Age: {hsts.get('max-age', 'N/A')} 秒")
                print(f"  • IncludeSubDomains: {'是' if hsts.get('includeSubDomains') else '否'}")
                print(f"  • Preload: {'是' if hsts.get('preload') else '否'}")
            
            # 显示安全头详情
            if security_headers:
                print(f"\n🛡️ 安全头配置详情:")
                headers_assessment = [
                    f"Content-Security-Policy: {'✅' if assessment.get('has_csp') else '❌'}",
                    f"X-Content-Type-Options: {'✅' if assessment.get('has_x_content_type_options') else '❌'}",
                    f"X-Frame-Options: {'✅' if assessment.get('has_x_frame_options') else '❌'}",
                    f"Referrer-Policy: {'✅' if assessment.get('has_referrer_policy') else '❌'}"
                ]
                for header in headers_assessment:
                    print(f"  • {header}")
            
            # 显示安全建议
            if security_report['recommendations']:
                print(f"\n💡 安全改进建议:")
                for i, recommendation in enumerate(security_report['recommendations'], 1):
                    print(f"  {i}. {recommendation}")
            
            # 计算安全分数
            security_score = enhancer._calculate_comprehensive_security_score(security_report)
            print(f"\n📊 综合安全评分: {security_score:.1f}/100")
            
            if security_score >= 80:
                print("🎉 安全状态: 优秀")
            elif security_score >= 60:
                print("👍 安全状态: 良好") 
            elif security_score >= 40:
                print("⚠️  安全状态: 一般")
            else:
                print("🔴 安全状态: 需要改进")
                
        except Exception as e:
            print(f"❌ 分析过程中出错: {str(e)}")
            import traceback
            traceback.print_exc()
        
        print("\n" + "-" * 50)
    
    # 演示批量分析功能
    print(f"\n🔄 批量分析演示 ({len(demo_domains)} 个域名)")
    print("=" * 50)
    
    try:
        batch_report = enhancer.generate_security_report(demo_domains)
        
        print(f"\n📈 批量分析结果摘要:")
        print(f"  • 分析域名总数: {batch_report['summary']['total_domains']}")
        print(f"  • 平均安全分数: {batch_report['summary']['security_score']:.1f}/100")
        print(f"  • 启用HTTPS强制的域名: {batch_report['summary']['domains_with_https_enforcement']}")
        print(f"  • 启用HSTS保护的域名: {batch_report['summary']['domains_with_hsts']}")
        print(f"  • 安全头配置良好的域名: {batch_report['summary']['domains_with_good_security_headers']}")
        print(f"  • 证书链完整的域名: {batch_report['summary']['domains_with_valid_certificate_chains']}")
        
        print(f"\n📊 分数分布:")
        distribution = batch_report['scoreDistribution']
        print(f"  • 优秀 (80-100): {distribution[0]} 个域名")
        print(f"  • 良好 (60-79): {distribution[1]} 个域名") 
        print(f"  • 一般 (40-59): {distribution[2]} 个域名")
        print(f"  • 需要改进 (0-39): {distribution[3]} 个域名")
        
        print(f"\n💡 总体改进建议:")
        for i, recommendation in enumerate(batch_report['recommendations'], 1):
            print(f"  {i}. {recommendation}")
            
    except Exception as e:
        print(f"❌ 批量分析过程中出错: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n=== 演示结束 ===")