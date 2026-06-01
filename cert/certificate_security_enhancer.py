#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证书安全增强模块 - 集成数据库版本（v2.0 兼容新表结构）
"""

import hashlib
import json
import os
import sys
import queue
import threading
from datetime import datetime
import time  
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db_session import get_db, get_current_task_id

logger = logging.getLogger(__name__)

from certificate_fetcher import CertificateFetcher
from http_security_checker import HttpSecurityChecker, HttpSecurityCheckerCompat
from certificate_chain_validator import CertificateChainValidator


class CertificateSecurityEnhancer:
    """证书安全增强类"""

    def __init__(self, pinning_db_path: str = "certificate_pinning_db.json"):
        self.pinning_db_path = pinning_db_path
        self.pinning_db = self._load_pinning_database()
        self.hsts_domains: set = set()
        self.cert_fetcher = CertificateFetcher(timeout=10)
        self.http_checker = HttpSecurityCheckerCompat(timeout=5)
        self.chain_validator = CertificateChainValidator()
        self._db_write_queue = queue.Queue(maxsize=500)
        self._db_writer_running = True
        self._db_writer_thread = threading.Thread(target=self._db_writer_loop, daemon=True)
        self._db_writer_thread.start()
    
    def _db_writer_loop(self):
        """后台数据库写入线程 - 单线程避免锁竞争"""
        while self._db_writer_running:
            try:
                batch = []
                start_time = time.time()
                # 批量收集：最多等2秒或攒够20条
                while len(batch) < 20 and time.time() - start_time < 2.0:
                    try:
                        item = self._db_write_queue.get(timeout=0.5)
                        if item is None:  # 结束信号
                            self._db_writer_running = False
                            break
                        batch.append(item)
                    except queue.Empty:
                        continue

                if batch:
                    self._batch_save_to_db(batch)

            except Exception as e:
                logger.error(f"DB writer thread error: {e}")

    def _batch_save_to_db(self, batch):
        """批量保存到数据库 - 使用事务"""
        db = get_db()
        if not db:
            return
        try:
            db.conn.execute("BEGIN IMMEDIATE TRANSACTION")
            for item in batch:
                if item['type'] == 'security_analysis':
                    self._save_security_analysis_single(db, item['data'])
                elif item['type'] == 'chain_relationship':
                    self._save_chain_relationship_single(db, item['data'])
            db.conn.commit()
            logger.debug(f"Batch write complete: {len(batch)} records")
        except Exception as e:
            db.conn.rollback()
            logger.error(f"Batch write failed: {e}")

    def _save_security_analysis_single(self, db, data: Dict):
        """单条安全分析记录写入数据库（供批量写入调用）"""
        try:
            db.conn.execute("""
                INSERT INTO security_analysis (
                    task_id, domain, https_enf, https_score,
                    hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_score,
                    csp_enabled, csp_value, xcto, xcto_value,
                    xfo, xfo_value, ref_pol, ref_value,
                    headers_score, cert_chain_valid, chain_score,
                    total_score, grade
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['task_id'], data['domain'], data['https_enf'], data['https_score'],
                data['hsts_enabled'], data['hsts_max_age'], data['hsts_include_subdomains'], data['hsts_score'],
                data['csp_enabled'], data['csp_value'], data['xcto'], data['xcto_value'],
                data['xfo'], data['xfo_value'], data['ref_pol'], data['ref_value'],
                data['headers_score'], data['cert_chain_valid'], data['chain_score'],
                data['total_score'], data['grade']
            ))
        except Exception as e:
            logger.error(f"保存安全分析记录失败 {data.get('domain')}: {e}")

    def _save_chain_relationship_single(self, db, data: Dict):
        """单条证书链关系写入数据库（供批量写入调用）"""
        try:
            db.conn.execute(
                """INSERT OR IGNORE INTO certificate_relationships
                   (task_id, domain, certificate_asset_id, chain_index, is_leaf)
                   VALUES (?, ?, ?, ?, ?)""",
                (data['task_id'], data['domain'], data['asset_id'], data['chain_index'], data['is_leaf'])
            )
        except Exception as e:
            logger.error(f"保存证书链关系失败 {data.get('domain')}: {e}")
        

    def analyze_domain_security(self, domain: str, cert_data: bytes = None) -> Dict:
        security_report = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'certificate_pinning': {'configured': False, 'verified': False, 'error': None},
            'https_enforcement': {'enforced': False, 'error': None},
            'hsts': {'enabled': False, 'details': None, 'error': None},
            'certificate_info': None,
            'security_headers': None,
            'certificate_chain_valid': False,
            'certificate_chain': [],
            'certificate_chain_self_signed': False,
            'recommendations': []
        }
        try:
            # 获取证书（可选）
            if not cert_data:
                cert_data, cert_info = self.cert_fetcher.fetch_certificate_from_domain(domain)
                if cert_data:
                    security_report['certificate_info'] = self.cert_fetcher.parse_certificate_info(cert_data)

            # 钉扎检查
            if cert_data and domain in self.pinning_db:
                security_report['certificate_pinning']['configured'] = True
                pinned, error = self.verify_certificate_pinning(domain, cert_data)
                security_report['certificate_pinning']['verified'] = pinned
                security_report['certificate_pinning']['error'] = error

            # HTTPS 强制
            https_enforced, redirect_target, https_details = self.http_checker.check_https_redirect_compat(domain)
            security_report['https_enforcement']['enforced'] = https_enforced
            security_report['https_enforcement']['details'] = https_details

            # HSTS
            hsts_enabled, hsts_details, headers_info, hsts_error = self.http_checker.check_hsts_header_compat(domain)
            security_report['hsts']['enabled'] = hsts_enabled
            security_report['hsts']['details'] = hsts_details
            security_report['hsts']['error'] = hsts_error

            # 安全头
            security_headers = self.http_checker.check_security_headers(domain)
            security_report['security_headers'] = security_headers

            # 证书链
            cert_chain_der, chain_info = self.cert_fetcher.fetch_certificate_chain(domain)
            if cert_chain_der:
                # 证书链验证
                chain_valid = len(cert_chain_der) >= 2
                is_self_signed = False
                if len(cert_chain_der) == 1:
                    chain_valid = False
                    is_self_signed = True
                security_report['certificate_chain_valid'] = chain_valid
                security_report['certificate_chain_self_signed'] = is_self_signed
                # 调用 validator 获取详细问题
                chain_valid_detailed, issues, report = self.chain_validator.validate_certificate_chain(cert_chain_der)
                security_report['certificate_chain_issues'] = issues

                # ----- 新增：写入证书链关系 -----
                task_id = get_current_task_id()
                if task_id:
                    self._save_certificate_chain_relationships(domain, cert_chain_der, task_id)
            else:
                security_report['certificate_chain_valid'] = False

            self._generate_comprehensive_recommendations(security_report)
            self._save_security_analysis_to_db(domain, security_report)
            return security_report

        except Exception as e:
            logger.error(f"域名安全分析失败 {domain}: {str(e)}")
            security_report['error'] = str(e)
            return security_report

    def analyze_domain_security_light(self, domain: str, chain_data: list = None) -> Dict:
        """轻量级分析 - 使用传入的证书链，避免重复网络请求"""
        security_report = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'https_enforcement': {'enforced': False, 'error': None},
            'hsts': {'enabled': False, 'details': None, 'error': None},
            'security_headers': None,
            'certificate_chain_valid': False,
            'certificate_chain': chain_data or [],
            'certificate_chain_self_signed': False,
            'recommendations': []
        }
        try:
            # 只执行HTTP检查，不再获取证书
            https_enforced, _, https_details = self.http_checker.check_https_redirect_compat(domain)
            security_report['https_enforcement']['enforced'] = https_enforced
            security_report['https_enforcement']['details'] = https_details

            hsts_enabled, hsts_details, _, hsts_error = self.http_checker.check_hsts_header_compat(domain)
            security_report['hsts']['enabled'] = hsts_enabled
            security_report['hsts']['details'] = hsts_details
            security_report['hsts']['error'] = hsts_error

            security_headers = self.http_checker.check_security_headers(domain)
            security_report['security_headers'] = security_headers

            # 使用传入的证书链数据
            if chain_data:
                chain_valid = len(chain_data) >= 2
                security_report['certificate_chain_valid'] = chain_valid
                security_report['certificate_chain_self_signed'] = (len(chain_data) == 1)
        
            self._generate_comprehensive_recommendations(security_report)
            # 轻量级分析不自动保存到数据库，由调用方统一处理
            return security_report
        except Exception as e:
            logger.error(f"Lightweight analysis failed {domain}: {e}")
            security_report['error'] = str(e)
            return security_report

    def _save_certificate_chain_relationships(self, domain: str, cert_chain_der: List[bytes], task_id: str):
        """将证书链中的每个证书与域名关联，存入 certificate_relationships 表"""
        db = get_db()
        for idx, cert_der in enumerate(cert_chain_der):
            try:
                fingerprint = db.compute_fingerprint_sha256(cert_der)
                # 如果资产不存在则创建（使用空信息占位，实际内容由PCAP分析负责补全）
                asset_info = {
                    "subject_cn": "",
                    "issuer_cn": "",
                    "not_before": None,
                    "not_after": None,
                    "key_algorithm": "",
                    "key_size": 0,
                    "signature_algorithm": "",
                    "san_list": "[]",
                    "san_count": 0,
                    "key_usage": "",
                    "extended_key_usage": "",
                    "is_self_signed": 0,
                    "is_ca": 0,
                }
                asset_id = db.get_or_create_certificate_asset(fingerprint, asset_info)
                # 插入关系表
                db.conn.execute(
                    """INSERT OR IGNORE INTO certificate_relationships
                       (task_id, domain, certificate_asset_id, chain_index, is_leaf)
                       VALUES (?, ?, ?, ?, ?)""",
                    (task_id, domain, asset_id, idx, 1 if idx == 0 else 0)
                )
                db.conn.commit()
            except Exception as e:
                logger.warning(f"写入证书链关系失败 domain={domain} idx={idx}: {e}")
        
    def _save_security_analysis_to_db(self, domain: str, security_report: Dict):
        db = get_db()
        task_id = get_current_task_id()
        if not db or not task_id:
            return

        # 计算分数
        https_enf = security_report['https_enforcement']['enforced']
        https_score = 20 if https_enf else 0

        hsts_enabled = security_report['hsts']['enabled']
        if hsts_enabled:
            hsts_details = security_report['hsts'].get('details') or {}
            max_age = hsts_details.get('max-age', 0)
            incl_sub = hsts_details.get('includeSubDomains', False)
            hsts_score = 20 if (max_age >= 31536000 and incl_sub) else 15 if max_age >= 31536000 else 10
        else:
            max_age = 0
            incl_sub = False
            hsts_score = 0

        headers = security_report.get('security_headers', {})
        assess = headers.get('assessment', {})
        csp_enabled = assess.get('has_csp', False)
        csp_value = headers.get('content_security_policy', '')
        xcto = assess.get('has_x_content_type_options', False)
        xcto_value = headers.get('x_content_type_options', '')
        xfo = assess.get('has_x_frame_options', False)
        xfo_value = headers.get('x_frame_options', '')
        ref_pol = assess.get('has_referrer_policy', False)
        ref_value = headers.get('referrer_policy', '')
        headers_score = (8 if csp_enabled else 0) + (4 if xcto else 0) + (4 if xfo else 0) + (4 if ref_pol else 0)

        chain_valid = security_report.get('certificate_chain_valid', False)
        self_signed = security_report.get('certificate_chain_self_signed', False)
        chain_score = 40 if (chain_valid and not self_signed) else (10 if self_signed and chain_valid else 0)

        total_score = https_score + hsts_score + headers_score + chain_score

        # 新等级：A 90+  B 70+  C 50+  D <50
        if total_score >= 90:
            grade = 'A'
        elif total_score >= 70:
            grade = 'B'
        elif total_score >= 50:
            grade = 'C'
        else:
            grade = 'D'

        # ===== 修改：改为异步队列写入，不阻塞分析线程 =====
        try:
            self._db_write_queue.put({
                'type': 'security_analysis',
                'data': {
                    'task_id': task_id,
                    'domain': domain,
                    'https_enf': https_enf,
                    'https_score': https_score,
                    'hsts_enabled': hsts_enabled,
                    'hsts_max_age': max_age,
                    'hsts_include_subdomains': incl_sub,
                    'hsts_score': hsts_score,
                    'csp_enabled': csp_enabled,
                    'csp_value': csp_value,
                    'xcto': xcto,
                    'xcto_value': xcto_value,
                    'xfo': xfo,
                    'xfo_value': xfo_value,
                    'ref_pol': ref_pol,
                    'ref_value': ref_value,
                    'headers_score': headers_score,
                    'cert_chain_valid': chain_valid,
                    'chain_score': chain_score,
                    'total_score': total_score,
                    'grade': grade
                }
            }, block=False)
        except queue.Full:
            logger.warning(f"DB write queue full, dropping security analysis for: {domain}")

    def shutdown(self):
        """优雅关闭 - 等待队列清空"""
        logger.info("Shutting down async DB writer thread...")
        self._db_writer_running = False
        self._db_write_queue.put(None)  # 发送结束信号
        self._db_writer_thread.join(timeout=10)
        logger.info("Async DB writer thread shut down")

    def _calculate_comprehensive_security_score(self, domain_report: Dict) -> float:
        score = 0
        if domain_report['https_enforcement']['enforced']:
            score += 20
        if domain_report['hsts']['enabled']:
            hsts_details = domain_report['hsts'].get('details') or {}
            max_age = hsts_details.get('max-age', 0)
            include_subdomains = hsts_details.get('includeSubDomains', False)
            if max_age >= 31536000:
                score += 20 if include_subdomains else 15
            else:
                score += 10
        assessment = domain_report.get('security_headers', {}).get('assessment', {})
        if assessment:
            if assessment.get('has_csp'): score += 8
            if assessment.get('has_x_content_type_options'): score += 4
            if assessment.get('has_x_frame_options'): score += 4
            if assessment.get('has_referrer_policy'): score += 4
        chain_valid = domain_report.get('certificate_chain_valid', False)
        self_signed = domain_report.get('certificate_chain_self_signed', False)
        if chain_valid:
            score += 10 if self_signed else 40
        return score

    # 原其他方法保持不变，此处省略 _generate_comprehensive_recommendations 等（无需修改）
    def _generate_comprehensive_recommendations(self, security_report: Dict):
        # 保留原有逻辑
        recommendations = security_report.setdefault('recommendations', [])
        if not security_report['https_enforcement']['enforced']:
            recommendations.append("配置HTTP到HTTPS的重定向")
        if not security_report['hsts']['enabled']:
            recommendations.append("启用HSTS头")
        if security_report.get('security_headers'):
            sa = security_report['security_headers'].get('assessment', {})
            if not sa.get('has_csp'): recommendations.append("添加Content-Security-Policy头")
            if not sa.get('has_x_content_type_options'): recommendations.append("添加X-Content-Type-Options: nosniff")
            if not sa.get('has_x_frame_options'): recommendations.append("添加X-Frame-Options")
            if not sa.get('has_referrer_policy'): recommendations.append("添加Referrer-Policy")
        if not security_report.get('certificate_chain_valid') and not security_report.get('certificate_chain_self_signed'):
            recommendations.append("修复证书链完整性问题")
        security_report['recommendations'] = list(set(recommendations))

    # 其余 pinning、hash 等方法保持不变，为节省篇幅此处略，但必须保留原文件中的其他方法。
    # 保证原有 pinning 相关方法完整。
    def _load_pinning_database(self) -> Dict:
        try:
            if os.path.exists(self.pinning_db_path):
                with open(self.pinning_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except:
            return {}

    def _save_pinning_database(self):
        try:
            with open(self.pinning_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.pinning_db, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存钉扎数据库失败: {e}")

    def calculate_certificate_hash(self, cert_data: bytes, hash_algorithm: str = "sha256") -> str:
        if hash_algorithm == "sha256":
            return hashlib.sha256(cert_data).hexdigest()
        elif hash_algorithm == "sha1":
            return hashlib.sha1(cert_data).hexdigest()
        else:
            raise ValueError(f"不支持的哈希算法: {hash_algorithm}")

    def pin_certificate(self, domain: str, cert_data: bytes, pin_type: str = "leaf", hash_algorithm: str = "sha256") -> bool:
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
            return True
        except Exception as e:
            logger.error(f"钉扎失败: {e}")
            return False

    def verify_certificate_pinning(self, domain: str, cert_data: bytes, pin_type: str = "leaf") -> Tuple[bool, Optional[str]]:
        try:
            if domain not in self.pinning_db:
                return False, f"域名 {domain} 未配置证书钉扎"
            domain_pins = self.pinning_db[domain]
            if pin_type not in domain_pins:
                return False, f"域名 {domain} 未配置 {pin_type} 钉扎"
            pin_info = domain_pins[pin_type]
            current_hash = self.calculate_certificate_hash(cert_data, pin_info["algorithm"])
            expected_hash = pin_info["hash"]
            if current_hash == expected_hash:
                return True, None
            else:
                return False, f"证书钉扎验证失败: 期望 {expected_hash}, 实际 {current_hash}"
        except Exception as e:
            return False, f"验证异常: {str(e)}"

    def check_certificate_chain_integrity(self, cert_chain: List[bytes]) -> Tuple[bool, List[str]]:
        return self.chain_validator.validate_certificate_chain(cert_chain)

    def generate_security_report(self, domains: List[str]) -> Dict:
        # 这里保留原有批量分析逻辑，但内部调用 analyze_domain_security 就会入库
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
            'scoreDistribution': [0, 0, 0, 0],
            'featureStats': {
                'https': 0,
                'hsts': 0,
                'good_headers': 0,
                'valid_chains': 0,
                'total_domains': len(domains)
            }
        }
        security_scores = []
        for domain in domains:
            domain_report = self.analyze_domain_security(domain)
            report['detailed_results'].append(domain_report)
            score = self._calculate_comprehensive_security_score(domain_report)
            security_scores.append(score)
            if domain_report['https_enforcement']['enforced']:
                report['summary']['domains_with_https_enforcement'] += 1
                report['featureStats']['https'] += 1
            if domain_report['hsts']['enabled']:
                report['summary']['domains_with_hsts'] += 1
                report['featureStats']['hsts'] += 1
            sa = domain_report.get('security_headers', {}).get('assessment', {})
            if sa.get('has_csp') and sa.get('has_x_content_type_options'):
                report['summary']['domains_with_good_security_headers'] += 1
                report['featureStats']['good_headers'] += 1
            if domain_report.get('certificate_chain_valid'):
                report['summary']['domains_with_valid_certificate_chains'] += 1
                report['featureStats']['valid_chains'] += 1
            if score >= 80:
                report['scoreDistribution'][0] += 1
            elif score >= 60:
                report['scoreDistribution'][1] += 1
            elif score >= 40:
                report['scoreDistribution'][2] += 1
            else:
                report['scoreDistribution'][3] += 1
        if security_scores:
            report['summary']['security_score'] = round(sum(security_scores) / len(security_scores), 1)
        report['recommendations'] = self._generate_overall_recommendations(report)
        return report

    def _generate_overall_recommendations(self, report: Dict) -> List[str]:
        """生成总体改进建议"""
        recommendations = []
        summary = report['summary']
        total = summary['total_domains']
    
        https_percentage = (summary['domains_with_https_enforcement'] / total) * 100 if total > 0 else 0
        if https_percentage < 100:
            recommendations.append(f"配置HTTPS强制重定向：当前{https_percentage:.1f}%的域名已配置，建议达到100%")
    
        hsts_percentage = (summary['domains_with_hsts'] / total) * 100 if total > 0 else 0
        if hsts_percentage < 80:
            recommendations.append(f"启用HSTS保护：当前{hsts_percentage:.1f}%的域名已配置，建议达到80%以上")
    
        headers_percentage = (summary['domains_with_good_security_headers'] / total) * 100 if total > 0 else 0
        if headers_percentage < 70:
            recommendations.append(f"完善安全头配置：当前{headers_percentage:.1f}%的域名配置良好，建议达到70%以上")
    
        chain_percentage = (summary['domains_with_valid_certificate_chains'] / total) * 100 if total > 0 else 0
        if chain_percentage < 90:
            recommendations.append(f"修复证书链问题：当前{chain_percentage:.1f}%的域名证书链完整，建议达到90%以上")
    
        overall_score = summary['security_score']
        if overall_score < 60:
            recommendations.append("整体安全状况需要立即改进，建议优先处理HTTPS强制和HSTS配置")
        elif overall_score < 80:
            recommendations.append("整体安全状况良好，建议继续优化安全头配置和证书链完整性")
        else:
            recommendations.append("整体安全状况优秀，建议保持并定期审查安全配置")
    
        return recommendations

    def _calculate_comprehensive_security_score(self, domain_report: Dict) -> float:
        score = 0
    
        # HTTPS强制重定向：20分
        if domain_report['https_enforcement']['enforced']:
            score += 20
       
        # HSTS保护：20分
        if domain_report['hsts']['enabled']:
            hsts_details = domain_report['hsts']['details'] or {}
            max_age = hsts_details.get('max-age', 0)
            include_subdomains = hsts_details.get('includeSubDomains', False)
            if max_age >= 31536000:
                if include_subdomains:
                    score += 20
                else:
                    score += 15
            else:
                score += 10
    
        # 安全响应头配置：20分
        if domain_report.get('security_headers', {}).get('assessment', {}):
            assessment = domain_report['security_headers']['assessment']
            if assessment.get('has_csp'): score += 8
            if assessment.get('has_x_content_type_options'): score += 4
            if assessment.get('has_x_frame_options'): score += 4
            if assessment.get('has_referrer_policy'): score += 4
    
        # 证书链完整性：40分
        chain_valid = domain_report.get('certificate_chain_valid', False)
        is_self_signed = domain_report.get('certificate_chain_self_signed', False)
        if chain_valid:
            if is_self_signed:
                score += 10   # 自签名证书仅得10分
            else:
                score += 40   # 完整且受信任得满分
    
        return score

if __name__ == "__main__":
    enhancer = CertificateSecurityEnhancer()
    
    print("=== 证书安全分析器演示 ===")
    
    demo_domains = ["github.com", "example.com", "httpbin.org"]
    
    for demo_domain in demo_domains:
        print(f"\n正在分析域名: {demo_domain}")
        print("=" * 50)
        
        try:
            security_report = enhancer.analyze_domain_security(demo_domain)
            
            print("\n🔒 安全状态概览:")
            print(f"  • HTTPS强制重定向: {'✅ 已启用' if security_report['https_enforcement']['enforced'] else '❌ 未启用'}")
            print(f"  • HSTS保护: {'✅ 已启用' if security_report['hsts']['enabled'] else '❌ 未启用'}")
            
            security_headers = security_report.get('security_headers', {})
            assessment = security_headers.get('assessment', {})
            print(f"  • 安全头配置: {'✅ 良好' if assessment.get('has_csp') and assessment.get('has_x_content_type_options') else '⚠️  需改进'}")
            
            if security_report.get('certificate_chain_valid') is not None:
                print(f"  • 证书链完整性: {'✅ 有效' if security_report['certificate_chain_valid'] else '❌ 无效'}")
            
            if security_report['hsts']['enabled'] and security_report['hsts']['details']:
                hsts = security_report['hsts']['details']
                print(f"\n📋 HSTS配置详情:")
                print(f"  • Max-Age: {hsts.get('max-age', 'N/A')} 秒")
                print(f"  • IncludeSubDomains: {'是' if hsts.get('includeSubDomains') else '否'}")
                print(f"  • Preload: {'是' if hsts.get('preload') else '否'}")
            
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
            
            if security_report['recommendations']:
                print(f"\n💡 安全改进建议:")
                for i, recommendation in enumerate(security_report['recommendations'], 1):
                    print(f"  {i}. {recommendation}")
            
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