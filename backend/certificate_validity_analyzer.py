#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数字证书有效性分析器
分析证书的有效期、加密强度、颁发机构等信息
"""

import os
import re
import ssl
import socket
import hashlib
import binascii
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from collections import defaultdict, Counter
import json
import logging
from typing import Dict, List, Optional, Any, Tuple

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CertificateValidityAnalyzer:
    """数字证书有效性分析器"""
    
    def __init__(self, expiry_warning_days: int = 30):
        """
        初始化分析器
        
        Args:
            expiry_warning_days: 过期预警天数阈值
        """
        self.expiry_warning_days = expiry_warning_days
        self.results = {
            'total_certificates': 0,
            'valid_certificates': 0,
            'expiring_soon_certificates': 0,
            'expired_certificates': 0,
            'crypto_stats': defaultdict(int),
            'san_stats': {
                'with_san': 0,
                'wildcard': 0,
                'domain_counts': defaultdict(int)
            },
            'ca_stats': defaultdict(int),
            'key_usage_stats': defaultdict(int),
            'parse_errors': 0,
            'cert_details': [],
            'total_before_deduplication': 0
        }
        self.certificate_hashes = set()
    
    def safe_division(self, numerator, denominator, default=0):
        """安全的除法运算"""
        if denominator == 0:
            return default
        return numerator / denominator
    
    def analyze_certificates_directory(self, directory_path: str) -> Dict:
        """
        分析目录中的所有证书文件
        
        Args:
            directory_path: 证书文件目录路径
            
        Returns:
            分析结果字典
        """
        logger.info(f"开始分析证书目录: {directory_path}")
        
        # 重置结果
        self.results = {
            'total_certificates': 0,
            'valid_certificates': 0,
            'expiring_soon_certificates': 0,
            'expired_certificates': 0,
            'crypto_stats': defaultdict(int),
            'san_stats': {
                'with_san': 0,
                'wildcard': 0,
                'domain_counts': defaultdict(int)
            },
            'ca_stats': defaultdict(int),
            'key_usage_stats': defaultdict(int),
            'parse_errors': 0,
            'cert_details': [],
            'total_before_deduplication': 0
        }
        self.certificate_hashes = set()
        
        # 支持的证书文件扩展名
        cert_extensions = ('.cer', '.crt', '.pem', '.der')
        
        try:
            # 遍历目录中的所有文件
            for filename in os.listdir(directory_path):
                if filename.lower().endswith(cert_extensions):
                    filepath = os.path.join(directory_path, filename)
                    self._analyze_certificate_file(filepath)
            
            # 计算统计信息
            self._calculate_statistics()
            
            logger.info(f"分析完成: 共处理 {self.results['total_before_deduplication']} 个证书文件")
            logger.info(f"唯一证书数: {self.results['total_certificates']}")
            logger.info(f"解析错误: {self.results['parse_errors']}")
            
            return self.results
            
        except Exception as e:
            logger.error(f"分析证书目录时出错: {str(e)}")
            raise
    
    def _analyze_certificate_file(self, filepath: str) -> None:
        """
        分析单个证书文件
        
        Args:
            filepath: 证书文件路径
        """
        try:
            with open(filepath, 'rb') as f:
                cert_data = f.read()
            
            # 尝试解析证书
            cert = self._parse_certificate(cert_data, filepath)
            if not cert:
                self.results['parse_errors'] += 1
                return
            
            # 计算证书哈希（用于去重）
            cert_hash = self._calculate_certificate_hash(cert)
            self.results['total_before_deduplication'] += 1
            
            # 检查是否已分析过相同证书
            if cert_hash in self.certificate_hashes:
                return
            
            self.certificate_hashes.add(cert_hash)
            self.results['total_certificates'] += 1
            
            # 分析证书详细信息
            cert_info = self._analyze_certificate_details(cert, filepath, cert_hash)
            self.results['cert_details'].append(cert_info)
            
            # 更新统计信息
            self._update_statistics(cert_info)
            
        except Exception as e:
            logger.error(f"分析证书文件 {filepath} 时出错: {str(e)}")
            self.results['parse_errors'] += 1
    
    def _parse_certificate(self, cert_data: bytes, filepath: str) -> Optional[x509.Certificate]:
        """
        解析证书数据
        
        Args:
            cert_data: 证书原始数据
            filepath: 文件路径（用于错误信息）
            
        Returns:
            x509证书对象或None
        """
        try:
            # 尝试DER格式
            try:
                return x509.load_der_x509_certificate(cert_data, default_backend())
            except ValueError:
                # 尝试PEM格式
                try:
                    return x509.load_pem_x509_certificate(cert_data, default_backend())
                except ValueError:
                    logger.warning(f"无法解析证书文件: {filepath}")
                    return None
        except Exception as e:
            logger.error(f"解析证书时出错 {filepath}: {str(e)}")
            return None
    
    def _calculate_certificate_hash(self, cert: x509.Certificate) -> str:
        """
        计算证书哈希（用于去重）
        
        Args:
            cert: x509证书对象
            
        Returns:
            证书哈希值
        """
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_der).hexdigest()
    
    def _analyze_certificate_details(self, cert: x509.Certificate, filepath: str, cert_hash: str) -> Dict:
        """
        分析证书详细信息
        
        Args:
            cert: x509证书对象
            filepath: 文件路径
            cert_hash: 证书哈希
            
        Returns:
            证书详细信息字典
        """
        try:
            # 基本信息
            subject = self._get_name_string(cert.subject)
            issuer = self._get_name_string(cert.issuer)
            
            # 有效期
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            now = datetime.utcnow()
            
            # 证书状态
            is_expired = not_after < now
            days_remaining = (not_after - now).days if not_after > now else 0
            is_expiring_soon = 0 < days_remaining <= self.expiry_warning_days
            
            # 加密信息
            public_key = cert.public_key()
            crypto_info = self._analyze_crypto_strength(public_key)
            
            # SAN信息
            san_info = self._analyze_san_extension(cert)
            
            # 密钥用途
            key_usage = self._analyze_key_usage(cert)
            
            return {
                'file_path': filepath,
                'cert_hash': cert_hash,
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'is_expired': is_expired,
                'is_expiring_soon': is_expiring_soon,
                'days_remaining': days_remaining,
                'crypto_strength': crypto_info,
                'san_domains': san_info['domains'],
                'has_san': san_info['has_san'],
                'has_wildcard': san_info['has_wildcard'],
                'key_usage': key_usage,
                'serial_number': cert.serial_number,
                'version': cert.version.name
            }
            
        except Exception as e:
            logger.error(f"分析证书详细信息时出错: {str(e)}")
            raise
    
    def _get_name_string(self, name: x509.Name) -> str:
        """
        获取名称字符串
        
        Args:
            name: x509名称对象
            
        Returns:
            格式化的名称字符串
        """
        try:
            return ', '.join([f'{attr.oid._name}={attr.value}' for attr in name])
        except:
            return str(name)
    
    def _analyze_crypto_strength(self, public_key) -> str:
        """
        分析加密强度
        
        Args:
            public_key: 公钥对象
            
        Returns:
            加密强度描述
        """
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < 1024:
                    return f"RSA:{key_size}(弱)"
                elif key_size < 2048:
                    return f"RSA:{key_size}(中等)"
                else:
                    return f"RSA:{key_size}(强)"
            
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                if '256' in curve_name:
                    return f"ECC:{curve_name}(强)"
                elif '384' in curve_name:
                    return f"ECC:{curve_name}(很强)"
                else:
                    return f"ECC:{curve_name}"
            
            else:
                return "Unknown"
                
        except Exception as e:
            logger.warning(f"分析加密强度时出错: {str(e)}")
            return "Unknown"
    
    def _analyze_san_extension(self, cert: x509.Certificate) -> Dict:
        """
        分析SAN扩展
        
        Args:
            cert: x509证书对象
            
        Returns:
            SAN信息字典
        """
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value
            domains = []
            has_wildcard = False
            
            for name in san:
                if isinstance(name, x509.DNSName):
                    domains.append(name.value)
                    if name.value.startswith('*'):
                        has_wildcard = True
            
            return {
                'has_san': len(domains) > 0,
                'domains': domains,
                'has_wildcard': has_wildcard,
                'domain_count': len(domains)
            }
            
        except x509.ExtensionNotFound:
            return {
                'has_san': False,
                'domains': [],
                'has_wildcard': False,
                'domain_count': 0
            }
        except Exception as e:
            logger.warning(f"分析SAN扩展时出错: {str(e)}")
            return {
                'has_san': False,
                'domains': [],
                'has_wildcard': False,
                'domain_count': 0
            }
    
    def _analyze_key_usage(self, cert: x509.Certificate) -> List[str]:
        """
        分析密钥用途
        
        Args:
            cert: x509证书对象
            
        Returns:
            密钥用途列表
        """
        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            key_usage = key_usage_ext.value
            usages = []
            
            if key_usage.digital_signature:
                usages.append('Digital Signature')
            if key_usage.key_encipherment:
                usages.append('Key Encipherment')
            if key_usage.data_encipherment:
                usages.append('Data Encipherment')
            if key_usage.key_agreement:
                usages.append('Key Agreement')
            if key_usage.key_cert_sign:
                usages.append('Certificate Sign')
            if key_usage.crl_sign:
                usages.append('CRL Sign')
            
            return usages
            
        except x509.ExtensionNotFound:
            return []
        except Exception as e:
            logger.warning(f"分析密钥用途时出错: {str(e)}")
            return []
    
    def _update_statistics(self, cert_info: Dict) -> None:
        """
        更新统计信息
        
        Args:
            cert_info: 证书信息字典
        """
        try:
            # 证书状态统计
            if cert_info['is_expired']:
                self.results['expired_certificates'] += 1
            elif cert_info['is_expiring_soon']:
                self.results['expiring_soon_certificates'] += 1
            else:
                self.results['valid_certificates'] += 1
            
            # 加密强度统计
            crypto_strength = cert_info.get('crypto_strength', 'Unknown')
            self.results['crypto_stats'][crypto_strength] += 1
            
            # 颁发机构统计
            issuer = cert_info.get('issuer', 'Unknown')
            self.results['ca_stats'][issuer] += 1
            
            # SAN统计
            san_info = {
                'has_san': cert_info.get('has_san', False),
                'has_wildcard': cert_info.get('has_wildcard', False),
                'domain_count': len(cert_info.get('san_domains', []))
            }
            
            if san_info['has_san']:
                self.results['san_stats']['with_san'] += 1
            
            if san_info['has_wildcard']:
                self.results['san_stats']['wildcard'] += 1
            
            self.results['san_stats']['domain_counts'][san_info['domain_count']] += 1
            
            # 密钥用途统计
            key_usages = cert_info.get('key_usage', [])
            for usage in key_usages:
                self.results['key_usage_stats'][usage] += 1
                
        except Exception as e:
            logger.error(f"更新统计信息时出错: {str(e)}")
    
    def _calculate_statistics(self) -> None:
        """
        计算最终统计信息
        """
        try:
            # 确保数值有效性
            total = max(1, self.results['total_certificates'])
            
            # 计算百分比（使用安全除法）
            self.results['valid_percentage'] = round(
                self.safe_division(self.results['valid_certificates'], total) * 100, 1
            )
            self.results['expiring_percentage'] = round(
                self.safe_division(self.results['expiring_soon_certificates'], total) * 100, 1
            )
            self.results['expired_percentage'] = round(
                self.safe_division(self.results['expired_certificates'], total) * 100, 1
            )
            
        except Exception as e:
            logger.error(f"计算统计信息时出错: {str(e)}")
            # 设置默认值
            self.results['valid_percentage'] = 0.0
            self.results['expiring_percentage'] = 0.0
            self.results['expired_percentage'] = 0.0

def main():
    """主函数"""
    import sys
    
    if len(sys.argv) != 2:
        print("使用方法: python certificate_validity_analyzer.py <证书目录>")
        sys.exit(1)
    
    cert_dir = sys.argv[1]
    analyzer = CertificateValidityAnalyzer(expiry_warning_days=30)
    
    try:
        results = analyzer.analyze_certificates_directory(cert_dir)
        print(json.dumps(results, indent=2, default=str))
    except Exception as e:
        print(f"分析失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()