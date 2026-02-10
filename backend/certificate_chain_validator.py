from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from typing import List, Tuple, Dict, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CertificateChainValidator:
    """证书链验证器"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def validate_certificate_chain(self, cert_chain: List[bytes]) -> Tuple[bool, List[str], Dict]:
        """
        验证证书链完整性
        
        Args:
            cert_chain: 证书链（叶子证书在前）
            
        Returns:
            (是否有效, 问题列表, 详细报告)
        """
        issues = []
        report = {
            'chain_length': len(cert_chain),
            'valid_chain': False,
            'certificates': [],
            'validation_time': datetime.now().isoformat()
        }
        
        try:
            if not cert_chain:
                issues.append("证书链为空")
                return False, issues, report
            
            # 解析所有证书
            certificates = []
            for i, cert_data in enumerate(cert_chain):
                try:
                    cert = x509.load_der_x509_certificate(cert_data, self.backend)
                    certificates.append(cert)
                    
                    # 记录证书基本信息
                    cert_info = {
                        'index': i,
                        'subject': self._get_name_string(cert.subject),
                        'issuer': self._get_name_string(cert.issuer),
                        'not_before': cert.not_valid_before.isoformat(),
                        'not_after': cert.not_valid_after.isoformat(),
                        'serial_number': str(cert.serial_number),
                        'is_ca': self._is_ca_certificate(cert),
                        'is_self_signed': self._is_self_signed(cert)
                    }
                    report['certificates'].append(cert_info)
                    
                except Exception as e:
                    issues.append(f"证书 {i} 解析失败: {str(e)}")
                    return False, issues, report
            
            # 检查证书链长度
            if len(certificates) < 2:
                issues.append("证书链不完整，至少需要叶子证书和中间CA证书")
            
            # 验证证书链签名
            chain_valid = self._validate_chain_signature(certificates, issues)
            
            # 检查有效期
            self._check_validity_periods(certificates, issues)
            
            # 检查基本约束
            self._check_basic_constraints(certificates, issues)
            
            # 检查密钥用法
            self._check_key_usage(certificates, issues)
            
            report['valid_chain'] = len(issues) == 0
            report['issues'] = issues.copy()
            
            return len(issues) == 0, issues, report
            
        except Exception as e:
            error_msg = f"证书链验证异常: {str(e)}"
            issues.append(error_msg)
            logger.error(error_msg)
            return False, issues, report
    
    def _validate_chain_signature(self, certificates: List[x509.Certificate], issues: List[str]) -> bool:
        """验证证书链签名"""
        chain_valid = True
        
        for i in range(len(certificates) - 1):
            subject_cert = certificates[i]
            issuer_cert = certificates[i + 1]
            
            try:
                # 验证签名
                public_key = issuer_cert.public_key()
                # 注意：这里需要更复杂的签名验证逻辑
                # 实际项目中应该使用完整的签名验证
                
                # 简化验证：检查颁发者名称匹配
                if subject_cert.issuer != issuer_cert.subject:
                    issues.append(f"证书 {i} 的颁发者与证书 {i+1} 的主题不匹配")
                    chain_valid = False
                    
            except Exception as e:
                issues.append(f"证书链签名验证失败 (证书 {i}): {str(e)}")
                chain_valid = False
        
        return chain_valid
    
    def _check_validity_periods(self, certificates: List[x509.Certificate], issues: List[str]):
        """检查有效期"""
        current_time = datetime.utcnow()
        
        for i, cert in enumerate(certificates):
            if cert.not_valid_after < current_time:
                issues.append(f"证书 {i} 已过期: {cert.not_valid_after}")
            if cert.not_valid_before > current_time:
                issues.append(f"证书 {i} 尚未生效: {cert.not_valid_before}")
    
    def _check_basic_constraints(self, certificates: List[x509.Certificate], issues: List[str]):
        """检查基本约束"""
        for i, cert in enumerate(certificates):
            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                basic_constraints = bc_ext.value
                
                if i == 0 and basic_constraints.ca:  # 叶子证书不应是CA
                    issues.append("叶子证书不应具有CA基本约束")
                elif i > 0 and not basic_constraints.ca:  # 中间证书应该是CA
                    issues.append(f"中间证书 {i} 应具有CA基本约束")
                    
            except x509.ExtensionNotFound:
                if i > 0:  # 中间证书应该具有基本约束扩展
                    issues.append(f"中间证书 {i} 缺少基本约束扩展")
    
    def _check_key_usage(self, certificates: List[x509.Certificate], issues: List[str]):
        """检查密钥用法"""
        for i, cert in enumerate(certificates):
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                key_usage = ku_ext.value
                
                if i == 0:  # 叶子证书
                    if not key_usage.digital_signature:
                        issues.append(f"叶子证书应具有数字签名密钥用法")
                elif i > 0:  # CA证书
                    if not key_usage.key_cert_sign:
                        issues.append(f"CA证书 {i} 应具有证书签名密钥用法")
                        
            except x509.ExtensionNotFound:
                if i > 0:  # CA证书应该具有密钥用法扩展
                    issues.append(f"CA证书 {i} 缺少密钥用法扩展")
    
    def _get_name_string(self, name: x509.Name) -> str:
        """获取名称字符串"""
        try:
            return ', '.join([f'{attr.oid._name}={attr.value}' for attr in name])
        except:
            return str(name)
    
    def _is_ca_certificate(self, cert: x509.Certificate) -> bool:
        """检查是否为CA证书"""
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            return bc_ext.value.ca
        except x509.ExtensionNotFound:
            return False
    
    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        """检查是否为自签名证书"""
        return cert.subject == cert.issuer
    
    def validate_certificate_files(self, cert_files: List[bytes]) -> Tuple[bool, List[str], Dict]:
        """
        验证证书文件链
        
        Args:
            cert_files: 证书文件数据列表
            
        Returns:
            (是否有效, 问题列表, 详细报告)
        """
        return self.validate_certificate_chain(cert_files)