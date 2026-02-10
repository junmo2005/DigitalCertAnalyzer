import socket
import ssl
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib3.util.ssl_ import create_urllib3_context
import OpenSSL
from typing import Optional, Tuple, Dict, Any,List
import logging

logger = logging.getLogger(__name__)

class CertificateFetcher:
    """证书获取器 - 从域名获取真实证书"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def fetch_certificate_from_domain(self, domain: str, port: int = 443) -> Tuple[Optional[bytes], Optional[Dict]]:
        """
        从域名获取证书
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            (证书数据, 证书信息)
        """
        try:
            # 创建SSL上下文
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 连接并获取证书
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    
                    if cert_der:
                        return cert_der, cert_info
                    else:
                        logger.warning(f"无法从 {domain} 获取证书")
                        return None, None
                        
        except Exception as e:
            logger.error(f"获取 {domain} 证书失败: {str(e)}")
            return None, None
    
    def fetch_certificate_chain(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """
        获取完整证书链
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            (证书链数据, 证书信息)
        """
        try:
            # 使用requests获取更详细的证书信息
            session = requests.Session()
            response = session.get(f"https://{domain}:{port}", timeout=self.timeout, verify=False)
            
            # 从响应中提取证书信息
            if hasattr(response.connection, 'sock') and hasattr(response.connection.sock, 'getpeercert'):
                cert_info = response.connection.sock.getpeercert()
                cert_chain = response.connection.sock.getpeercertchain()
                
                if cert_chain:
                    return cert_chain, cert_info
            
            # 备选方法：使用socket直接获取
            return self._get_certificate_chain_socket(domain, port)
            
        except Exception as e:
            logger.error(f"获取 {domain} 证书链失败: {str(e)}")
            return None, None
    
    def _get_certificate_chain_socket(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """使用socket获取证书链"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # 获取证书链
                    cert_chain = ssock.getpeercertchain()
                    cert_info = ssock.getpeercert()
                    
                    return cert_chain, cert_info
                    
        except Exception as e:
            logger.error(f"Socket方式获取 {domain} 证书链失败: {str(e)}")
            return None, None
    
    def parse_certificate_info(self, cert_data: bytes) -> Dict[str, Any]:
        """
        解析证书信息
        
        Args:
            cert_data: 证书数据
            
        Returns:
            证书详细信息
        """
        try:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            return {
                'subject': dict(cert.subject),
                'issuer': dict(cert.issuer),
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'serial_number': str(cert.serial_number),
                'version': cert.version,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_type': type(cert.public_key()).__name__,
                'extensions': self._parse_extensions(cert)
            }
        except Exception as e:
            logger.error(f"解析证书信息失败: {str(e)}")
            return {}
    
    def _parse_extensions(self, cert: x509.Certificate) -> Dict[str, Any]:
        """解析证书扩展"""
        extensions = {}
        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                extensions[ext_name] = str(ext.value)
        except Exception as e:
            logger.warning(f"解析证书扩展失败: {str(e)}")
        
        return extensions