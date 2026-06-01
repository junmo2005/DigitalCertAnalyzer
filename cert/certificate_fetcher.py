# certificate_fetcher.py - 完整优化版
import socket
import ssl
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple, Dict, Any, List
import logging
import time

logger = logging.getLogger(__name__)

# 禁用 requests 的 SSL 警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CertificateFetcher:
    """证书获取器 - 优化版"""
    
    def __init__(self, timeout: int = 3, max_retries: int = 1):
        """
        初始化证书获取器
        
        Args:
            timeout: 超时时间（秒），默认3秒
            max_retries: 最大重试次数，默认1次
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self._setup_session()
    
    def _setup_session(self):
        """设置 requests session（禁用代理，优化连接池）"""
        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False  # 关键：禁用系统代理
        self.session.proxies = {'http': None, 'https': None}  # 明确禁用代理
        
        # 配置连接池适配器
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=1,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # 设置默认请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def fetch_certificate_from_domain(self, domain: str, port: int = 443) -> Tuple[Optional[bytes], Optional[Dict]]:
        """
        从域名获取证书（带重试）
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            (证书数据, 证书信息)
        """
        for attempt in range(self.max_retries):
            try:
                result = self._fetch_certificate_socket(domain, port)
                if result[0] is not None:
                    return result
            except Exception as e:
                logger.debug(f"获取证书失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                
                if attempt < self.max_retries - 1:
                    time.sleep(0.5)  # 短暂等待后重试
        
        logger.warning(f"获取 {domain} 证书失败（已重试 {self.max_retries} 次）")
        return None, None
    
    def _fetch_certificate_socket(self, domain: str, port: int = 443) -> Tuple[Optional[bytes], Optional[Dict]]:
        """使用 socket 获取证书"""
        # 尝试多个 TLS 版本
        ssl_configs = [
            # 配置1：现代 TLS（TLS 1.2+）
            {
                'context': ssl.create_default_context(),
                'options': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            },
            # 配置2：兼容旧版 TLS
            {
                'context': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
                'options': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            },
            # 配置3：最宽松配置
            {
                'context': ssl._create_unverified_context(),
                'options': 0
            }
        ]
        
        last_error = None
        
        for i, config in enumerate(ssl_configs):
            try:
                context = config['context']
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # 创建连接（使用更短的超时）
                sock = socket.create_connection((domain, port), timeout=min(self.timeout, 5))
                
                try:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # 设置超时
                        ssock.settimeout(self.timeout)
                        
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_info = ssock.getpeercert()
                        
                        if cert_der:
                            logger.debug(f"成功从 {domain} 获取证书（配置{i+1}）")
                            return cert_der, cert_info
                            
                except ssl.SSLError as e:
                    last_error = e
                    logger.debug(f"SSL配置{i+1}失败: {e}")
                    continue
                finally:
                    sock.close()
                    
            except socket.timeout:
                last_error = "连接超时"
                continue
            except socket.gaierror:
                last_error = "域名解析失败"
                break  # DNS失败不需要重试其他配置
            except ConnectionRefusedError:
                last_error = "连接被拒绝"
                break
            except Exception as e:
                last_error = str(e)
                continue
        
        logger.debug(f"获取 {domain} 证书失败: {last_error}")
        return None, None
    
    def fetch_certificate_chain(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """
        获取完整证书链（带重试和多种方法）
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            (证书链数据, 证书信息)
        """
        for attempt in range(self.max_retries):
            # 方法1：使用 requests（可以获取更多信息）
            result = self._fetch_chain_requests(domain, port)
            if result[0] is not None:
                return result
            
            # 方法2：使用 socket + OpenSSL
            result = self._fetch_chain_openssl(domain, port)
            if result[0] is not None:
                return result
            
            # 方法3：只获取叶子证书
            result = self._fetch_chain_fallback(domain, port)
            if result[0] is not None:
                return result
            
            if attempt < self.max_retries - 1:
                time.sleep(0.5)
        
        logger.warning(f"获取 {domain} 证书链失败（已重试 {self.max_retries} 次）")
        return None, None
    
    def _fetch_chain_requests(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """使用 requests 获取证书链"""
        try:
            url = f"https://{domain}:{port}"
            response = self.session.get(url, timeout=self.timeout)
            
            # 尝试从连接中提取证书
            if hasattr(response, 'raw') and hasattr(response.raw, '_connection'):
                conn = response.raw._connection
                if hasattr(conn, 'sock'):
                    sock = conn.sock
                    
                    # 尝试获取证书链
                    if hasattr(sock, 'getpeercertchain'):
                        try:
                            cert_chain = sock.getpeercertchain()
                            cert_info = sock.getpeercert()
                            if cert_chain:
                                logger.debug(f"requests 获取到 {len(cert_chain)} 个证书")
                                return cert_chain, cert_info
                        except:
                            pass
                    
                    # 只获取叶子证书
                    if hasattr(sock, 'getpeercert'):
                        cert_der = sock.getpeercert(binary_form=True)
                        if cert_der:
                            logger.debug(f"requests 获取到叶子证书")
                            return [cert_der], sock.getpeercert()
                            
        except requests.exceptions.Timeout:
            logger.debug(f"requests 请求 {domain} 超时")
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"requests 连接 {domain} 失败: {e}")
        except Exception as e:
            logger.debug(f"requests 获取 {domain} 证书链失败: {e}")
        
        return None, None
    
    def _fetch_chain_openssl(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """使用 pyOpenSSL 获取证书链"""
        try:
            # 先获取叶子证书
            cert_der, cert_info = self._fetch_certificate_socket(domain, port)
            if not cert_der:
                return None, None
            
            # 使用 pyOpenSSL 解析
            try:
                pem_data = ssl.DER_cert_to_PEM_cert(cert_der)
                x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data)
                
                # 构建证书链（pyOpenSSL 可以获取更多信息）
                chain = [cert_der]
                
                # 尝试获取颁发者信息
                issuer = x509_cert.get_issuer()
                if issuer:
                    logger.debug(f"pyOpenSSL 解析成功，颁发者: {issuer.CN}")
                
                return chain, cert_info
                
            except Exception as e:
                logger.debug(f"pyOpenSSL 解析失败: {e}")
                return [cert_der], cert_info
                
        except Exception as e:
            logger.debug(f"OpenSSL 方式失败: {e}")
        
        return None, None
    
    def _fetch_chain_fallback(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """降级方案：只获取叶子证书"""
        try:
            cert_der, cert_info = self._fetch_certificate_socket(domain, port)
            if cert_der:
                logger.debug(f"降级方案获取到叶子证书")
                return [cert_der], cert_info
        except Exception as e:
            logger.debug(f"降级方案失败: {e}")
        
        return None, None
    
    def _get_certificate_chain_socket(self, domain: str, port: int = 443) -> Tuple[Optional[List[bytes]], Optional[Dict]]:
        """
        使用socket获取证书链（兼容旧接口）
        注意：Python标准库的 SSLSocket 没有 getpeercertchain() 方法
        """
        logger.warning(f"_get_certificate_chain_socket 已被弃用，请使用 fetch_certificate_chain")
        return self._fetch_chain_fallback(domain, port)
    
    def parse_certificate_info(self, cert_data: bytes) -> Dict[str, Any]:
        """
        解析证书信息（安全处理）
        
        Args:
            cert_data: 证书数据
            
        Returns:
            证书详细信息
        """
        try:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # 安全地获取 subject
            subject_dict = {}
            for attr in cert.subject:
                try:
                    subject_dict[attr.oid._name] = str(attr.value)
                except:
                    subject_dict[str(attr.oid)] = str(attr.value)
            
            # 安全地获取 issuer
            issuer_dict = {}
            for attr in cert.issuer:
                try:
                    issuer_dict[attr.oid._name] = str(attr.value)
                except:
                    issuer_dict[str(attr.oid)] = str(attr.value)
            
            # 安全地获取签名算法
            try:
                sig_algo = cert.signature_algorithm_oid._name
            except:
                sig_algo = str(cert.signature_algorithm_oid)
            
            # 安全地获取公钥类型
            try:
                pub_key = cert.public_key()
                pub_key_type = type(pub_key).__name__
            except:
                pub_key_type = "Unknown"
            
            # 安全地获取版本
            try:
                version = cert.version.value if hasattr(cert.version, 'value') else str(cert.version)
            except:
                version = "Unknown"
            
            return {
                'subject': subject_dict,
                'issuer': issuer_dict,
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'serial_number': str(cert.serial_number),
                'version': version,
                'signature_algorithm': sig_algo,
                'public_key_type': pub_key_type,
                'extensions': self._parse_extensions(cert)
            }
        except Exception as e:
            logger.error(f"解析证书信息失败: {str(e)}")
            return {
                'error': str(e),
                'raw_length': len(cert_data) if cert_data else 0
            }
    
    def _parse_extensions(self, cert: x509.Certificate) -> Dict[str, Any]:
        """解析证书扩展"""
        extensions = {}
        try:
            for ext in cert.extensions:
                try:
                    ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                    extensions[ext_name] = str(ext.value)
                except:
                    pass
        except Exception as e:
            logger.debug(f"解析证书扩展失败: {str(e)}")
        
        return extensions


# ====================== 兼容旧接口 ======================

# 为了兼容旧代码，保留原有的方法签名
def get_certificate_chain_socket(domain: str, port: int = 443):
    """兼容旧接口"""
    fetcher = CertificateFetcher()
    return fetcher._fetch_chain_fallback(domain, port)