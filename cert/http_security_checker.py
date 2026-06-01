# http_security_checker.py - 完整优化版
import requests
from urllib.parse import urlparse
import re
from typing import Dict, Optional, Tuple, Any
import logging
import ssl
import socket
import time

logger = logging.getLogger(__name__)


class HttpSecurityChecker:
    """HTTP安全检查器 - 优化版"""
    
    def __init__(self, timeout: int = 3, max_retries: int = 1):
        """
        初始化安全检查器
        
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
        
        # 禁用SSL验证以便检查有问题的证书
        self.session.verify = False
        
        # 关键：禁用系统代理
        self.session.trust_env = False
        self.session.proxies = {'http': None, 'https': None}
        
        # 配置连接池适配器（提高并发性能）
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'  # 避免 keep-alive 导致的超时
        })
        
        # 忽略SSL警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _request_with_retry(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        带重试的请求
        
        Args:
            url: 请求URL
            method: 请求方法
            **kwargs: 传递给 requests 的参数
            
        Returns:
            响应对象，失败返回None
        """
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                return response
                
            except requests.exceptions.Timeout:
                logger.debug(f"请求超时 {url} (尝试 {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(0.3)
                    
            except requests.exceptions.ConnectionError as e:
                logger.debug(f"连接错误 {url}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(0.5)
                    
            except requests.exceptions.SSLError as e:
                logger.debug(f"SSL错误 {url}: {e}")
                # SSL错误不重试
                break
                
            except Exception as e:
                logger.debug(f"请求异常 {url}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(0.3)
        
        return None
    
    def check_https_redirect(self, domain: str) -> Dict[str, Any]:
        """
        检查HTTPS重定向
        
        Args:
            domain: 域名
            
        Returns:
            {
                'enabled': bool,
                'redirect_url': str or None,
                'status_code': int or None,
                'error': str or None
            }
        """
        result = {
            'enabled': False,
            'redirect_url': None,
            'status_code': None,
            'error': None
        }
        
        try:
            http_url = f"http://{domain}"
            response = self._request_with_retry(http_url, allow_redirects=False)
            
            if response is None:
                result['error'] = '连接失败'
                return result
            
            result['status_code'] = response.status_code
            
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                result['redirect_url'] = location
                
                if location.startswith('https://'):
                    result['enabled'] = True
                elif location.startswith('/'):
                    # 相对路径重定向
                    result['redirect_url'] = f"https://{domain}{location}"
                    result['enabled'] = False
            elif response.status_code == 200:
                # 直接HTTP访问成功，未配置重定向
                result['enabled'] = False
                
        except Exception as e:
            logger.debug(f"HTTPS重定向检查失败 {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    def check_hsts_header(self, domain: str) -> Dict[str, Any]:
        """
        检查HSTS头
        
        Args:
            domain: 域名
            
        Returns:
            {
                'enabled': bool,
                'max_age': int,
                'include_subdomains': bool,
                'preload': bool,
                'raw_header': str or None,
                'error': str or None
            }
        """
        result = {
            'enabled': False,
            'max_age': 0,
            'include_subdomains': False,
            'preload': False,
            'raw_header': None,
            'error': None
        }
        
        try:
            https_url = f"https://{domain}"
            response = self._request_with_retry(https_url)
            
            if response is None:
                result['error'] = '连接失败'
                return result
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if not hsts_header:
                result['error'] = 'NO_HSTS_HEADER'
                return result
            
            result['raw_header'] = hsts_header
            hsts_info = self._parse_hsts_header(hsts_header)
            
            result['max_age'] = hsts_info['max-age']
            result['include_subdomains'] = hsts_info['includeSubDomains']
            result['preload'] = hsts_info['preload']
            result['enabled'] = hsts_info['max-age'] > 0
            
        except Exception as e:
            logger.debug(f"HSTS检查失败 {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _parse_hsts_header(self, hsts_header: str) -> Dict[str, Any]:
        """
        解析HSTS头
        
        Args:
            hsts_header: HSTS头内容
            
        Returns:
            HSTS信息字典
        """
        hsts_info = {
            'max-age': 0,
            'includeSubDomains': False,
            'preload': False,
            'raw_header': hsts_header
        }
        
        try:
            parts = [part.strip() for part in hsts_header.split(';')]
            
            for part in parts:
                part_lower = part.lower()
                if 'max-age' in part_lower:
                    try:
                        max_age_str = part.split('=')[1].strip()
                        hsts_info['max-age'] = int(max_age_str)
                    except (IndexError, ValueError, AttributeError):
                        pass
                elif 'includesubdomains' in part_lower:
                    hsts_info['includeSubDomains'] = True
                elif 'preload' in part_lower:
                    hsts_info['preload'] = True
            
            return hsts_info
            
        except Exception as e:
            logger.debug(f"解析HSTS头失败: {e}")
            return hsts_info
    
    def check_security_headers(self, domain: str) -> Dict[str, Any]:
        """
        检查所有安全头
        
        Args:
            domain: 域名
            
        Returns:
            安全头信息字典
        """
        result = {
            'content_security_policy': None,
            'x_content_type_options': None,
            'x_frame_options': None,
            'x_xss_protection': None,
            'referrer_policy': None,
            'feature_policy': None,
            'permissions_policy': None,
            'assessment': {},
            'error': None
        }
        
        try:
            https_url = f"https://{domain}"
            response = self._request_with_retry(https_url)
            
            if response is None:
                result['error'] = '连接失败'
                return result
            
            headers = response.headers
            
            # 检查常见安全头
            result['content_security_policy'] = headers.get('Content-Security-Policy')
            result['x_content_type_options'] = headers.get('X-Content-Type-Options')
            result['x_frame_options'] = headers.get('X-Frame-Options')
            result['x_xss_protection'] = headers.get('X-XSS-Protection')
            result['referrer_policy'] = headers.get('Referrer-Policy')
            result['feature_policy'] = headers.get('Feature-Policy')
            result['permissions_policy'] = headers.get('Permissions-Policy')
            
            # 评估安全头状态
            result['assessment'] = self._assess_security_headers(result)
            
        except Exception as e:
            logger.debug(f"安全头检查失败 {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _assess_security_headers(self, security_headers: Dict) -> Dict[str, bool]:
        """评估安全头状态"""
        assessment = {
            'has_csp': False,
            'has_x_content_type_options': False,
            'has_x_frame_options': False,
            'has_referrer_policy': False,
            'csp_insecure': False,
            'x_frame_options_insecure': False
        }
        
        # CSP检查
        csp = security_headers.get('content_security_policy')
        if csp:
            assessment['has_csp'] = True
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                assessment['csp_insecure'] = True
        
        # X-Content-Type-Options检查
        xcto = security_headers.get('x_content_type_options')
        if xcto and xcto.lower() == 'nosniff':
            assessment['has_x_content_type_options'] = True
        
        # X-Frame-Options检查
        xfo = security_headers.get('x_frame_options')
        if xfo:
            assessment['has_x_frame_options'] = True
            xfo_upper = xfo.upper()
            if xfo_upper not in ['DENY', 'SAMEORIGIN']:
                assessment['x_frame_options_insecure'] = True
        
        # Referrer-Policy检查
        if security_headers.get('referrer_policy'):
            assessment['has_referrer_policy'] = True
        
        return assessment
    
    def get_ssl_certificate_info(self, domain: str, port: int = 443) -> Optional[Dict]:
        """
        获取SSL证书信息（支持多种TLS版本）
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            SSL证书信息
        """
        # 尝试多种SSL配置
        ssl_configs = [
            # 配置1：现代TLS
            {
                'context': ssl.create_default_context(),
                'name': 'modern'
            },
            # 配置2：兼容旧版TLS
            {
                'context': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
                'name': 'compatible'
            },
            # 配置3：最宽松
            {
                'context': ssl._create_unverified_context(),
                'name': 'legacy'
            }
        ]
        
        for config in ssl_configs:
            try:
                context = config['context']
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # 设置更短的连接超时
                sock = socket.create_connection((domain, port), timeout=min(self.timeout, 5))
                
                try:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        ssock.settimeout(self.timeout)
                        cert = ssock.getpeercert()
                        if cert:
                            logger.debug(f"获取SSL证书成功 {domain} (配置: {config['name']})")
                            return cert
                finally:
                    sock.close()
                    
            except socket.timeout:
                logger.debug(f"SSL连接超时 {domain} (配置: {config['name']})")
                continue
            except ssl.SSLError as e:
                logger.debug(f"SSL错误 {domain} (配置: {config['name']}): {e}")
                continue
            except Exception as e:
                logger.debug(f"SSL连接失败 {domain} (配置: {config['name']}): {e}")
                continue
        
        logger.debug(f"获取SSL证书信息失败 {domain}: 所有配置均失败")
        return None
    
    def check_all(self, domain: str) -> Dict[str, Any]:
        """
        执行所有安全检查（便捷方法）
        
        Args:
            domain: 域名
            
        Returns:
            完整的安全检查结果
        """
        return {
            'domain': domain,
            'https_redirect': self.check_https_redirect(domain),
            'hsts': self.check_hsts_header(domain),
            'security_headers': self.check_security_headers(domain),
            'ssl_certificate': self.get_ssl_certificate_info(domain),
            'timestamp': time.time()
        }


# ====================== 兼容旧接口 ======================

# 为了兼容旧代码，保留原有的返回格式
class HttpSecurityCheckerCompat(HttpSecurityChecker):
    """兼容旧接口的HTTP安全检查器"""
    
    def check_https_redirect_compat(self, domain: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """兼容旧版返回格式"""
        result = self.check_https_redirect(domain)
        return (
            result['enabled'],
            result['redirect_url'],
            {
                'status_code': result['status_code'],
                'error': result['error']
            }
        )
    
    def check_hsts_header_compat(self, domain: str) -> Tuple[bool, Optional[Dict], Optional[Dict], Optional[str]]:
        """兼容旧版返回格式"""
        result = self.check_hsts_header(domain)
        hsts_info = {
            'max-age': result['max_age'],
            'includeSubDomains': result['include_subdomains'],
            'preload': result['preload'],
            'raw_header': result['raw_header']
        } if result['enabled'] or result['raw_header'] else None
        
        return (
            result['enabled'],
            hsts_info,
            None,  # headers_info 不再返回
            result['error']
        )