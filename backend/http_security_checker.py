import requests
from urllib.parse import urlparse
import re
from typing import Dict, Optional, Tuple, Any
import logging
import ssl
import socket

logger = logging.getLogger(__name__)

class HttpSecurityChecker:
    """HTTP安全检查器"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        # 禁用SSL验证以便能够检查有问题的证书
        self.session.verify = False
        # 忽略不安全的请求警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def check_https_redirect(self, domain: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        检查HTTPS重定向
        
        Args:
            domain: 域名
            
        Returns:
            (是否重定向, 重定向目标, 详细信息)
        """
        try:
            http_url = f"http://{domain}"
            response = self.session.get(http_url, allow_redirects=False, timeout=self.timeout)
            
            redirect_info = {
                'status_code': response.status_code,
                'location': response.headers.get('Location'),
                'final_url': http_url
            }
            
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                redirect_info['final_url'] = location
                
                if location.startswith('https://'):
                    return True, location, redirect_info
                else:
                    return False, location, redirect_info
            else:
                return False, None, redirect_info
                
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTPS重定向检查失败 {domain}: {str(e)}")
            return False, None, {'error': str(e)}

    def check_hsts_header(self, domain: str) -> Tuple[bool, Optional[Dict], Optional[Dict]]:
        """
        检查HSTS头
        
        Args:
            domain: 域名
            
        Returns:
            (是否启用HSTS, HSTS信息, 响应头信息，错误类型)
        """
        try:
            https_url = f"https://{domain}"
            # 添加更详细的请求配置
            response = self.session.get(
                https_url, 
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            headers_info = dict(response.headers)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if not hsts_header:
                # 明确区分"没有HSTS"和"请求成功但没有HSTS头"
                return False, None, headers_info, "NO_HSTS_HEADER"
            
            # 解析HSTS头
            hsts_info = self._parse_hsts_header(hsts_header)
            is_valid = hsts_info['max-age'] > 0
            
            return is_valid, hsts_info, headers_info, None
            
        except requests.exceptions.Timeout:
            logger.error(f"HSTS检查超时 {domain}")
            return False, None, None, "TIMEOUT"
        
        except requests.exceptions.SSLError as e:
            logger.error(f"HSTS检查SSL错误 {domain}: {str(e)}")
            return False, None, None, "SSL_ERROR"
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"HSTS检查连接错误 {domain}: {str(e)}")
            return False, None, None, "CONNECTION_ERROR"
        
        except requests.exceptions.RequestException as e:
            logger.error(f"HSTS检查请求异常 {domain}: {str(e)}")
            return False, None, None, "REQUEST_ERROR"
    
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
                if 'max-age' in part.lower():
                    try:
                        max_age_str = part.split('=')[1].strip()
                        hsts_info['max-age'] = int(max_age_str)
                    except (IndexError, ValueError, AttributeError):
                        pass
                elif 'includesubdomains' in part.lower():
                    hsts_info['includeSubDomains'] = True
                elif 'preload' in part.lower():
                    hsts_info['preload'] = True
            
            return hsts_info
            
        except Exception as e:
            logger.warning(f"解析HSTS头失败: {hsts_header}, 错误: {str(e)}")
            return hsts_info
    
    def check_security_headers(self, domain: str) -> Dict[str, Any]:
        """
        检查所有安全头
        
        Args:
            domain: 域名
            
        Returns:
            安全头信息字典
        """
        try:
            https_url = f"https://{domain}"
            response = self.session.get(https_url, timeout=self.timeout)
            
            headers = dict(response.headers)
            security_headers = {}
            
            # 检查常见安全头
            security_headers['content_security_policy'] = headers.get('Content-Security-Policy')
            security_headers['x_content_type_options'] = headers.get('X-Content-Type-Options')
            security_headers['x_frame_options'] = headers.get('X-Frame-Options')
            security_headers['x_xss_protection'] = headers.get('X-XSS-Protection')
            security_headers['referrer_policy'] = headers.get('Referrer-Policy')
            security_headers['feature_policy'] = headers.get('Feature-Policy')
            security_headers['permissions_policy'] = headers.get('Permissions-Policy')
            
            # 评估安全头状态
            security_headers['assessment'] = self._assess_security_headers(security_headers)
            
            return security_headers
            
        except requests.exceptions.RequestException as e:
            logger.error(f"安全头检查失败 {domain}: {str(e)}")
            return {'error': str(e)}
    
    def _assess_security_headers(self, security_headers: Dict) -> Dict[str, bool]:
        """评估安全头状态"""
        assessment = {}
        
        # 检查关键安全头
        assessment['has_csp'] = bool(security_headers.get('content_security_policy'))
        assessment['has_x_content_type_options'] = security_headers.get('x_content_type_options') == 'nosniff'
        assessment['has_x_frame_options'] = bool(security_headers.get('x_frame_options'))
        assessment['has_referrer_policy'] = bool(security_headers.get('referrer_policy'))
        
        return assessment
    
    def get_ssl_certificate_info(self, domain: str, port: int = 443) -> Optional[Dict]:
        """
        获取SSL证书信息
        
        Args:
            domain: 域名
            port: 端口号
            
        Returns:
            SSL证书信息
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert
                    
        except Exception as e:
            logger.error(f"获取SSL证书信息失败 {domain}: {str(e)}")
            return None