# security_routes.py - 资产化数据库集成版（添加动态困难域名检测）
# 优化项：并发分析 + tshark解析 + 域名缓存 + 最优配置

from flask import request, jsonify, send_file
import os
import traceback
import shutil
import threading
import uuid
import concurrent.futures
import time
import hashlib
import json
from datetime import datetime
from werkzeug.utils import secure_filename
import logging
import base64
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import socket
socket.setdefaulttimeout(10)  # 全局10秒超时

# 导入核心模块
from certificate_security_enhancer import CertificateSecurityEnhancer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils.file_utils import is_valid_domain, extract_archive, find_certificate_files
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db_session import get_db, set_current_task_id
logger = logging.getLogger(__name__)

# ====================== 性能配置（12核16线程优化） ======================
MAX_CONCURRENT_DOMAINS = 50          # 并发分析域名数
DOMAIN_ANALYSIS_TIMEOUT = 8          # 单域名超时（秒）
MAX_ANALYZE_DOMAINS = 3000           # 单次最大分析域名数
USE_TSHARK_FOR_PCAP = True           # 使用 tshark 加速 PCAP 解析
ENABLE_DOMAIN_CACHE = True           # 启用域名分析缓存
PCAP_EXTRACT_TIMEOUT = 180           # PCAP提取超时（秒）
THREAD_POOL_SIZE = 50                # 线程池大小

# ====================== 困难域名管理 ======================
DIFFICULT_DOMAINS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'difficult_domains.json')
_difficult_domains_cache = set()
_difficult_patterns_cache = []
_difficult_lock = threading.RLock()

def _load_difficult_domains():
    """加载困难域名数据库（修复版）"""
    global _difficult_domains_cache, _difficult_patterns_cache
    
    try:
        os.makedirs(os.path.dirname(DIFFICULT_DOMAINS_FILE), exist_ok=True)
        
        if os.path.exists(DIFFICULT_DOMAINS_FILE):
            with open(DIFFICULT_DOMAINS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                _difficult_domains_cache = set(data.get('domains', []))
                _difficult_patterns_cache = data.get('patterns', [])
        else:
            _init_default_difficult_domains()  # 提取为独立函数
            
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"困难域名数据库损坏或丢失: {e}，将重建默认数据")
        _init_default_difficult_domains()
        _save_difficult_domains()  # 重建文件
        
    except Exception as e:
        logger.error(f"加载困难域名数据库失败: {e}")
        _init_default_difficult_domains()

def _init_default_difficult_domains():
    """初始化默认困难域名（去重版）"""
    global _difficult_domains_cache, _difficult_patterns_cache
    
    _difficult_domains_cache = {
        # 被墙服务
        'google.com', 'googleapis.com', 'gmail.com', 'youtube.com', 'ytimg.com',
        'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
        'twitter.com', 'twimg.com', 't.co',
        'telegram.org', 'discord.com', 'discord.gg',
        # 常见超时域名（去重）
        'tqos.anticheatexpert.com', 'ws.chatgpt.com', 'superyou.zapto.org',
        'frontier100-toutiao-hl.fqnovel.com', 'tracker.moxing.party',
        'control.mna.qq.com', 'dns.msftncsi.com', 'nexus-websocket-a.intercom.io',
        '19jp.networklinkpro.net', '16us.networklinkpro.net', '27fr.networklinkpro.net',
        'hnsrmyy.lih.yesleep.com.cn', 'dedc4a.apple.24xdpls.top',
        'access-cube.coolccloud.com', 'galaxy.safe.360.cn',
        'alpha1-pas.val.qq.com', 'jswz.zzu.edu.cn', 'masterconn2.qq.com',
        'sa0.tuisong.baidu.com',
    }
    
    _difficult_patterns_cache = [
        '.zapto.org', '.moxing.party', '.intercom.io', '.fqnovel.com',
        '.google.com', '.googleapis.com', '.gmail.com', '.youtube.com',
        '.facebook.com', '.twitter.com', '.telegram.org',
        '.networklinkpro.net', '.yesleep.com.cn', '.24xdpls.top',
        '.coolccloud.com',
    ]


def _save_difficult_domains():
    """保存困难域名数据库"""
    try:
        os.makedirs(os.path.dirname(DIFFICULT_DOMAINS_FILE), exist_ok=True)
        
        data = {
            'domains': list(_difficult_domains_cache),
            'patterns': _difficult_patterns_cache,
            'last_updated': datetime.now().isoformat(),
            'total_count': len(_difficult_domains_cache)
        }
        
        with open(DIFFICULT_DOMAINS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            
        logger.debug(f"困难域名数据库已保存: {len(_difficult_domains_cache)} 个域名")
        
    except Exception as e:
        logger.error(f"保存困难域名数据库失败: {e}")

def _is_difficult_domain(domain):
    """检查是否为已知困难域名（修复版）"""
    domain_lower = domain.lower()
    
    with _difficult_lock:
        # 精确匹配（最安全）
        if domain_lower in _difficult_domains_cache:
            return True
        
        # 模式匹配：只检查域名后缀，避免子串误判
        for pattern in _difficult_patterns_cache:
            if domain_lower.endswith(pattern):
                return True
    
    return False

def _mark_domain_as_difficult(domain):
    """将域名标记为困难域名（修复版：锁外IO）"""
    domain_lower = domain.lower()
    should_save = False
    
    with _difficult_lock:
        if domain_lower not in _difficult_domains_cache:
            _difficult_domains_cache.add(domain_lower)
            # 每新增10个域名标记一次保存需求
            if len(_difficult_domains_cache) % 10 == 0:
                should_save = True
    
    # 在锁外执行IO操作
    if should_save:
        _save_difficult_domains()
    
    return True

def _extract_domain_pattern(domain):
    """从域名提取模式（用于匹配相似域名）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        # 返回主域名部分
        return '.' + '.'.join(parts[-2:])
    return None

# 启动时加载困难域名数据库
_load_difficult_domains()

# ====================== 国家代码映射 ======================
COUNTRY_CODE_MAP = {
    'CN': '中国', 'US': '美国', 'GB': '英国', 'FR': '法国', 'DE': '德国',
    'JP': '日本', 'KR': '韩国', 'SG': '新加坡', 'IN': '印度', 'RU': '俄罗斯',
    'CA': '加拿大', 'AU': '澳大利亚', 'BE': '比利时', 'NL': '荷兰', 'CH': '瑞士',
    'SE': '瑞典', 'FI': '芬兰', 'NO': '挪威', 'DK': '丹麦', 'IT': '意大利',
    'ES': '西班牙', 'PT': '葡萄牙', 'IE': '爱尔兰', 'AT': '奥地利',
    'BR': '巴西', 'MX': '墨西哥', 'ZA': '南非', 'NZ': '新西兰',
    'HK': '香港', 'TW': '台湾', 'MO': '澳门', 'PL': '波兰',
}

# ====================== 域名分析缓存 ======================
_domain_analysis_cache = {}
_cache_ttl = 3600  # 缓存有效期1小时
_cache_lock = threading.RLock()

# ====================== 全局任务管理 ======================
pcap_tasks = {}
pcap_task_results = {}
pcap_task_lock = threading.RLock()

report_tasks = {}
task_results = {}
task_lock = threading.RLock()

# 全局安全增强器实例
security_enhancer = None


def register_security_routes(app, upload_folder, reports_folder, pinning_db_path):
    """注册安全分析路由"""
    print("✅ register_security_routes 被调用了")
    global security_enhancer
    security_enhancer = CertificateSecurityEnhancer(pinning_db_path)
    
    # ====================== 域名缓存函数 ======================
    
    def _get_cached_domain_analysis(domain):
        """获取缓存的域名分析结果"""
        if not ENABLE_DOMAIN_CACHE:
            return None
        
        cache_key = domain.lower()
        with _cache_lock:
            if cache_key in _domain_analysis_cache:
                cached = _domain_analysis_cache[cache_key]
                if time.time() - cached['timestamp'] < _cache_ttl:
                    logger.debug(f"使用缓存结果: {domain}")
                    return cached['result']
        return None
    
    def _cache_domain_analysis(domain, result):
        """缓存域名分析结果"""
        if not ENABLE_DOMAIN_CACHE:
            return
        
        cache_key = domain.lower()
        with _cache_lock:
            _domain_analysis_cache[cache_key] = {
                'result': result.copy(),
                'timestamp': time.time()
            }
        
        if len(_domain_analysis_cache) % 100 == 0:
            _clean_expired_cache()
    
    def _clean_expired_cache():
        """清理过期缓存"""
        current_time = time.time()
        with _cache_lock:
            expired_keys = [
                k for k, v in _domain_analysis_cache.items()
                if current_time - v['timestamp'] > _cache_ttl
            ]
            for k in expired_keys:
                del _domain_analysis_cache[k]
    
    # ====================== 机构名称规范化 ======================
    
    def _normalize_organization_name(org_name):
        """规范化机构名称"""
        if not org_name:
            return '未知'
        
        ca_mapping = {
            'DigiCert': 'DigiCert',
            'GlobalSign': 'GlobalSign',
            'Let\'s Encrypt': "Let's Encrypt",
            'Sectigo': 'Sectigo',
            'GoDaddy': 'GoDaddy',
            'Amazon': 'Amazon',
            'Google': 'Google',
            'Microsoft': 'Microsoft',
            'Cloudflare': 'Cloudflare',
            'ZeroSSL': 'ZeroSSL',
            'COMODO': 'Sectigo',
            'Thawte': 'DigiCert',
            'GeoTrust': 'DigiCert',
            'RapidSSL': 'DigiCert',
        }
        
        for key, value in ca_mapping.items():
            if key.lower() in org_name.lower():
                return value
        
        return org_name.split(',')[0].strip()
    
    # ====================== PCAP域名提取函数 ======================
    
    def _extract_domains_from_pcap_fast(pcap_path):
        """使用 tshark 快速提取域名"""
        domains = set()
        
        if not USE_TSHARK_FOR_PCAP:
            return _extract_domains_from_pcap(pcap_path)
        
        try:
            import subprocess
            
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['LANG'] = 'en_US.UTF-8'
            
            cmd = [
                'tshark', '-r', pcap_path,
                '-Y', 'dns.qry.name or tls.handshake.extensions_server_name or http.host',
                '-T', 'fields',
                '-e', 'dns.qry.name',
                '-e', 'tls.handshake.extensions_server_name',
                '-e', 'http.host'
            ]
            
            logger.info(f"使用 tshark 快速提取域名...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=PCAP_EXTRACT_TIMEOUT,
                encoding='utf-8',
                errors='ignore',
                env=env
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    for field in line.split('\t'):
                        field = field.strip().rstrip('.')
                        if field and '.' in field and len(field) < 253:
                            domain = field.lower()
                            if ':' in domain:
                                domain = domain.split(':')[0]
                            domains.add(domain)
                
                logger.info(f"tshark 提取到 {len(domains)} 个域名")
            else:
                logger.warning(f"tshark 未提取到域名，尝试降级方案")
                return _extract_domains_from_pcap(pcap_path)
                
        except subprocess.TimeoutExpired:
            logger.error(f"tshark 提取超时，尝试降级方案")
            return _extract_domains_from_pcap(pcap_path)
        except FileNotFoundError:
            logger.warning("tshark 未安装，使用 Scapy 降级方案")
            return _extract_domains_from_pcap(pcap_path)
        except Exception as e:
            logger.error(f"tshark 提取失败: {e}，尝试降级方案")
            return _extract_domains_from_pcap(pcap_path)
        
        return list(domains)
    
    def _extract_domains_from_pcap(pcap_path):
        """使用 Scapy 提取域名（降级方案）"""
        domains = set()
        
        try:
            from scapy.all import rdpcap, DNS, DNSQR, DNSRR, TCP, IP, Raw
            from scapy.layers.tls.all import TLS, TLSClientHello
            
            logger.info(f"使用 Scapy 解析 PCAP 文件...")
            packets = rdpcap(pcap_path)
            
            for packet in packets:
                if packet.haslayer(DNSQR):
                    try:
                        qname = packet[DNSQR].qname
                        if qname:
                            domain = qname.decode('utf-8', errors='ignore').rstrip('.')
                            if domain and '.' in domain:
                                domains.add(domain.lower())
                    except:
                        pass
                
                if packet.haslayer(DNSRR):
                    try:
                        rrname = packet[DNSRR].rrname
                        if rrname:
                            domain = rrname.decode('utf-8', errors='ignore').rstrip('.')
                            if domain and '.' in domain:
                                domains.add(domain.lower())
                    except:
                        pass
                
                if packet.haslayer(TLS) and packet.haslayer(TLSClientHello):
                    try:
                        sni = packet[TLSClientHello].sni
                        if sni and '.' in sni:
                            domains.add(sni.decode('utf-8').lower())
                    except:
                        pass
                
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    try:
                        import re
                        payload = packet[Raw].load
                        if b'Host: ' in payload:
                            host_match = re.search(b'Host: ([^\r\n]+)', payload)
                            if host_match:
                                host = host_match.group(1).decode('utf-8', errors='ignore').strip()
                                if host and '.' in host:
                                    host = host.split(':')[0]
                                    domains.add(host.lower())
                    except:
                        pass
            
            logger.info(f"Scapy 提取到 {len(domains)} 个域名")
            
        except Exception as e:
            logger.error(f"Scapy 解析失败: {e}")
            return _extract_domains_simple(pcap_path)
        
        return list(domains)
    
    def _extract_domains_simple(pcap_path):
        """简单文本搜索提取域名（最终降级方案）"""
        domains = set()
        try:
            import re
            with open(pcap_path, 'rb') as f:
                content = f.read()
            
            domain_pattern = rb'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
            matches = re.findall(domain_pattern, content)
            
            for match in matches:
                if isinstance(match, tuple):
                    domain = match[0].decode('utf-8', errors='ignore')
                else:
                    domain = match.decode('utf-8', errors='ignore')
                
                domain = domain.lower().rstrip('.')
                if domain and '.' in domain and len(domain) < 253:
                    if not any(x in domain for x in ['\x00', '\x01', '\x02']):
                        domains.add(domain)
            
            logger.info(f"简单文本搜索提取到 {len(domains)} 个域名")
        except Exception as e:
            logger.error(f"简单文本搜索失败: {e}")
        
        return list(domains)
    
    # ====================== 单域名分析函数 ======================
    def _analyze_single_domain(domain):
        """分析单个域名 - 修复：避免重复获取证书 + 严格超时"""
        try:
            import certificate_checker
        
            # 只获取一次证书链
            certificate_checker.certificate_chain_data = []
            certificate_checker.get_certificate_chain_fast(domain)
            chain_data = certificate_checker.certificate_chain_data
        
            # 使用轻量级分析，传入已有证书链
            if chain_data:
                security_analysis = security_enhancer.analyze_domain_security_light(
                    domain, 
                    chain_data=chain_data
                )
            else:
                # 没有证书链时降级处理
                security_analysis = {
                    'domain': domain,
                    'https_enforcement': {'enforced': False},
                    'hsts': {'enabled': False},
                    'security_headers': {},
                    'certificate_chain_valid': False,
                    'certificate_chain': [],
                    'certificate_chain_self_signed': False,
                    'recommendations': ['Unable to obtain certificate chain']
                }
        
            # 修正证书链字段
            chain_length = len(chain_data)
            is_chain_valid = chain_length >= 2
            is_self_signed = False
        
            if chain_length == 1:
                cert = chain_data[0]
                if cert.get('issuer_common_name') == cert.get('common_name'):
                    is_self_signed = True
                    is_chain_valid = False
            elif chain_length >= 2:
                leaf_cert = chain_data[0]
                if leaf_cert.get('issuer_common_name') == leaf_cert.get('common_name'):
                    is_self_signed = True
        
            security_analysis['certificate_chain_valid'] = is_chain_valid
            security_analysis['certificate_chain'] = chain_data
            security_analysis['certificate_chain_self_signed'] = is_self_signed
        
            security_score = security_enhancer._calculate_comprehensive_security_score(security_analysis)
        
            return {
                'domain': domain,
                'security_score': security_score,
                'https_enforcement': security_analysis.get('https_enforcement', {}),
                'hsts': security_analysis.get('hsts', {}),
                'security_headers': security_analysis.get('security_headers', {}),
                'certificate_chain_valid': is_chain_valid,
                'certificate_chain_self_signed': is_self_signed,
                'certificate_chain_length': chain_length,
                'chain_data': chain_data,
                'status': 'success'
            }
        except Exception as e:
            logger.warning(f"Analyze domain {domain} failed: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'security_score': 0,
                'status': 'failed'
            }
    
    def _analyze_single_domain_cached(domain):
        """带缓存的单域名分析"""
        cached = _get_cached_domain_analysis(domain)
        if cached:
            return cached
    
        result = _analyze_single_domain(domain)
    
        if result.get('status') == 'success':
            _cache_domain_analysis(domain, result)
    
        return result

    def _analyze_domains_parallel(domains, progress_callback=None, task_id=None, db_task_id=None):
        """并行分析域名列表"""
        results = []
        # 先过滤困难域名和无效域名
        domains_to_analyze = [d for d in domains if _is_likely_valid_domain(d)]
        skipped_count = len(domains) - len(domains_to_analyze)
        if skipped_count > 0:
            logger.info(f"Prescreen skipped {skipped_count} difficult/invalid domains")
    
        if not domains_to_analyze:
            logger.warning("No valid domains to analyze")
            return []
        
        total = len(domains)
        completed = 0
        failed = 0
        cached = 0
        
        start_time = time.time()
        
        # 定义一个包装函数，显式接收 db_task_id 参数
        def analyze_with_context(domain, db_id):
            if db_id:
                set_current_task_id(db_id)
            return _analyze_single_domain_cached(domain)
        
        print(f"并行分析开始，db_task_id={db_task_id}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
            future_to_domain = {}
            for domain in domains:
                future = executor.submit(analyze_with_context, domain, db_task_id)
                future_to_domain[future] = domain
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1
                
                try:
                    result = future.result(timeout=DOMAIN_ANALYSIS_TIMEOUT)
                    results.append(result)
                    
                    if result.get('status') == 'success':
                        if _get_cached_domain_analysis(domain) is not None:
                            cached += 1
                    else:
                        failed += 1
                        
                except concurrent.futures.TimeoutError:
                    # ✅ 超时域名标记为困难域名
                    _mark_domain_as_difficult(domain)
                    logger.warning(f"分析域名 {domain} 超时，已加入困难域名黑名单")
                    results.append({
                        'domain': domain,
                        'error': '分析超时',
                        'security_score': 0,
                        'status': 'timeout'
                    })
                    failed += 1
                except Exception as e:
                    logger.error(f"分析域名 {domain} 异常: {e}")
                    results.append({
                        'domain': domain,
                        'error': str(e),
                        'security_score': 0,
                        'status': 'error'
                    })
                    failed += 1
                
                if progress_callback:
                    progress_callback(completed, total, domain)
                
                if task_id:
                    with pcap_task_lock:
                        if task_id in pcap_tasks:
                            pcap_tasks[task_id]['analyzed_count'] = completed
                            pcap_tasks[task_id]['message'] = f'分析域名 {completed}/{total}'
                
                if completed % 50 == 0:
                    elapsed = time.time() - start_time
                    avg_time = elapsed / completed if completed > 0 else 0
                    logger.info(f"分析进度: {completed}/{total} (成功: {completed-failed}, 失败: {failed}, 缓存命中: {cached}, 平均: {avg_time:.2f}秒/个)")
        
        elapsed = time.time() - start_time
        logger.info(f"并行分析完成: {total}个域名, 耗时 {elapsed:.2f}秒, 成功: {total-failed}, 失败: {failed}, 缓存命中: {cached}")
        
        # 保存困难域名数据库
        _save_difficult_domains()
        
        return results
    
    #=======================预筛选域名========================
    def _is_likely_valid_domain(domain):
        """预筛查：过滤明显无效的域名（CDN节点、内网域名、IP地址等）"""
        import re
    
        # 排除IP地址
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
            return False
        
        # 检查是否为已知困难域名 - 直接跳过
        if _is_difficult_domain(domain):
            logger.debug(f"Prescreen skipping difficult domain: {domain}")
            return False
    
        # 无效域名模式
        invalid_patterns = [
            # 内网/本地域名
            '.local', '.internal', '.corp', '.lan', '.home', '.office',
            # 特殊用途域名
            '.arpa', '.onion', '.test', '.example', '.invalid', '.localhost',
            # CDN流媒体节点
            'pull-flv-', 'push-rtmp-', 'pull-hls-', 'push-hls-',
            'pull-lls-', 'push-tsl-', 'pull-tsl-',
            # 直播CDN域名
            '.tlivepush.com', '.tlivepull.com', '.tlivecdn.com',
            # 抖音/字节系CDN
            '.douyincdn.com', '.douyinliving.com', '.douyinpic.com',
            '.amemv.com', '.ixigua.com', '.bytecdn.com',
            # 静态资源CDN
            '.bdstatic.com', '.alicdn.com', '.myqcloud.com', '.qcloud.com',
            '.cloudfront.net', '.akamai.net', '.fastly.net',
            # WebRTC/STUN/TURN服务器
            'stun.', 'turn.', 'ice.', 'relay.',
            # NTP时间服务器
            'ntp.', 'time.', 'pool.ntp',
            # 其他
            'ocsp.', 'crl.', 'cdn.',
        ]
    
        for pattern in invalid_patterns:
            if pattern in domain:
                return False
    
        # 排除过长的域名（可能是随机生成的哈希域名）
        if len(domain) > 50:
            return False
    
        # 排除包含大量十六进制字符的哈希域名
        parts = domain.split('.')
        if parts and re.match(r'^[a-f0-9]{20,}$', parts[0], re.IGNORECASE):
            return False
    
        return True

    # ====================== PCAP异步任务处理 ======================
    
    def _process_pcap_task(task_id, pcap_path, filename):
        """后台处理PCAP任务 - 分析全部域名（带预筛选）"""
        db_task_id = None
        try:
            start_time = time.time()
            
            # ---- 创建数据库任务 ----
            db = get_db()
            db_task_id = db.create_task(
                user_id=None,
                analysis_module='security',
                task_type='pcap',
                source_file=filename
            )
            set_current_task_id(db_task_id)          # 设置当前线程的任务ID
            db.update_task_status(db_task_id, 'running', progress=5)

            with pcap_task_lock:
                if task_id in pcap_tasks:
                    pcap_tasks[task_id]['message'] = '正在从PCAP提取域名...'
        
            logger.info(f"[{task_id}] 开始提取PCAP域名...")
        
            domains = _extract_domains_from_pcap_fast(pcap_path)
        
            if not domains:
                with pcap_task_lock:
                    pcap_task_results[task_id] = {
                        'status': 'failed',
                        'error': '无法从PCAP文件中提取域名',
                        'completed_at': datetime.now().isoformat()
                    }
                    if task_id in pcap_tasks:
                        del pcap_tasks[task_id]
                return
        
            extract_time = time.time() - start_time
            logger.info(f"[{task_id}] 提取到 {len(domains)} 个域名，耗时 {extract_time:.2f}秒")
        
            # 第一步：格式验证过滤
            filtered_domains = list(set([d for d in domains if is_valid_domain(d)]))
            after_format_filter = len(filtered_domains)
            logger.info(f"[{task_id}] 格式过滤: {len(domains)} -> {after_format_filter} (过滤掉 {len(domains) - after_format_filter} 个)")
        
            # ✅ 第二步：预筛查（过滤CDN节点、内网域名、困难域名等）
            before_prescreen = len(filtered_domains)
            filtered_domains = [d for d in filtered_domains if _is_likely_valid_domain(d)]
            after_prescreen = len(filtered_domains)
            logger.info(f"[{task_id}] 预筛查: {before_prescreen} -> {after_prescreen} (过滤掉 {before_prescreen - after_prescreen} 个无效/CDN/困难域名)")
        
            # 最终要分析的域名（安全分析限制前200个）
            MAX_SECURITY_ANALYSIS_DOMAINS = 200
            domains_to_analyze = filtered_domains[:MAX_SECURITY_ANALYSIS_DOMAINS]
        
            if len(domains_to_analyze) == 0:
                logger.warning(f"[{task_id}] 预筛查后没有有效域名")
                with pcap_task_lock:
                    pcap_task_results[task_id] = {
                        'status': 'completed',
                        'security_report': _create_empty_security_report_with_message(
                            domains, filtered_domains, "预筛查后没有有效域名（过滤掉了CDN节点、内网域名、困难域名等）"
                        ),
                        'completed_at': datetime.now().isoformat()
                    }
                    if task_id in pcap_tasks:
                        del pcap_tasks[task_id]
                return
        
            logger.info(f"[{task_id}] 预筛查后剩余 {len(domains_to_analyze)} 个有效域名，将分析全部")
        
            with pcap_task_lock:
                if task_id in pcap_tasks:
                    pcap_tasks[task_id]['message'] = f'提取 {len(domains)} 个，预筛查后 {len(domains_to_analyze)} 个有效域名'
                    pcap_tasks[task_id]['total_domains'] = len(domains_to_analyze)
                    pcap_tasks[task_id]['analyzed_count'] = 0
                
            # 更新数据库任务基本信息
            db.update_task_status(db_task_id, 'running', progress=20,
                                  total_domains=len(domains_to_analyze))
        
            # 保存域名到文件（异步进行）
            from domain_saver import save_filtered_domains, save_domains_to_txt
            saved_files = {}
        
            def save_domains_async():
                nonlocal saved_files
                try:
                    if filtered_domains:
                        json_path = save_filtered_domains(filtered_domains, "pcap", filename)
                        txt_path = save_domains_to_txt(filtered_domains, "pcap", filename)
                        saved_files['json'] = json_path
                        saved_files['txt'] = txt_path
                        logger.info(f"[{task_id}] 域名已保存")
                except Exception as e:
                    logger.error(f"[{task_id}] 保存域名失败: {e}")
        
            save_thread = threading.Thread(target=save_domains_async, daemon=True)
            save_thread.start()
        
            def progress_callback(completed, total, domain):
                if completed % 50 == 0:  # 每50个输出一次
                    logger.info(f"[{task_id}] 分析进度: {completed}/{total}")
        
            logger.info(f"[{task_id}] 开始并行分析 {len(domains_to_analyze)} 个域名，并发数: {THREAD_POOL_SIZE}")
            analyze_start = time.time()
        
            # 并行分析（传入 db_task_id 确保入库）
            detailed_results = _analyze_domains_parallel(
                domains_to_analyze,
                progress_callback=lambda completed, total, domain: (
                    # 更新数据库进度（每 50 个或全部完成时）
                    db.update_task_status(db_task_id, 'running',
                                          progress=20 + int(70 * completed / total),
                                          processed_domains=completed)
                    if completed % 50 == 0 or completed == total else None
                ),
                task_id=task_id,
                db_task_id=db_task_id      # ← 关键：传入数据库任务ID
            )
            logger.info(f"详细结果数量: {len(detailed_results)}")
            if detailed_results:
                logger.info(f"第一个结果: {detailed_results[0]}")
            else:
                logger.warning("分析结果为空，请检查域名提取或分析过程")
                
            analyze_time = time.time() - analyze_start
            total_time = time.time() - start_time
        
            logger.info(f"[{task_id}] 分析完成: {len(detailed_results)} 个域名")
            logger.info(f"[{task_id}] 提取耗时: {extract_time:.2f}秒")
            logger.info(f"[{task_id}] 分析耗时: {analyze_time:.2f}秒")
            logger.info(f"[{task_id}] 总耗时: {total_time:.2f}秒")
            if detailed_results:
                logger.info(f"[{task_id}] 平均每域名: {analyze_time/len(detailed_results):.2f}秒")
        
            save_thread.join(timeout=10)
        
            # 生成汇总报告
            security_report = _build_security_report(
                detailed_results, domains, filtered_domains, domains_to_analyze, saved_files
            )
        
            # 添加性能统计
            security_report['performance_stats'] = {
                'extract_time': round(extract_time, 2),
                'analyze_time': round(analyze_time, 2),
                'total_time': round(total_time, 2),
                'avg_per_domain': round(analyze_time / len(detailed_results), 2) if detailed_results else 0,
                'concurrent_workers': THREAD_POOL_SIZE,
                'total_domains_extracted': len(domains),
                'total_domains_filtered': len(filtered_domains),
                'total_domains_analyzed': len(detailed_results),
                'prescreen_filtered': before_prescreen - after_prescreen,  # 预筛查过滤数量
                'difficult_domains_count': len(_difficult_domains_cache)  # 困难域名数量
            }
        
            # 更新任务为完成
            db.update_task_status(db_task_id, 'completed', progress=100,
                                  total_domains=len(domains_to_analyze),
                                  processed_domains=len(detailed_results))
            
            with pcap_task_lock:
                pcap_task_results[task_id] = {
                    'status': 'completed',
                    'security_report': security_report,
                    'completed_at': datetime.now().isoformat()
                }
                if task_id in pcap_tasks:
                    del pcap_tasks[task_id]
        
            logger.info(f"[{task_id}] PCAP任务完成")
        
        except Exception as e:
            logger.error(f"PCAP任务处理失败: {str(e)}")
            if db_task_id:
                try:
                    db = get_db()
                    db.update_task_status(db_task_id, 'failed', error_msg=str(e))
                except:
                    pass

            traceback.print_exc()
        
            with pcap_task_lock:
                pcap_task_results[task_id] = {
                    'status': 'failed',
                    'error': str(e),
                    'completed_at': datetime.now().isoformat()
                }
                if task_id in pcap_tasks:
                    del pcap_tasks[task_id]
        finally:
            set_current_task_id(None)        # 清除线程局部变量
            if pcap_path and os.path.exists(pcap_path):
                try:
                    os.remove(pcap_path)
                except:
                    pass

    def _create_empty_security_report_with_message(all_domains, filtered_domains, message):
        """创建带消息的空安全报告"""
        report = _create_empty_security_report()
        report['domain_stats'] = {
            'total_extracted': len(all_domains),
            'after_filtering': len(filtered_domains),
            'to_analyze': 0,
            'successfully_analyzed': 0,
            'failed_analyzed': 0
        }
        report['message'] = message
        return report

    def _build_security_report(detailed_results, all_domains, filtered_domains, analyzed_domains, saved_files):
        """构建安全报告"""
        total = len(detailed_results)
        if total == 0:
            return _create_empty_security_report()
        
        https_count = sum(1 for r in detailed_results if r.get('https_enforcement', {}).get('enforced', False))
        hsts_count = sum(1 for r in detailed_results if r.get('hsts', {}).get('enabled', False))
        good_headers_count = 0
        valid_chains_count = sum(1 for r in detailed_results if r.get('certificate_chain_valid', False))
        
        for r in detailed_results:
            headers = r.get('security_headers', {}).get('assessment', {})
            good_headers = sum([
                headers.get('has_csp', False),
                headers.get('has_x_content_type_options', False),
                headers.get('has_x_frame_options', False),
                headers.get('has_referrer_policy', False)
            ])
            if good_headers >= 2:
                good_headers_count += 1
        
        scores = [r.get('security_score', 0) for r in detailed_results if r.get('status') == 'success']
        avg_score = sum(scores) / len(scores) if scores else 0
        
        score_distribution = [0, 0, 0, 0]
        for score in scores:
            if score >= 80:
                score_distribution[0] += 1
            elif score >= 60:
                score_distribution[1] += 1
            elif score >= 40:
                score_distribution[2] += 1
            else:
                score_distribution[3] += 1
        
        failed_count = sum(1 for r in detailed_results if r.get('status') != 'success')
        
        return {
            'summary': {
                'security_score': round(avg_score),
                'analyzed_domains': total,
                'successful_domains': total - failed_count,
                'failed_domains': failed_count,
                'domains_with_https_enforcement': https_count,
                'domains_with_hsts': hsts_count,
                'domains_with_good_security_headers': good_headers_count,
                'domains_with_valid_certificate_chains': valid_chains_count,
                'total_domains': len(all_domains)
            },
            'detailed_results': detailed_results,
            'scoreDistribution': score_distribution,
            'featureStats': {
                'https': https_count,
                'hsts': hsts_count,
                'good_headers': good_headers_count,
                'valid_chains': valid_chains_count
            },
            'domain_stats': {
                'total_extracted': len(all_domains),
                'after_filtering': len(filtered_domains),
                'to_analyze': len(analyzed_domains),
                'successfully_analyzed': total - failed_count,
                'failed_analyzed': failed_count
            },
            'saved_files': saved_files
        }
    
    def _create_empty_security_report():
        """创建空的安全报告"""
        return {
            'summary': {
                'security_score': 0,
                'analyzed_domains': 0,
                'successful_domains': 0,
                'failed_domains': 0,
                'domains_with_https_enforcement': 0,
                'domains_with_hsts': 0,
                'domains_with_good_security_headers': 0,
                'domains_with_valid_certificate_chains': 0,
                'total_domains': 0
            },
            'detailed_results': [],
            'scoreDistribution': [0, 0, 0, 0],
            'featureStats': {'https': 0, 'hsts': 0, 'good_headers': 0, 'valid_chains': 0},
            'domain_stats': {'total_extracted': 0, 'after_filtering': 0, 'to_analyze': 0, 'successfully_analyzed': 0, 'failed_analyzed': 0},
            'saved_files': {'json': None, 'txt': None}
        }
    
    # ====================== API路由 ======================
    
    @app.route('/api/security/analyze-domain', methods=['POST'])
    def analyze_domain_security():
        """深度证书链分析API"""
        try:
            data = request.get_json()
            domain = data.get('domain')
            
            if not domain:
                return jsonify({'status': 'error', 'error': '域名不能为空'}), 400
            
            logger.info(f"开始深度证书分析: {domain}")
            
            import certificate_checker
            from collections import Counter
            
            certificate_checker.certificate_chain_data = []
            certificate_checker.get_certificate_chain_fast(domain)
            chain_data = certificate_checker.certificate_chain_data
            
            if not chain_data:
                return jsonify({'status': 'error', 'error': '无法获取该域名的有效证书链'}), 404
            
            countries = []
            for cert in chain_data:
                country = cert.get('issuer_country')
                country_name = certificate_checker.get_country_name(country) if country else "未知"
                countries.append(country_name)
            
            country_counts = Counter(countries)
            
            return jsonify({
                'status': 'success',
                'domain': domain,
                'analysis_type': 'certificate_deep_metadata',
                'chain_data': chain_data,
                'chart_data': {
                    'labels': list(country_counts.keys()),
                    'values': list(country_counts.values())
                }
            })
            
        except Exception as e:
            logger.error(f"证书分析失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'分析失败: {str(e)}'}), 500

    @app.route('/api/security/analyze-pcap-async', methods=['POST'])
    def analyze_pcap_async():
        """异步PCAP分析（高性能版）"""
        pcap_path = None
        
        try:
            if 'file' not in request.files:
                return jsonify({'status': 'error', 'error': '未上传文件'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'status': 'error', 'error': '未选择文件'}), 400
            
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = secure_filename(f"pcap_{timestamp}_{file.filename}")
            pcap_path = os.path.join(upload_folder, filename)
            file.save(pcap_path)
            
            task_id = str(uuid.uuid4())
            
            with pcap_task_lock:
                pcap_tasks[task_id] = {
                    'status': 'processing',
                    'created_at': datetime.now().isoformat(),
                    'pcap_path': pcap_path,
                    'filename': file.filename,
                    'message': '正在提取域名...',
                    'file_size_mb': round(os.path.getsize(pcap_path) / (1024 * 1024), 2)
                }
            
            thread = threading.Thread(
                target=_process_pcap_task,
                args=(task_id, pcap_path, file.filename),
                daemon=True
            )
            thread.start()
            
            logger.info(f"PCAP异步任务已提交: {task_id}, 文件大小: {pcap_tasks[task_id]['file_size_mb']}MB")
            
            return jsonify({
                'status': 'processing',
                'task_id': task_id,
                'message': '任务已提交',
                'file_size_mb': pcap_tasks[task_id]['file_size_mb']
            })
            
        except Exception as e:
            logger.error(f"提交PCAP任务失败: {str(e)}")
            if pcap_path and os.path.exists(pcap_path):
                try:
                    os.remove(pcap_path)
                except:
                    pass
            return jsonify({'status': 'error', 'error': str(e)}), 500

    @app.route('/api/security/task-status/<task_id>', methods=['GET'])
    def get_pcap_task_status(task_id):
        """获取PCAP任务状态"""
        try:
            with pcap_task_lock:
                if task_id in pcap_task_results:
                    result = pcap_task_results[task_id].copy()
                    # 确保返回的数据格式正确
                    return jsonify(result)
                
                if task_id in pcap_tasks:
                    task_info = pcap_tasks[task_id].copy()
                    if 'pcap_path' in task_info:
                        del task_info['pcap_path']
                    return jsonify(task_info)
                
                return jsonify({'status': 'not_found'})
                
        except Exception as e:
            logger.error(f"获取任务状态失败: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500

    @app.route('/api/security/analyze-certificates', methods=['POST'])
    def analyze_certificate_files():
        """分析证书文件 - 分析全部域名"""
        file_path = None
        try:
            analysis_type = request.form.get('analysis_type', 'der')
            file = request.files.get('file')
            
            if not file or file.filename == '':
                return jsonify({'status': 'error', 'error': '未选择文件'}), 400
            
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = secure_filename(f"cert_{timestamp}_{file.filename}")
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            
            logger.info(f"开始分析证书文件: {filename}, 类型: {analysis_type}")
            
            domains = []
            certificate_analysis = []
            
            if analysis_type == 'zip':
                domains, certificate_analysis = _extract_domains_from_certificate_zip(file_path, upload_folder)
            else:
                domains, cert_info = _extract_domains_from_der_file(file_path)
                certificate_analysis = [cert_info]
            
            if not domains:
                logger.warning(f"从证书文件中提取到 0 个域名")
                feedback_message = _build_certificate_feedback(certificate_analysis)
                cert_info = certificate_analysis[0] if certificate_analysis else {}
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                return jsonify({
                    'status': 'info',
                    'message': feedback_message,
                    'certificate_analysis': certificate_analysis,
                    'certificate_type': cert_info.get('type', '未知类型'),
                    'is_ca': cert_info.get('is_ca', False),
                    'is_self_signed': cert_info.get('is_self_signed', False)
                })
            
            logger.info(f"从证书文件中提取到 {len(domains)} 个域名")
            
            filtered_domains = [d for d in domains if is_valid_domain(d)]
            domains_to_analyze = filtered_domains
            logger.info(f"过滤后 {len(filtered_domains)} 个域名，将分析全部 {len(domains_to_analyze)} 个")
            
            from domain_saver import save_filtered_domains, save_domains_to_txt
            saved_files = {}
            if filtered_domains:
                json_path = save_filtered_domains(filtered_domains, f"cert_{analysis_type}", file.filename)
                txt_path = save_domains_to_txt(filtered_domains, f"cert_{analysis_type}", file.filename)
                saved_files = {'json': json_path, 'txt': txt_path}
            
            detailed_results = _analyze_domains_parallel(domains_to_analyze)
            
            security_report = _build_security_report(
                detailed_results, domains, filtered_domains, domains_to_analyze, saved_files
            )
            security_report['certificate_analysis'] = certificate_analysis
            
            if os.path.exists(file_path):
                os.remove(file_path)
            
            return jsonify({
                "status": "success",
                "security_report": security_report,
                "extracted_domains_count": len(domains),
                "analyzed_domains_count": security_report['summary']['analyzed_domains']
            })

        except Exception as e:
            logger.error(f"证书文件分析失败: {str(e)}")
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'status': 'error', 'error': f'证书分析失败: {str(e)}'}), 500

    @app.route('/api/security/generate-report', methods=['POST'])
    def generate_security_report_api():
        """生成AI报告"""
        try:
            data = request.get_json()
            task_id = str(uuid.uuid4())
            
            with task_lock:
                report_tasks[task_id] = {
                    'status': 'processing',
                    'created_at': datetime.now().isoformat(),
                    'data': data
                }
            
            thread = threading.Thread(
                target=_process_report_task,
                args=(task_id, data),
                daemon=True
            )
            thread.start()
            
            return jsonify({
                'status': 'processing',
                'task_id': task_id,
                'message': '报告生成任务已提交'
            })
            
        except Exception as e:
            logger.error(f"报告任务提交失败: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500

    @app.route('/api/security/report-status/<task_id>', methods=['GET'])
    def get_report_status(task_id):
        """获取报告生成状态"""
        try:
            with task_lock:
                if task_id in task_results:
                    return jsonify(task_results[task_id])
                elif task_id in report_tasks:
                    return jsonify({
                        'status': 'processing',
                        'message': '报告生成中...'
                    })
                else:
                    return jsonify({'status': 'not_found'})
        except Exception as e:
            return jsonify({'status': 'error', 'error': str(e)}), 500

    def _process_report_task(task_id, data):
        """后台处理报告任务"""
        try:
            from services.deepseek_service import generate_ai_report
            
            # 从前端传入的数据中获取报告类型，默认 security
            report_type = data.get('report_type', 'security') if isinstance(data, dict) else 'security'
            original_filename = data.get('original_filename', data.get('original_file', '')) if isinstance(data, dict) else ''

            report_content = generate_ai_report(
                data,
                source_type="security",
                original_filename=original_filename,
                report_type=report_type
            )
            
            with task_lock:
                task_results[task_id] = {
                    'status': 'completed',
                    'report_content': report_content,
                    'completed_at': datetime.now().isoformat()
                }
                if task_id in report_tasks:
                    del report_tasks[task_id]
                    
        except Exception as e:
            logger.error(f"报告任务处理失败: {str(e)}")
            with task_lock:
                task_results[task_id] = {
                    'status': 'failed',
                    'error': str(e)
                }
                if task_id in report_tasks:
                    del report_tasks[task_id]

    # ====================== 汇总报告导出接口 ======================

    @app.route('/api/security/export-summary-report', methods=['POST'])
    def export_summary_report():
        """导出汇总分析报告（文本格式）"""
        try:
            data = request.get_json()
            detailed_results = data.get('detailed_results', [])
            return_content = data.get('return_content', False)
            
            if not detailed_results:
                return jsonify({'status': 'error', 'error': '没有分析数据'}), 400
            
            report_content = _generate_summary_report_content(detailed_results)
            
            if return_content:
                return jsonify({
                    'status': 'success',
                    'content': report_content
                })
            else:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"summary_report_{timestamp}.txt"
                
                from io import BytesIO
                bio = BytesIO()
                bio.write(report_content.encode('utf-8'))
                bio.seek(0)
                
                return send_file(
                    bio,
                    mimetype='text/plain',
                    as_attachment=True,
                    download_name=filename
                )
                
        except Exception as e:
            logger.error(f"导出汇总报告失败: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500

    def _generate_summary_report_content(detailed_results):
        """生成汇总报告内容"""
        total = len(detailed_results)
        success_count = sum(1 for r in detailed_results if r.get('status') != 'failed' and not r.get('error'))
        failed_count = total - success_count
        
        chain_lengths = []
        issuer_countries = []
        organizations = []
        
        for r in detailed_results:
            if r.get('chain_data'):
                chain_lengths.append(len(r['chain_data']))
                for cert in r['chain_data']:
                    country = cert.get('issuer_country')
                    if country:
                        country_name = COUNTRY_CODE_MAP.get(country, country)
                        issuer_countries.append(country_name)
                    org = cert.get('organization')
                    if org:
                        organizations.append(org)
        
        report = f"""================================================================================
                        域名证书链汇总分析报告
================================================================================

生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

【总体统计】
  分析域名总数: {total}
  成功解析: {success_count} ({success_count/total*100:.1f}%)
  解析失败: {failed_count} ({failed_count/total*100:.1f}%)

【证书链长度分布】
"""
        
        if chain_lengths:
            length_counter = Counter(chain_lengths)
            for length, count in sorted(length_counter.items()):
                report += f"  {length}级证书链: {count} 个域名 ({count/total*100:.1f}%)\n"
        else:
            report += "  无证书链数据\n"
        
        report += "\n【证书颁发国家分布】\n"
        
        if issuer_countries:
            country_counter = Counter(issuer_countries)
            for country, count in country_counter.most_common(10):
                report += f"  {country}: {count} 次\n"
        else:
            report += "  无国家数据\n"
        
        report += "\n【证书颁发机构统计】\n"
        
        if organizations:
            normalized_orgs = {}
            for org in organizations:
                normalized = _normalize_organization_name(org)
                normalized_orgs[normalized] = normalized_orgs.get(normalized, 0) + 1
            
            for org, count in sorted(normalized_orgs.items(), key=lambda x: x[1], reverse=True)[:15]:
                report += f"  {org}: {count} 次\n"
        else:
            report += "  无机构数据\n"
        
        report += "\n================================================================================\n"
        
        return report

    @app.route('/api/security/export-country-chart-base64', methods=['POST'])
    def export_country_chart_base64():
        """导出国家分布饼图（Base64格式）——优化版，使用图例避免标签重叠"""
        try:
            data = request.get_json()
            detailed_results = data.get('detailed_results', [])
 
            if not detailed_results:
                return jsonify({'status': 'error', 'error': '没有分析数据'}), 400

            countries = []
            for r in detailed_results:
                if r.get('chain_data'):
                    for cert in r['chain_data']:
                        country = cert.get('issuer_country')
                        if country:
                            country_name = COUNTRY_CODE_MAP.get(country, country)
                            countries.append(country_name)

            if not countries:
                return jsonify({'status': 'error', 'error': '无国家数据'}), 400

            country_counter = Counter(countries)

            plt.figure(figsize=(10, 8))
            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False

            # 取前8个国家，其余合并为“其他”
            most_common = country_counter.most_common(8)
            labels = [item[0] for item in most_common]
            sizes = [item[1] for item in most_common]
            if len(country_counter) > 8:
                other_count = sum(count for _, count in country_counter.most_common()[8:])
                labels.append('其他')
                sizes.append(other_count)

            colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))

            # 不在饼图上直接显示标签，改用图例
            wedges, texts, autotexts = plt.pie(
                sizes,
                labels=None,                 # 不显示标签文字
                autopct='%1.1f%%',
                startangle=90,
                colors=colors,
                pctdistance=0.85,
                wedgeprops={'linewidth': 0.5, 'edgecolor': 'white'}
            )

            # 构建带百分比的图例标签
            total = sum(sizes)
            legend_labels = []
            for name, size in zip(labels, sizes):
                pct = size / total * 100
                label = f'{name} ({pct:.1f}%)'
                legend_labels.append(label)

            plt.legend(
                wedges, legend_labels,
                title="国家",
                loc="center left",
                bbox_to_anchor=(1.0, 0.5),
                fontsize=10
            )

            plt.title(f'证书颁发国家分布 (总计: {len(countries)} 个证书)', fontsize=14, fontweight='bold')

            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            buf.seek(0)
            plt.close()

            image_base64 = base64.b64encode(buf.read()).decode('utf-8')
            buf.close()

            return jsonify({
                'status': 'success',
                'image_base64': f'data:image/png;base64,{image_base64}'
            })

        except Exception as e:
            logger.error(f"生成国家分布饼图失败: {str(e)}")
            traceback.print_exc()
            return jsonify({'status': 'error', 'error': str(e)}), 500


    @app.route('/api/security/export-topology-base64', methods=['POST'])
    def export_topology_base64():
        """导出颁发机构拓扑图（Base64格式）——优化节点大小、字体和连线宽度"""
        try:
            data = request.get_json()
            detailed_results = data.get('detailed_results', [])

            if not detailed_results:
                return jsonify({'status': 'error', 'error': '没有分析数据'}), 400

            organizations = {}
            for r in detailed_results:
                if r.get('chain_data'):
                    for cert in r['chain_data']:
                        org = cert.get('organization')
                        if org:
                            normalized = _normalize_organization_name(org)
                            if normalized not in organizations:
                                organizations[normalized] = {'count': 0, 'countries': set()}
                            organizations[normalized]['count'] += 1
                            country = cert.get('issuer_country')
                            if country:
                                organizations[normalized]['countries'].add(country)

            if not organizations:
                return jsonify({'status': 'error', 'error': '无机构数据'}), 400

            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False

            fig, ax = plt.subplots(figsize=(14, 10))
            ax.set_xlim(0, 12)
            ax.set_ylim(0, 10)
            ax.axis('off')

            sorted_orgs = sorted(organizations.items(), key=lambda x: x[1]['count'], reverse=True)[:15]
            colors = plt.cm.tab20(np.linspace(0, 1, len(sorted_orgs)))

            center_x, center_y = 6, 5

            # 中心节点稍大
            ax.add_patch(plt.Circle((center_x, center_y), 0.7, color='#FF6B6B', alpha=0.9,
                                    edgecolor='black', linewidth=3))
            ax.text(center_x, center_y, f'颁发机构\n({len(sorted_orgs)}个)',
                    ha='center', va='center', fontsize=11, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.9))

            for i, (org_name, org_data) in enumerate(sorted_orgs):
                angle = 2 * np.pi * i / len(sorted_orgs)
                radius = 3.5
                x = center_x + radius * np.cos(angle)
                y = center_y + radius * np.sin(angle)

                max_count = max(data['count'] for _, data in sorted_orgs)
                # 增大节点尺寸差距
                node_size = 0.5 + (org_data['count'] / max_count) * 1.2

                ax.add_patch(plt.Circle((x, y), node_size, color=colors[i], alpha=0.8,
                                        edgecolor='black', linewidth=2.5))

                if len(org_name) > 12:
                    short_name = org_name[:10] + "..."
                else:
                    short_name = org_name

                display_text = f"{short_name}\n{org_data['count']}次"

                # 调整文字位置参数
                ha = 'left' if x > center_x else 'right'
                x_text = x + node_size + 0.2 if x > center_x else x - node_size - 0.2
                va = 'bottom' if y > center_y else 'top'
                y_text = y + node_size + 0.15 if y > center_y else y - node_size - 0.15

                ax.text(x_text, y_text, display_text, ha=ha, va=va, fontsize=9, fontweight='bold',
                        bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8))

                # 连线加粗
                ax.plot([center_x, x], [center_y, y], color=colors[i], alpha=0.6, linewidth=2)

            ax.set_title('证书颁发机构拓扑关系图', fontsize=16, fontweight='bold', pad=20)

            stats_text = f"机构总数: {len(organizations)}\n"
            stats_text += f"证书总数: {sum(d['count'] for d in organizations.values())}\n"
            all_countries = set()
            for d in organizations.values():
                all_countries.update(d['countries'])
            stats_text += f"涉及国家: {len(all_countries)}"

            ax.text(0.5, 9, stats_text, fontsize=10, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.9))

            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            buf.seek(0)
            plt.close()

            image_base64 = base64.b64encode(buf.read()).decode('utf-8')
            buf.close()

            return jsonify({
                'status': 'success',
                'image_base64': f'data:image/png;base64,{image_base64}'
            })

        except Exception as e:
            logger.error(f"生成拓扑图失败: {str(e)}")
            traceback.print_exc()
            return jsonify({'status': 'error', 'error': str(e)}), 500

    @app.route('/api/security/export-summary-topology', methods=['POST'])
    def export_summary_topology():
        """导出拓扑图（PNG文件下载）"""
        try:
            data = request.get_json()
            detailed_results = data.get('detailed_results', [])
            
            if not detailed_results:
                return jsonify({'status': 'error', 'error': '没有分析数据'}), 400
            
            result = export_topology_base64()
            result_data = result.get_json()
            
            if result_data.get('status') == 'success':
                image_base64 = result_data['image_base64']
                if image_base64.startswith('data:image/png;base64,'):
                    image_base64 = image_base64.replace('data:image/png;base64,', '')
                
                image_data = base64.b64decode(image_base64)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"topology_{timestamp}.png"
                
                return send_file(
                    io.BytesIO(image_data),
                    mimetype='image/png',
                    as_attachment=True,
                    download_name=filename
                )
            else:
                return jsonify(result_data), 400
                
        except Exception as e:
            logger.error(f"导出拓扑图失败: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500

    # ====================== 辅助函数 ======================
    
    def _extract_domains_from_certificate_zip(zip_path, upload_folder):
        """从证书压缩包中提取域名"""
        domains = set()
        certificate_analysis_list = []
        extract_dir = os.path.join(upload_folder, f"extract_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        try:
            os.makedirs(extract_dir, exist_ok=True)
            extract_archive(zip_path, extract_dir)
            cert_files = find_certificate_files(extract_dir)
            
            for cert_file in cert_files:
                try:
                    file_domains, cert_info = _extract_domains_from_der_file(cert_file)
                    domains.update(file_domains)
                    cert_info['filename'] = os.path.basename(cert_file)
                    certificate_analysis_list.append(cert_info)
                except Exception as e:
                    logger.warning(f"无法解析证书 {cert_file}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"证书压缩包处理失败: {str(e)}")
        finally:
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir, ignore_errors=True)
        
        return list(domains), certificate_analysis_list
    
    def _extract_domains_from_der_file(der_path):
        """从单个证书文件中提取域名"""
        domains = set()
        certificate_info = {
            'type': 'unknown',
            'subject': '',
            'issuer': '',
            'is_ca': False,
            'has_domains': False,
            'is_self_signed': False
        }
        
        try:
            with open(der_path, 'rb') as f:
                cert_data = f.read()
            
            cert = None
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            except ValueError:
                try:
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                except ValueError:
                    certificate_info['error'] = '证书格式不支持'
                    return [], certificate_info
            
            certificate_info['subject'] = cert.subject.rfc4514_string()
            certificate_info['issuer'] = cert.issuer.rfc4514_string()
            certificate_info['is_self_signed'] = (cert.subject == cert.issuer)
            
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
                certificate_info['is_ca'] = basic_constraints.value.ca
                certificate_info['type'] = '自签名根证书' if certificate_info['is_self_signed'] else '中间CA证书' if certificate_info['is_ca'] else '叶子证书'
            except x509.ExtensionNotFound:
                certificate_info['is_ca'] = False
                certificate_info['type'] = '叶子证书'
            
            certificate_info['not_valid_before'] = cert.not_valid_before.isoformat()
            certificate_info['not_valid_after'] = cert.not_valid_after.isoformat()
            
            cn_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            for attr in cn_attributes:
                domain = attr.value
                if domain and '.' in domain and is_valid_domain(domain):
                    domains.add(domain.lower())
                    certificate_info['has_domains'] = True
            
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_domains = san_ext.value.get_values_for_type(x509.DNSName)
                for domain in san_domains:
                    if domain and '.' in domain and is_valid_domain(domain):
                        domains.add(domain.lower())
                        certificate_info['has_domains'] = True
            except x509.ExtensionNotFound:
                pass
                
        except Exception as e:
            logger.error(f"证书解析失败: {str(e)}")
            certificate_info['error'] = str(e)
        
        return list(domains), certificate_info
    
    def _build_certificate_feedback(certificate_analysis):
        """构建证书分析反馈信息"""
        if not certificate_analysis:
            return "无法分析证书文件"
        
        cert_info = certificate_analysis[0]
        if cert_info.get('error'):
            return f"证书解析错误: {cert_info['error']}"
        
        if cert_info.get('is_ca'):
            return "这是一个CA证书，不包含可访问的域名。请上传叶子证书（服务器证书）进行分析。"
        
        if not cert_info.get('has_domains'):
            return "证书中未找到有效的域名信息。"
        
        return "证书分析完成"
    
    logger.info("✅ 安全分析API路由已注册（高性能优化版 + 导出接口）")