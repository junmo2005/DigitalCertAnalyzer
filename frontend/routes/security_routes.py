from flask import request, jsonify, send_file
import os
import traceback
import shutil
import threading
import queue
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from certificate_security_enhancer import CertificateSecurityEnhancer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils.file_utils import is_valid_domain, extract_archive, find_certificate_files, safe_division
from services.deepseek_service import (
    generate_ai_report, 
    generate_security_default_report,
    generate_certificate_default_report
)
import logging
import json
from services.task_queue import task_queue

logger = logging.getLogger(__name__)

def register_security_routes(app, upload_folder, reports_folder, pinning_db_path):
    """注册安全分析路由"""
    
    security_enhancer = CertificateSecurityEnhancer(pinning_db_path)
    
    # ==================== 安全分析API路由 ====================
    
    @app.route('/api/security/analyze-domain', methods=['POST'])
    def analyze_domain_security():
        """分析单个域名安全状态"""
        try:
            data = request.get_json()
            domain = data.get('domain')
            
            if not domain:
                return jsonify({'status': 'error', 'error': '域名不能为空'}), 400
            
            logger.info(f"开始安全分析: {domain}")

            security_report = security_enhancer.analyze_domain_security(domain)
            
            logger.info(f"HSTS检测结果: {security_report.get('hsts', {})}")
            logger.info(f"HTTPS重定向结果: {security_report.get('https_enforcement', {})}")

            security_score = security_enhancer._calculate_comprehensive_security_score(security_report)
            security_report['security_score'] = security_score
            
            return jsonify({
                'status': 'success',
                'security_report': security_report
            })
            
        except Exception as e:
            logger.error(f"域名安全分析失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'安全分析失败: {str(e)}'}), 500
    
    @app.route('/api/security/pin-certificate', methods=['POST'])
    def pin_certificate():
        """证书钉扎配置"""
        try:
            domain = request.form.get('domain')
            pin_type = request.form.get('pin_type', 'leaf')
            cert_file = request.files.get('cert_file')
            
            if not all([domain, cert_file]):
                return jsonify({'status': 'error', 'error': '域名和证书文件不能为空'}), 400
            
            cert_data = cert_file.read()
            
            if not cert_data:
                return jsonify({'status': 'error', 'error': '证书文件为空'}), 400
            
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            except ValueError:
                try:
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                except ValueError:
                    return jsonify({'status': 'error', 'error': '无法解析证书文件，请确保证书格式正确'}), 400
            
            pinned = security_enhancer.pin_certificate(domain, cert_data, pin_type)
            
            if pinned:
                return jsonify({
                    'status': 'success',
                    'message': f'证书钉扎配置成功 - 域名: {domain}, 类型: {pin_type}',
                    'certificate_hash': security_enhancer.calculate_certificate_hash(cert_data)
                })
            else:
                return jsonify({'status': 'error', 'error': '证书钉扎失败'}), 500
            
        except Exception as e:
            logger.error(f"证书钉扎失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'证书钉扎失败: {str(e)}'}), 500
    
    @app.route('/api/security/check-chain', methods=['POST'])
    def check_certificate_chain():
        """检查证书链完整性"""
        try:
            cert_files = request.files.getlist('cert_files[]')
            
            if not cert_files:
                return jsonify({'status': 'error', 'error': '请选择证书文件'}), 400
            
            cert_chain = []
            file_info = []
            
            for cert_file in cert_files:
                if cert_file.filename == '':
                    continue
                    
                cert_data = cert_file.read()
                if cert_data:
                    cert_chain.append(cert_data)
                    file_info.append({
                        'filename': cert_file.filename,
                        'size': len(cert_data)
                    })
            
            if not cert_chain:
                return jsonify({'status': 'error', 'error': '未找到有效的证书文件'}), 400
            
            chain_valid, issues, detailed_report = security_enhancer.chain_validator.validate_certificate_chain(cert_chain)
            
            return jsonify({
                'status': 'success',
                'chain_valid': chain_valid,
                'issues': issues,
                'file_info': file_info,
                'detailed_report': detailed_report
            })
            
        except Exception as e:
            logger.error(f"证书链验证失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'证书链验证失败: {str(e)}'}), 500
    
    @app.route('/api/security/batch-analyze', methods=['POST'])
    def batch_security_analyze():
        """批量域名安全分析"""
        try:
            data = request.get_json()
            domains = data.get('domains', [])
            
            if not domains:
                return jsonify({'status': 'error', 'error': '域名列表不能为空'}), 400
            
            valid_domains = []
            for domain in domains:
                domain = domain.strip()
                if domain and '.' in domain:
                    valid_domains.append(domain)
            
            if not valid_domains:
                return jsonify({'status': 'error', 'error': '未提供有效的域名'}), 400
            
            logger.info(f"开始批量安全分析，域名数量: {len(valid_domains)}")
            
            security_report = security_enhancer.generate_security_report(valid_domains)
            
            score_distribution = [0, 0, 0, 0]
            feature_stats = {
                'pinning': 0,
                'https': 0,
                'hsts': 0,
                'good_headers': 0,
                'valid_chains': 0
            }
            
            for result in security_report['detailed_results']:
                score = security_enhancer._calculate_comprehensive_security_score(result)
                
                if score >= 80:
                    score_distribution[0] += 1
                elif score >= 60:
                    score_distribution[1] += 1
                elif score >= 40:
                    score_distribution[2] += 1
                else:
                    score_distribution[3] += 1
                
                if result['certificate_pinning']['verified']:
                    feature_stats['pinning'] += 1
                if result['https_enforcement']['enforced']:
                    feature_stats['https'] += 1
                if result['hsts']['enabled']:
                    feature_stats['hsts'] += 1
                if result.get('security_headers', {}).get('assessment', {}).get('has_csp', False):
                    feature_stats['good_headers'] += 1
                if result.get('certificate_chain_valid', False):
                    feature_stats['valid_chains'] += 1
            
            security_report['scoreDistribution'] = score_distribution
            security_report['featureStats'] = feature_stats
            
            logger.info(f"批量安全分析完成，平均安全分数: {security_report['summary']['security_score']:.1f}")
            
            return jsonify({
                'status': 'success',
                'security_report': security_report
            })
            
        except Exception as e:
            logger.error(f"批量安全分析失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'批量分析失败: {str(e)}'}), 500
    
    @app.route('/api/security/analyze-pcap', methods=['POST'])
    def analyze_pcap_file():
        """分析PCAP文件并提取域名进行安全分析"""
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
            
            logger.info(f"开始分析PCAP文件: {filename}")
            
            domains = extract_domains_from_pcap(pcap_path)
            
            if not domains:
                logger.warning("无法从PCAP文件中提取域名")
                empty_report = create_empty_security_report()
                if pcap_path and os.path.exists(pcap_path):
                    os.remove(pcap_path)
                return jsonify({
                    'status': 'success',
                    'security_report': empty_report,
                    'extracted_domains': [],
                    'note': '无法从PCAP文件中提取域名'
                })
            
            logger.info(f"从PCAP文件中提取到 {len(domains)} 个域名")
            
            domain_stats = {
                'total_extracted': len(domains),
                'after_filtering': 0,
                'to_analyze': 0
            }
            
            filtered_domains = []
            for domain in domains:
                if is_valid_domain(domain):
                    filtered_domains.append(domain)
            
            domain_stats['after_filtering'] = len(filtered_domains)
            
            MAX_ANALYZE_DOMAINS = 20
            domains_to_analyze = filtered_domains[:MAX_ANALYZE_DOMAINS]
            domain_stats['to_analyze'] = len(domains_to_analyze)
            
            logger.info(f"PCAP域名统计: 提取{domain_stats['total_extracted']} -> 过滤后{domain_stats['after_filtering']} -> 实际分析{domain_stats['to_analyze']}")
            
            from domain_saver import save_filtered_domains, save_domains_to_txt
            saved_files = {}
            if filtered_domains:
                json_path = save_filtered_domains(
                    filtered_domains, 
                    analysis_type="pcap", 
                    source_file=file.filename
                )
                txt_path = save_domains_to_txt(
                    filtered_domains,
                    analysis_type="pcap", 
                    source_file=file.filename
                )
                saved_files = {
                    'json': json_path,
                    'txt': txt_path
                }

            security_report = simple_security_analyze(domains_to_analyze)
            
            security_report['domain_stats'] = domain_stats
            
            if pcap_path and os.path.exists(pcap_path):
                os.remove(pcap_path)
            
            return jsonify({
                'status': 'success',
                'security_report': security_report,
                'extracted_domains': domains[:10],
                'domain_stats': domain_stats,
                'saved_files': saved_files
            })
            
        except Exception as e:
            logger.error(f"PCAP文件分析失败: {str(e)}")
            
            if pcap_path and os.path.exists(pcap_path):
                try:
                    os.remove(pcap_path)
                    logger.info("已清理临时PCAP文件")
                except Exception as cleanup_error:
                    logger.warning(f"清理临时文件失败: {str(cleanup_error)}")
            
            empty_report = create_empty_security_report()
            return jsonify({
                'status': 'success',
                'security_report': empty_report,
                'extracted_domains': [],
                'note': f'PCAP分析失败: {str(e)}'
            })
    
    @app.route('/api/security/analyze-certificates', methods=['POST'])
    def analyze_certificate_files():
        """分析证书文件或压缩包并提取域名进行安全分析"""
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
                domains, cert_analysis_list = extract_domains_from_certificate_zip(file_path)
                certificate_analysis = cert_analysis_list
            else:
                domains, cert_info = extract_domains_from_der_file(file_path)
                certificate_analysis = [cert_info]
            
            if not domains:
                logger.warning(f"从证书文件中提取到 0 个域名")
                
                feedback_message = build_certificate_feedback(certificate_analysis)
                
                cert_info = certificate_analysis[0] if certificate_analysis else {}
                logger.info(f"证书类型: {cert_info.get('type', '未知')}")
                logger.info(f"是否是CA: {cert_info.get('is_ca', False)}")
                logger.info(f"是否自签名: {cert_info.get('is_self_signed', False)}")
                logger.info(f"反馈信息: {feedback_message}")
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                return jsonify({
                    'status': 'info', 
                    'message': feedback_message,
                    'certificate_analysis': certificate_analysis,
                    'certificate_type': cert_info.get('type', '未知类型'),
                    'is_ca': cert_info.get('is_ca', False),
                    'is_self_signed': cert_info.get('is_self_signed', False),
                    'subject': cert_info.get('subject', ''),
                    'issuer': cert_info.get('issuer', ''),
                    'extracted_domains_count': 0,
                    'certificate_details': cert_info
                })
            
            logger.info(f"从证书文件中提取到 {len(domains)} 个域名")
                    
            domain_stats = {
                'total_extracted': len(domains),
                'after_filtering': 0,
                'to_analyze': 0
            }
            
            filtered_domains = []
            for domain in domains:
                if is_valid_domain(domain):
                    filtered_domains.append(domain)
            
            domain_stats['after_filtering'] = len(filtered_domains)
            
            MAX_ANALYZE_DOMAINS = 20
            domains_to_analyze = filtered_domains[:MAX_ANALYZE_DOMAINS]
            domain_stats['to_analyze'] = len(domains_to_analyze)
            
            logger.info(f"域名分析统计: 提取{domain_stats['total_extracted']} -> 过滤后{domain_stats['after_filtering']} -> 实际分析{domain_stats['to_analyze']}")
            
            from domain_saver import save_filtered_domains, save_domains_to_txt
            saved_files = {}
            if filtered_domains:
                json_path = save_filtered_domains(
                    filtered_domains,
                    analysis_type=f"cert_{analysis_type}",
                    source_file=file.filename
                )
                txt_path = save_domains_to_txt(
                    filtered_domains,
                    analysis_type=f"cert_{analysis_type}",
                    source_file=file.filename
                )
                saved_files = {
                    'json': json_path,
                    'txt': txt_path
                }
            
            security_report = simple_security_analyze(domains_to_analyze)
            
            security_report['domain_stats'] = domain_stats
            security_report['certificate_analysis'] = certificate_analysis
            security_report['saved_files'] = saved_files
            
            if os.path.exists(file_path):
                os.remove(file_path)
            
            return jsonify({
                "status": "success",
                "security_report": security_report,
                "extracted_domains_count": len(domains),
                "analyzed_domains_count": security_report['summary']['analyzed_domains'],
                "domain_stats": domain_stats,
                "certificate_analysis": certificate_analysis,
                "saved_files": saved_files
            })

        except Exception as e:
            logger.error(f"证书文件分析失败: {str(e)}")
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'status': 'error', 'error': f'证书分析失败: {str(e)}'}), 500
    
    # 创建全局任务队列（简单版本）
    report_tasks = {}
    task_results = {}
    task_lock = threading.Lock()

    @app.route('/api/security/generate-report', methods=['POST'])
    def generate_security_report_api():
        """为安全分析生成AI报告（异步版本）"""
        try:
            data = request.get_json()
        
            # 生成唯一任务ID
            task_id = str(uuid.uuid4())
        
            # 记录任务开始
            with task_lock:
                report_tasks[task_id] = {
                    'status': 'processing',
                    'created_at': datetime.now().isoformat(),
                    'data': data  # 保存任务数据
                }
        
            # 启动后台线程处理任务
            thread = threading.Thread(
                target=process_report_task,
                args=(task_id, data),
                daemon=True
            )
            thread.start()
        
            logger.info(f"报告生成任务已提交，任务ID: {task_id}")
        
            return jsonify({
                'status': 'processing',
                'task_id': task_id,
                'message': '报告生成任务已提交，请稍后查询结果',
                'created_at': datetime.now().isoformat()
            })
        
        except Exception as e:
            logger.error(f"报告任务提交失败: {str(e)}")
            return jsonify({'status': 'error', 'error': f'报告任务提交失败: {str(e)}'}), 500

    def process_report_task(task_id, data):
        """后台处理报告任务"""
        try:
            logger.info(f"开始处理报告任务: {task_id}")
        
            # 调用你的报告生成函数
            from services.deepseek_service import generate_ai_report
        
            report_content = generate_ai_report(
                data, 
                source_type="security",
                original_filename=data.get('original_file', ''),
                report_type="security"
            )
             # 修复1：清理报告内容，移除可能导致JSON问题的字符
            if report_content:
                # 移除可能引起JSON解析问题的字符
                report_content = report_content.replace('\n', '\\n').replace('\r', '\\r')
                # 确保没有未闭合的引号
                report_content = report_content.replace('"', '\\"')
                # 限制报告长度，避免过长
                if len(report_content) > 100000:  # 限制为100K字符
                    report_content = report_content[:100000] + "\n\n[报告因过长被截断]"
        
            # 修复2：确保数据结构正确
            result_data = {
                'status': 'success',
                'report_content': report_content or '报告生成失败，内容为空',
                'completed_at': datetime.now().isoformat(),
                'report_length': len(report_content) if report_content else 0
            }
        
            # 修复3：记录报告信息用于调试
            logger.info(f"报告生成完成，长度: {len(report_content) if report_content else 0} 字符")
        
            with task_lock:
                task_results[task_id] = result_data
            
                    # 从任务队列移除（可选）
            if task_id in report_tasks:
                    del report_tasks[task_id]
        
            logger.info(f"报告任务完成: {task_id}")
        
        except Exception as e:
            logger.error(f"报告任务处理失败 {task_id}: {str(e)}")
        
            with task_lock:
                task_results[task_id] = {
                    'status': 'failed',
                    'error': str(e),
                    'completed_at': datetime.now().isoformat()
                }
            
                if task_id in report_tasks:
                    del report_tasks[task_id]
    
    @app.route('/api/security/report-status/<task_id>', methods=['GET'])
    def get_report_status(task_id):
        """获取报告生成状态"""
        try:
            with task_lock:
                logger.info(f"查询任务状态: {task_id}")
            
                # 先检查结果
                if task_id in task_results:
                    result = task_results[task_id]
                    logger.info(f"任务 {task_id} 结果: {result}")
                    return jsonify(result)
            
                # 检查任务是否仍在处理中
                elif task_id in report_tasks:
                    task_info = report_tasks[task_id]
                    logger.info(f"任务 {task_id} 处理中")
                    return jsonify({
                        'status': 'processing',
                        'created_at': task_info['created_at'],
                        'message': '报告生成中...'
                    })
            
                else:
                    logger.warning(f"任务 {task_id} 不存在")
                    return jsonify({'status': 'not_found'})
                
        except Exception as e:
            logger.error(f"获取任务状态失败 {task_id}: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500

        # 可选：清理过期任务的路由
    @app.route('/api/security/cleanup-tasks', methods=['POST'])
    def cleanup_tasks():
        """清理过期任务"""
        try:
            cleanup_count = 0
            current_time = datetime.now()
        
            with task_lock:
                # 清理超过1小时的已完成任务
                task_ids_to_remove = []
                for task_id, result in task_results.items():
                    completed_time = datetime.fromisoformat(result['completed_at'])
                    if (current_time - completed_time).seconds > 3600:
                        task_ids_to_remove.append(task_id)
            
                for task_id in task_ids_to_remove:
                    del task_results[task_id]
                    cleanup_count += 1
            
                # 清理超过10分钟的未完成任务
                task_ids_to_remove = []
                for task_id, task_info in report_tasks.items():
                    created_time = datetime.fromisoformat(task_info['created_at'])
                    if (current_time - created_time).seconds > 600:
                        task_ids_to_remove.append(task_id)
            
                for task_id in task_ids_to_remove:
                    del report_tasks[task_id]
                    cleanup_count += 1
        
            logger.info(f"清理了 {cleanup_count} 个过期任务")
            return jsonify({'status': 'success', 'cleaned_count': cleanup_count})
        
        except Exception as e:
            logger.error(f"清理任务失败: {str(e)}")
            return jsonify({'status': 'error', 'error': str(e)}), 500
    
    # ==================== 安全分析辅助函数 ====================
    
    def extract_domains_from_pcap(pcap_path):
        """从PCAP文件中提取域名"""
        domains = set()
        
        try:
            from scapy.all import rdpcap, DNSQR, DNSRR, TLSClientHello
            packets = rdpcap(pcap_path)
            
            for packet in packets:
                if packet.haslayer(DNSQR):
                    dns_qry = packet[DNSQR]
                    domain = dns_qry.qname.decode('utf-8').rstrip('.')
                    if domain and '.' in domain:
                        domains.add(domain)
                
                if packet.haslayer(TLSClientHello):
                    try:
                        sni = packet[TLSClientHello].sni
                        if sni and '.' in sni:
                            domains.add(sni.decode('utf-8'))
                    except:
                        pass
                
                if packet.haslayer('Raw'):
                    try:
                        raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
                        if 'Host: ' in raw_data:
                            for line in raw_data.split('\n'):
                                if line.startswith('Host: '):
                                    host = line[6:].strip()
                                    if host and '.' in host:
                                        domains.add(host)
                                    break
                    except:
                        pass
                        
        except ImportError:
            logger.warning("Scapy未安装，使用备用方法提取域名")
            domains = extract_domains_with_tshark(pcap_path)
        except Exception as e:
            logger.error(f"PCAP域名提取失败: {str(e)}")
        
        return list(domains)
    
    def extract_domains_with_tshark(pcap_path):
        """使用tshark从PCAP文件中提取域名（备用方法）"""
        domains = set()
        try:
            import subprocess
            
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            cmd_dns = ['tshark', '-r', pcap_path, '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'dns.qry.name']
            
            logger.info(f"执行tshark命令提取DNS域名: {' '.join(cmd_dns)}")
            
            result_dns = subprocess.run(
                cmd_dns, 
                capture_output=True, 
                text=True, 
                timeout=15,
                encoding='utf-8',
                errors='ignore',
                env=env
            )
            
            if result_dns.returncode == 0 and result_dns.stdout:
                for domain in result_dns.stdout.split('\n'):
                    domain = domain.strip()
                    if domain and '.' in domain and len(domain) < 253:
                        domain = domain.rstrip('.')
                        domains.add(domain)
                        logger.debug(f"从DNS提取到域名: {domain}")
            
            cmd_tls = ['tshark', '-r', pcap_path, '-Y', 'tls.handshake.extensions_server_name', '-T', 'fields', '-e', 'tls.handshake.extensions_server_name']
            
            logger.info(f"执行tshark命令提取TLS SNI: {' '.join(cmd_tls)}")
            
            result_tls = subprocess.run(
                cmd_tls, 
                capture_output=True, 
                text=True, 
                timeout=15,
                encoding='utf-8',
                errors='ignore',
                env=env
            )
            
            if result_tls.returncode == 0 and result_tls.stdout:
                for domain in result_tls.stdout.split('\n'):
                    domain = domain.strip()
                    if domain and '.' in domain and len(domain) < 253:
                        domains.add(domain)
                        logger.debug(f"从TLS SNI提取到域名: {domain}")
            
            logger.info(f"tshark共提取到 {len(domains)} 个唯一域名")
                        
        except subprocess.TimeoutExpired:
            logger.warning("tshark命令执行超时，返回已提取的域名")
        except Exception as e:
            logger.error(f"tshark域名提取失败: {str(e)}")
        
        return list(domains)
    
    def build_certificate_feedback(certificate_analysis):
        """构建证书分析反馈信息"""
        if not certificate_analysis:
            return "无法分析证书文件，请检查文件格式是否正确"
        
        cert_info = certificate_analysis[0]
        
        if cert_info.get('error'):
            return f"证书解析错误: {cert_info['error']}"
        
        feedback_parts = []
        
        cert_type = cert_info.get('type', '未知类型')
        feedback_parts.append(f"📄 证书类型: {cert_type}")
        
        subject = cert_info.get('subject', '')
        if subject:
            feedback_parts.append(f"🏷️ 证书主题: {subject}")
        
        issuer = cert_info.get('issuer', '')
        if issuer:
            feedback_parts.append(f"🏢 颁发机构: {issuer}")
        
        if cert_info.get('not_valid_before') and cert_info.get('not_valid_after'):
            feedback_parts.append(f"📅 有效期: {cert_info['not_valid_before'][:10]} 至 {cert_info['not_valid_after'][:10]}")
        
        if cert_info.get('is_ca'):
            if cert_info.get('is_self_signed'):
                feedback_parts.append("🔐 这是一个自签名根证书")
                feedback_parts.append("💡 用途: 用于建立信任链，签发其他证书")
                feedback_parts.append("❓ 原因: 根证书不包含可访问的域名")
            else:
                feedback_parts.append("🔐 这是一个中间CA证书")
                feedback_parts.append("💡 用途: 用于签发终端实体证书")
                feedback_parts.append("❓ 原因: CA证书不包含可访问的域名")
            
            feedback_parts.append("✅ 建议: 请上传叶子证书（终端实体证书）进行分析")
            
        elif cert_info.get('type', '').startswith('叶子证书'):
            if not cert_info.get('has_domains'):
                feedback_parts.append("❓ 原因: 证书中未找到有效的域名信息")
                feedback_parts.append("💡 可能原因:")
                feedback_parts.append("   • 证书用于代码签名或文档签名")
                feedback_parts.append("   • 证书用于设备认证而非网站")
                feedback_parts.append("   • 证书的Common Name不是域名格式")
                feedback_parts.append("✅ 建议: 请上传用于网站的证书")
            else:
                feedback_parts.append("✅ 这是一个有效的网站证书")
        
        elif cert_info.get('is_self_signed'):
            feedback_parts.append("🔐 这是一个自签名证书")
            feedback_parts.append("💡 用途: 通常用于内部测试或开发环境")
            feedback_parts.append("❓ 原因: 自签名证书可能不包含标准域名")
            feedback_parts.append("✅ 建议: 对于生产环境，请使用CA签发的证书")
        
        return "\n".join(feedback_parts)
    
    def extract_domains_from_certificate_zip(zip_path):
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
                    file_domains, cert_info = extract_domains_from_der_file(cert_file)
                    domains.update(file_domains)
                    cert_info['filename'] = os.path.basename(cert_file)
                    certificate_analysis_list.append(cert_info)
                except Exception as e:
                    logger.warning(f"无法从文件 {cert_file} 提取域名: {str(e)}")
                    certificate_analysis_list.append({
                        'filename': os.path.basename(cert_file),
                        'error': str(e)
                    })
                    continue
                    
        except Exception as e:
            logger.error(f"证书压缩包处理失败: {str(e)}")
        finally:
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir, ignore_errors=True)
        
        return list(domains), certificate_analysis_list
    
    def extract_domains_from_der_file(der_path):
        """从单个证书文件中提取域名（支持多种格式）"""
        domains = set()
        certificate_info = {
            'type': 'unknown',
            'subject': '',
            'issuer': '',
            'is_ca': False,
            'has_domains': False,
            'is_self_signed': False,
            'certificate_details': {}
        }
        
        try:
            logger.info(f"开始解析证书文件: {der_path}")
            
            with open(der_path, 'rb') as f:
                cert_data = f.read()
            
            logger.info(f"文件大小: {len(cert_data)} 字节")
            
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert = None
            parse_attempts = []
            
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                parse_attempts.append("DER解析成功")
            except Exception as e1:
                parse_attempts.append(f"DER解析失败: {str(e1)}")
                try:
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    parse_attempts.append("PEM解析成功")
                except Exception as e2:
                    parse_attempts.append(f"PEM解析失败: {str(e2)}")
            
            if not cert:
                logger.error(f"所有解析尝试都失败: {'; '.join(parse_attempts)}")
                certificate_info['error'] = '证书格式不支持'
                certificate_info['parse_attempts'] = parse_attempts
                return [], certificate_info
            
            logger.info(f"证书解析成功，开始提取域名")
            
            certificate_info['subject'] = cert.subject.rfc4514_string()
            certificate_info['issuer'] = cert.issuer.rfc4514_string()
            
            certificate_info['is_self_signed'] = (cert.subject == cert.issuer)
            
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
                certificate_info['is_ca'] = basic_constraints.value.ca
                if basic_constraints.value.ca:
                    if certificate_info['is_self_signed']:
                        certificate_info['type'] = '自签名根证书'
                    else:
                        certificate_info['type'] = '中间CA证书'
                else:
                    certificate_info['type'] = '叶子证书'
            except x509.ExtensionNotFound:
                certificate_info['is_ca'] = False
                certificate_info['type'] = '叶子证书（可能）'
            
            certificate_info['not_valid_before'] = cert.not_valid_before.isoformat()
            certificate_info['not_valid_after'] = cert.not_valid_after.isoformat()
            
            certificate_info['serial_number'] = str(cert.serial_number)
            
            subject = cert.subject
            cn_attributes = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attributes:
                for attr in cn_attributes:
                    domain = attr.value
                    if (domain and '.' in domain and 
                        not domain.startswith('*') and
                        len(domain) > 3 and len(domain) < 253 and
                        is_valid_domain(domain)):
                        domains.add(domain)
                        certificate_info['has_domains'] = True
                        logger.info(f"从CN提取到域名: {domain}")
                    else:
                        logger.info(f"CN值 '{domain}' 不是有效域名格式")
            
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_domains = san_ext.value.get_values_for_type(x509.DNSName)
                for domain in san_domains:
                    if (domain and '.' in domain and 
                        len(domain) > 3 and len(domain) < 253 and
                        is_valid_domain(domain)):
                        domains.add(domain)
                        certificate_info['has_domains'] = True
                logger.info(f"从SAN提取到域名: {san_domains}")
            except x509.ExtensionNotFound:
                logger.info("未找到SAN扩展")
            except Exception as e:
                logger.warning(f"SAN扩展解析失败: {str(e)}")
            
            if not domains:
                logger.info("尝试从其他名称属性中提取域名")
                for attr in subject:
                    try:
                        value = attr.value
                        if (isinstance(value, str) and '.' in value and 
                            not value.startswith('*') and
                            len(value) > 3 and len(value) < 253 and
                            is_valid_domain(value)):
                            domains.add(value)
                            certificate_info['has_domains'] = True
                            logger.info(f"从属性 {attr.oid._name} 提取到域名: {value}")
                    except Exception as e:
                        continue
            
            logger.info(f"总共提取到 {len(domains)} 个域名: {list(domains)}")
            logger.info(f"证书信息: {certificate_info}")
                
        except Exception as e:
            logger.error(f"证书解析失败 {der_path}: {str(e)}\n{traceback.format_exc()}")
            certificate_info['error'] = f"证书解析失败: {str(e)}"
        
        return list(domains), certificate_info
    
    def simple_security_analyze(domains):
        """简化的安全分析函数"""
        results = {
            'summary': {
                'security_score': 0,
                'domains_with_https_enforcement': 0,
                'domains_with_hsts': 0,
                'domains_with_valid_certificate_chains': 0,
                'total_domains': len(domains),
                'analyzed_domains': 0
            },
            'detailed_results': [],
            'scoreDistribution': [0, 0, 0, 0],
            'featureStats': {
                'https': 0,
                'hsts': 0,
                'good_headers': 0,
                'valid_chains': 0
            }
        }
        
        analyzed_count = 0
        total_score = 0
        
        logger.info(f"开始分析 {len(domains)} 个域名")
        
        for i, domain in enumerate(domains, 1):
            try:
                logger.info(f"分析进度: {i}/{len(domains)} - {domain}")
                
                domain_result = analyze_single_domain_simple(domain)
                if domain_result and domain_result.get('security_score', 0) > 0:
                    results['detailed_results'].append(domain_result)
                    score = domain_result.get('security_score', 0)
                    total_score += score
                    analyzed_count += 1
                    
                    if domain_result.get('https_enforcement', {}).get('enforced'):
                        results['featureStats']['https'] += 1
                        results['summary']['domains_with_https_enforcement'] += 1
                        
                    if domain_result.get('hsts', {}).get('enabled'):
                        results['featureStats']['hsts'] += 1
                        results['summary']['domains_with_hsts'] += 1
                        
                    if domain_result.get('certificate_chain_valid'):
                        results['featureStats']['valid_chains'] += 1
                        results['summary']['domains_with_valid_certificate_chains'] += 1
                    
                    headers = domain_result.get('security_headers', {}).get('assessment', {})
                    if headers.get('has_csp') or headers.get('has_x_frame_options'):
                        results['featureStats']['good_headers'] += 1
                    
                    if score >= 80:
                        results['scoreDistribution'][0] += 1
                    elif score >= 60:
                        results['scoreDistribution'][1] += 1
                    elif score >= 40:
                        results['scoreDistribution'][2] += 1
                    else:
                        results['scoreDistribution'][3] += 1
                        
            except Exception as e:
                logger.warning(f"域名 {domain} 分析失败: {str(e)}")
                continue
        
        if analyzed_count > 0:
            results['summary']['security_score'] = round(total_score / analyzed_count, 1)
            results['summary']['analyzed_domains'] = analyzed_count
        
        logger.info(f"安全分析完成: 成功分析 {analyzed_count}/{len(domains)} 个域名")
        
        return results
    
    def analyze_single_domain_simple(domain):
        """简化版单域名分析"""
        if not is_valid_domain(domain):
            return None
        
        result = {
            'domain': domain,
            'https_enforcement': {'enforced': False, 'status': '未知'},
            'hsts': {'enabled': False, 'status': '未知'},
            'security_headers': {
                'assessment': {
                    'has_csp': False,
                    'has_x_content_type_options': False,
                    'has_x_frame_options': False,
                    'has_referrer_policy': False
                }
            },
            'certificate_chain_valid': False,
            'security_score': 0
        }
        
        try:
            import requests
            
            https_result = check_https_simple(domain)
            result['https_enforcement'] = https_result
            
            hsts_result = check_hsts_simple(domain)
            result['hsts'] = hsts_result
            
            headers_result = check_security_headers_simple(domain)
            if headers_result:
                result['security_headers']['assessment'] = headers_result
            
            result['certificate_chain_valid'] = True
            
            score = 0
            if https_result.get('enforced'):
                score += 30
            if hsts_result.get('enabled'):
                score += 30
            if headers_result.get('has_csp'):
                score += 10
            if headers_result.get('has_x_content_type_options'):
                score += 5
            if headers_result.get('has_x_frame_options'):
                score += 5
            if headers_result.get('has_referrer_policy'):
                score += 5
            if result['certificate_chain_valid']:
                score += 15
                
            result['security_score'] = min(score, 100)
            
        except Exception as e:
            logger.warning(f"域名 {domain} 简化分析异常: {str(e)}")
            result['security_score'] = 0
        
        return result
    
    def check_https_simple(domain):
        """简化HTTPS检查"""
        import requests
        
        try:
            timeout = 3

            http_url = f"http://{domain}"
            response = requests.get(http_url, timeout=5, allow_redirects=False)
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('location', '')
                if location.startswith('https://'):
                    return {'enforced': True, 'status': '已启用重定向'}
            
            https_url = f"https://{domain}"
            response = requests.get(https_url, timeout=5)
            if response.status_code == 200:
                return {'enforced': True, 'status': 'HTTPS可直接访问'}
                
        except requests.exceptions.SSLError:
            return {'enforced': False, 'status': 'SSL证书错误'}
        except requests.exceptions.ConnectTimeout:
            return {'enforced': False, 'status': '连接超时'}
        except requests.exceptions.ConnectionError:
            return {'enforced': False, 'status': '连接失败'}
        except Exception:
            pass
        
        return {'enforced': False, 'status': '未启用'}
    
    def check_hsts_simple(domain):
        """简化HSTS检查"""
        import requests
        try:
            https_url = f"https://{domain}"
            response = requests.get(https_url, timeout=5)
            hsts_header = response.headers.get('strict-transport-security', '')
            
            if hsts_header:
                return {'enabled': True, 'status': '已配置'}
            else:
                return {'enabled': False, 'status': '未配置'}
                
        except Exception:
            return {'enabled': False, 'status': '检查失败'}
    
    def check_security_headers_simple(domain):
        """简化安全头检查"""
        import requests
        try:
            https_url = f"https://{domain}"
            response = requests.get(https_url, timeout=5)
            headers = response.headers
            
            return {
                'has_csp': 'content-security-policy' in headers,
                'has_x_content_type_options': 'x-content-type-options' in headers,
                'has_x_frame_options': 'x-frame-options' in headers,
                'has_referrer_policy': 'referrer-policy' in headers
            }
        except Exception:
            return {
                'has_csp': False,
                'has_x_content_type_options': False,
                'has_x_frame_options': False,
                'has_referrer_policy': False
            }
    
    def create_empty_security_report():
        """创建空的安全报告"""
        return {
            'summary': {
                'security_score': 0,
                'domains_with_https_enforcement': 0,
                'domains_with_hsts': 0,
                'domains_with_valid_certificate_chains': 0,
                'total_domains': 0,
                'analyzed_domains': 0
            },
            'detailed_results': [],
            'scoreDistribution': [0, 0, 0, 0],
            'featureStats': {
                'https': 0,
                'hsts': 0,
                'good_headers': 0,
                'valid_chains': 0
            },
            'domain_stats': {
                'total_extracted': 0,
                'after_filtering': 0,
                'to_analyze': 0,
                'successfully_analyzed': 0
            },
            'saved_files': { 
                'json': None,
                'txt': None
            },
            'recommendations': [
                "PCAP文件分析失败，请检查文件格式是否正确",
                "确保PCAP文件包含TLS/SSL握手流量",
                "尝试重新上传文件或使用其他PCAP文件"
            ]
        }
    
    def save_report_to_file(report_content, source_type, original_filename, reports_folder):
        """保存报告到文件"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = secure_filename(original_filename or 'unknown') if original_filename else 'unknown'
        report_filename = f"cert_report_{source_type}_{safe_filename}_{timestamp}.txt"
        report_path = os.path.join(reports_folder, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return report_path, report_filename