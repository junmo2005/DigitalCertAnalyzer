from flask import request, jsonify
import os
import traceback
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from batch_process_pcaps import analyze_pcap_with_detailed_stats
from certificate_validity_analyzer import CertificateValidityAnalyzer
from utils.file_utils import safe_division, extract_archive, find_certificate_files
import logging

logger = logging.getLogger(__name__)
# ==================== 定义常量 ====================
SUPPORTED_CERTIFICATE_FORMATS = ['.cer', '.crt', '.pem', '.der']
SUPPORTED_ARCHIVE_FORMATS = ['.zip', '.rar', '.7z']

def register_cert_routes(app, upload_folder):
    """注册证书分析路由"""
    
    @app.route('/upload-pcap', methods=['POST'])
    def handle_pcap_upload():
        """处理PCAP文件上传"""
        if 'file' not in request.files:
            return jsonify({"error": "未上传文件"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "未选择文件"}), 400
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = secure_filename(f"pcap_{timestamp}_{file.filename}")
        pcap_path = os.path.join(upload_folder, filename)

        try:
            file.save(pcap_path)
            app.logger.info(f"PCAP文件保存至: {pcap_path}")
            
            detailed_results = analyze_pcap_with_detailed_stats(pcap_path)
            
            if not detailed_results:
                return jsonify({
                    "error": "PCAP分析失败",
                    "details": "无法从PCAP文件中提取证书信息"
                }), 400
            
            pcap_stats = detailed_results["pcap_statistics"]
            validity_analysis = detailed_results["certificate_validity"]
            
            total_certs = validity_analysis.get('total_certificates', 0) or 1
            valid_certs = validity_analysis.get('valid_certificates', 0)
            expiring_soon = validity_analysis.get('expiring_soon_certificates', 0)
            expired = validity_analysis.get('expired_certificates', 0)
            
            formatted_result = {
                "status": "success",
                "source_type": "pcap",
                "original_file": file.filename,
                "pcap_statistics": pcap_stats,
                "analysis": {
                    "total_certificates": total_certs,
                    "valid_certificates": valid_certs,
                    "expiring_soon_certificates": expiring_soon,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid_certs, total_certs) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring_soon, total_certs) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total_certs) * 100, 1),
                    "crypto_stats": validity_analysis.get('crypto_stats', {}),
                    "san_stats": validity_analysis.get('san_stats', {}),
                    "ca_stats": validity_analysis.get('ca_stats', {}),
                    "key_usage_stats": validity_analysis.get('key_usage_stats', {}),
                    "parse_errors": validity_analysis.get('parse_errors', 0),
                    "total_before_deduplication": pcap_stats.get('total_certificates', total_certs),
                    "unique_certificates": pcap_stats.get('unique_certificates', total_certs),
                    "duplicate_rate": pcap_stats.get('duplicate_rate', 0)
                }
            }
            
            return jsonify(formatted_result)
            
        except Exception as e:
            app.logger.error(f"PCAP处理失败: {str(e)}\n{traceback.format_exc()}")
            return jsonify({
                "error": f"PCAP处理失败: {str(e)}",
                "details": traceback.format_exc() if app.debug else "请查看服务器日志获取详细信息"
            }), 500
            
        finally:
            if pcap_path and os.path.exists(pcap_path):
                os.remove(pcap_path)
    
    @app.route('/batch-analyze', methods=['POST'])
    def handle_batch_analysis():
        """处理批量证书上传"""
        if 'files[]' not in request.files:
            return jsonify({'error': '未选择文件'}), 400
        
        files = request.files.getlist('files[]')
        if not files or files[0].filename == '':
            return jsonify({'error': '未选择有效文件'}), 400
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        temp_dir = os.path.join(upload_folder, f"batch_{timestamp}")
        
        try:
            os.makedirs(temp_dir, exist_ok=True)
            saved_files = []

            for file in files:
                if file.filename == '':
                    continue
                filename = secure_filename(file.filename)
                filepath = os.path.join(temp_dir, filename)
                file.save(filepath)
                saved_files.append(filepath)
            
            if not saved_files:
                return jsonify({"error": "无有效文件"}), 400
            
            analyzer = CertificateValidityAnalyzer(expiry_warning_days=30)
            results = analyzer.analyze_certificates_directory(temp_dir)
            
            total_certs = results.get('total_certificates', 0) or 1
            valid_certs = results.get('valid_certificates', 0)
            expiring_soon = results.get('expiring_soon_certificates', 0)
            expired = results.get('expired_certificates', 0)

            return jsonify({
                "status": "success",
                "source_type": "batch",
                "file_count": len(saved_files),
                "analysis": {
                    "total_certificates": total_certs,
                    "valid_certificates": valid_certs,
                    "expiring_soon_certificates": expiring_soon,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid_certs, total_certs) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring_soon, total_certs) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total_certs) * 100, 1),
                    "crypto_stats": results.get('crypto_stats', {}),
                    "san_stats": results.get('san_stats', {}),
                    "ca_stats": results.get('ca_stats', {}),
                    "key_usage_stats": results.get('key_usage_stats', {}),
                    "parse_errors": results.get('parse_errors', 0),
                    "total_before_deduplication": results.get('total_before_deduplication', total_certs)
                }
            })
            
        except Exception as e:
            app.logger.error(f"批量处理失败: {str(e)}\n{traceback.format_exc()}")
            return jsonify({
                "error": f"批量处理失败: {str(e)}",
                "details": traceback.format_exc() if app.debug else None
            }), 500
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def analyze_zip_file(zip_path):
        """分析压缩包中的证书文件"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        extract_dir = os.path.join(upload_folder, f"zip_extract_{timestamp}")
        
        try:
            os.makedirs(extract_dir, exist_ok=True)
            extract_archive(zip_path, extract_dir)
            
            cert_files = find_certificate_files(extract_dir)
            
            if not cert_files:
                raise ValueError("压缩包中未找到支持的证书文件")
            
            temp_cert_dir = os.path.join(upload_folder, f"certs_{timestamp}")
            os.makedirs(temp_cert_dir, exist_ok=True)
            
            for cert_file in cert_files:
                filename = os.path.basename(cert_file)
                dest_path = os.path.join(temp_cert_dir, filename)
                
                counter = 1
                while os.path.exists(dest_path):
                    name, ext = os.path.splitext(filename)
                    dest_path = os.path.join(temp_cert_dir, f"{name}_{counter}{ext}")
                    counter += 1
                
                shutil.copy2(cert_file, dest_path)
            
            analyzer = CertificateValidityAnalyzer(expiry_warning_days=30)
            results = analyzer.analyze_certificates_directory(temp_cert_dir)
            
            return {
                "total_files": len(cert_files),
                "analysis": results,
                "extracted_files": [os.path.basename(f) for f in cert_files]
            }
            
        finally:
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir, ignore_errors=True)
            if 'temp_cert_dir' in locals() and os.path.exists(temp_cert_dir):
                shutil.rmtree(temp_cert_dir, ignore_errors=True)
    
    @app.route('/upload-zip', methods=['POST'])
    def handle_zip_upload():
        """处理压缩包上传"""
        if 'file' not in request.files:
            return jsonify({"error": "未上传文件"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "未选择文件"}), 400
        
        SUPPORTED_ARCHIVE_FORMATS = ['.zip', '.rar', '.7z']
        file_ext = os.path.splitext(file.filename.lower())[1]
        if file_ext not in SUPPORTED_ARCHIVE_FORMATS:
            return jsonify({
                "error": f"不支持的压缩格式: {file_ext}",
                "supported_formats": SUPPORTED_ARCHIVE_FORMATS
            }), 400
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = secure_filename(f"archive_{timestamp}_{file.filename}")
        archive_path = os.path.join(upload_folder, filename)
        
        try:
            file.save(archive_path)
            app.logger.info(f"压缩包文件保存至: {archive_path}")
            
            result = analyze_zip_file(archive_path)
            
            analysis = result["analysis"]
            total_certs = analysis.get('total_certificates', 0) or 1
            valid_certs = analysis.get('valid_certificates', 0)
            expiring_soon = analysis.get('expiring_soon_certificates', 0)
            expired = analysis.get('expired_certificates', 0)
            
            response_data = {
                "status": "success",
                "source_type": "zip",
                "original_file": file.filename,
                "file_count": result["total_files"],
                "extracted_files": result["extracted_files"],
                "analysis": {
                    "total_certificates": total_certs,
                    "valid_certificates": valid_certs,
                    "expiring_soon_certificates": expiring_soon,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid_certs, total_certs) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring_soon, total_certs) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total_certs) * 100, 1),
                    "crypto_stats": analysis.get('crypto_stats', {}),
                    "san_stats": analysis.get('san_stats', {}),
                    "ca_stats": analysis.get('ca_stats', {}),
                    "key_usage_stats": analysis.get('key_usage_stats', {}),
                    "parse_errors": analysis.get('parse_errors', 0),
                    "total_before_deduplication": analysis.get('total_before_deduplication', total_certs)
                }
            }
            
            return jsonify(response_data)
            
        except ImportError as e:
            app.logger.error(f"依赖库缺失: {str(e)}")
            return jsonify({
                "error": f"依赖库缺失: {str(e)}",
                "solution": "请安装所需的库: pip install rarfile py7zr"
            }), 500
            
        except ValueError as e:
            app.logger.error(f"压缩包处理错误: {str(e)}")
            return jsonify({
                "error": str(e),
                "supported_formats": SUPPORTED_CERTIFICATE_FORMATS
            }), 400
            
        except Exception as e:
            app.logger.error(f"压缩包处理失败: {str(e)}\n{traceback.format_exc()}")
            return jsonify({
                "error": f"压缩包处理失败: {str(e)}",
                "details": traceback.format_exc() if app.debug else None
            }), 500
            
        finally:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)