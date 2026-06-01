from flask import request, jsonify
import os
import traceback
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from batch_process_pcaps import (
    analyze_pcap_with_detailed_stats,
    batch_process_certificates,
    process_certificate_archive
)
from certificate_validity_analyzer import CertificateValidityAnalyzer
from utils.file_utils import safe_division, extract_archive, find_certificate_files
import logging

# 新增导入
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db_session import get_db, set_current_task_id

logger = logging.getLogger(__name__)

SUPPORTED_CERTIFICATE_FORMATS = ['.cer', '.crt', '.pem', '.der']
SUPPORTED_ARCHIVE_FORMATS = ['.zip', '.rar', '.7z']

def register_cert_routes(app, upload_folder):
    """注册证书分析路由"""

    @app.route('/upload-pcap', methods=['POST'])
    def handle_pcap_upload():
        """处理PCAP文件上传，创建任务并运行分析"""
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

            # 创建数据库任务
            db = get_db()
            task_id = db.create_task(user_id=None, analysis_module='certificate', task_type='pcap',
                                    source_file=file.filename)
            set_current_task_id(task_id)
            db.update_task_status(task_id, 'running', progress=10)

            # 执行分析（内部会入库）
            detailed_results = analyze_pcap_with_detailed_stats(pcap_path)
            if not detailed_results:
                db.update_task_status(task_id, 'failed', error_msg="无法从PCAP中提取证书")
                return jsonify({"error": "PCAP分析失败"}), 400

            total_certs = detailed_results['summary']['total_certificates']
            unique_certs = detailed_results['summary']['unique_certificates']

            db.update_task_status(task_id, 'completed', progress=100,
                                  total_domains=0, total_certs=total_certs, unique_certs=unique_certs)

            # 组装返回数据（保持前端兼容）
            pcap_stats = detailed_results["pcap_statistics"]
            validity = detailed_results["certificate_validity"]
            total = validity.get('total_certificates', 0) or 1
            valid = validity.get('valid_certificates', 0)
            expiring = validity.get('expiring_soon_certificates', 0)
            expired = validity.get('expired_certificates', 0)

            formatted_result = {
                "status": "success",
                "task_id": task_id,
                "source_type": "pcap",
                "original_file": file.filename,
                "pcap_statistics": pcap_stats,
                "analysis": {
                    "total_certificates": total,
                    "valid_certificates": valid,
                    "expiring_soon_certificates": expiring,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid, total) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring, total) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total) * 100, 1),
                    "crypto_stats": validity.get('crypto_stats', {}),
                    "san_stats": validity.get('san_stats', {}),
                    "ca_stats": validity.get('ca_stats', {}),
                    "key_usage_stats": validity.get('key_usage_stats', {}),
                    "parse_errors": validity.get('parse_errors', 0),
                    "total_before_deduplication": pcap_stats.get('total_certificates', total),
                    "unique_certificates": pcap_stats.get('unique_certificates', total),
                    "duplicate_rate": pcap_stats.get('duplicate_rate', 0),
                    "cert_details": validity.get('cert_details', [])
                }
            }
            return jsonify(formatted_result)

        except Exception as e:
            app.logger.error(f"PCAP处理失败: {str(e)}\n{traceback.format_exc()}")
            try:
                db = get_db()
                db.update_task_status(task_id if 'task_id' in locals() else '', 'failed', error_msg=str(e))
            except:
                pass
            return jsonify({"error": f"PCAP处理失败: {str(e)}"}), 500
        finally:
            if pcap_path and os.path.exists(pcap_path):
                os.remove(pcap_path)
            set_current_task_id(None)

    @app.route('/batch-analyze', methods=['POST'])
    def handle_batch_analysis():
        """批量证书上传分析"""
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

            # 创建任务
            db = get_db()
            task_id = db.create_task(user_id=None, analysis_module='certificate', task_type='batch_der',
                                    source_file="multiple files")
            set_current_task_id(task_id)
            db.update_task_status(task_id, 'running', progress=10)

            # 调用批量处理（自动入库）
            results = batch_process_certificates(temp_dir, expiry_days=30)

            total_certs = results.get('total_certificates', 0) or 1
            valid = results.get('valid_certificates', 0)
            expiring = results.get('expiring_soon_certificates', 0)
            expired = results.get('expired_certificates', 0)
            db.update_task_status(task_id, 'completed', progress=100,
                                  total_certs=total_certs, unique_certs=total_certs)

            return jsonify({
                "status": "success",
                "task_id": task_id,
                "source_type": "batch",
                "file_count": len(saved_files),
                "analysis": {
                    "total_certificates": total_certs,
                    "valid_certificates": valid,
                    "expiring_soon_certificates": expiring,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid, total_certs) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring, total_certs) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total_certs) * 100, 1),
                    "crypto_stats": results.get('crypto_stats', {}),
                    "san_stats": results.get('san_stats', {}),
                    "ca_stats": results.get('ca_stats', {}),
                    "key_usage_stats": results.get('key_usage_stats', {}),
                    "parse_errors": results.get('parse_errors', 0),
                    "total_before_deduplication": results.get('total_before_deduplication', total_certs),
                    "cert_details": results.get('cert_details', [])   # 修正：使用 results
                }
            })
        except Exception as e:
            app.logger.error(f"批量处理失败: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": f"批量处理失败: {str(e)}"}), 500
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            set_current_task_id(None)

    @app.route('/upload-zip', methods=['POST'])
    def handle_zip_upload():
        """压缩包上传分析"""
        if 'file' not in request.files:
            return jsonify({"error": "未上传文件"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "未选择文件"}), 400
        file_ext = os.path.splitext(file.filename.lower())[1]
        if file_ext not in SUPPORTED_ARCHIVE_FORMATS:
            return jsonify({"error": f"不支持的压缩格式: {file_ext}"}), 400

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = secure_filename(f"archive_{timestamp}_{file.filename}")
        archive_path = os.path.join(upload_folder, filename)

        try:
            file.save(archive_path)
            app.logger.info(f"压缩包文件保存至: {archive_path}")

            db = get_db()
            task_id = db.create_task(user_id=None, analysis_module='certificate', task_type='zip',
                                    source_file=file.filename)
            set_current_task_id(task_id)
            db.update_task_status(task_id, 'running', progress=10)

            result, cert_files = process_certificate_archive(archive_path, upload_folder)
            analysis = result  # 这是 batch_process_certificates 返回的分析结果

            total_certs = analysis.get('total_certificates', 0) or 1
            valid = analysis.get('valid_certificates', 0)
            expiring = analysis.get('expiring_soon_certificates', 0)
            expired = analysis.get('expired_certificates', 0)

            db.update_task_status(task_id, 'completed', progress=100,
                                  total_certs=total_certs, unique_certs=total_certs)

            return jsonify({
                "status": "success",
                "task_id": task_id,
                "source_type": "zip",
                "original_file": file.filename,
                "file_count": len(cert_files),
                "extracted_files": [os.path.basename(f) for f in cert_files],
                "analysis": {
                    "total_certificates": total_certs,
                    "valid_certificates": valid,
                    "expiring_soon_certificates": expiring,
                    "expired_certificates": expired,
                    "valid_percentage": round(safe_division(valid, total_certs) * 100, 1),
                    "expiring_percentage": round(safe_division(expiring, total_certs) * 100, 1),
                    "expired_percentage": round(safe_division(expired, total_certs) * 100, 1),
                    "crypto_stats": analysis.get('crypto_stats', {}),
                    "san_stats": analysis.get('san_stats', {}),
                    "ca_stats": analysis.get('ca_stats', {}),
                    "key_usage_stats": analysis.get('key_usage_stats', {}),
                    "parse_errors": analysis.get('parse_errors', 0),
                    "total_before_deduplication": analysis.get('total_before_deduplication', total_certs),
                    "cert_details": analysis.get('cert_details', [])   # 修正：使用 analysis
                }
            })
        except ImportError as e:
            return jsonify({"error": f"依赖库缺失: {str(e)}"}), 500
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            app.logger.error(f"压缩包处理失败: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": f"压缩包处理失败: {str(e)}"}), 500
        finally:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
            set_current_task_id(None)