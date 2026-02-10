from flask import request, jsonify, send_file
import os
from datetime import datetime
from utils.report_utils import save_report_to_file
from werkzeug.utils import secure_filename
import logging

# 创建独立的日志记录器
logger = logging.getLogger(__name__)

def register_report_routes(app, reports_folder, deepseek_api_key, deepseek_api_url):
    """注册报告相关路由"""
    from services.deepseek_service import DeepSeekConfig
    if deepseek_api_key:
        DeepSeekConfig.configure(api_key=deepseek_api_key, api_url=deepseek_api_url)

    # 导入 deepseek_service 的函数
    try:
        from services.deepseek_service import (
            generate_ai_report, 
            generate_security_default_report,
            generate_certificate_default_report,
            check_network_connection,
            call_deepseek_api_with_retry,
            call_deepseek_api
        )
        deepseek_available = True
    except ImportError as e:
        logger.warning(f"无法导入 deepseek_service: {str(e)}")
        deepseek_available = False
    
    def save_report_to_file_local(report_content, source_type, original_filename):
        """本地保存报告到文件函数"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = secure_filename(original_filename or 'unknown') if original_filename else 'unknown'
        report_filename = f"cert_report_{source_type}_{safe_filename}_{timestamp}.txt"
        report_path = os.path.join(reports_folder, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return report_path, report_filename
        
    @app.route('/generate-report', methods=['POST'])
    def generate_report():
        """生成分析报告接口"""
        try:
            data = request.get_json()
            if not data or 'analysis' not in data:
                return jsonify({'error': '缺少分析数据'}), 400
            
            source_type = data.get('source_type', 'unknown')
            original_file = data.get('original_file', '')
            
           # 使用修复后的 deepseek_service 函数
            report_content = generate_ai_report(
                data, 
                source_type, 
                original_file,
                "certificate",  # 报告类型
            )
            
            report_path, report_filename = save_report_to_file(
                report_content, 
                source_type, 
                original_file, 
                reports_folder
            )
            
            return jsonify({
                'status': 'success',
                'report_content': report_content,
                'report_filename': report_filename,
                'report_path': report_path,
                'generated_at': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"报告生成失败: {str(e)}")
            return jsonify({'error': f'报告生成失败: {str(e)}'}), 500
    
    @app.route('/api/security/generate-report', methods=['POST'])
    def generate_security_report_api_route():
        """为安全分析生成AI报告"""
        data = request.get_json()
        
        # 使用修复后的 deepseek_service 函数
        report_content = generate_ai_report(
            data, 
            source_type="security",
            original_filename=data.get('original_file', ''),
            report_type="security",
            api_key=deepseek_api_key,
            api_url=deepseek_api_url
        )
        
        # 保存报告文件
        from werkzeug.utils import secure_filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = secure_filename(data.get('original_file', '') or 'unknown')
        report_filename = f"cert_report_security_{safe_filename}_{timestamp}.txt"
        report_path = os.path.join(reports_folder, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return jsonify({
            'status': 'success',
            'report_content': report_content,
            'report_filename': report_filename,
            'generated_at': datetime.now().isoformat()  # 添加这个字段
        })
    
    @app.route('/download-report/<filename>')
    def download_report(filename):
        """下载报告文件"""
        try:
            from werkzeug.utils import secure_filename
            safe_filename = secure_filename(filename)
            report_path = os.path.join(reports_folder, safe_filename)

            if not os.path.exists(report_path):
                return jsonify({'error': '报告文件不存在'}), 404
            
            return send_file(
                report_path, 
                as_attachment=True, 
                download_name=safe_filename,
                mimetype='text/plain')
            
        except Exception as e:
            app.logger.error(f"报告下载失败: {str(e)}")
            return jsonify({'error': f'报告下载失败: {str(e)}'}), 500
    
    @app.route('/list-reports')
    def list_reports():
        """获取报告列表"""
        try:
            reports = []
            for filename in os.listdir(reports_folder):
                if filename.endswith('.txt'):
                    filepath = os.path.join(reports_folder, filename)
                    stats = os.stat(filepath)
                    reports.append({
                        'filename': filename,
                        'size': stats.st_size,
                        'created_at': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                        'download_url': f'/download-report/{filename}'
                    })
            
            return jsonify({'reports': sorted(reports, key=lambda x: x['created_at'], reverse=True)})
            
        except Exception as e:
            app.logger.error(f"获取报告列表失败: {str(e)}")
            return jsonify({'error': f'获取报告列表失败: {str(e)}'}), 500