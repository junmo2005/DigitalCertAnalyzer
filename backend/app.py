import os
from dotenv import load_dotenv
from flask import Flask, jsonify
from utils.logging_utils import setup_logging

# 导入路由模块
from routes.main_routes import register_main_routes
from routes.cert_routes import register_cert_routes
from routes.security_routes import register_security_routes
from routes.report_routes import register_report_routes

load_dotenv()

app = Flask(__name__)

# ==================== 应用配置 ====================
app.config.update(
    MAX_CONTENT_LENGTH=520 * 1024 * 1024,
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key'),
    UPLOAD_FOLDER=os.path.join(os.getcwd(), 'uploads'),
    REPORTS_FOLDER=os.path.join(os.getcwd(), 'reports'),
    DEEPSEEK_API_KEY=os.getenv('DEEPSEEK_API_KEY', ''),
    DEEPSEEK_API_URL=os.getenv('DEEPSEEK_API_URL', 'https://api.deepseek.com/chat/completions'),             
    PINNING_DB_PATH=os.path.join(os.getcwd(), 'data', 'certificate_pinning_db.json')
)

# 创建必要的目录
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.getcwd(), 'data'), exist_ok=True)

# ==================== 注册路由 ====================

# 注册主页面路由
register_main_routes(app)

# 注册证书分析路由
register_cert_routes(app, app.config['UPLOAD_FOLDER'])

# 注册安全分析路由
register_security_routes(app, 
                        app.config['UPLOAD_FOLDER'], 
                        app.config['REPORTS_FOLDER'],
                        app.config['PINNING_DB_PATH'])

# 注册报告相关路由 - 传递必要的参数
register_report_routes(app, 
                      app.config['REPORTS_FOLDER'],
                      app.config['DEEPSEEK_API_KEY'],
                      app.config['DEEPSEEK_API_URL'])

# ==================== 错误处理 ====================

@app.errorhandler(413) 
def too_large(e):
    return jsonify({"error": "文件大小超过520MB限制"}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "服务器内部错误"}), 500

# ==================== 启动应用 ====================

# 确保静态文件夹存在
app.static_folder = 'static'
os.makedirs(app.static_folder, exist_ok=True)

# 在应用启动时调用
setup_logging(app)

if __name__ == '__main__':
    debug_mode = os.environ.get('ENV') != 'production'
    if not debug_mode:
        # type: ignore
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000)
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)