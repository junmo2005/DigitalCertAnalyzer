import os
import atexit
from flask import Flask, jsonify, session, redirect, url_for, render_template
from utils.logging_utils import setup_logging

from db_session import init_db, get_db

from routes.main_routes import register_main_routes
from routes.cert_routes import register_cert_routes
from routes.security_routes import register_security_routes
from routes.report_routes import register_report_routes
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp

from dotenv import load_dotenv

load_dotenv()


def create_app():
    app = Flask(__name__)

    # ==================== 应用配置 ====================
    app.config.update(
        MAX_CONTENT_LENGTH=520 * 1024 * 1024,
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key'),
        UPLOAD_FOLDER=os.path.join(os.getcwd(), 'uploads'),
        REPORTS_FOLDER=os.path.join(os.getcwd(), 'reports'),
        DEEPSEEK_API_KEY=os.getenv('DEEPSEEK_API_KEY', ''),
        DEEPSEEK_API_URL=os.getenv('DEEPSEEK_API_URL', 'https://api.deepseek.com/chat/completions'),
        PINNING_DB_PATH=os.path.join(os.getcwd(), 'data', 'certificate_pinning_db.json'),
        DB_PATH=os.path.join(os.getcwd(), 'database', 'database_schema.db')
    )

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(os.getcwd(), 'data'), exist_ok=True)
    os.makedirs(os.path.dirname(app.config['DB_PATH']), exist_ok=True)

    # 初始化全局数据库
    init_db(app.config['DB_PATH'])

    # ==================== 注册蓝图 ====================
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    register_main_routes(app)
    register_cert_routes(app, app.config['UPLOAD_FOLDER'])
    register_security_routes(app,
                             app.config['UPLOAD_FOLDER'],
                             app.config['REPORTS_FOLDER'],
                             app.config['PINNING_DB_PATH'])
    register_report_routes(app,
                           app.config['REPORTS_FOLDER'],
                           app.config['DEEPSEEK_API_KEY'],
                           app.config['DEEPSEEK_API_URL'])

    # ==================== 主页路由（已在 main_routes 中处理，此处可省略） ====================
    # 如果 main_routes 没有正确处理跳转，可以保留以下代码，但注意不要重复路由
    # 已由 main_routes 的 index 处理

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "文件大小超过520MB限制"}), 413

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "服务器内部错误"}), 500

    # ---------- 关键修改：不在每个请求后关闭数据库 ----------
    # 注释掉原来的 teardown_db，改为应用退出时关闭
    # @app.teardown_appcontext
    # def teardown_db(exception):
    #     db = get_db()
    #     if db:
    #         db.close()

    # 注册退出时的清理
    def close_db():
        db = get_db()
        if db:
            db.close()
    atexit.register(close_db)

    setup_logging(app)

    # 启动时检查今日快照
    with app.app_context():
        db = get_db()
        from datetime import date
        today = date.today().isoformat()
        db.cursor.execute("SELECT 1 FROM certificate_health_snapshot WHERE snapshot_date = ?", (today,))
        if db.cursor.fetchone() is None:
            print("今日快照未生成，立即执行每日维护...")
            db.daily_maintenance()
        else:
            print("今日快照已存在，跳过维护。")

    return app


app = create_app()

if __name__ == '__main__':
    debug_mode = os.environ.get('ENV') != 'production'
    if not debug_mode:
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000)
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)