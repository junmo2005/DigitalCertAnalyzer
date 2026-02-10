from flask import render_template, send_from_directory
import os

def register_main_routes(app):
    """注册主页面路由"""
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/system-intro')
    def system_intro():
        return render_template('system_intro.html')
    
    @app.route('/cert-analysis')
    def cert_analysis():
        return render_template('cert_analysis.html')
    
    @app.route('/security-analysis')
    def security_analysis():
        return render_template('security_analysis.html')
    
    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory(app.static_folder, filename)
    
    @app.route('/favicon.ico')
    def favicon():
        try:
            return send_from_directory(os.path.join(app.root_path, 'static'),
                                     'favicon.ico', 
                                     mimetype='image/vnd.microsoft.icon')
        except:
            return '', 204