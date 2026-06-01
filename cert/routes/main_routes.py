from flask import Blueprint, render_template, request,session, redirect, url_for,send_from_directory
import os

def register_main_routes(app):
    """注册主页面路由"""
    
    @app.route('/')
    def index():
        # 如果 URL 中携带 force_home=1，则清空 session 并显示首页（不跳转）
        if request.args.get('force_home') == '1':
            session.pop('user', None)  # 退出登录
            return render_template('index.html')
        
        # 已登录 → 按角色跳转
        if 'user' in session:
            user = session['user']
            if user.get('role') == 'admin':
                return redirect(url_for('dashboard.dashboard_page'))
            else:
                return redirect(url_for('system_intro'))
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