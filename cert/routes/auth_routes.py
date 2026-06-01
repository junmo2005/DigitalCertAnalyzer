# routes/auth_routes.py
from flask import Blueprint, request, jsonify, session, redirect, url_for
from database.db_manager import DatabaseManager
from werkzeug.security import generate_password_hash, check_password_hash
import os

auth_bp = Blueprint('auth', __name__)

ADMIN_REGISTER_TOKEN = "YourSecureAdminToken2026"  # 管理者注册口令，可放环境变量

def get_db():
    # 此处需从应用上下文中获取数据库实例，简单起见直接实例化（生产环境应使用单例）
    from db_session import get_db as _get_db
    return _get_db()

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email', '')
    role = data.get('role', 'user')
    admin_token = data.get('adminToken', '')

    if not username or not password:
        return jsonify({'status': 'error', 'error': '用户名和密码不能为空'}), 400

    # 管理者注册需校验口令
    if role == 'admin':
        if admin_token != ADMIN_REGISTER_TOKEN:
            return jsonify({'status': 'error', 'error': '管理者口令错误'}), 403

    db = get_db()
    # 检查用户名是否已存在
    existing = db.get_user_by_username(username)
    if existing:
        return jsonify({'status': 'error', 'error': '用户名已被占用'}), 409

    hashed = generate_password_hash(password)
    success = db.create_user(username, hashed, email, role)
    if success:
        return jsonify({'status': 'success', 'message': '注册成功'})
    else:
        return jsonify({'status': 'error', 'error': '注册失败，请稍后重试'}), 500

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'error', 'error': '请输入用户名和密码'}), 400

    db = get_db()
    user = db.get_user_by_username(username)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'status': 'error', 'error': '用户名或密码错误'}), 401

    session['user'] = {
        'id': user['id'],
        'username': user['username'],
        'role': user['role']
    }
    if user['role'] == 'admin':
        redirect_url = url_for('dashboard.dashboard_page')
    else:
        redirect_url = url_for('cert_analysis')  # 跳转到普通用户页面（原有证书分析）
    return jsonify({'status': 'success', 'redirect': redirect_url})

@auth_bp.route('/api/auth/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))