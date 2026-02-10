import os
import shutil
import zipfile
import rarfile
import py7zr
from werkzeug.utils import secure_filename

SUPPORTED_ARCHIVE_FORMATS = ['.zip', '.rar', '.7z']
SUPPORTED_CERTIFICATE_FORMATS = ['.cer', '.crt', '.pem', '.der']

def safe_division(numerator, denominator, default=0):
    """安全的除法运算，避免除以零错误"""
    if denominator == 0:
        return default
    return numerator / denominator

def extract_archive(archive_path, extract_dir):
    """解压各种格式的压缩包"""
    if not os.path.exists(archive_path):
        raise ValueError("压缩包文件不存在")
    
    if archive_path.lower().endswith('.zip'):
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
    
    elif archive_path.lower().endswith('.rar'):
        if not hasattr(rarfile, 'is_rarfile'):
            raise ImportError("请安装rarfile库: pip install rarfile")
        with rarfile.RarFile(archive_path, 'r') as rar_ref:
            rar_ref.extractall(extract_dir)
    
    elif archive_path.lower().endswith('.7z'):
        if not hasattr(py7zr, 'SevenZipFile'):
            raise ImportError("请安装py7zr库: pip install py7zr")
        with py7zr.SevenZipFile(archive_path, 'r') as sevenz_ref:
            sevenz_ref.extractall(extract_dir)
    
    else:
        raise ValueError(f"不支持的压缩格式: {os.path.splitext(archive_path)[1]}")

def find_certificate_files(directory):
    """递归查找目录中的所有证书文件"""
    cert_files = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_ext = os.path.splitext(file.lower())[1]
            if file_ext in SUPPORTED_CERTIFICATE_FORMATS:
                cert_files.append(os.path.join(root, file))
    
    return cert_files

def is_valid_domain(domain):
    """检查域名是否有效 - 增强版"""
    if not domain or len(domain) < 3 or len(domain) > 253:
        return False
    
    invalid_patterns = [
        '.local', '.arpa', 'localhost', '*.',
        '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
    ]
    
    domain_lower = domain.lower()
    for pattern in invalid_patterns:
        if pattern in domain_lower:
            return False
    
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return False
    
    return ('.' in domain and 
            not domain.startswith(('.', '-')) and 
            not domain.endswith(('.', '-')) and
            ' ' not in domain)