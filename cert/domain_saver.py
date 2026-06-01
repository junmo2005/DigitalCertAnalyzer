# domain_saver.py - 修复版
import os
import json
import datetime
from pathlib import Path

def get_project_root():
    """
    获取项目根目录
    通过查找 app.py 或向上遍历找到包含特定文件的目录
    """
    current_dir = Path(__file__).resolve().parent
    
    # 向上查找包含 app.py 的目录
    for parent in [current_dir] + list(current_dir.parents):
        if (parent / "app.py").exists():
            return parent
    
    # 如果找不到 app.py，返回当前文件的父目录
    return current_dir

def get_save_directory():
    """
    获取域名保存目录（项目根目录下的"域名筛选"文件夹）
    """
    project_root = get_project_root()
    save_dir = project_root / "域名筛选"
    return save_dir

def save_filtered_domains(domains, analysis_type="unknown", source_file=None):
    """
    保存筛选后的域名到JSON文件
    保存位置：项目根目录/域名筛选/
    
    Args:
        domains: 域名列表
        analysis_type: 分析类型（pcap/cert_der/cert_zip等）
        source_file: 源文件名
    
    Returns:
        保存的文件路径，失败返回None
    """
    try:
        # 获取保存目录（项目根目录下的"域名筛选"文件夹）
        save_dir = get_save_directory()
        
        # 确保目录存在
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if source_file:
            # 清理文件名，移除不安全字符
            source_name = Path(source_file).stem
            # 替换可能导致路径问题的字符
            source_name = "".join(c for c in source_name if c.isalnum() or c in "._-")
            filename = f"{timestamp}_{analysis_type}_{source_name}.json"
        else:
            filename = f"{timestamp}_{analysis_type}_domains.json"
        
        file_path = save_dir / filename
        
        # 准备保存的数据
        save_data = {
            "metadata": {
                "analysis_type": analysis_type,
                "source_file": source_file,
                "timestamp": datetime.datetime.now().isoformat(),
                "domain_count": len(domains),
                "save_directory": str(save_dir)
            },
            "domains": domains
        }
        
        # 保存到JSON文件
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
        
        print(f"✅ 域名已保存到: {file_path}")
        return str(file_path)
        
    except Exception as e:
        print(f"❌ 保存域名时出错: {e}")
        import traceback
        traceback.print_exc()
        return None

def save_domains_to_txt(domains, analysis_type="unknown", source_file=None):
    """
    保存域名到纯文本文件
    保存位置：项目根目录/域名筛选/
    
    Args:
        domains: 域名列表
        analysis_type: 分析类型
        source_file: 源文件名
    
    Returns:
        保存的文件路径，失败返回None
    """
    try:
        # 获取保存目录（项目根目录下的"域名筛选"文件夹）
        save_dir = get_save_directory()
        
        # 确保目录存在
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if source_file:
            source_name = Path(source_file).stem
            source_name = "".join(c for c in source_name if c.isalnum() or c in "._-")
            filename = f"{timestamp}_{analysis_type}_{source_name}.txt"
        else:
            filename = f"{timestamp}_{analysis_type}_domains.txt"
        
        file_path = save_dir / filename
        
        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# 域名分析结果\n")
            f.write(f"# 分析类型: {analysis_type}\n")
            f.write(f"# 源文件: {source_file or 'N/A'}\n")
            f.write(f"# 分析时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(domains)}\n")
            f.write(f"# 保存目录: {save_dir}\n")
            f.write("#" * 50 + "\n\n")
            
            for i, domain in enumerate(domains, 1):
                f.write(f"{i}. {domain}\n")
        
        print(f"✅ 域名已保存到文本文件: {file_path}")
        return str(file_path)
        
    except Exception as e:
        print(f"❌ 保存文本文件时出错: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_saved_domains_list():
    """
    获取已保存的域名文件列表
    
    Returns:
        文件信息列表
    """
    try:
        save_dir = get_save_directory()
        if not save_dir.exists():
            return []
        
        files = []
        for file_path in save_dir.iterdir():
            if file_path.is_file() and file_path.suffix in ['.json', '.txt']:
                stat = file_path.stat()
                files.append({
                    'filename': file_path.name,
                    'path': str(file_path),
                    'size': stat.st_size,
                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'type': file_path.suffix
                })
        
        # 按修改时间倒序排列
        files.sort(key=lambda x: x['modified'], reverse=True)
        return files
        
    except Exception as e:
        print(f"获取文件列表失败: {e}")
        return []

def clean_old_files(days=30):
    """
    清理超过指定天数的旧文件
    
    Args:
        days: 保留天数，默认30天
    
    Returns:
        清理的文件数量
    """
    try:
        save_dir = get_save_directory()
        if not save_dir.exists():
            return 0
        
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)
        cleaned_count = 0
        
        for file_path in save_dir.iterdir():
            if file_path.is_file():
                mtime = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)
                if mtime < cutoff_time:
                    try:
                        file_path.unlink()
                        cleaned_count += 1
                        print(f"已删除过期文件: {file_path.name}")
                    except Exception as e:
                        print(f"删除文件失败 {file_path.name}: {e}")
        
        print(f"清理完成，共删除 {cleaned_count} 个文件")
        return cleaned_count
        
    except Exception as e:
        print(f"清理文件失败: {e}")
        return 0

# ====================== 测试代码 ======================

if __name__ == "__main__":
    # 测试获取项目根目录
    print(f"项目根目录: {get_project_root()}")
    print(f"保存目录: {get_save_directory()}")
    
    # 测试保存功能
    test_domains = ["example.com", "google.com", "github.com"]
    json_path = save_filtered_domains(test_domains, "test", "test_source.pcap")
    txt_path = save_domains_to_txt(test_domains, "test", "test_source.pcap")
    
    print(f"\nJSON文件: {json_path}")
    print(f"TXT文件: {txt_path}")
    
    # 测试获取文件列表
    files = get_saved_domains_list()
    print(f"\n已保存的文件 ({len(files)} 个):")
    for f in files[:5]:
        print(f"  - {f['filename']} ({f['size']} bytes)")