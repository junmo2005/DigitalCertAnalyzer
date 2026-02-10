import os
import json
import datetime
from pathlib import Path

def save_filtered_domains(domains, analysis_type="unknown", source_file=None):
    """
    保存筛选后的域名到文件
    """
    try:
        # 定义保存目录
        save_dir = Path(r"D:\PythonTest\Digital Certificate\cert\域名筛选")
        
        # 确保目录存在
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成文件名
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if source_file:
            source_name = Path(source_file).stem
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
                "domain_count": len(domains)
            },
            "domains": domains
        }
        
        # 保存到JSON文件
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
        
        print(f"域名已保存到: {file_path}")
        return str(file_path)
        
    except Exception as e:
        print(f"保存域名时出错: {e}")
        return None

def save_domains_to_txt(domains, analysis_type="unknown", source_file=None):
    """
    保存域名到纯文本文件
    """
    try:
        save_dir = Path(r"D:\PythonTest\Digital Certificate\cert\域名筛选")
        save_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if source_file:
            source_name = Path(source_file).stem
            filename = f"{timestamp}_{analysis_type}_{source_name}.txt"
        else:
            filename = f"{timestamp}_{analysis_type}_domains.txt"
        
        file_path = save_dir / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# 域名分析结果\n")
            f.write(f"# 分析类型: {analysis_type}\n")
            f.write(f"# 源文件: {source_file or 'N/A'}\n")
            f.write(f"# 分析时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(domains)}\n")
            f.write("#" * 50 + "\n\n")
            
            for i, domain in enumerate(domains, 1):
                f.write(f"{i}. {domain}\n")
        
        print(f"域名已保存到文本文件: {file_path}")
        return str(file_path)
        
    except Exception as e:
        print(f"保存文本文件时出错: {e}")
        return None