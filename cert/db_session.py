# cert/db_session.py
import threading
import logging
import sqlite3

from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

_db_manager = None
_current_task_id = threading.local()

def init_db(db_path=None):
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
        # ===== 新增：优化 SQLite 连接配置 =====
        _optimize_sqlite_connection(_db_manager)
        logger.info("DatabaseManager 全局实例已创建 (WAL模式已启用)")
    return _db_manager

def _optimize_sqlite_connection(db_manager):
    """优化 SQLite 连接以提高多线程并发性能"""
    try:
        conn = db_manager.conn
        # 启用 WAL 模式 - 允许读写并发，避免文件级锁阻塞
        conn.execute("PRAGMA journal_mode=WAL")
        # 降低同步级别，提高写入性能（崩溃安全由WAL保证）
        conn.execute("PRAGMA synchronous=NORMAL")
        # 增大缓存到 64MB
        conn.execute("PRAGMA cache_size=-64000")
        # 临时表使用内存存储
        conn.execute("PRAGMA temp_store=memory")
        # 设置 busy 超时为 5 秒，自动重试而非立即报错
        conn.execute("PRAGMA busy_timeout=5000")
        # 限制 WAL 文件大小为 64MB
        conn.execute("PRAGMA journal_size_limit=67108864")
        # 启用内存映射 I/O（如果支持）
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB
        logger.info("SQLite 优化配置已应用: WAL模式, 64MB缓存, 5s超时")
    except Exception as e:
        logger.warning(f"SQLite 优化配置失败: {e}")

def get_db():
    if _db_manager is None:
        raise RuntimeError("数据库未初始化，请先调用 init_db()")
    return _db_manager

def set_current_task_id(task_id: str):
    _current_task_id.task_id = task_id

def get_current_task_id():
    return getattr(_current_task_id, 'task_id', None)