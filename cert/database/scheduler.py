# scheduler.py
import sys
import os
import logging
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_session import init_db, get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def daily_maintenance(db_path: str = None):
    """执行每日维护任务"""
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), 'database', 'database_schema.db')
    init_db(db_path)
    db = get_db()
    try:
        db.daily_maintenance()
        logger.info("每日维护执行成功")
    except Exception as e:
        logger.error(f"每日维护失败: {e}")
    finally:
        db.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='证书卫生监控定时维护工具')
    parser.add_argument('--force', action='store_true', help='强制重新执行维护')
    parser.add_argument('--db', type=str, default=None, help='数据库文件路径')
    args = parser.parse_args()

    db_path = args.db or os.path.join(os.path.dirname(__file__), 'database', 'database_schema.db')
    init_db(db_path)
    db = get_db()

    if args.force:
        logger.info("强制执行每日维护...")
        db.close()
        daily_maintenance(db_path)
        return

    today = date.today().isoformat()
    db.cursor.execute("SELECT 1 FROM certificate_health_snapshot WHERE snapshot_date = ?", (today,))
    if db.cursor.fetchone() is None:
        db.close()
        daily_maintenance(db_path)
    else:
        logger.info("今日已存在快照，跳过维护。")
        db.close()


if __name__ == '__main__':
    main()