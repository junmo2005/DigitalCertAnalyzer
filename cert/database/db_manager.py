import sqlite3
import os
import hashlib
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class DatabaseManager:
    def __init__(self, db_path: str = None):
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(current_dir, "database_schema.db")
        self.db_path = db_path
        self.conn = None
        self.cursor = None          # 保留 cursor 仅用于需要时，但主要使用 conn.execute
        self._connect()
        self._initialize_tables()

    def _connect(self):
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        logger.info("数据库连接已建立")

    def _initialize_tables(self):
        """执行建表脚本"""
        schema_path = os.path.join(os.path.dirname(__file__), "database_schema.sql")
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            self.conn.executescript(schema_sql)
            self.conn.commit()
            logger.info("数据库表结构初始化完成")
        else:
            logger.warning("找不到数据库建表脚本，请手动初始化")

    def close(self):
        if self.conn:
            self.conn.close()

    def _commit(self):
        self.conn.commit()

    # ------------------------------ 用户相关 ---------------------------------
    def create_user(self, username: str, password_hash: str, email: str = None, role: str = "user") -> bool:
        try:
            self.conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, role)
            )
            self._commit()
            return True
        except Exception as e:
            logger.error(f"创建用户失败: {e}")
            return False

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    # ------------------------------ 任务相关 ---------------------------------
    def create_task(self, user_id: int, analysis_module: str, task_type: str,
                    source_file: str = None) -> str:
        task_id = uuid.uuid4().hex
        self.conn.execute(
            """INSERT INTO analysis_tasks
               (task_id, user_id, analysis_module, task_type, source_file, status)
               VALUES (?, ?, ?, ?, ?, 'pending')""",
            (task_id, user_id, analysis_module, task_type, source_file)
        )
        self._commit()
        return task_id

    def update_task_status(self, task_id: str, status: str, progress: int = 100,
                           total_domains: int = None, total_certs: int = None,
                           unique_certs: int = None, error_msg: str = None,
                           processed_domains: int = None):
        fields = ["status = ?", "progress = ?", "completed_at = CURRENT_TIMESTAMP"]
        params = [status, progress]
        if total_domains is not None:
            fields.append("total_domains = ?")
            params.append(total_domains)
        if total_certs is not None:
            fields.append("total_certificates = ?")
            params.append(total_certs)
        if unique_certs is not None:
            fields.append("unique_certificates = ?")
            params.append(unique_certs)
        if error_msg is not None:
            fields.append("error_message = ?")
            params.append(error_msg)
        if processed_domains is not None:
            fields.append("processed_domains = ?")
            params.append(processed_domains)
        params.append(task_id)
        self.conn.execute(f"UPDATE analysis_tasks SET {', '.join(fields)} WHERE task_id = ?", params)
        self._commit()

    # ------------------------------ 证书资产管理 ---------------------------------
    def compute_fingerprint_sha256(self, cert_der: bytes) -> str:
        return hashlib.sha256(cert_der).hexdigest()

    def get_or_create_certificate_asset(self, fingerprint: str, cert_info: dict) -> int:
        """
        获取或创建资产记录。cert_info 应包含:
        subject_cn, issuer_cn, issuer_o, issuer_c, not_before, not_after,
        key_algorithm, key_size, signature_algorithm, san_list, san_count,
        key_usage, extended_key_usage, is_self_signed, is_ca
        """
        row = self.conn.execute(
            "SELECT id, first_seen FROM certificate_assets WHERE fingerprint_sha256 = ?",
            (fingerprint,)
        ).fetchone()
        if row:
            asset_id = row["id"]
            # 更新 not_after 和有效性，刷新 updated_at（不再使用 last_seen）
            self.conn.execute(
                """UPDATE certificate_assets
                   SET not_after = ?,
                       is_currently_valid = CASE WHEN ? > CURRENT_TIMESTAMP THEN 1 ELSE 0 END,
                       updated_at = CURRENT_TIMESTAMP
                   WHERE id = ?""",
                (cert_info.get("not_after"), cert_info.get("not_after"), asset_id)
            )
            self._commit()
            return asset_id
        else:
            self.conn.execute(
                """INSERT INTO certificate_assets
                   (fingerprint_sha256, subject_cn, issuer_cn, issuer_o, issuer_c,
                    not_before, not_after, key_algorithm, key_size, signature_algorithm,
                    san_list, san_count, key_usage, extended_key_usage,
                    is_self_signed, is_ca, first_seen, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                (fingerprint,
                 cert_info.get("subject_cn"),
                 cert_info.get("issuer_cn"),
                 cert_info.get("issuer_o"),
                 cert_info.get("issuer_c"),
                 cert_info.get("not_before"),
                 cert_info.get("not_after"),
                 cert_info.get("key_algorithm"),
                 cert_info.get("key_size"),
                 cert_info.get("signature_algorithm"),
                 cert_info.get("san_list"),
                 cert_info.get("san_count", 0),
                 cert_info.get("key_usage"),
                 cert_info.get("extended_key_usage"),
                 cert_info.get("is_self_signed", 0),
                 cert_info.get("is_ca", 0))
            )
            self._commit()
            return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def save_certificate_analysis(self, task_id: str, asset_id: int, fingerprint: str, cert_data: dict):
        """保存任务级证书快照（已去掉 chain_index/chain_length/source_index，保留 source_file）"""
        self.conn.execute(
            """INSERT INTO certificate_analyses
               (task_id, asset_id, fingerprint_sha256, domain, serial_number, issuer_key,
                subject_cn, issuer_cn, not_before, not_after, days_valid, days_remaining,
                validity_status, key_algorithm, key_size, signature_algorithm,
                san_list, san_count, key_usage, extended_key_usage,
                is_self_signed, is_valid, source_file)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, asset_id, fingerprint,
             cert_data.get("domain"),
             cert_data.get("serial_number"),
             cert_data.get("issuer_key"),
             cert_data.get("subject_cn"),
             cert_data.get("issuer_cn"),
             cert_data.get("not_before"),
             cert_data.get("not_after"),
             cert_data.get("days_valid"),
             cert_data.get("days_remaining"),
             cert_data.get("validity_status"),
             cert_data.get("key_algorithm"),
             cert_data.get("key_size"),
             cert_data.get("signature_algorithm"),
             cert_data.get("san_list"),
             cert_data.get("san_count", 0),
             cert_data.get("key_usage"),
             cert_data.get("extended_key_usage"),
             cert_data.get("is_self_signed", 0),
             cert_data.get("is_valid", 1),
             cert_data.get("source_file", ""))
        )
        self._commit()

    def get_expiring_certs(self, days: int = 30) -> List[Dict]:
        # risk_level 已删除，不再查询
        rows = self.conn.execute(
            """SELECT id, subject_cn, issuer_cn, not_after, is_unauthorized
               FROM certificate_assets
               WHERE is_currently_valid = 1
                 AND not_after BETWEEN CURRENT_TIMESTAMP AND datetime('now', '+' || ? || ' days')
               ORDER BY not_after""", (days,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_shadow_certs(self) -> List[Dict]:
        # last_seen 改为 updated_at
        rows = self.conn.execute(
            "SELECT id, subject_cn, issuer_cn, first_seen, updated_at FROM certificate_assets WHERE is_unauthorized = 1"
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------ 域名资产与管理 ---------------------------------
    def get_or_create_domain_asset(self, domain: str) -> int:
        """域名资产创建或更新（is_internal 已删除）"""
        row = self.conn.execute("SELECT id FROM domain_assets WHERE domain_name = ?", (domain,)).fetchone()
        if row:
            self.conn.execute(
                "UPDATE domain_assets SET last_seen = CURRENT_TIMESTAMP, total_encountered = total_encountered + 1 WHERE id = ?",
                (row[0],)
            )
            self.conn.commit()
            return row[0]
        else:
            cur = self.conn.execute(
                "INSERT INTO domain_assets (domain_name, first_seen, updated_at) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                (domain,)
            )
            self.conn.commit()
            return cur.lastrowid

    def update_domain_security_score(self, domain: str, total_score: int, grade: str):
        self.conn.execute(
            "UPDATE domain_assets SET last_https_score = ?, last_security_grade = ?, updated_at = CURRENT_TIMESTAMP WHERE domain_name = ?",
            (total_score, grade, domain)
        )
        self.conn.commit()

    # ------------------------------ 安全分析存储 ---------------------------------
    def save_security_analysis(self, task_id: str, domain: str, https_enf: bool, https_score: int,
                               hsts_enabled: bool, hsts_max_age: int, hsts_include_subdomains: bool,
                               hsts_score: int,
                               csp_enabled: bool, csp_value: str,
                               xcto: bool, xcto_value: str,
                               xfo: bool, xfo_value: str,
                               ref_pol: bool, ref_value: str,
                               headers_score: int,
                               cert_chain_valid: bool, chain_score: int,
                               total_score: int, grade: str):
        self.conn.execute(
            """INSERT INTO security_analyses
               (task_id, domain, https_enforcement, https_score,
                hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_score,
                has_csp, csp_value,
                has_x_content_type_options, x_content_type_options_value,
                has_x_frame_options, x_frame_options_value,
                has_referrer_policy, referrer_policy_value,
                headers_score,
                certificate_chain_valid, chain_score,
                total_score, security_grade)
               VALUES (?,?,?,?, ?,?,?,?, ?,?, ?,?, ?,?, ?,?, ?, ?,?,?,?)""",
            (task_id, domain, https_enf, https_score,
             hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_score,
             csp_enabled, csp_value,
             xcto, xcto_value,
             xfo, xfo_value,
             ref_pol, ref_value,
             headers_score,
             cert_chain_valid, chain_score,
             total_score, grade))
        self._commit()
        # 确保域名资产记录存在并更新评分
        self.get_or_create_domain_asset(domain)
        self.update_domain_security_score(domain, total_score, grade)

    # ------------------------------ 态势快照 ---------------------------------
    def calculate_daily_snapshot(self, snapshot_date: str = None):
        if snapshot_date is None:
            snapshot_date = datetime.now().strftime("%Y-%m-%d")
        # 活跃资产基于 updated_at
        total_active = self.conn.execute(
            "SELECT COUNT(*) FROM certificate_assets WHERE updated_at >= datetime('now', '-90 days')"
        ).fetchone()[0]

        expired = self.conn.execute(
            "SELECT COUNT(*) FROM certificate_assets WHERE updated_at >= datetime('now', '-90 days') AND not_after < CURRENT_TIMESTAMP"
        ).fetchone()[0]
        expired_ratio = (expired / total_active * 100) if total_active else 0

        expire_30d = self.conn.execute(
            "SELECT COUNT(*) FROM certificate_assets WHERE updated_at >= datetime('now', '-90 days') AND not_after BETWEEN CURRENT_TIMESTAMP AND datetime('now', '+30 days')"
        ).fetchone()[0]

        self_signed = self.conn.execute(
            "SELECT COUNT(*) FROM certificate_assets WHERE updated_at >= datetime('now', '-90 days') AND is_self_signed = 1"
        ).fetchone()[0]
        self_signed_ratio = (self_signed / total_active * 100) if total_active else 0

        weak_crypto = self.conn.execute(
            """SELECT COUNT(*) FROM certificate_assets
               WHERE updated_at >= datetime('now', '-90 days')
                 AND (key_size < 2048 OR signature_algorithm LIKE '%SHA-1%')"""
        ).fetchone()[0]
        weak_crypto_ratio = (weak_crypto / total_active * 100) if total_active else 0

        unauthorized = self.conn.execute(
            "SELECT COUNT(*) FROM certificate_assets WHERE updated_at >= datetime('now', '-90 days') AND is_unauthorized = 1"
        ).fetchone()[0]

        avg_score = self.conn.execute(
            "SELECT AVG(total_score) FROM security_analyses WHERE created_at >= ?", (snapshot_date,)
        ).fetchone()[0] or 0

        metrics = {
            "total_active_certs": total_active,
            "expired_ratio": round(expired_ratio, 2),
            "expire_30d_count": expire_30d,
            "self_signed_ratio": round(self_signed_ratio, 2),
            "weak_crypto_ratio": round(weak_crypto_ratio, 2),
            "unauthorized_certs": unauthorized,
            "avg_security_score": round(avg_score, 2)
        }

        for name, value in metrics.items():
            self.conn.execute(
                "INSERT OR REPLACE INTO certificate_health_snapshot (snapshot_date, metric_name, metric_value) VALUES (?, ?, ?)",
                (snapshot_date, name, value)
            )
        self._commit()
        logger.info(f"每日快照已生成：{snapshot_date}")
        return metrics

    # ------------------------------ 影子证书检测 ---------------------------------
    def detect_unauthorized_certs(self):
        # 获取配置
        row = self.conn.execute(
            "SELECT config_value FROM system_config WHERE config_key = 'internal_domain_suffixes'"
        ).fetchone()
        internal_suffixes = row["config_value"].split(",") if row else [".local", ".internal"]

        row = self.conn.execute(
            "SELECT config_value FROM system_config WHERE config_key = 'unauthorized_issuer_keywords'"
        ).fetchone()
        unauthorized_keywords = row["config_value"].split(",") if row else ["Self-Signed", "Test CA"]

        # 标记自签名 + 外联域名（基于 updated_at 活跃）
        rows = self.conn.execute(
            "SELECT id, san_list FROM certificate_assets WHERE is_self_signed = 1 AND updated_at >= datetime('now', '-90 days')"
        ).fetchall()
        for r in rows:
            if r["san_list"]:
                try:
                    domains = json.loads(r["san_list"])
                except:
                    continue
                if any(not any(d.endswith(suffix) for suffix in internal_suffixes) for d in domains):
                    self.conn.execute(
                        "UPDATE certificate_assets SET is_unauthorized = 1 WHERE id = ?", (r["id"],)
                    )

        # 标记颁发者关键字
        for keyword in unauthorized_keywords:
            self.conn.execute(
                "UPDATE certificate_assets SET is_unauthorized = 1 WHERE issuer_cn LIKE ? AND is_unauthorized = 0",
                ('%' + keyword.strip() + '%',)
            )
        self._commit()

    # ------------------------------ 定时维护任务 ---------------------------------
    def daily_maintenance(self):
        logger.info("开始每日维护：刷新有效期状态...")
        self.conn.execute(
            "UPDATE certificate_assets SET is_currently_valid = CASE WHEN not_after > CURRENT_TIMESTAMP THEN 1 ELSE 0 END"
        )
        self._commit()

        logger.info("检测影子证书...")
        self.detect_unauthorized_certs()

        logger.info("计算每日快照...")
        self.calculate_daily_snapshot()

        logger.info("每日维护完成")

    # ------------------------------ 通用查询（兼容旧接口） ---------------------------------
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        return [dict(row) for row in self.conn.execute(query, params).fetchall()]