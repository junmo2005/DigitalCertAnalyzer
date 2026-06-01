"""
数据库迁移脚本 v2.0
功能：精简表结构、修复数据、保留现有数据
运行前请务必备份数据库文件！
"""
import sqlite3
import os
import shutil
from datetime import datetime

DB_PATH = "database/database_schema.db"      # 根据实际路径调整
BACKUP_DIR = "database/backups"

def backup_db():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"database_schema_backup_{timestamp}.db")
    shutil.copy2(DB_PATH, backup_path)
    print(f"[+] 数据库已备份至: {backup_path}")

def migrate():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = OFF")
    cur = conn.cursor()

    try:
        cur.execute("BEGIN IMMEDIATE")

        # ===================== 1. users =====================
        print("[1/9] 迁移 users 表...")
        cur.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE,
                role VARCHAR(20) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status INTEGER DEFAULT 1
            )
        """)
        cur.execute("""
            INSERT INTO users_new (id, username, password_hash, email, role, created_at, status)
            SELECT id, username, password_hash, email, role, created_at, status FROM users
        """)
        cur.execute("DROP TABLE users")
        cur.execute("ALTER TABLE users_new RENAME TO users")

        # ===================== 2. analysis_tasks =====================
        print("[2/9] 迁移 analysis_tasks 表...")
        cur.execute("""
            CREATE TABLE analysis_tasks_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id VARCHAR(64) NOT NULL UNIQUE,
                user_id INTEGER,
                analysis_module VARCHAR(20) NOT NULL,
                task_type VARCHAR(20) NOT NULL,
                source_file VARCHAR(255),
                file_size INTEGER DEFAULT 0,
                status VARCHAR(20) DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                total_domains INTEGER DEFAULT 0,
                processed_domains INTEGER DEFAULT 0,
                total_certificates INTEGER DEFAULT 0,
                unique_certificates INTEGER DEFAULT 0,
                parse_errors INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        cur.execute("""
            INSERT INTO analysis_tasks_new (
                id, task_id, user_id, analysis_module, task_type, source_file,
                file_size, status, progress, created_at, completed_at, error_message,
                total_domains, processed_domains, total_certificates, unique_certificates, parse_errors
            )
            SELECT
                id, task_id, user_id, analysis_module, task_type, source_file,
                COALESCE(file_size, 0), status, progress, created_at, completed_at, error_message,
                total_domains, processed_domains, total_certificates, unique_certificates, parse_errors
            FROM analysis_tasks
        """)
        cur.execute("DROP TABLE analysis_tasks")
        cur.execute("ALTER TABLE analysis_tasks_new RENAME TO analysis_tasks")

        # ===================== 3. certificate_assets =====================
        print("[3/9] 迁移 certificate_assets 表...")
        cur.execute("""
            CREATE TABLE certificate_assets_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
                subject_cn VARCHAR(255),
                issuer_cn VARCHAR(255),
                issuer_o VARCHAR(255),
                issuer_c VARCHAR(10),
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                key_algorithm VARCHAR(50),
                key_size INTEGER,
                signature_algorithm VARCHAR(100),
                san_list TEXT,
                san_count INTEGER DEFAULT 0,
                key_usage TEXT,
                extended_key_usage TEXT,
                is_self_signed BOOLEAN DEFAULT 0,
                is_ca BOOLEAN DEFAULT 0,
                first_seen TIMESTAMP,
                is_currently_valid BOOLEAN DEFAULT 1,
                remediation_status VARCHAR(20) DEFAULT 'none',
                is_unauthorized BOOLEAN DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            INSERT INTO certificate_assets_new (
                id, fingerprint_sha256, subject_cn, issuer_cn, issuer_o, issuer_c,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                san_list, san_count, key_usage, extended_key_usage,
                is_self_signed, is_ca, first_seen,
                is_currently_valid, remediation_status, is_unauthorized, updated_at
            )
            SELECT
                id, fingerprint_sha256, subject_cn, issuer_cn, issuer_o, issuer_c,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                san_list, san_count, key_usage, extended_key_usage,
                is_self_signed, is_ca, first_seen,
                is_currently_valid, remediation_status, is_unauthorized, COALESCE(updated_at, created_at)
            FROM certificate_assets
        """)
        cur.execute("DROP TABLE certificate_assets")
        cur.execute("ALTER TABLE certificate_assets_new RENAME TO certificate_assets")

        # ===================== 4. certificate_analyses =====================
        print("[4/9] 迁移 certificate_analyses 表...")
        cur.execute("""
            CREATE TABLE certificate_analyses_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id VARCHAR(64) NOT NULL,
                asset_id INTEGER,
                fingerprint_sha256 VARCHAR(64),
                domain VARCHAR(255),
                serial_number VARCHAR(100),
                issuer_key VARCHAR(255),
                subject_cn VARCHAR(255),
                issuer_cn VARCHAR(255),
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                days_valid INTEGER,
                days_remaining INTEGER,
                validity_status VARCHAR(20),
                key_algorithm VARCHAR(50),
                key_size INTEGER,
                signature_algorithm VARCHAR(100),
                san_list TEXT,
                san_count INTEGER DEFAULT 0,
                key_usage TEXT,
                extended_key_usage TEXT,
                is_self_signed BOOLEAN DEFAULT 0,
                is_valid BOOLEAN DEFAULT 1,
                source_file VARCHAR(255) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE,
                FOREIGN KEY (asset_id) REFERENCES certificate_assets(id) ON DELETE SET NULL
            )
        """)
        cur.execute("""
            INSERT INTO certificate_analyses_new (
                id, task_id, asset_id, fingerprint_sha256, domain, serial_number, issuer_key,
                subject_cn, issuer_cn, not_before, not_after, days_valid, days_remaining,
                validity_status, key_algorithm, key_size, signature_algorithm,
                san_list, san_count, key_usage, extended_key_usage,
                is_self_signed, is_valid, source_file, created_at
            )
            SELECT
                id, task_id, asset_id, fingerprint_sha256, domain, serial_number, issuer_key,
                subject_cn, issuer_cn, not_before, not_after, days_valid, days_remaining,
                validity_status, key_algorithm, key_size, signature_algorithm,
                san_list, san_count, key_usage, extended_key_usage,
                is_self_signed, is_valid, COALESCE(source_file, ''), created_at
            FROM certificate_analyses
        """)
        cur.execute("DROP TABLE certificate_analyses")
        cur.execute("ALTER TABLE certificate_analyses_new RENAME TO certificate_analyses")

        # ===================== 5. domain_assets =====================
        print("[5/9] 迁移 domain_assets 表并修改安全等级...")
        cur.execute("""
            CREATE TABLE domain_assets_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name VARCHAR(255) NOT NULL UNIQUE,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                total_encountered INTEGER DEFAULT 1,
                last_https_score INTEGER,
                last_security_grade VARCHAR(10),
                is_authorized BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            INSERT INTO domain_assets_new (id, domain_name, first_seen, last_seen, total_encountered,
                last_https_score, last_security_grade, is_authorized, created_at, updated_at)
            SELECT
                id, domain_name, first_seen, last_seen, total_encountered,
                last_https_score,
                CASE
                    WHEN last_https_score >= 90 THEN 'A'
                    WHEN last_https_score >= 70 THEN 'B'
                    WHEN last_https_score >= 50 THEN 'C'
                    ELSE 'D'
                END,
                is_authorized, created_at, updated_at
            FROM domain_assets
        """)
        cur.execute("DROP TABLE domain_assets")
        cur.execute("ALTER TABLE domain_assets_new RENAME TO domain_assets")

        # ===================== 6. security_analyses =====================
        print("[6/9] 迁移 security_analyses 表并修改安全等级...")
        cur.execute("""
            CREATE TABLE security_analyses_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id VARCHAR(64) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                https_enforcement BOOLEAN DEFAULT 0,
                https_score INTEGER DEFAULT 0,
                hsts_enabled BOOLEAN DEFAULT 0,
                hsts_max_age INTEGER,
                hsts_include_subdomains BOOLEAN DEFAULT 0,
                hsts_score INTEGER DEFAULT 0,
                has_csp BOOLEAN DEFAULT 0,
                csp_value TEXT,
                has_x_content_type_options BOOLEAN DEFAULT 0,
                x_content_type_options_value VARCHAR(20),
                has_x_frame_options BOOLEAN DEFAULT 0,
                x_frame_options_value VARCHAR(20),
                has_referrer_policy BOOLEAN DEFAULT 0,
                referrer_policy_value VARCHAR(50),
                headers_score INTEGER DEFAULT 0,
                certificate_chain_valid BOOLEAN DEFAULT 0,
                chain_score INTEGER DEFAULT 0,
                total_score INTEGER DEFAULT 0,
                security_grade VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE
            )
        """)
        cur.execute("""
            INSERT INTO security_analyses_new (
                id, task_id, domain,
                https_enforcement, https_score, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_score,
                has_csp, csp_value, has_x_content_type_options, x_content_type_options_value,
                has_x_frame_options, x_frame_options_value, has_referrer_policy, referrer_policy_value,
                headers_score, certificate_chain_valid, chain_score, total_score, security_grade, created_at
            )
            SELECT
                id, task_id, domain,
                https_enforcement, https_score, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_score,
                has_csp, csp_value, has_x_content_type_options, x_content_type_options_value,
                has_x_frame_options, x_frame_options_value, has_referrer_policy, referrer_policy_value,
                headers_score, certificate_chain_valid, chain_score, total_score,
                CASE
                    WHEN total_score >= 90 THEN 'A'
                    WHEN total_score >= 70 THEN 'B'
                    WHEN total_score >= 50 THEN 'C'
                    ELSE 'D'
                END,
                created_at
            FROM security_analyses
        """)
        cur.execute("DROP TABLE security_analyses")
        cur.execute("ALTER TABLE security_analyses_new RENAME TO security_analyses")

        # ===================== 7. certificate_relationships =====================
        print("[7/9] 重设计 certificate_relationships 表...")
        # 备份旧表（如果存在）
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificate_relationships'")
        if cur.fetchone():
            cur.execute("ALTER TABLE certificate_relationships RENAME TO certificate_relationships_old")
        cur.execute("""
            CREATE TABLE certificate_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id VARCHAR(64) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                certificate_asset_id INTEGER NOT NULL,
                chain_index INTEGER DEFAULT 0,
                is_leaf BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE,
                FOREIGN KEY (certificate_asset_id) REFERENCES certificate_assets(id) ON DELETE CASCADE
            )
        """)
        # 如果需要迁移旧数据，可在此处编写（本次忽略）
        cur.execute("DROP TABLE IF EXISTS certificate_relationships_old")

        # ===================== 8. 删除 uploaded_files =====================
        print("[8/9] 删除 uploaded_files 表...")
        cur.execute("DROP TABLE IF EXISTS uploaded_files")

        # ===================== 9. 修改 system_config =====================
        print("[9/9] 更新 system_config...")
        cur.execute("UPDATE system_config SET config_value='200' WHERE config_key='max_domains_per_analysis'")
        cur.execute("UPDATE system_config SET config_value='.local, .internal, .home.arpa, .test, .example, .localhost, .lan, .corp, .company, .home, .private, .cloud' WHERE config_key='internal_domain_suffixes'")

        conn.commit()
        print("[✓] 所有迁移成功！")
    except Exception as e:
        conn.rollback()
        print(f"[!] 迁移失败，已回滚: {e}")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.close()

if __name__ == "__main__":
    print("数据库迁移前请确认已备份！")
    backup_db()
    migrate()
    print("迁移完成，请重启应用。")