-- =====================================================
-- 证链智审 —— 内网证书卫生态势感知平台
-- 数据库：Digital Certificate Manager
-- 版本：2.0（资产化 + AI驱动的运维报告）
-- =====================================================

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    status INTEGER DEFAULT 1,
    api_key VARCHAR(64) UNIQUE,
    api_requests INTEGER DEFAULT 0
);

-- 分析任务表
CREATE TABLE IF NOT EXISTS analysis_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(64) NOT NULL UNIQUE,
    user_id INTEGER,
    analysis_module VARCHAR(20) NOT NULL,
    task_type VARCHAR(20) NOT NULL,
    source_type VARCHAR(20),
    source_file VARCHAR(255),
    file_size INTEGER,
    file_hash VARCHAR(64),
    status VARCHAR(20) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    total_domains INTEGER DEFAULT 0,
    processed_domains INTEGER DEFAULT 0,
    total_certificates INTEGER DEFAULT 0,
    unique_certificates INTEGER DEFAULT 0,
    parse_errors INTEGER DEFAULT 0,
    extracted_domains_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 证书资产主表（唯一指纹去重，支撑生命周期管理）
CREATE TABLE IF NOT EXISTS certificate_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
    subject_cn VARCHAR(255),
    subject_o VARCHAR(255),
    issuer_cn VARCHAR(255),
    issuer_o VARCHAR(255),
    issuer_c VARCHAR(10),
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    key_algorithm VARCHAR(50),
    key_size INTEGER,
    signature_algorithm VARCHAR(100),
    san_list TEXT,               -- JSON数组
    san_count INTEGER DEFAULT 0,
    key_usage TEXT,
    extended_key_usage TEXT,
    is_self_signed BOOLEAN DEFAULT 0,
    is_ca BOOLEAN DEFAULT 0,

    -- 生命周期与状态字段
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_currently_valid BOOLEAN DEFAULT 1,
    remediation_status VARCHAR(20) DEFAULT 'none',  -- none/acknowledged/replaced/revoked
    risk_level VARCHAR(10) DEFAULT 'low',           -- low/medium/high/critical
    is_unauthorized BOOLEAN DEFAULT 0,
    owner_department VARCHAR(100),
    notes TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 证书分析快照表（任务级记录，关联资产）
CREATE TABLE IF NOT EXISTS certificate_analyses (
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
    chain_index INTEGER,
    chain_length INTEGER,
    is_self_signed BOOLEAN DEFAULT 0,
    is_valid BOOLEAN DEFAULT 1,
    source_file VARCHAR(255),
    source_index INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES certificate_assets(id) ON DELETE SET NULL
);

-- 域名资产表（跨任务聚合，追踪内部域名与外联域名）
CREATE TABLE IF NOT EXISTS domain_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    is_internal BOOLEAN DEFAULT 0,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    total_encountered INTEGER DEFAULT 1,
    last_https_score INTEGER,
    last_security_grade VARCHAR(10),
    is_authorized BOOLEAN DEFAULT 1,
    owner VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 安全分析表（每个域名每次检查一条记录，保留完整评分细节）
CREATE TABLE IF NOT EXISTS security_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(64) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    https_enforcement BOOLEAN DEFAULT 0,
    https_score INTEGER DEFAULT 0,
    hsts_enabled BOOLEAN DEFAULT 0,
    hsts_max_age INTEGER,
    hsts_include_subdomains BOOLEAN DEFAULT 0,
    hsts_preload BOOLEAN DEFAULT 0,
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
    response_headers TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE
);

-- 证书链关系表（可选，用于显示证书链结构）
CREATE TABLE IF NOT EXISTS certificate_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(64) NOT NULL,
    child_asset_id INTEGER,
    parent_asset_id INTEGER,
    relationship_type VARCHAR(20),
    is_valid BOOLEAN DEFAULT 1,
    validation_details TEXT,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (child_asset_id) REFERENCES certificate_assets(id) ON DELETE SET NULL,
    FOREIGN KEY (parent_asset_id) REFERENCES certificate_assets(id) ON DELETE SET NULL
);

-- 态势快照表（每天存储关键指标，AI趋势分析的数据源）
CREATE TABLE IF NOT EXISTS certificate_health_snapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date DATE NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    metric_value REAL,
    metric_detail TEXT,          -- JSON详细数据
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(snapshot_date, metric_name)
);

-- 其他基础配置表（简化保留）
CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key VARCHAR(50) NOT NULL UNIQUE,
    config_value TEXT,
    config_type VARCHAR(20),
    module VARCHAR(20) DEFAULT 'global',
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain VARCHAR(255) NOT NULL,
    analysis_type VARCHAR(20) NOT NULL,
    certificate_hash VARCHAR(64),
    result_data TEXT,
    hit_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_hit TIMESTAMP,
    UNIQUE(domain, analysis_type, certificate_hash)
);

CREATE TABLE IF NOT EXISTS uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(64) NOT NULL,
    user_id INTEGER,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    file_size INTEGER,
    file_hash VARCHAR(64),
    mime_type VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(64) NOT NULL,
    domain VARCHAR(255),
    error_type VARCHAR(50),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(task_id) ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_tasks_taskid ON analysis_tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_cert_analyses_task ON certificate_analyses(task_id, fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_assets_fingerprint ON certificate_assets(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_assets_expiry ON certificate_assets(not_after);
CREATE INDEX IF NOT EXISTS idx_domain_assets_name ON domain_assets(domain_name);
CREATE INDEX IF NOT EXISTS idx_security_analyses_task_domain ON security_analyses(task_id, domain);
CREATE INDEX IF NOT EXISTS idx_health_snapshot_date ON certificate_health_snapshot(snapshot_date);

-- 初始配置
INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, module, description) VALUES
('max_domains_per_analysis', '150', 'integer', 'global', '每次分析最大域名数'),
('cert_expiry_warning_days', '30', 'integer', 'certificate', '证书过期预警天数'),
('unauthorized_issuer_keywords', 'Self-Signed,Test CA', 'string', 'certificate', '自动标记未授权颁发者关键字，逗号分隔'),
('internal_domain_suffixes', '.local,.internal,.corp,.lan', 'string', 'domain', '内网域名后缀');