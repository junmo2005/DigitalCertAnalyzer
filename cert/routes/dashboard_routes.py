from flask import Blueprint, render_template, jsonify, session, redirect, url_for
from datetime import datetime, timedelta,date, time
from services.deepseek_service import generate_ai_report
import json
import logging
import traceback
import decimal

dashboard_bp = Blueprint('dashboard', __name__)
logger = logging.getLogger(__name__)

def make_json_safe(obj):
    """递归地将对象中的 Decimal/日期/字节 转为 JSON 可序列化的类型"""
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, (datetime, date, time)):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    else:
        return obj
    
def get_db():
    from db_session import get_db as _get_db
    return _get_db()

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session or session['user'].get('role') != 'admin':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

@dashboard_bp.route('/dashboard')
@require_admin
def dashboard_page():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard/stats')
@require_admin
def dashboard_stats():
    try:
        db = get_db()
        now = datetime.utcnow().isoformat()
        one_month_later = (datetime.utcnow() + timedelta(days=30)).isoformat()
        one_week_later = (datetime.utcnow() + timedelta(days=7)).isoformat()

        # 所有查询将 last_seen 替换为 updated_at
        row = db.conn.execute("""
            SELECT 
                COUNT(*) AS total_active,
                SUM(CASE WHEN not_after < ? THEN 1 ELSE 0 END) AS expired,
                SUM(CASE WHEN not_after BETWEEN ? AND ? THEN 1 ELSE 0 END) AS expire_30d,
                SUM(CASE WHEN not_after BETWEEN ? AND ? THEN 1 ELSE 0 END) AS expire_7d,
                SUM(CASE WHEN not_after < ? THEN 1 ELSE 0 END) AS expired_still_used,
                ROUND(AVG(julianday(not_after) - julianday(not_before)), 1) AS avg_valid_days,
                SUM(CASE WHEN is_self_signed = 1 THEN 1 ELSE 0 END) AS self_signed,
                SUM(CASE WHEN (key_size < 2048 OR signature_algorithm LIKE '%SHA-1%') THEN 1 ELSE 0 END) AS weak_crypto,
                SUM(CASE WHEN is_unauthorized = 1 THEN 1 ELSE 0 END) AS unauthorized,
                SUM(CASE WHEN key_usage IS NULL OR key_usage = '' THEN 1 ELSE 0 END) AS missing_key_usage,
                SUM(CASE WHEN is_ca = 1 THEN 1 ELSE 0 END) AS ca_certs,
                SUM(CASE WHEN san_count > 0 THEN 1 ELSE 0 END) AS with_san,
                ROUND(AVG(CASE WHEN san_count > 0 THEN san_count ELSE NULL END), 1) AS avg_san_domains,
                MAX(CASE WHEN san_count > 0 THEN san_count ELSE NULL END) AS max_san_domains
            FROM certificate_assets
            WHERE updated_at >= datetime('now', '-90 days')
        """, (now, now, one_month_later, now, one_week_later, now)).fetchone()

        total = row[0] or 1
        expired_ratio = round((row[1] or 0) / total * 100, 1)
        expire_30d = row[2] or 0
        expire_7d = row[3] or 0
        expired_still_used = row[4] or 0
        avg_valid_days = row[5] or 0
        self_signed_ratio = round((row[6] or 0) / total * 100, 1)
        weak_crypto_ratio = round((row[7] or 0) / total * 100, 1)
        unauthorized = row[8] or 0
        missing_ku_ratio = round((row[9] or 0) / total * 100, 1)
        with_san_ratio = round((row[11] or 0) / total * 100, 1)
        avg_san_domains = row[12] or 0
        max_san_domains = row[13] or 0

        # ---- 颁发机构生态 ----
        ca_rows = db.conn.execute("""
            SELECT issuer_cn, COUNT(*) AS cnt 
            FROM certificate_assets 
            WHERE updated_at >= datetime('now', '-90 days') AND issuer_cn IS NOT NULL 
            GROUP BY issuer_cn ORDER BY cnt DESC
        """).fetchall()
        ca_total = sum(r[1] for r in ca_rows) if ca_rows else 1
        top_ca = ca_rows[:10] if len(ca_rows) > 10 else ca_rows
        ca_market = [{'name': r[0], 'count': r[1], 'share': round(r[1]/ca_total*100, 1)} for r in top_ca]

        free_ca_keywords = ["Let's Encrypt", "ZeroSSL", "BuyPass", "Cloudflare"]
        free_ca_count = sum(r[1] for r in ca_rows if any(k in (r[0] or '') for k in free_ca_keywords))
        free_ca_share = round(free_ca_count / ca_total * 100, 1) if ca_total else 0

        multi_rows = db.conn.execute("""
            SELECT domain, COUNT(DISTINCT issuer_cn) AS issuer_cnt 
            FROM certificate_analyses 
            WHERE domain IS NOT NULL AND issuer_cn IS NOT NULL 
            GROUP BY domain HAVING COUNT(DISTINCT issuer_cn) > 1
        """).fetchall()
        multi_issuer_domains = len(multi_rows)

        # ---- 密钥用途分布 ----
        usage_rows = db.conn.execute("""
            SELECT key_usage, extended_key_usage, COUNT(*) AS cnt 
            FROM certificate_assets 
            WHERE updated_at >= datetime('now', '-90 days') AND key_usage IS NOT NULL 
            GROUP BY key_usage, extended_key_usage ORDER BY cnt DESC
        """).fetchall()
        key_usage_stats = {}
        for r in usage_rows:
            ku = (r[0] or '') + ('|' + r[1] if r[1] else '')
            if 'Certificate Sign' in ku:
                category = 'CA证书'
            elif 'Digital Signature' in ku and 'Key Encipherment' in ku:
                category = '服务器证书(签名+加密)'
            elif 'Digital Signature' in ku:
                category = '数字签名'
            elif 'Key Encipherment' in ku:
                category = '密钥加密'
            else:
                category = '其他用途'
            key_usage_stats[category] = key_usage_stats.get(category, 0) + r[2]

        # ---- 域名安全维度 ----
        sec_rows = db.conn.execute("""
            SELECT 
                COUNT(DISTINCT domain) AS total_domains,
                SUM(CASE WHEN https_enforcement THEN 1 ELSE 0 END) AS https_enf,
                SUM(CASE WHEN hsts_enabled THEN 1 ELSE 0 END) AS hsts_ena,
                SUM(CASE WHEN hsts_max_age >= 31536000 AND hsts_include_subdomains THEN 1 ELSE 0 END) AS hsts_long_sub,
                SUM(CASE WHEN hsts_max_age >= 31536000 AND NOT hsts_include_subdomains THEN 1 ELSE 0 END) AS hsts_long_nosub,
                SUM(CASE WHEN hsts_max_age > 0 AND hsts_max_age < 31536000 THEN 1 ELSE 0 END) AS hsts_short,
                SUM(CASE WHEN has_csp THEN 1 ELSE 0 END) AS csp_cnt,
                SUM(CASE WHEN has_x_frame_options THEN 1 ELSE 0 END) AS xfo_cnt,
                SUM(CASE WHEN has_x_content_type_options THEN 1 ELSE 0 END) AS xcto_cnt,
                SUM(CASE WHEN has_referrer_policy THEN 1 ELSE 0 END) AS refpol_cnt,
                SUM(CASE WHEN has_csp AND has_x_frame_options AND has_x_content_type_options AND has_referrer_policy THEN 1 ELSE 0 END) AS all4_headers,
                SUM(CASE WHEN certificate_chain_valid THEN 1 ELSE 0 END) AS chain_ok,
                ROUND(AVG(total_score), 1) AS avg_score,
                MAX(total_score) AS max_score,
                MIN(total_score) AS min_score
            FROM security_analyses
            WHERE created_at >= datetime('now', '-30 days')
        """).fetchone()

        domain_stats = {
            'total': sec_rows[0] or 0,
            'https_enforced': sec_rows[1] or 0,
            'hsts_enabled': sec_rows[2] or 0,
            'hsts_long_sub': sec_rows[3] or 0,
            'hsts_long_nosub': sec_rows[4] or 0,
            'hsts_short': sec_rows[5] or 0,
            'csp': sec_rows[6] or 0,
            'xfo': sec_rows[7] or 0,
            'xcto': sec_rows[8] or 0,
            'referrer_policy': sec_rows[9] or 0,
            'all_four_headers': sec_rows[10] or 0,
            'chain_ok': sec_rows[11] or 0,
            'avg_score': sec_rows[12] or 0,
            'max_score': sec_rows[13] or 0,
            'min_score': sec_rows[14] or 0
        }

        grade_rows = db.conn.execute("""
            SELECT security_grade, COUNT(*) AS cnt 
            FROM security_analyses 
            WHERE created_at >= datetime('now', '-7 days') 
            GROUP BY security_grade
        """).fetchall()
        grade_dist = {r[0]: r[1] for r in grade_rows}

        return jsonify({
            'status': 'success',
            'certificate': {
                'total_active': total,
                'expired_ratio': expired_ratio,
                'expire_30d': expire_30d,
                'expire_7d': expire_7d,
                'expired_still_used': expired_still_used,
                'avg_valid_days': avg_valid_days,
                'self_signed_ratio': self_signed_ratio,
                'weak_crypto_ratio': weak_crypto_ratio,
                'unauthorized': unauthorized,
                'missing_key_usage_ratio': missing_ku_ratio,
                'with_san_ratio': with_san_ratio,
                'avg_san_domains': avg_san_domains,
                'max_san_domains': max_san_domains,
                'ca_market': ca_market,
                'free_ca_share': free_ca_share,
                'multi_issuer_domains': multi_issuer_domains,
                'key_usage_stats': key_usage_stats
            },
            'domain': domain_stats,
            'grade_distribution': grade_dist
        })
    except Exception as e:
        logger.error(f"stats接口错误: {e}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@dashboard_bp.route('/api/dashboard/trends')
@require_admin
def dashboard_trends():
    db = get_db()
    # 证书有效性趋势 (从快照表)
    snap_rows = db.conn.execute("""
        SELECT snapshot_date, metric_name, metric_value 
        FROM certificate_health_snapshot
        WHERE metric_name IN ('expired_ratio', 'self_signed_ratio', 'weak_crypto_ratio')
        ORDER BY snapshot_date DESC LIMIT 30
    """).fetchall()
    date_map = {}
    for r in snap_rows:
        date_map.setdefault(r[0], {})[r[1]] = r[2]
    validity_trend = [{'date': k, 'expired_ratio': v.get('expired_ratio', 0),
                       'self_signed_ratio': v.get('self_signed_ratio', 0),
                       'weak_crypto_ratio': v.get('weak_crypto_ratio', 0)} 
                      for k, v in sorted(date_map.items())]

    # 密码学分布 (活跃资产) - 基于 updated_at
    crypto_rows = db.conn.execute("""
        SELECT 
            CASE 
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size >= 4096 THEN 'RSA-4096+'
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size >= 2048 THEN 'RSA-2048'
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size < 2048 THEN 'RSA-弱'
                WHEN key_algorithm IN ('EC', 'ECPublicKey', 'EllipticCurvePublicKey') THEN 'ECC'
                ELSE '其他'
            END AS algo, COUNT(*) cnt
        FROM certificate_assets
        WHERE updated_at >= datetime('now', '-90 days')
        GROUP BY algo
    """).fetchall()
    crypto_dist = {r[0]: r[1] for r in crypto_rows}

    # 颁发机构Top10 - 基于 updated_at
    issuer_rows = db.conn.execute("""
        SELECT issuer_cn, COUNT(*) cnt FROM certificate_assets
        WHERE updated_at >= datetime('now', '-90 days') AND issuer_cn IS NOT NULL
        GROUP BY issuer_cn ORDER BY cnt DESC LIMIT 10
    """).fetchall()
    top_issuers = [{'name': r[0], 'count': r[1]} for r in issuer_rows]

    # 域名安全等级分布 (近7天)
    grade_rows = db.conn.execute("""
        SELECT security_grade, COUNT(*) cnt FROM security_analyses
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY security_grade
    """).fetchall()
    grade_dist = {r[0]: r[1] for r in grade_rows}

    # 域名安全评分趋势 (按月) 从 security_analyses 按月聚合
    score_trend_rows = db.conn.execute("""
        SELECT strftime('%Y-%m', created_at) AS month, 
               ROUND(AVG(total_score),1) AS avg_score, 
               COUNT(DISTINCT domain) AS domains
        FROM security_analyses
        WHERE created_at >= datetime('now', '-6 months')
        GROUP BY month ORDER BY month
    """).fetchall()
    score_trend = [{'month': r[0], 'avg_score': r[1], 'domains': r[2]} for r in score_trend_rows]

    return jsonify({
        'status': 'success',
        'validity_trend': validity_trend,
        'crypto_distribution': crypto_dist,
        'top_issuers': top_issuers,
        'grade_distribution': grade_dist,
        'score_trend': score_trend
    })

@dashboard_bp.route('/api/dashboard/generate-report', methods=['POST'])
@require_admin
def generate_report():
    try:
        db = get_db()
        # 重新收集完整统计数据供AI使用
        stats = _collect_all_stats(db)
        prompt = _build_report_prompt(stats)
        report = generate_ai_report({'prompt': prompt, 'stats': stats}, 
                                     source_type='dashboard', report_type='dashboard')
        print("="*50)
        print("报告长度:", len(report))
        print("报告开头200字符:", report[:200])
        print("报告结尾200字符:", report[-200:] if len(report) >= 200 else report)
        print("="*50)
        return jsonify({'status': 'success', 'report_html': report})
    except Exception as e:
        logger.error(f"生成报告失败: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

def _collect_all_stats(db):
    print("DB PATH:", db.db_path)   # 验证使用的数据库路径
    now = datetime.utcnow().isoformat()
    one_month_later = (datetime.utcnow() + timedelta(days=30)).isoformat()

    # ---- 证书资产整体统计 ----
    cert_row = db.conn.execute("""
        SELECT 
            COUNT(*) AS total_active,
            SUM(CASE WHEN not_after < ? THEN 1 ELSE 0 END) AS expired,
            SUM(CASE WHEN not_after BETWEEN ? AND ? THEN 1 ELSE 0 END) AS soon_expire,
            SUM(CASE WHEN not_after < ? AND updated_at >= datetime('now', '-90 days') THEN 1 ELSE 0 END) AS expired_still_used,
            ROUND(AVG(julianday(not_after) - julianday(not_before)), 1) AS avg_lifetime,
            SUM(CASE WHEN is_self_signed = 1 THEN 1 ELSE 0 END) AS self_signed,
            SUM(CASE WHEN (key_size < 2048 OR signature_algorithm LIKE '%SHA-1%') THEN 1 ELSE 0 END) AS weak_crypto,
            SUM(CASE WHEN is_unauthorized = 1 THEN 1 ELSE 0 END) AS unauthorized,
            SUM(CASE WHEN key_usage IS NULL OR key_usage = '' THEN 1 ELSE 0 END) AS missing_ku,
            SUM(CASE WHEN san_count > 0 THEN 1 ELSE 0 END) AS with_san,
            ROUND(AVG(CASE WHEN san_count > 0 THEN san_count ELSE NULL END), 1) AS avg_san_domains,
            MAX(CASE WHEN san_count > 0 THEN san_count ELSE NULL END) AS max_san_domains
        FROM certificate_assets
        WHERE updated_at >= datetime('now', '-90 days')
    """, (now, now, one_month_later, now)).fetchone()

    total_active = cert_row[0] or 1
    expired_ratio = round((cert_row[1] or 0) / total_active * 100, 1)
    soon_expire = cert_row[2] or 0
    expired_still_used = cert_row[3] or 0
    avg_lifetime = cert_row[4] or 0
    self_signed_count = cert_row[5] or 0
    weak_crypto_count = cert_row[6] or 0
    unauthorized_count = cert_row[7] or 0
    missing_ku_count = cert_row[8] or 0
    with_san_count = cert_row[9] or 0
    avg_san = cert_row[10] or 0
    max_san = cert_row[11] or 0

    # ---- 密码学详细分桶 ----
    crypto_rows = db.conn.execute("""
        SELECT 
            CASE 
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size >= 4096 THEN 'RSA-4096+'
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size >= 2048 THEN 'RSA-2048'
                WHEN key_algorithm IN ('RSA', 'RSAPublicKey') AND key_size < 2048 THEN 'RSA-弱'
                WHEN key_algorithm IN ('EC', 'ECPublicKey', 'EllipticCurvePublicKey') THEN 'ECC'
                ELSE '其他'
            END AS algo, COUNT(*) cnt
        FROM certificate_assets
        WHERE updated_at >= datetime('now', '-90 days')
        GROUP BY algo
    """).fetchall()
    crypto_distribution = {r[0]: r[1] for r in crypto_rows}

    # ---- 颁发机构生态 ----
    ca_rows = db.conn.execute("""
        SELECT issuer_cn, COUNT(*) cnt FROM certificate_assets
        WHERE updated_at >= datetime('now', '-90 days') AND issuer_cn IS NOT NULL
        GROUP BY issuer_cn ORDER BY cnt DESC
    """).fetchall()
    ca_total = sum(r[1] for r in ca_rows) if ca_rows else 1
    top_ca = [{'name': r[0], 'count': r[1]} for r in ca_rows[:5]]

    # 免费 CA 比例 (Let's Encrypt, ZeroSSL 等)
    free_keywords = ["Let's Encrypt", "ZeroSSL", "BuyPass", "Cloudflare"]
    free_count = sum(r[1] for r in ca_rows if any(k in (r[0] or '') for k in free_keywords))
    free_ca_share = round(free_count / ca_total * 100, 1) if ca_total else 0

    # 多 CA 供应商域名数
    multi_rows = db.conn.execute("""
        SELECT domain, COUNT(DISTINCT issuer_cn) AS issuer_cnt 
        FROM certificate_analyses 
        WHERE domain IS NOT NULL AND issuer_cn IS NOT NULL 
        GROUP BY domain HAVING COUNT(DISTINCT issuer_cn) > 1
    """).fetchall()
    multi_issuer_domains = len(multi_rows)

    # ---- 域名安全详细统计 ----
    domain_row = db.conn.execute("""
        SELECT 
            COUNT(DISTINCT domain) AS total,
            SUM(CASE WHEN https_enforcement THEN 1 ELSE 0 END) AS https,
            SUM(CASE WHEN hsts_enabled THEN 1 ELSE 0 END) AS hsts,
            SUM(CASE WHEN hsts_max_age >= 31536000 AND hsts_include_subdomains THEN 1 ELSE 0 END) AS hsts_long_sub,
            SUM(CASE WHEN hsts_max_age >= 31536000 AND NOT hsts_include_subdomains THEN 1 ELSE 0 END) AS hsts_long_nosub,
            SUM(CASE WHEN hsts_max_age > 0 AND hsts_max_age < 31536000 THEN 1 ELSE 0 END) AS hsts_short,
            SUM(CASE WHEN has_csp AND has_x_frame_options AND has_x_content_type_options AND has_referrer_policy THEN 1 ELSE 0 END) AS good_headers,
            SUM(CASE WHEN certificate_chain_valid THEN 1 ELSE 0 END) AS chain_ok,
            ROUND(AVG(total_score), 1) AS avg_score
        FROM security_analyses
        WHERE created_at >= datetime('now', '-30 days')
    """).fetchone()

    # 安全等级分布 (近7天)
    grade_rows = db.conn.execute("""
        SELECT security_grade, COUNT(*) cnt FROM security_analyses
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY security_grade
    """).fetchall()
    grade_dist = {r[0]: r[1] for r in grade_rows}

    # 组装所有数据
    stats = {
        'certificate': {
            'total_active': total_active,
            'expired_count': cert_row[1] or 0,
            'expired_ratio': expired_ratio,
            'soon_expire': soon_expire,
            'expired_still_used': expired_still_used,
            'avg_lifetime_days': avg_lifetime,
            'self_signed_count': self_signed_count,
            'weak_crypto_count': weak_crypto_count,
            'unauthorized_count': unauthorized_count,
            'missing_ku_count': missing_ku_count,
            'with_san_count': with_san_count,
            'avg_san_domains': avg_san,
            'max_san_domains': max_san,
            'crypto_distribution': crypto_distribution,
            'free_ca_share': free_ca_share,
            'multi_issuer_domains': multi_issuer_domains
        },
        'domain': {
            'total_analyzed': domain_row[0] or 0,
            'https_enforced': domain_row[1] or 0,
            'hsts_enabled': domain_row[2] or 0,
            'hsts_long_sub': domain_row[3] or 0,
            'hsts_long_nosub': domain_row[4] or 0,
            'hsts_short': domain_row[5] or 0,
            'good_headers': domain_row[6] or 0,
            'chain_valid': domain_row[7] or 0,
            'avg_score': domain_row[8] or 0
        },
        'top_ca': top_ca,
        'grade_distribution': grade_dist
    }
    stats = make_json_safe(stats)
    return stats

def _build_report_prompt(stats):
    return f"""
你是一位顶级的网络安全态势分析师，擅长从数字证书和域名安全数据中提炼出可执行的洞察。请基于以下实时统计信息，生成一份专业、详细、可直接用于高管汇报的内网证书与域名安全态势报告。

【重要】输出格式要求：
- 只输出 HTML 片段，**严禁**包含 <!DOCTYPE html>、<html>、<head>、<body> 等标签。
- 直接从 <div class="report-container"> 开始，内部可以使用 <style> 标签定义样式。
- 所有样式必须内嵌（使用 <style> 或内联 style），不要依赖外部 CSS。
- 保持报告结构完整（七个部分），使用 <h2>、<h3>、<p>、<ul>、<table> 等基础标签。
- 关键数据用 <strong> 或 <span class="..."> 高亮，并在 <style> 中定义好高亮类。
---

当前统计数据（JSON 格式）

```json
{json.dumps(stats, indent=2, ensure_ascii=False)}
注意：以上数据仅为基础统计。作为专家，你还需要结合网络安全最佳实践和报告中给出的参考行业基准（例如 56% 组织经历过 PKI 中断、约 20% 过期证书仍在使用、约 60% 组织使用 3 家以上 CA 等）进行对比分析，指出本环境的优劣。

一、报告内容要求（必须包含以下七个部分，且每个部分内需覆盖所列子项）
1. 执行摘要
一句话评价当前整体风险等级（高/中/低/信息性）。

列出 最严重的 3 个问题（例如：过期证书占比过高、弱加密残留、HSTS 未启用等）。

列出 最重要的 3 个积极发现（例如：无自签名证书、HTTPS 强制覆盖率高、CA 供应商单一可控等）。

结合行业基准（如 PKI 中断比例、证书过期后未替换比例）说明本环境相对行业水平的表现。

2. 证书资产管理态势（扩展至五个子维度）
2.1 证书有效性趋势

有效证书总数、已过期证书数量及占比。

未来 30 天/7 天内将要过期的证书数量（高危预警），并指出是否需要立即行动。

已过期但仍可能被使用的证书数量（基于 expired_still_used 指标，若未提供则按 0 计）。

平均证书有效期，评价生命周期管理是否合理（推荐 ≤ 398 天）。

2.2 密码学强度分布与退化趋势

按算法分类（RSA-2048、RSA-4096+、ECC、弱 RSA 等）的占比。

弱密钥算法残留比例（RSA<2048 或 SHA-1），判断是否低于行业底线。

是否有国密算法使用（若有数据则提及）。

2.3 证书颁发机构（CA）生态地图

展示 Top 5 CA 市场占有率（百分比）。

免费 CA（Let's Encrypt 等）使用占比，分析成本与风险（DV 证书易被滥用）。

单域名使用多家 CA 的域名数量（多供应商风险），指出是否存在碎片化管理隐患。

2.4 SAN 域名关联分析

平均每张证书包含的 SAN 域名数，最大 SAN 数。

是否存在 SAN 数量异常的证书（例如远超平均值 + 2 倍标准差），提示可能的 CDN 共享或滥用风险。

（可选）若可提取共现关系，输出“高风险簇”建议。

2.5 密钥用途（Key Usage）合规性

缺少 Key Usage 字段的证书占比，解释风险（私钥可被任意使用）。

若有 Key Usage 与证书类型不匹配的情况（例如代码签名证书用于服务器认证），请指出。

3. 域名安全防护评估
HTTPS 强制：未启用 HTTPS 的域名比例，对比上月趋势（若提供趋势数据）。

HSTS 保护：区分长期配置（含子域名）、短期配置、完全未启用的占比。

安全头配置：CSP、XFO、XCTO、Referrer-Policy 各自的启用率，以及四项全部齐备的域名占比。指出最薄弱的安全头。

证书链完整性：完整受信的域名比例，自签名证书占比，链不完整占比。

给出平均安全评分（0-100），并指出最高分和最低分域名数量（若有）。

4. 合规性分析（PCI DSS 及等保 2.0）
对照 PCI DSS v3.2.1 要求 4.1（加密传输敏感数据）和 要求 2.3（禁用不安全协议/算法），统计：

TLS 1.0/1.1 禁用比例（若未提供，假设未检测）。

强密码套件使用比例（基于弱加密证书占比反向说明）。

证书有效且链完整的域名比例。

给出总体合规率（例如“60% 域名完全符合 PCI DSS 加密要求”）。

输出不合规项的具体数量，并建议整改优先级。

5. 威胁情报与影子 IT 风险
未授权证书（unauthorized_count）：指出是否存在未经批准的证书，潜在攻击面。

自签名证书：数量及占比，分析内部横向移动风险（参考行业案例）。

DV 证书过度使用：若免费 CA 占比过高，提示可能被攻击者用于品牌仿冒。

SAN 共现异常：若有异常簇，说明可能关联到恶意基础设施（基于 Infoblox 研究方法）。

短有效期证书聚集：若检测到大量有效期 ≤ 7 天的证书，提示规避检测行为。

6. 证书管理运维预警
接下来 30 天即将过期的证书清单（模拟）：列出数字（例如 “15 张证书将在 30 天内过期，其中 5 张属于核心域名”）。

已过期仍在使用的证书：若数量 > 0，列为最高优先级续期任务。

多 CA 碎片化域名：若存在，建议统一供应商以减少中断风险。

缺少 Key Usage 的证书：建议逐一审计并重新签发。

提供从预警到续期的运维工作流建议（可参考 Keyfactor 方案）。

7. 改进建议（按紧急程度排序，3-5 条）
优先级 1（立即执行）：如替换弱密钥、续期高危过期证书。

优先级 2（7 天内）：启用 HSTS includeSubDomains、补全缺失安全头。

优先级 3（月度规划）：建立自动化证书续期（ACME）、统一 CA 供应商。

长期建议：实施 SAN 异常检测、密钥用途合规检查纳入 CI/CD。

额外分析要求（如果统计数据中未直接提供，请基于已有数据进行合理推断或明确说明“本次未检测”）
对于 趋势类数据（如月度过期率变化），若 stats 中未提供时间序列，请在报告中说明“本次为静态快照分析，建议集成历史快照表获取趋势”。

对于 SAN 共现图谱，若无现成关系数据，可基于平均 SAN 数和最大 SAN 数推测是否存在过度共享风险。

对于 行业基准对比，必须引用文档中提到的数字（如 56%、20%、0.9%、27.1% 等）进行对比，以突出本环境的相对位置
额外分析要求（如果统计数据中未直接提供，请基于已有数据进行合理推断或明确说明“本次未检测”）
对于 趋势类数据（如月度过期率变化），若 stats 中未提供时间序列，请在报告中说明“本次为静态快照分析，建议集成历史快照表获取趋势”。

对于 SAN 共现图谱，若无现成关系数据，可基于平均 SAN 数和最大 SAN 数推测是否存在过度共享风险。

对于 行业基准对比，必须引用文档中提到的数字（如 56%、20%、0.9%、27.1% 等）进行对比，以突出本环境的相对位置。

请严格按照上述结构生成 HTML 报告。报告语言要求专业、客观、数据驱动，避免使用“可能”“大概”等模糊词汇
"""