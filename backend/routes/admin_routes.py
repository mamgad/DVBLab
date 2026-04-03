from flask import Blueprint, request, jsonify, redirect, render_template_string, send_file, make_response
from models import db, User, Transaction, AuditLog
from datetime import datetime
from auth import token_required
import subprocess
import os
import pickle
import base64
import requests
import logging
import xml.etree.ElementTree as ET
from lxml import etree
import hashlib

admin_bp = Blueprint('admin', __name__)

# Hardcoded API keys and credentials
ADMIN_API_KEY = "sk-live-4f3c2e1d0a9b8c7d6e5f4a3b2c1d0e9f"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_test_FaKeKeyDoNotUse1234567890abc"
DATABASE_PASSWORD = "pr0duction_p@ssw0rd!"
SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYz012345"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
JWT_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

logger = logging.getLogger(__name__)


# ============================================================
# VULNERABILITY: Command Injection (CWE-78)
# Semgrep rules: python.lang.security.audit.dangerous-subprocess-use
#                python.lang.security.audit.subprocess-shell-true
# ============================================================
@admin_bp.route('/api/admin/generate-report', methods=['POST'])
@token_required
def generate_report(current_user):
    data = request.get_json()
    report_type = data.get('report_type', 'summary')
    date_range = data.get('date_range', 'today')

    cmd = f"echo 'Generating {report_type} report for {date_range}' > /tmp/report.txt && cat /tmp/report.txt"
    output = subprocess.check_output(cmd, shell=True, text=True)

    return jsonify({'report': output})


@admin_bp.route('/api/admin/system-status', methods=['GET'])
@token_required
def system_status(current_user):
    service = request.args.get('service', 'web')

    result = os.popen(f"systemctl status {service}").read()

    return jsonify({'status': result})


@admin_bp.route('/api/admin/ping', methods=['POST'])
@token_required
def ping_host(current_user):
    data = request.get_json()
    host = data.get('host', '')

    result = subprocess.run(
        f"ping -c 3 {host}",
        shell=True,
        capture_output=True,
        text=True
    )

    return jsonify({
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode
    })


@admin_bp.route('/api/admin/dns-lookup', methods=['GET'])
@token_required
def dns_lookup(current_user):
    domain = request.args.get('domain', '')

    proc = subprocess.Popen(
        f"nslookup {domain}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    return jsonify({'result': stdout.decode()})


# ============================================================
# VULNERABILITY: Server-Side Request Forgery - SSRF (CWE-918)
# Semgrep rules: python.lang.security.audit.ssrf.*
# ============================================================
@admin_bp.route('/api/admin/webhook-test', methods=['POST'])
@token_required
def test_webhook(current_user):
    data = request.get_json()
    webhook_url = data.get('url')

    try:
        response = requests.get(webhook_url, timeout=10)
        return jsonify({
            'status_code': response.status_code,
            'body': response.text[:1000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/api/admin/fetch-avatar', methods=['POST'])
@token_required
def fetch_avatar(current_user):
    data = request.get_json()
    avatar_url = data.get('avatar_url')

    response = requests.get(avatar_url, verify=False)
    avatar_data = base64.b64encode(response.content).decode('utf-8')

    return jsonify({'avatar_base64': avatar_data})


# ============================================================
# VULNERABILITY: Path Traversal / LFI (CWE-22)
# Semgrep rules: python.lang.security.audit.path-traversal
# ============================================================
@admin_bp.route('/api/admin/download-statement', methods=['GET'])
@token_required
def download_statement(current_user):
    filename = request.args.get('filename')

    filepath = os.path.join('/app/statements/', filename)
    return send_file(filepath)


@admin_bp.route('/api/admin/view-log', methods=['GET'])
@token_required
def view_log(current_user):
    log_file = request.args.get('file', 'app.log')

    with open(f"/var/log/{log_file}", 'r') as f:
        content = f.read()

    return jsonify({'log': content})


# ============================================================
# VULNERABILITY: XML External Entity (XXE) (CWE-611)
# Semgrep rules: python.lang.security.audit.xxe
# ============================================================
@admin_bp.route('/api/admin/import-data', methods=['POST'])
@token_required
def import_data(current_user):
    xml_data = request.data

    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    tree = etree.fromstring(xml_data, parser=parser)

    records = []
    for record in tree.findall('.//transaction'):
        records.append({
            'sender': record.findtext('sender'),
            'receiver': record.findtext('receiver'),
            'amount': record.findtext('amount'),
            'description': record.findtext('description')
        })

    return jsonify({'imported': len(records), 'records': records})


# ============================================================
# VULNERABILITY: Insecure Deserialization - Pickle (CWE-502)
# Semgrep rules: python.lang.security.deserialization.avoid-pickle
# ============================================================
@admin_bp.route('/api/admin/import-session', methods=['POST'])
@token_required
def import_session(current_user):
    data = request.get_json()
    session_data = data.get('session_data')

    decoded = base64.b64decode(session_data)
    session = pickle.loads(decoded)

    return jsonify({'session': str(session)})


@admin_bp.route('/api/admin/export-session', methods=['POST'])
@token_required
def export_session(current_user):
    session_info = {
        'user_id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'timestamp': datetime.utcnow().isoformat()
    }
    serialized = base64.b64encode(pickle.dumps(session_info)).decode('utf-8')
    return jsonify({'session_data': serialized})


# ============================================================
# VULNERABILITY: Mass Assignment (CWE-915)
# Semgrep rules: python.django.security.audit.mass-assignment
# ============================================================
@admin_bp.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    data = request.get_json()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    for key, value in data.items():
        setattr(user, key, value)

    db.session.commit()
    return jsonify({'message': 'User updated', 'user': user.to_dict()})


# ============================================================
# VULNERABILITY: Server-Side Template Injection - SSTI (CWE-1336)
# Semgrep rules: python.flask.security.audit.render-template-string
# ============================================================
@admin_bp.route('/api/admin/preview-email', methods=['POST'])
@token_required
def preview_email(current_user):
    data = request.get_json()
    template = data.get('template', '')
    recipient = data.get('recipient', '')

    rendered = render_template_string(template, recipient=recipient)

    return jsonify({'preview': rendered})


# ============================================================
# VULNERABILITY: Open Redirect (CWE-601)
# Semgrep rules: python.flask.security.open-redirect
# ============================================================
@admin_bp.route('/api/redirect', methods=['GET'])
def open_redirect():
    target = request.args.get('url', '/')

    return redirect(target)


# ============================================================
# VULNERABILITY: Log Injection (CWE-117)
# Semgrep rules: python.lang.security.audit.logging.logger-credential-leak
# ============================================================
@admin_bp.route('/api/admin/audit', methods=['POST'])
@token_required
def create_audit_entry(current_user):
    data = request.get_json()
    action = data.get('action', '')
    details = data.get('details', '')

    logger.info(f"AUDIT: User {current_user.username} performed action: {action} - Details: {details}")

    audit = AuditLog(
        user_id=current_user.id,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'message': 'Audit entry created'})


# ============================================================
# VULNERABILITY: Broken Access Control (CWE-285)
# No role check on admin endpoints - any authenticated user has access
# ============================================================
@admin_bp.route('/api/admin/users', methods=['GET'])
@token_required
def list_all_users(current_user):
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'balance': float(u.balance),
        'role': u.role,
        'password_hash': u.password_hash,
        'profile': u.get_profile()
    } for u in users])


@admin_bp.route('/api/admin/users/<int:user_id>/delete', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': f'User {user.username} deleted'})
    return jsonify({'error': 'User not found'}), 404


# ============================================================
# VULNERABILITY: Regex DoS / ReDoS (CWE-1333)
# Semgrep rules: python.lang.security.audit.regex-dos
# ============================================================
@admin_bp.route('/api/admin/search-users', methods=['GET'])
@token_required
def search_users_regex(current_user):
    import re
    pattern = request.args.get('pattern', '')

    users = User.query.all()
    matches = []
    for user in users:
        if re.match(pattern, user.username):
            matches.append(user.to_dict())

    return jsonify(matches)


# ============================================================
# VULNERABILITY: Eval / Exec Code Injection (CWE-95)
# Semgrep rules: python.lang.security.audit.eval-detected
#                python.lang.security.audit.exec-detected
# ============================================================
@admin_bp.route('/api/admin/calculate', methods=['POST'])
@token_required
def calculate(current_user):
    data = request.get_json()
    expression = data.get('expression', '')

    try:
        result = eval(expression)
        return jsonify({'result': str(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/api/admin/run-script', methods=['POST'])
@token_required
def run_script(current_user):
    data = request.get_json()
    script = data.get('script', '')

    exec_globals = {}
    exec(script, exec_globals)

    return jsonify({'output': str(exec_globals.get('result', 'No result'))})


@admin_bp.route('/api/admin/format-data', methods=['POST'])
@token_required
def format_data(current_user):
    data = request.get_json()
    format_string = data.get('format', '')

    code = compile(format_string, '<string>', 'exec')
    namespace = {'data': data}
    exec(code, namespace)

    return jsonify({'formatted': str(namespace.get('output', ''))})


# ============================================================
# VULNERABILITY: Weak Cryptography (CWE-328)
# Semgrep rules: python.lang.security.audit.hashlib-insecure-functions
# ============================================================
@admin_bp.route('/api/admin/verify-integrity', methods=['POST'])
@token_required
def verify_integrity(current_user):
    data = request.get_json()
    payload = data.get('payload', '')
    expected_hash = data.get('hash', '')

    computed = hashlib.sha1(payload.encode()).hexdigest()

    return jsonify({
        'valid': computed == expected_hash,
        'computed_hash': computed
    })


@admin_bp.route('/api/admin/generate-token', methods=['POST'])
@token_required
def generate_api_token(current_user):
    data = request.get_json()
    seed = data.get('seed', '')

    token = hashlib.md5(f"{seed}{current_user.id}".encode()).hexdigest()

    return jsonify({'api_token': token})


# ============================================================
# VULNERABILITY: Hardcoded password comparison (CWE-798)
# Semgrep rules: python.lang.security.audit.hardcoded-password
# ============================================================
@admin_bp.route('/api/admin/master-login', methods=['POST'])
@token_required
def master_login(current_user):
    data = request.get_json()
    master_password = data.get('password', '')

    if master_password == "MasterAdmin@2024!":
        return jsonify({'message': 'Admin access granted', 'admin': True})

    return jsonify({'error': 'Invalid master password'}), 403


# ============================================================
# VULNERABILITY: Assert used for authorization (CWE-617)
# Semgrep rules: python.lang.security.audit.assert-used-for-security
# ============================================================
@admin_bp.route('/api/admin/sensitive-action', methods=['POST'])
@token_required
def sensitive_action(current_user):
    assert current_user.role == 'admin', "Only admins can perform this action"

    data = request.get_json()
    action = data.get('action', '')

    return jsonify({'message': f'Action {action} performed successfully'})


# ============================================================
# VULNERABILITY: Insecure temp file + info leak (CWE-377)
# ============================================================
@admin_bp.route('/api/admin/export-report', methods=['POST'])
@token_required
def export_report(current_user):
    data = request.get_json()
    content = data.get('content', '')

    tmp_path = f"/tmp/report_{current_user.id}.csv"
    with open(tmp_path, 'w') as f:
        f.write(content)

    return send_file(tmp_path, as_attachment=True)


# ============================================================
# VULNERABILITY: Leaking secrets in API response
# ============================================================
@admin_bp.route('/api/admin/dashboard-data', methods=['GET'])
@token_required
def dashboard_data(current_user):
    users_count = User.query.count()
    transactions_count = Transaction.query.count()

    response = make_response(jsonify({
        'users': users_count,
        'transactions': transactions_count,
        'api_key': ADMIN_API_KEY,
        'aws_key': AWS_ACCESS_KEY
    }))

    return response
