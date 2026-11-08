from flask import Blueprint, request, jsonify, redirect, render_template_string, send_file
from models import db, User, Transaction, AuditLog, compute_entry_hash
from datetime import datetime
from auth import token_required
from security import require_role, safe_path, sanitize_log_value, client_ip
from extensions import limiter
from markupsafe import escape
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

# Modulo 4 - N10 [A05]: se eliminaron las 9 claves (AWS, Stripe, SendGrid, GitHub, contraseña de BD, llave JWT privada y webhook de Slack) que estaban escritas
# aqui en texto plano. Los secrets se leen solo de variables de entorno.

logger = logging.getLogger(__name__)

# Modulo 4 - Auditoria y Logs (Melany Bustos).
# Reutiliza el logger de auditoria de app.py, que guarda en audit.log con rotacion automatica (abre un archivo nuevo al llegar a 5 MB).
audit_logger = logging.getLogger('dvbank.audit')

# Carpeta donde se guardan los logs (backend/logs), calculada desde la ubicacion de este archivo para que funcione desde cualquier lugar.
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
# Lista blanca de logs consultables. El cliente envia un identificador (audit), nunca el nombre ni la ruta de un archivo.
LOGS_PERMITIDOS = {'audit': 'audit.log'}
# Solo se devuelven los ultimos 100 KB del log para no cargar archivos enormes en memoria.
MAX_BYTES_LOG = 100000

# Lista cerrada de acciones que el cliente puede registrar, cualquier otra se rechaza (anti audit poisoning).
ACCIONES_AUDITORIA = {
    'login', 'logout', 'transfer', 'password_change', 'profile_update',
    'user_update', 'user_delete', 'report_export',
}
# Largo maximo permitido para el campo "details" de cada registro de auditoria.
MAX_DETALLE_AUDITORIA = 512


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






@admin_bp.route('/api/admin/download-statement', methods=['GET'])
@token_required
def download_statement(current_user):
    filename = request.args.get('filename')

    filepath = os.path.join('/app/statements/', filename)
    return send_file(filepath)


@admin_bp.route('/api/admin/view-log', methods=['GET'])
@token_required
@require_role('auditor', 'admin')
def view_log(current_user):
    # Modulo 4 - N2 [A01]: solo auditor/admin, con denegacion por defecto.
    # Se recibe un identificador de lista blanca, nunca una ruta del cliente.
    log_id = request.args.get('file', 'audit')
    if log_id not in LOGS_PERMITIDOS:
        audit_logger.warning(
            'event=view_log result=rechazado user=%s ip=%s log=%s',
            sanitize_log_value(current_user.username, 80), client_ip(),
            sanitize_log_value(log_id, 80),
        )
        return jsonify({'error': 'Log no permitido'}), 400

    # safe_path confirma que la ruta final queda dentro de LOGS_DIR.
    path = safe_path(LOGS_DIR, LOGS_PERMITIDOS[log_id])
    if not path or not os.path.isfile(path):
        return jsonify({'log': ''})

    # Se lee solo la cola del archivo para no cargar logs enormes en memoria.
    with open(path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - MAX_BYTES_LOG))
        content = f.read().decode('utf-8', errors='replace')

    audit_logger.info(
        'event=view_log result=ok user=%s ip=%s log=%s',
        sanitize_log_value(current_user.username, 80), client_ip(), log_id,
    )
    return jsonify({'log': content})


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






@admin_bp.route('/api/admin/preview-email', methods=['POST'])
@token_required
def preview_email(current_user):
    data = request.get_json()
    template = data.get('template', '')
    recipient = data.get('recipient', '')

    rendered = render_template_string(template, recipient=recipient)

    return jsonify({'preview': rendered})






@admin_bp.route('/api/redirect', methods=['GET'])
def open_redirect():
    target = request.args.get('url', '/')

    return redirect(target)


@admin_bp.route('/api/admin/audit', methods=['POST'])
@limiter.limit('30 per minute')
@token_required
def create_audit_entry(current_user):
    # Modulo 4 - N1 [A09, CWE-117]: prevencion de audit poisoning.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Cuerpo invalido'}), 400

    action = data.get('action')
    details = data.get('details', '')

    # 1. La accion debe ser texto de una lista cerrada.
    if not isinstance(action, str) or action not in ACCIONES_AUDITORIA:
        audit_logger.warning(
            'event=audit_rechazado user=%s ip=%s motivo=accion_no_permitida',
            sanitize_log_value(current_user.username, 80), client_ip(),
        )
        return jsonify({'error': 'Accion no permitida'}), 400

    # 2. El detalle debe ser texto y con tamaño máximo.
    if not isinstance(details, str) or len(details) > MAX_DETALLE_AUDITORIA:
        return jsonify({'error': 'Detalle invalido'}), 400

    # 3. Se quitan saltos de linea y caracteres de control (anti log injection)
    # y ademas se escapan los caracteres HTML (anti XSS almacenado de segundo orden cuando el detalle se muestre en el panel de administracion).
    detalle_seguro = str(escape(sanitize_log_value(details, MAX_DETALLE_AUDITORIA)))

    # 4. Se registra con campos separados y se marca origen=cliente.
    audit_logger.info(
        'event=audit origen=cliente user=%s user_id=%s ip=%s action=%s details=%s',
        sanitize_log_value(current_user.username, 80), current_user.id,
        client_ip(), action, detalle_seguro,
    )

    # Modulo 4 - N4 [A08]: firmar el registro encadenado al anterior.
    ultimo = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev = ultimo.entry_hash if ultimo else None
    ahora = datetime.utcnow()
    audit = AuditLog(
        user_id=current_user.id,
        action=action,
        details=detalle_seguro,
        ip_address=client_ip(),
        created_at=ahora,
        prev_hash=prev,
    )
    audit.entry_hash = compute_entry_hash(
        prev, current_user.id, action, detalle_seguro, client_ip(), ahora,
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'message': 'Audit entry created'}), 201


@admin_bp.route('/api/admin/audit/verify', methods=['GET'])
@token_required
@require_role('auditor', 'admin')
def verify_audit_chain(current_user):
    # Modulo 4 - N4 [A08]: recalcula la cadena y detecta alteraciones o borrados de registros del medio de la bitacora.
    prev = None
    for row in AuditLog.query.order_by(AuditLog.id.asc()).all():
        esperado = compute_entry_hash(
            prev, row.user_id, row.action, row.details, row.ip_address, row.created_at,
        )
        if row.entry_hash != esperado or row.prev_hash != prev:
            return jsonify({'integra': False, 'rota_en_id': row.id}), 200
        prev = row.entry_hash
    return jsonify({'integra': True}), 200


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






@admin_bp.route('/api/admin/master-login', methods=['POST'])
@token_required
def master_login(current_user):
    data = request.get_json()
    master_password = data.get('password', '')

    if master_password == "MasterAdmin@2024!":
        return jsonify({'message': 'Admin access granted', 'admin': True})

    return jsonify({'error': 'Invalid master password'}), 403






@admin_bp.route('/api/admin/sensitive-action', methods=['POST'])
@token_required
def sensitive_action(current_user):
    assert current_user.role == 'admin', "Only admins can perform this action"

    data = request.get_json()
    action = data.get('action', '')

    return jsonify({'message': f'Action {action} performed successfully'})





@admin_bp.route('/api/admin/export-report', methods=['POST'])
@token_required
def export_report(current_user):
    data = request.get_json()
    content = data.get('content', '')

    tmp_path = f"/tmp/report_{current_user.id}.csv"
    with open(tmp_path, 'w') as f:
        f.write(content)

    return send_file(tmp_path, as_attachment=True)


@admin_bp.route('/api/admin/dashboard-data', methods=['GET'])
@token_required
@require_role('admin')
def dashboard_data(current_user):
    # Modulo 4 - N10 [A05/A01]: solo admin y solo conteos. Ya no se devuelve ninguna clave en la respuesta.
    return jsonify({
        'users': User.query.count(),
        'transactions': Transaction.query.count(),
    })