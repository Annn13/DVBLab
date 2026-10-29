from flask import Blueprint, request, jsonify, redirect, render_template_string, send_file, make_response
from models import db, User, Transaction, AuditLog
from datetime import datetime
from auth import token_required
import subprocess
import os
import re
import base64
import hashlib
import requests
import logging
from lxml import etree
from urllib.parse import urlparse, urljoin

from security import (
    require_role, is_safe_external_url, safe_path, client_ip,
    clamp_str, valid_email,
)

admin_bp = Blueprint('admin', __name__)

logger = logging.getLogger(__name__)


def _user_public(u):
    """Serializa un usuario SIN exponer credenciales (hash, reset_token)."""
    return {
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'balance': float(u.balance),
        'role': u.role,
        'profile': u.get_profile(),
    }







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
@require_role('admin')
def fetch_avatar(current_user):
    data = request.get_json(silent=True) or {}
    avatar_url = data.get('avatar_url', '')

    # Guardia anti-SSRF: solo https, bloquea IPs internas/metadatos, TLS verificado.
    if not is_safe_external_url(avatar_url):
        return jsonify({'error': 'URL no permitida'}), 400

    try:
        response = requests.get(avatar_url, timeout=5, verify=True,
                                stream=True, allow_redirects=False)
        content = response.raw.read(1_000_000, decode_content=True)  # limite 1 MB
    except Exception:
        return jsonify({'error': 'No se pudo obtener el recurso'}), 400

    ctype = response.headers.get('Content-Type', '')
    if not ctype.startswith('image/'):
        return jsonify({'error': 'El recurso no es una imagen'}), 400

    avatar_data = base64.b64encode(content).decode('utf-8')
    return jsonify({'avatar_base64': avatar_data})






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
@require_role('admin')
def import_session(current_user):
    data = request.get_json(silent=True) or {}
    session_data = data.get('session_data', '')

    # Se usa JSON en vez de pickle: pickle.loads sobre datos del cliente es RCE.
    try:
        decoded = base64.b64decode(session_data)
        import json
        session = json.loads(decoded)
    except Exception:
        return jsonify({'error': 'Datos de sesion invalidos'}), 400

    return jsonify({'session': session})


@admin_bp.route('/api/admin/export-session', methods=['POST'])
@token_required
def export_session(current_user):
    import json
    session_info = {
        'user_id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'timestamp': datetime.utcnow().isoformat()
    }
    # Serializacion segura con JSON (no pickle).
    serialized = base64.b64encode(json.dumps(session_info).encode()).decode('utf-8')
    return jsonify({'session_data': serialized})






@admin_bp.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@token_required
@require_role('admin')
def update_user(current_user, user_id):
    data = request.get_json(silent=True) or {}
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Lista blanca de campos editables: evita mass assignment (p. ej. subir
    # el propio role a 'admin' o alterar el balance). OWASP A08/A01.
    if 'email' in data:
        if not valid_email(data['email']):
            return jsonify({'error': 'Correo invalido'}), 400
        user.email = data['email']
    if 'role' in data:
        if data['role'] not in ('user', 'admin', 'auditor'):
            return jsonify({'error': 'Rol invalido'}), 400
        user.role = data['role']

    db.session.commit()
    return jsonify({'message': 'User updated', 'user': _user_public(user)})






@admin_bp.route('/api/admin/preview-email', methods=['POST'])
@token_required
@require_role('admin')
def preview_email(current_user):
    data = request.get_json(silent=True) or {}
    recipient = clamp_str(data.get('recipient', ''), 254)

    # NO se renderiza una plantilla provista por el cliente (eso es SSTI/RCE).
    # Se usa una plantilla fija del servidor con la variable autoescapada.
    FIXED_TEMPLATE = "Hola {{ recipient }}, este es un correo de prueba de DVBank."
    rendered = render_template_string(FIXED_TEMPLATE, recipient=recipient)

    return jsonify({'preview': rendered})






@admin_bp.route('/api/redirect', methods=['GET'])
def open_redirect():
    target = request.args.get('url', '/')

    # Solo se permiten redirecciones internas (rutas relativas del mismo sitio).
    # Se bloquean URLs absolutas y esquemas peligrosos (open redirect, A01).
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith('/') or target.startswith('//'):
        return redirect('/')
    return redirect(target)






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






@admin_bp.route('/api/admin/users', methods=['GET'])
@token_required
@require_role('admin')
def list_all_users(current_user):
    users = User.query.all()
    # NO se devuelve password_hash ni reset_token en ninguna respuesta.
    return jsonify([_user_public(u) for u in users])


@admin_bp.route('/api/admin/users/<int:user_id>/delete', methods=['DELETE'])
@token_required
@require_role('admin')
def delete_user(current_user, user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted'})
    return jsonify({'error': 'User not found'}), 404






@admin_bp.route('/api/admin/search-users', methods=['GET'])
@token_required
@require_role('admin')
def search_users_regex(current_user):
    # No se acepta una expresion regular del cliente (ReDoS). Se busca por
    # subcadena con consulta parametrizada, termino acotado y paginacion.
    term = clamp_str(request.args.get('pattern', ''), 50)
    page = request.args.get('page', 1, type=int)
    per_page = 25

    query = User.query.filter(User.username.ilike(f"%{term}%"))
    users = query.limit(per_page).offset((max(page, 1) - 1) * per_page).all()

    return jsonify([_user_public(u) for u in users])







@admin_bp.route('/api/admin/calculate', methods=['POST'])
@token_required
@require_role('admin')
def calculate(current_user):
    data = request.get_json(silent=True) or {}
    expression = clamp_str(data.get('expression', ''), 100)

    # eval() sobre entrada del cliente es RCE. Se evalua solo aritmetica simple
    # con un parser restringido a numeros y operadores + - * / ( ).
    if not re.fullmatch(r"[0-9+\-*/(). %]+", expression or ""):
        return jsonify({'error': 'Expresion no permitida'}), 400
    try:
        import ast
        import operator as op
        ops = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
               ast.Div: op.truediv, ast.Mod: op.mod, ast.USub: op.neg}

        def _eval(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.BinOp) and type(node.op) in ops:
                return ops[type(node.op)](_eval(node.left), _eval(node.right))
            if isinstance(node, ast.UnaryOp) and type(node.op) in ops:
                return ops[type(node.op)](_eval(node.operand))
            raise ValueError("nodo no permitido")

        result = _eval(ast.parse(expression, mode='eval').body)
        return jsonify({'result': str(result)})
    except Exception:
        return jsonify({'error': 'Expresion invalida'}), 400


# Endpoints eliminados: /api/admin/run-script y /api/admin/format-data ejecutaban
# codigo Python arbitrario del cliente (exec), lo que es RCE directo y no tiene
# un caso de uso legitimo. Se retiran por completo (reduccion de superficie).






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
@require_role('admin')
def generate_api_token(current_user):
    # Token aleatorio criptograficamente seguro (no derivado de MD5(seed+id),
    # que era predecible). OWASP A02.
    import secrets
    token = secrets.token_urlsafe(32)
    return jsonify({'api_token': token})






# Endpoint eliminado: /api/admin/master-login era una puerta trasera con una
# contrasena maestra escrita en el codigo. Se retira por completo. El acceso
# administrativo se obtiene solo con el rol 'admin' asignado en la base de datos.






@admin_bp.route('/api/admin/sensitive-action', methods=['POST'])
@token_required
@require_role('admin')
def sensitive_action(current_user):
    # La autorizacion se hace con require_role, NUNCA con assert (assert se
    # desactiva con python -O y dejaria el control sin efecto). OWASP A01.
    data = request.get_json(silent=True) or {}
    action = clamp_str(data.get('action', ''), 50)

    return jsonify({'message': 'Action performed successfully'})





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
