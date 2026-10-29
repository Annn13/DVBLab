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
from urllib.parse import urlparse

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







_REPORT_TYPES = {'summary', 'detailed', 'audit'}
_DATE_RANGES = {'today', 'week', 'month', 'year'}
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_SERVICE_WHITELIST = {'web', 'db', 'cache'}


@admin_bp.route('/api/admin/generate-report', methods=['POST'])
@token_required
@require_role('admin')
def generate_report(current_user):
    data = request.get_json(silent=True) or {}
    report_type = data.get('report_type', 'summary')
    date_range = data.get('date_range', 'today')

    # Entradas contra lista cerrada; el reporte se arma en Python, sin shell.
    if report_type not in _REPORT_TYPES or date_range not in _DATE_RANGES:
        return jsonify({'error': 'Parametros de reporte invalidos'}), 400

    output = f"Generating {report_type} report for {date_range}"
    return jsonify({'report': output})


@admin_bp.route('/api/admin/system-status', methods=['GET'])
@token_required
@require_role('admin')
def system_status(current_user):
    service = request.args.get('service', 'web')
    if service not in _SERVICE_WHITELIST:
        return jsonify({'error': 'Servicio no permitido'}), 400

    # Sin shell: argumentos como lista; el servicio esta en lista blanca.
    try:
        result = subprocess.run(
            ['systemctl', 'status', service],
            capture_output=True, text=True, timeout=5,
        )
        return jsonify({'status': result.stdout})
    except Exception:
        return jsonify({'error': 'No se pudo consultar el estado'}), 400


@admin_bp.route('/api/admin/ping', methods=['POST'])
@token_required
@require_role('admin')
def ping_host(current_user):
    data = request.get_json(silent=True) or {}
    host = data.get('host', '')

    # Se valida el host y se ejecuta SIN shell (lista de argumentos). A03.
    if not _HOST_RE.match(host or ''):
        return jsonify({'error': 'Host invalido'}), 400
    try:
        result = subprocess.run(
            ['ping', '-c', '3', host],
            capture_output=True, text=True, timeout=10,
        )
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
        })
    except Exception:
        return jsonify({'error': 'No se pudo ejecutar ping'}), 400


@admin_bp.route('/api/admin/dns-lookup', methods=['GET'])
@token_required
@require_role('admin')
def dns_lookup(current_user):
    import socket
    domain = request.args.get('domain', '')

    # Resolucion con la API nativa de sockets, sin invocar nslookup por shell.
    if not _HOST_RE.match(domain or ''):
        return jsonify({'error': 'Dominio invalido'}), 400
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
        return jsonify({'result': addrs})
    except Exception:
        return jsonify({'error': 'No se pudo resolver el dominio'}), 400






@admin_bp.route('/api/admin/webhook-test', methods=['POST'])
@token_required
@require_role('admin')
def test_webhook(current_user):
    data = request.get_json(silent=True) or {}
    webhook_url = data.get('url', '')

    # Guardia anti-SSRF: solo https, bloquea IPs internas/metadatos. A10.
    if not is_safe_external_url(webhook_url):
        return jsonify({'error': 'URL no permitida'}), 400

    try:
        response = requests.get(webhook_url, timeout=5, verify=True,
                                allow_redirects=False)
        return jsonify({
            'status_code': response.status_code,
            'body': response.text[:1000]
        })
    except Exception:
        return jsonify({'error': 'No se pudo contactar el destino'}), 400


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






STATEMENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'statements')


@admin_bp.route('/api/admin/download-statement', methods=['GET'])
@token_required
@require_role('admin')
def download_statement(current_user):
    filename = request.args.get('filename', '')

    # safe_path valida que la ruta final quede dentro del directorio permitido
    # (anti path traversal, ../../etc/passwd). A01/A05.
    filepath = safe_path(STATEMENTS_DIR, filename)
    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    return send_file(filepath, as_attachment=True)


@admin_bp.route('/api/admin/view-log', methods=['GET'])
@token_required
def view_log(current_user):
    log_file = request.args.get('file', 'app.log')

    with open(f"/var/log/{log_file}", 'r') as f:
        content = f.read()

    return jsonify({'log': content})






@admin_bp.route('/api/admin/import-data', methods=['POST'])
@token_required
@require_role('admin')
def import_data(current_user):
    xml_data = request.data

    # defusedxml deshabilita entidades externas y DTDs: bloquea XXE y
    # billion-laughs. Reemplaza a lxml con resolve_entities=True. A05/A03.
    from defusedxml.ElementTree import fromstring, ParseError
    try:
        tree = fromstring(xml_data)
    except (ParseError, ValueError):
        return jsonify({'error': 'XML invalido'}), 400

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
@require_role('admin')
def verify_integrity(current_user):
    import hmac
    from flask import current_app
    data = request.get_json(silent=True) or {}
    payload = data.get('payload', '')
    expected_hash = data.get('hash', '')

    # HMAC-SHA256 con clave secreta del servidor (antes SHA-1 sin clave, que
    # no prueba autenticidad y usa un algoritmo obsoleto). A02/A08.
    key = current_app.config['SECRET_KEY'].encode()
    computed = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    valid = hmac.compare_digest(computed, expected_hash or '')
    return jsonify({'valid': valid})


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
@require_role('admin')
def export_report(current_user):
    import tempfile
    data = request.get_json(silent=True) or {}
    content = clamp_str(data.get('content', ''), 1_000_000)

    # Archivo temporal con nombre seguro generado por el servidor.
    fd, tmp_path = tempfile.mkstemp(prefix='report_', suffix='.csv')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)

    return send_file(tmp_path, as_attachment=True, download_name='report.csv')





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
