from flask import Blueprint, request, jsonify, Response
from models import db
from auth import token_required
import os
import imghdr
import secrets

from security import safe_path

upload_bp = Blueprint('upload', __name__)


UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Solo imagenes; se valida tanto la extension como el contenido real.
ALLOWED_EXT = {'png': 'png', 'jpg': 'jpeg', 'jpeg': 'jpeg', 'gif': 'gif', 'webp': 'webp'}
MAX_BYTES = 2 * 1024 * 1024  # 2 MB


@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']
    original = uploaded.filename or ''
    ext = original.rsplit('.', 1)[-1].lower() if '.' in original else ''

    if ext not in ALLOWED_EXT:
        return jsonify({'error': 'Tipo de archivo no permitido'}), 400

    # Lee con limite de tamano para no agotar memoria/disco.
    data = uploaded.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return jsonify({'error': 'Archivo demasiado grande (max 2 MB)'}), 400

    # Verifica que el contenido sea realmente una imagen del tipo declarado.
    detected = imghdr.what(None, h=data)
    if detected is None or detected != ALLOWED_EXT[ext]:
        return jsonify({'error': 'El contenido no es una imagen valida'}), 400

    # Se ignora el nombre del cliente y se genera uno aleatorio (anti traversal
    # y anti sobrescritura). OWASP A05/A08.
    safe_name = f"{secrets.token_hex(16)}.{ext}"
    dest = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest, 'wb') as f:
        f.write(data)

    url = f"/uploads/{safe_name}"
    current_user.avatar_url = url
    db.session.commit()

    return jsonify({'message': 'Avatar uploaded', 'url': url})


@upload_bp.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    # Valida que la ruta final quede dentro de UPLOAD_DIR (anti path traversal).
    full_path = safe_path(UPLOAD_DIR, filename)
    if not full_path or not os.path.isfile(full_path):
        return jsonify({'error': 'Not found'}), 404

    detected = imghdr.what(full_path)
    if detected is None:
        return jsonify({'error': 'Not found'}), 404

    with open(full_path, 'rb') as f:
        data = f.read()

    resp = Response(data, content_type=f"image/{detected}")
    # Evita que el navegador interprete el archivo como HTML/JS (XSS via upload).
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Disposition'] = 'inline'
    return resp
