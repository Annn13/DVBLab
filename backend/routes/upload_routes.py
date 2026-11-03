from flask import Blueprint, request, jsonify, send_file
from models import db
from auth import token_required
import os
import uuid
from PIL import Image
from werkzeug.utils import safe_join

upload_bp = Blueprint('upload', __name__)


UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)



# Modulo 2 - Vector 2 [A03/A05]: XSS almacenado por subida de archivos.
EXTENSIONES_PERMITIDAS = {'png', 'jpg', 'jpeg', 'gif'}

TIPOS_POR_EXTENSION = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
}


@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']
    ext = uploaded.filename.rsplit('.', 1)[-1].lower()
    if ext not in EXTENSIONES_PERMITIDAS:
        return jsonify({'error': 'Tipo de archivo no permitido'}), 400

    try:
        Image.open(uploaded.stream).verify()
        uploaded.stream.seek(0)
    except Exception:
        return jsonify({'error': 'El archivo no es una imagen valida'}), 400

    nombre_seguro = f"{uuid.uuid4().hex}.{ext}"
    dest = os.path.join(UPLOAD_DIR, nombre_seguro)
    uploaded.save(dest)

    url = f"/uploads/{nombre_seguro}"
    current_user.avatar_url = url
    db.session.commit()

    return jsonify({'message': 'Avatar uploaded', 'url': url})


@upload_bp.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    full_path = safe_join(UPLOAD_DIR, filename)
    if full_path is None or not os.path.isfile(full_path):
        return jsonify({'error': 'Not found'}), 404

    ext = filename.rsplit('.', 1)[-1].lower()
    content_type = TIPOS_POR_EXTENSION.get(ext, 'application/octet-stream')
    response = send_file(full_path, mimetype=content_type)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response