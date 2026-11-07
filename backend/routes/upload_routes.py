from flask import Blueprint, request, jsonify, Response
from models import db
from auth import token_required
import os
import mimetypes

upload_bp = Blueprint('upload', __name__)


UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)












@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']

    filename = uploaded.filename or 'upload.bin'
    dest = os.path.join(UPLOAD_DIR, filename)

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    uploaded.save(dest)


    url = f"/uploads/{filename}"
    current_user.avatar_url = url
    db.session.commit()

    return jsonify({'message': 'Avatar uploaded', 'url': url})









@upload_bp.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    full_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(full_path):
        return jsonify({'error': 'Not found'}), 404

    content_type = mimetypes.guess_type(full_path)[0] or 'application/octet-stream'
    with open(full_path, 'rb') as f:
        data = f.read()

    return Response(data, content_type=content_type)
