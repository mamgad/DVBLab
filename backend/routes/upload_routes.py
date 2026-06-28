from flask import Blueprint, request, jsonify, Response
from models import db
from auth import token_required
import os
import mimetypes

upload_bp = Blueprint('upload', __name__)

# Files are written here and served back verbatim from /uploads/<name>.
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# VULNERABILITY: Unrestricted File Upload (CWE-434)
#                + Stored XSS (CWE-79) + Path Traversal (CWE-22)
# Semgrep rules: python.flask.security.audit.unsafe-file-upload
# - No extension / content-type / size validation: an attacker can upload an
#   .svg or .html file containing <script> which becomes stored XSS once served
#   from the same origin, or a polyglot web shell.
# - The client-supplied filename is used verbatim (no secure_filename), so a
#   name like ../../something escapes the upload directory (path traversal).
# ============================================================
@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']
    # Raw, attacker-controlled filename -> traversal + dangerous extensions
    filename = uploaded.filename or 'upload.bin'
    dest = os.path.join(UPLOAD_DIR, filename)

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    uploaded.save(dest)

    # Remember the avatar location on the user (served from same origin)
    url = f"/uploads/{filename}"
    current_user.avatar_url = url
    db.session.commit()

    return jsonify({'message': 'Avatar uploaded', 'url': url})


# ============================================================
# Serve uploaded files back with their guessed content-type. Combined with the
# unrestricted upload above, an uploaded SVG/HTML is served as text/html or
# image/svg+xml from the application's own origin -> the embedded script runs
# in the victim's session (stored XSS). `<path:filename>` also lets traversal
# sequences through.
# ============================================================
@upload_bp.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    full_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(full_path):
        return jsonify({'error': 'Not found'}), 404

    content_type = mimetypes.guess_type(full_path)[0] or 'application/octet-stream'
    with open(full_path, 'rb') as f:
        data = f.read()
    # Served inline with attacker-influenced content-type -> SVG/HTML executes
    return Response(data, content_type=content_type)
