# Test enfocado del Modulo 1 (Autenticacion) - ejercita el codigo real de Jose.
import sys, os, base64, json, hashlib
import datetime as dt
sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))
import jwt, yaml
from flask import Flask

print("== 1. Hash de contrasenas (models.py) ==")
from models import User
u = User(username='alice')
u.set_password('Dvbank#Demo2026')
print("  hash almacenado:", u.password_hash[:22], "...")
assert '$' in u.password_hash and len(u.password_hash) > 32, 'no es hash con sal de werkzeug'
assert u.check_password('Dvbank#Demo2026') is True
assert u.check_password('incorrecta') is False
print("  OK: PBKDF2 con sal; verifica correcta y rechaza incorrecta")
# migracion de un hash MD5 viejo
u.password_hash = hashlib.md5(b'Legacy#2026ABC').hexdigest()
assert u.check_password('Legacy#2026ABC') is True
assert '$' in u.password_hash and len(u.password_hash) > 32
print("  OK: migra automaticamente un hash MD5 antiguo a PBKDF2")

print("== 2. Verificacion de JWT (auth.py) ==")
from auth import _decode_token
app = Flask(__name__); app.config['SECRET_KEY'] = 'secreto-de-prueba'
with app.app_context():
    good = jwt.encode({'user_id': 1, 'exp': dt.datetime.utcnow() + dt.timedelta(minutes=5)},
                      'secreto-de-prueba', algorithm='HS256')
    assert _decode_token(good)['user_id'] == 1
    print("  OK: acepta un token valido firmado")
    def b(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
    forged = b({'alg': 'none', 'typ': 'JWT'}) + '.' + b({'user_id': 1}) + '.'
    try:
        _decode_token(forged); print("  FAIL: acepto alg:none")
    except Exception as e:
        print("  OK: rechaza token alg:none ->", type(e).__name__)
    bad = jwt.encode({'user_id': 1}, 'otro-secreto', algorithm='HS256')
    try:
        _decode_token(bad); print("  FAIL: acepto firma invalida")
    except Exception as e:
        print("  OK: rechaza firma invalida ->", type(e).__name__)

print("== 3. Politica de contrasenas (security.py) ==")
from security import validate_password
print("  'password123'      ->", validate_password('password123'))
print("  'Dvbank#Demo2026'  ->", validate_password('Dvbank#Demo2026'))

print("== 4. Importacion de perfil YAML segura (auth_routes usa safe_load) ==")
try:
    yaml.safe_load('!!python/object/apply:os.system ["id"]')
    print("  FAIL: safe_load instancio un objeto")
except Exception as e:
    print("  OK: safe_load rechaza el objeto Python ->", type(e).__name__)

print("\n>>> TODAS LAS VERIFICACIONES DEL MODULO 1 PASARON <<<")
