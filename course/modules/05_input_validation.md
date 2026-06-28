# Module 5: Input Validation & Sanitization

## Understanding Input Validation

### What is Input Validation?
Input validation is the process of confirming that incoming data meets the
expected type, format, range, and business rules **before** the application acts
on it. Skipping it lets attackers smuggle malicious values into queries,
balances, files, and HTML.

### Types of Input Validation
- **Syntactic** - type, format, length, and range (e.g. an email looks like an email, an amount is a positive number).
- **Semantic** - business rules and cross-field consistency (e.g. you can only move money *out of* your own account).
- **Content** - allowed characters and file types (whitelist patterns, extension/MIME checks).

### Common Failure Modes
- **Missing** - input used raw, with no boundary or type checks.
- **Incomplete** - client-side-only checks, or escaping one character class but not another.
- **Incorrect** - flawed regex/encoding that can be bypassed.

## DVBank Input Validation Vulnerabilities

### 1. Transaction Amount Validation (negative-amount bypass)
**Location**: `backend/routes/transaction_routes.py:9-42`
```python
@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    amount = Decimal(str(data.get('amount', 0)))
    description = data.get('description', '')

    receiver = User.query.get(to_user_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    transaction = Transaction(...)
    if current_user.balance < amount:           # line 30 - the only guard
        return jsonify({'error': 'Insufficient balance'}), 400

    current_user.balance -= amount              # sender
    receiver.balance    += amount               # receiver
    db.session.add(transaction)
    db.session.commit()
```

**The bug**: the *only* check is `if current_user.balance < amount`. There is no
negative/zero check. With a **negative** amount the guard passes (a positive
balance is never `<` a negative number), then `current_user.balance -= amount`
*adds* to the sender's balance while `receiver.balance += amount` *subtracts*
from the victim. The attacker pulls money out of any chosen `to_user_id`.

**Exploitation**:
```json
{"to_user_id": <victim_id>, "amount": -1000}
```
Attacker's balance rises by 1000, victim's drops by 1000.

> Note on precision: `amount` is a `Decimal` (`Decimal(str(...))` coerces the
> JSON value), stored in `Numeric(10, 2)`. There is no integer overflow and no
> untyped value - the realistic flaws are the **missing positive-amount check**
> above and that values are silently **rounded to 2 decimal places** by the
> column (up to 10 total digits), so sub-cent inputs are quantized.

### 2. SQL Injection in Transaction Queries
**Location**: `backend/routes/transaction_routes.py:49` and `:93`
```python
# :47-50  user_id comes straight from the query string
user_id = request.args.get('user_id', current_user.id)
query = f'SELECT * FROM "Transaction" WHERE sender_id = {user_id} OR receiver_id = {user_id} ORDER BY created_at DESC'
result = db.session.execute(query)

# :89-95  search_term interpolated inside a LIKE string (commented as deliberately vulnerable)
search_term = request.args.get('description', '')
query = f"SELECT * FROM \"transaction\" WHERE (sender_id = {current_user.id} OR receiver_id = {current_user.id}) AND description LIKE '%{search_term}%'"
result = db.session.execute(query)
```

**The bug**: both queries are built with f-string concatenation of
user-controlled input - the classic SQL injection sink (CWE-89).

**Exploitation**:
```text
# :49  numeric context - dump every transaction in the database
GET /api/transactions?user_id=0 OR 1=1

# :93  string context inside the LIKE - break out of the quotes
GET /api/transactions/search?description=%' OR '1'='1
# UNION to read other tables (Transaction SELECT returns 8 columns, so match 8):
GET /api/transactions/search?description=%' UNION SELECT id,username,password,4,5,6,7,8 FROM user--
```

### 3. Profile Data Validation
**Location**: `backend/routes/auth_routes.py:116`
```python
@auth_bp.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    current_user.email = data.get('email')          # no format validation
    profile_data = {
        'fullName': data.get('fullName'),
        'phone':    data.get('phone'),
        'address':  data.get('address'),
    }
    current_user.set_profile(profile_data)           # set_profile -> json.dumps
    db.session.commit()
```

**The bug**: `email`, `fullName`, `phone`, and `address` are stored unvalidated.
Email format is never checked, and the free-text fields are persisted verbatim,
so a payload like `<script>...</script>` is stored and can fire wherever a
server-side sink renders it without escaping (see Module 10).

Note this handler is **ORM-only** - the assignment goes through SQLAlchemy and
`set_profile` serializes with `json.dumps`, so there is **no** SQL injection
here. For the genuine SQLi, see section 2 above.

**Exploitation**:
```json
{"email": "not-an-email", "fullName": "<script>alert(document.cookie)</script>"}
```

### 4. File Upload Validation
**Location**: `backend/routes/upload_routes.py:24`
```python
@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    uploaded = request.files['file']
    filename = uploaded.filename or 'upload.bin'    # raw, attacker-controlled
    dest = os.path.join(UPLOAD_DIR, filename)
    uploaded.save(dest)
```

**The bug**: no extension/MIME/size check (CWE-434) and the client filename is
used verbatim, so `../` sequences escape the upload directory (CWE-22). The file
is later served back from the app's own origin, turning an uploaded `.svg`/`.html`
into stored XSS. This flaw is covered in depth in
[Module 10](10_xss_and_file_upload.md).

**Exploitation**:
```text
filename = "../../evil.html"      # path traversal
filename = "avatar.svg"           # SVG with <script> -> stored XSS on app origin
```

## Prevention Methods

### 1. Proper Amount Validation
```python
from decimal import Decimal, InvalidOperation

def validate_amount(raw):
    try:
        amount = Decimal(str(raw))
    except InvalidOperation:
        raise ValidationError("Amount is not a valid number")
    if amount <= 0:
        raise ValidationError("Amount must be positive")     # blocks negatives/zero
    if amount.as_tuple().exponent < -2:
        raise ValidationError("Maximum 2 decimal places")    # match Numeric(10, 2)
    return amount

@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    amount = validate_amount(request.get_json().get('amount'))
    ...
```

### 2. Parameterized Queries (stop SQLi)
```python
from sqlalchemy import text

# Bind values instead of interpolating them
query = text('SELECT * FROM "Transaction" '
             'WHERE sender_id = :uid OR receiver_id = :uid')
result = db.session.execute(query, {'uid': user_id})
```

### 3. Profile Input Sanitization
```python
from markupsafe import escape
from email_validator import validate_email, EmailNotValidError

def sanitize_profile_input(data):
    try:
        data['email'] = validate_email(data['email']).normalized
    except EmailNotValidError as e:
        raise ValidationError(str(e))
    for field in ('fullName', 'phone', 'address'):
        if field in data and data[field] is not None:
            data[field] = str(escape(data[field]))   # neutralize HTML
    return data
```

### 4. Secure File Upload
```python
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Global guard: Flask rejects oversized bodies before they reach the view.
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def validate_file(file):
    if not file or not file.filename:
        raise ValidationError("No file provided")

    # Werkzeug does NOT set content_length on multipart uploads, so measure the
    # stream directly instead of trusting file.content_length.
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        raise ValidationError("File too large")

    ext = os.path.splitext(file.filename)[1][1:].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError("File type not allowed")

    return secure_filename(file.filename)   # strips ../ and dangerous chars

@upload_bp.route('/api/upload-avatar', methods=['POST'])
@token_required
def upload_avatar(current_user):
    try:
        file = request.files['file']
        filename = validate_file(file)
        file.save(os.path.join(UPLOAD_DIR, filename))
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
```

## Practice Exercises

1. **Negative-amount transfer**
   - Call `/api/transfer` with `{"to_user_id": <victim>, "amount": -1000}` and observe the balances.
   - Explain why the `current_user.balance < amount` check fails to stop it, and propose the missing guard.

2. **SQL injection in transaction queries**
   - Exploit `/api/transactions?user_id=...` (numeric context) to read other users' transactions.
   - Exploit `/api/transactions/search?description=...` (string/LIKE context), including a UNION that matches the 8-column result set.
   - Rewrite both with parameterized queries.

3. **Pull-from-any-account business-logic flaw**
   - Inspect `split_bill` (`backend/routes/transaction_routes.py:199-213`): `from_user_id` comes from the request body and is never checked against `current_user` (CWE-639 / CWE-840).
   - Send a request with another user's id as `from_user_id` and confirm you can debit *any* account.
   - Propose the ownership check that ties the payer to the authenticated user.

## Additional Resources

1. [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
2. [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
3. [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments.
</content>
</invoke>
