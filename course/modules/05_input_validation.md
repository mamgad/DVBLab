# Module 5: Input Validation & Sanitization

## Understanding Input Validation

### What is Input Validation?
Input validation is the process of ensuring that application data meets specific criteria before processing. Think of it like a bouncer at a club:
- Checks IDs (data format)
- Enforces dress code (data content)
- Maintains capacity limits (data size)
- Prevents troublemakers (malicious input)

### Types of Input Validation

1. **Syntactic Validation**
   - Data type checks (string, number, date)
   - Format validation (email, phone, ZIP)
   - Length restrictions
   - Range checks

2. **Semantic Validation**
   - Business rule compliance
   - Data consistency
   - Cross-field validation
   - State validation

3. **Content Validation**
   - Character set restrictions
   - Allowed patterns
   - Blacklist/whitelist
   - File type validation

### Common Input Validation Vulnerabilities

1. **Missing Validation**
   - Unchecked user input
   - Raw data processing
   - Implicit trust in client data
   - No boundary checks

2. **Incomplete Validation**
   - Single quote escaping only
   - Basic length checks only
   - Front-end validation only
   - Partial sanitization

3. **Incorrect Validation**
   - Wrong regex patterns
   - Improper encoding
   - Mishandled character sets
   - Flawed sanitization logic

## DVBank Input Validation Vulnerabilities

### 1. Transaction Amount Validation
**Location**: `backend/routes/transaction_routes.py`
```python
@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    amount = request.json.get('amount')
    # No type checking
    # No negative amount check
    # No decimal precision check
    
    execute_transfer(
        from_account=request.json.get('from_account'),
        to_account=request.json.get('to_account'),
        amount=amount
    )
```

**Impact**:
- Negative transfers possible
- Integer overflow attacks
- Precision-based attacks
- Account balance manipulation

**Exploitation**:
```python
# Negative amount transfer
payload = {
    'from_account': '1234',
    'to_account': '5678',
    'amount': -1000  # Steal money
}

# Precision attack
payload = {
    'amount': 10.999999999  # Round-off error
}
```

### 2. Profile Data Validation
**Location**: `backend/routes/user_routes.py`
```python
@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    # No input sanitization
    name = request.json.get('name')
    email = request.json.get('email')
    bio = request.json.get('bio')
    
    user.update_profile(name, email, bio)
```

**Impact**:
- XSS via profile fields
- SQL injection possible
- HTML injection in bio
- Email validation bypass

**Exploitation**:
```python
# XSS in bio
payload = {
    'bio': '<script>alert(document.cookie)</script>'
}

# Invalid email
payload = {
    'email': 'not-an-email'
}
```

### 3. File Upload Validation
**Location**: `backend/routes/document_routes.py`
```python
@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    file = request.files['document']
    # No file type validation
    # No size validation
    # No content check
    
    filename = file.filename  # Direct use of user input
    file.save(f'uploads/{filename}')
```

**Impact**:
- Arbitrary file upload
- Path traversal
- Malware upload
- Storage overflow

**Exploitation**:
```python
# Path traversal
filename = '../../../etc/passwd'

# Malicious file type
filename = 'malware.exe'
```

## Prevention Methods

### 1. Proper Amount Validation
```python
def validate_amount(amount):
    try:
        # Convert to decimal for precision
        amount = Decimal(str(amount))
        
        # Check constraints
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount.as_tuple().exponent < -2:
            raise ValueError("Maximum 2 decimal places")
            
        return amount
    except (ValueError, DecimalException) as e:
        raise ValidationError(str(e))

@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    try:
        amount = validate_amount(request.json.get('amount'))
        execute_transfer(amount=amount)
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
```

### 2. Input Sanitization
```python
from bleach import clean
from email_validator import validate_email, EmailNotValidError

def sanitize_profile_input(data):
    # Sanitize HTML content
    if 'bio' in data:
        data['bio'] = clean(
            data['bio'],
            tags=['p', 'br', 'strong', 'em'],
            attributes={},
            strip=True
        )
    
    # Validate email
    if 'email' in data:
        try:
            valid = validate_email(data['email'])
            data['email'] = valid.email
        except EmailNotValidError as e:
            raise ValidationError(str(e))
            
    return data

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    try:
        data = sanitize_profile_input(request.json)
        user.update_profile(**data)
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
```

### 3. Secure File Upload
```python
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_file(file):
    # Check file size
    if not file or not file.content_length:
        raise ValidationError("No file provided")
    if file.content_length > MAX_FILE_SIZE:
        raise ValidationError("File too large")
        
    # Check extension
    ext = os.path.splitext(file.filename)[1][1:].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError("File type not allowed")
        
    # Secure the filename
    filename = secure_filename(file.filename)
    return filename

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    try:
        file = request.files['document']
        filename = validate_file(file)
        
        # Save with secure name
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
```

## Practice Exercises

1. **Amount Validation in Transactions**
   - Test how the system handles negative transfer amounts
   - Attempt transfers exceeding reasonable limits to test range validation
   - Document the validation gaps and propose fixes for proper amount validation

2. **Transaction Input Sanitization**
   - Identify and exploit the SQL injection vulnerability in the transaction history feature
   - Test for XSS vulnerabilities in transaction descriptions and messages
   - Analyze how special characters are handled in transaction data
   - Create a list of input sanitization improvements needed

3. **User Input Validation**
   - Test the system's handling of invalid user IDs in transfer requests
   - Attempt self-transfers to identify missing validation checks
   - Probe for race conditions in concurrent transfers
   - Document all validation gaps found and their potential impact

Practice these exercises in the test environment to understand input validation vulnerabilities and their mitigations. For each vulnerability found, assess its potential impact on the system and propose secure validation methods.

## Additional Resources

1. [OWASP Input Validation Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
2. [File Upload Security Guide](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
3. [XSS Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
4. [Python Input Validation Libraries](https://pypi.org/project/validators/)
5. [SQLAlchemy Query API](https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql)
6. [Decimal Precision in Python](https://docs.python.org/3/library/decimal.html)
7. [OWASP Data Validation](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)
8. [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
9. [Unicode Security Guide](https://www.unicode.org/reports/tr36/)
10. [Regular Expression Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Regular_Expression_Security_Cheat_Sheet.html)

### Related Tools
1. [Bleach](https://bleach.readthedocs.io/) - Python HTML sanitization library
2. [Python-Validator](https://python-validator.readthedocs.io/) - Input validation framework
3. [Cerberus](https://docs.python-cerberus.org/) - Lightweight data validation library
4. [FastAPI's Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation using Python type annotations

### Industry Standards
1. [PCI DSS Input Validation Requirements](https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf)
2. [NIST Input Validation Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 
