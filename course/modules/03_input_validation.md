# Module 3: Input Validation & Sanitization

## Overview
This module examines input validation vulnerabilities in our banking application, focusing on transaction amounts, user input handling, and data type conversion issues.

## Vulnerable Code Examples

### 1. Insufficient Transaction Amount Validation
From our `transaction_routes.py`:

```python
@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    amount = Decimal(str(data.get('amount', 0)))  # Unsafe conversion
    description = data.get('description', '')
    
    # No validation of amount
    transaction = Transaction(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        amount=amount,
        description=description
    )
```

Issues:
1. No validation of amount value
2. Unsafe decimal conversion
3. No check for negative amounts
4. No balance verification before transfer

### 2. Unsafe User Input Handling
From our `auth_routes.py`:

```python
@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User(username=username)  # No validation
    user.set_password(password)     # No password strength check
```

## Proof of Concept (PoC)

### Attack 1: Negative Amount Transfer
```bash
curl -X POST http://localhost:5000/api/transfer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <valid_token>" \
  -d '{
    "receiver_id": 2,
    "amount": -1000.00,
    "description": "Negative amount transfer"
  }'
```

### Attack 2: Balance Overflow
```bash
curl -X POST http://localhost:5000/api/transfer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <valid_token>" \
  -d '{
    "receiver_id": 2,
    "amount": 999999999999999.99,
    "description": "Overflow attempt"
  }'
```

## Impact
1. Financial fraud
2. Account balance manipulation
3. System integrity compromise
4. Data corruption

## Secure Implementation

### 1. Proper Transaction Validation
```python
from decimal import Decimal, InvalidOperation
from typing import Optional

def validate_amount(amount: str) -> Optional[Decimal]:
    try:
        amount_decimal = Decimal(str(amount))
        
        # Amount must be positive and within reasonable limits
        if amount_decimal <= 0:
            return None
        if amount_decimal > Decimal('1000000.00'):  # Business limit
            return None
            
        # Ensure only 2 decimal places
        if amount_decimal.as_tuple().exponent < -2:
            return None
            
        return amount_decimal
    except (InvalidOperation, ValueError):
        return None

@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    amount = validate_amount(data.get('amount'))
    
    if amount is None:
        return jsonify({'error': 'Invalid amount'}), 400
        
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Proceed with transfer
```

### 2. Proper Input Validation
```python
def validate_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not 3 <= len(username) <= 80:
        return False
    if not username.isalnum():
        return False
    return True

def validate_password(password: str) -> tuple[bool, str]:
    if not isinstance(password, str):
        return False, "Invalid password type"
    if len(password) < 8:
        return False, "Password too short"
    if len(password) > 128:
        return False, "Password too long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain number"
    return True, ""

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not validate_username(username):
        return jsonify({'error': 'Invalid username'}), 400
        
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
```

## Prevention Techniques
1. Input Validation:
   - Type checking
   - Range validation
   - Format validation
   - Size limits
   - Character set restrictions

2. Data Sanitization:
   - HTML escaping
   - SQL escaping
   - Proper encoding

3. Error Handling:
```python
def safe_decimal_convert(value: str) -> Optional[Decimal]:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
```

## Practice Exercise
1. Implement comprehensive input validation for all API endpoints
2. Add transaction amount validation with business rules
3. Create password strength requirements
4. Implement proper error handling

## Additional Resources
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Python Decimal Documentation](https://docs.python.org/3/library/decimal.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) 