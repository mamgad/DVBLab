# Module 1: SQL Injection Vulnerabilities

## Overview
SQL Injection is a critical vulnerability that occurs when user input is directly concatenated into SQL queries without proper sanitization. This module examines a real SQL injection vulnerability in our banking application's login functionality.

## Vulnerable Code Example
From our `auth_routes.py`:

```python
@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    
    # Vulnerable SQL query
    query = f"SELECT * FROM user WHERE username = '{username}'"
    user = db.session.execute(query).fetchone()
```

## Why It's Vulnerable
1. Direct string concatenation in SQL query
2. No input validation or sanitization
3. No use of parameterized queries

## Proof of Concept (PoC)

### Attack 1: Authentication Bypass
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "' OR '1'='1", "password": "anything"}'
```

This works because the resulting SQL query becomes:
```sql
SELECT * FROM user WHERE username = '' OR '1'='1'
```

### Attack 2: Data Extraction
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice' UNION SELECT 1,2,3,4,5,6,7,8,9 FROM user--", "password": "anything"}'
```

## Impact
1. Unauthorized access to accounts
2. Data breach potential
3. System compromise
4. Financial fraud potential

## Secure Implementation
Here's how the code should be written:

```python
@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    
    # Secure query using SQLAlchemy
    user = User.query.filter_by(username=username).first()
```

Or using parameterized queries:

```python
@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    
    # Secure parameterized query
    query = "SELECT * FROM user WHERE username = :username"
    user = db.session.execute(query, {'username': username}).fetchone()
```

## Prevention Techniques
1. Use ORM methods whenever possible
2. Implement parameterized queries
3. Input validation and sanitization
4. Principle of least privilege for database users
5. Regular security audits

## Additional Security Measures
1. Implement input validation:
```python
def validate_username(username):
    if not username or not isinstance(username, str):
        return False
    if len(username) > 80:  # Match database column length
        return False
    if not username.isalnum():  # Only allow alphanumeric
        return False
    return True
```

2. Add rate limiting:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)
```

## Practice Exercise
1. Find other potential SQL injection points in the application
2. Write PoCs for different SQL injection techniques
3. Implement fixes for the vulnerabilities
4. Create automated tests to prevent regression

## Additional Resources
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/) 