# Module 0: Security Assessment Methodology

## Overview
Before diving into specific vulnerabilities, it's crucial to understand how to systematically approach security assessment of a web application. This module covers threat modeling, identifying critical paths, and methodologies for finding vulnerabilities.

## 1. Understanding the Application

### 1.1 Application Architecture
Our banking application consists of:
```
Backend (Flask)                Frontend (React)
├── API Endpoints             ├── Components
├── Database Models           ├── State Management
├── Authentication           ├── API Integration
└── Business Logic           └── User Interface
```

### 1.2 Critical Functions
1. Money Transfer System
   - Fund transfers between accounts
   - Balance management
   - Transaction history

2. User Authentication
   - Login/Registration
   - Session management
   - Password handling

3. Account Management
   - Profile updates
   - Balance viewing
   - Transaction history access

## 2. Threat Modeling

### 2.1 STRIDE Analysis
1. **Spoofing**
   - Impersonating other users
   - Session hijacking
   - Token theft

2. **Tampering**
   - Modifying transaction amounts
   - Altering transaction history
   - Manipulating API responses

3. **Repudiation**
   - Denying transactions
   - Lack of audit logs
   - Insufficient transaction tracking

4. **Information Disclosure**
   - Exposing user data
   - Leaking transaction details
   - Revealing system information

5. **Denial of Service**
   - Overwhelming transaction system
   - Database connection exhaustion
   - API rate limiting bypass

6. **Elevation of Privilege**
   - Accessing admin functions
   - Bypassing authorization
   - Exploiting IDOR vulnerabilities

### 2.2 Attack Trees
Example for Money Transfer:
```
Goal: Unauthorized Money Transfer
├── Authentication Bypass
│   ├── SQL Injection in login
│   ├── Session hijacking
│   └── Token manipulation
├── Authorization Bypass
│   ├── IDOR exploitation
│   ├── Missing access controls
│   └── Role manipulation
└── Transaction Manipulation
    ├── Negative amounts
    ├── Race conditions
    └── Decimal precision attacks
```

## 3. Source-to-Sink Analysis

### 3.1 Identifying Sources (User Input)
```python
# Example sources in our application
sources = {
    'HTTP Parameters': [
        request.args.get('user_id'),
        request.form['amount']
    ],
    'HTTP Headers': [
        request.headers['Authorization'],
        request.headers['Content-Type']
    ],
    'Request Body': [
        request.get_json(),
        request.data
    ],
    'File Uploads': [
        request.files['document']
    ]
}
```

### 3.2 Identifying Sinks (Dangerous Operations)
```python
# Example sinks in our application
sinks = {
    'SQL Operations': [
        'db.session.execute(query)',
        'User.query.filter_by()'
    ],
    'File Operations': [
        'open(filename, "w")',
        'file.write()'
    ],
    'Command Execution': [
        'os.system()',
        'subprocess.run()'
    ],
    'Financial Operations': [
        'update_balance()',
        'process_transfer()'
    ]
}
```

### 3.3 Tracing Data Flow
Example trace for transfer functionality:
```python
# Source: User input
amount = request.json.get('amount')  # SOURCE

# Data flow
amount = Decimal(str(amount))        # Transformation
validate_amount(amount)              # Validation
current_user.balance -= amount       # Business Logic

# Sink: Database operation
db.session.commit()                  # SINK
```

## 4. Risk Assessment Matrix

### 4.1 Impact vs Likelihood
```
Impact │ High    Med    Low
────────────────────────────
High   │  1      2      3
Med    │  2      3      4
Low    │  3      4      5

Priority 1 (Critical):
- SQL Injection in login
- Unauthorized transfers
- Token manipulation

Priority 2 (High):
- IDOR vulnerabilities
- Input validation bypass
- Rate limiting bypass
```

## 5. Testing Methodology

### 5.1 Static Analysis
1. Code Review Process:
   ```python
   # Example checklist for each endpoint
   def review_endpoint(endpoint):
       check_input_validation()
       check_authentication()
       check_authorization()
       check_business_logic()
       check_data_sanitization()
       check_error_handling()
   ```

### 5.2 Dynamic Analysis
1. Manual Testing:
   ```bash
   # Example test cases
   # 1. Authentication bypass
   curl -X POST http://localhost:5000/api/login \
     -d '{"username": "admin"; --"}'

   # 2. IDOR test
   curl http://localhost:5000/api/transactions/123 \
     -H "Authorization: Bearer <token>"
   ```

2. Automated Testing:
   ```python
   def test_security_controls():
       test_sql_injection()
       test_xss_vectors()
       test_csrf_protection()
       test_rate_limiting()
       test_input_validation()
   ```

## 6. Security Assessment Checklist

### 6.1 Pre-assessment
- [ ] Understand application architecture
- [ ] Identify critical functions
- [ ] Create threat model
- [ ] Map attack surface

### 6.2 Assessment
- [ ] Review authentication mechanisms
- [ ] Check authorization controls
- [ ] Validate input handling
- [ ] Test business logic
- [ ] Verify error handling
- [ ] Check data encryption
- [ ] Review API security

### 6.3 Post-assessment
- [ ] Prioritize findings
- [ ] Verify fixes
- [ ] Document recommendations
- [ ] Create security roadmap

## Practice Exercise
1. Create a threat model for the user registration process
2. Build an attack tree for the password reset functionality
3. Perform source-to-sink analysis on the transfer function
4. Create a risk assessment matrix for identified vulnerabilities

## Additional Resources
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft STRIDE Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) 